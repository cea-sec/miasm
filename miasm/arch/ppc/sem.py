from __future__ import print_function
from builtins import range

import miasm.expression.expression as expr
from miasm.ir.ir import AssignBlock, Lifter, IRBlock
from miasm.arch.ppc.arch import mn_ppc
from miasm.arch.ppc.regs import *
from miasm.core.sembuilder import SemBuilder
from miasm.jitter.csts import *

spr_dict = {
    8: LR, 9: CTR, 18: DSISR, 19: DAR,
    22: DEC, 25: SDR1, 26: SRR0, 27: SRR1,
    272: SPRG0, 273: SPRG0, 274: SPRG1, 275: SPRG2, 276: SPRG3,
    284: TBL, 285: TBU, 287: PVR,
    528: IBAT0U, 529: IBAT0L, 530: IBAT1U, 531: IBAT1L, 532: IBAT2U, 533: IBAT2L, 534: IBAT3U, 535: IBAT3L,
    536: DBAT0U, 537: DBAT0L, 538: DBAT1U, 539: DBAT1L, 540: DBAT2U, 541: DBAT2L, 542: DBAT3U, 543: DBAT3L,
    1023: PIR
}

sr_dict = {
    0: SR0, 1: SR1, 2: SR2, 3: SR3,
    4: SR4, 5: SR5, 6: SR6, 7: SR7,
    8: SR8, 9: SR9, 10: SR10, 11: SR11,
    12: SR12, 13: SR13, 14: SR14, 15: SR15
}

float_dict = {
    0: FPR0, 1: FPR1, 2: FPR2, 3: FPR3, 4: FPR4, 5: FPR5, 6: FPR6, 7: FPR7, 8: FPR8,
    9: FPR9, 10: FPR10, 11: FPR11, 12: FPR12, 13: FPR13, 14: FPR14, 15: FPR15, 16: FPR16,
    17: FPR17, 18: FPR18, 19: FPR19, 20: FPR20, 21: FPR21, 22: FPR22, 23: FPR23, 24: FPR24,
    25: FPR25, 26: FPR26, 27: FPR27, 28: FPR28, 29: FPR29, 30: FPR30, 31: FPR31
}

vex_dict = {
    0: VR0, 1: VR1, 2: VR2, 3: VR3, 4: VR4, 5: VR5, 6: VR6, 7: VR7, 8: VR8,
    9: VR9, 10: VR10, 11: VR11, 12: VR12, 13: VR13, 14: VR14, 15: VR15, 16: VR16,
    17: VR17, 18: VR18, 19: VR19, 20: VR20, 21: VR21, 22: VR22, 23: VR23, 24: VR24,
    25: VR25, 26: VR26, 27: VR27, 28: VR28, 29: VR29, 30: VR30, 31: VR31,
}

crf_dict = dict((ExprId("CR%d" % i, 4),
                 dict( (bit, ExprId("CR%d_%s" % (i, bit), 1))
                       for bit in ['LT', 'GT', 'EQ', 'SO' ] ))
                for i in range(8) )

ctx = {
    'crf_dict': crf_dict,
    'spr_dict': spr_dict,
    'sr_dict': sr_dict,
    'float_dict': float_dict,
    'vex_dict': vex_dict,
    'expr': expr,
}

ctx.update(all_regs_ids_byname)
sbuild = SemBuilder(ctx)

def mn_compute_flags(rvalue, overflow_expr=None):
    ret = []
    ret.append(ExprAssign(CR0_LT, rvalue.msb()))
    ret.append(ExprAssign(CR0_GT, (ExprCond(rvalue, ExprInt(1, 1),
                                         ExprInt(0, 1)) & ~rvalue.msb())))
    ret.append(ExprAssign(CR0_EQ, ExprCond(rvalue, ExprInt(0, 1),
                                        ExprInt(1, 1))))
    if overflow_expr != None:
        ret.append(ExprAssign(CR0_SO, XER_SO | overflow_expr))
    else:
        ret.append(ExprAssign(CR0_SO, XER_SO))

    return ret

def mn_do_add(ir, instr, arg1, arg2, arg3):
    assert instr.name[0:3] == 'ADD'

    flags_update = []

    has_dot = False
    has_c = False
    has_e = False
    has_o = False

    for l in instr.name[3:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'E':
            has_e = True
        elif l == 'O':
            has_o = True
        elif l == 'I' or l == 'M' or l == 'S' or l == 'Z':
            pass	# Taken care of earlier
        else:
            assert False

    rvalue = arg2 + arg3

    if has_e:
        rvalue = rvalue + XER_CA.zeroExtend(32)

    over_expr = None
    if has_o:
        msb1 = arg2.msb()
        msb2 = arg3.msb()
        msba = rvalue.msb()
        over_expr = ~(msb1 ^ msb2) & (msb1 ^ msba)
        flags_update.append(ExprAssign(XER_OV, over_expr))
        flags_update.append(ExprAssign(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    if has_c or has_e:
        carry_expr = (((arg2 ^ arg3) ^ rvalue) ^
                      ((arg2 ^ rvalue) & (~(arg2 ^ arg3)))).msb()
        flags_update.append(ExprAssign(XER_CA, carry_expr))

    return ([ ExprAssign(arg1, rvalue) ] + flags_update), []

def mn_do_and(ir, instr, ra, rs, arg2):
    if len(instr.name) > 3 and instr.name[3] == 'C':
        oarg = ~arg2
    else:
        oarg = arg2

    rvalue = rs & oarg
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_cntlzw(ir, instr, ra, rs):
    ret = [ ExprAssign(ra, ExprOp('cntleadzeros', rs)) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def crbit_to_reg(bit):
    bit = int(bit)
    crid = bit // 4
    bitname = [ 'LT', 'GT', 'EQ', 'SO' ][bit % 4]
    return all_regs_ids_byname["CR%d_%s" % (crid, bitname)]

def mn_do_cr(ir, instr, crd, cra, crb):
    a = crbit_to_reg(cra)
    b = crbit_to_reg(crb)
    d = crbit_to_reg(crd)

    op = instr.name[2:]

    if op == 'AND':
        r = a & b
    elif op == 'ANDC':
        r = a & ~b
    elif op == 'EQV':
        r = ~(a ^ b)
    elif op == 'NAND':
        r = ~(a & b)
    elif op == 'NOR':
        r = ~(a | b)
    elif op == 'OR':
        r = a | b
    elif op == 'ORC':
        r = a | ~b
    elif op == 'XOR':
        r = a ^ b
    else:
        raise RuntimeError("Unknown operation on CR")
    return [ ExprAssign(d, r) ], []

def mn_do_div(ir, instr, rd, ra, rb):
    assert instr.name[0:4] == 'DIVW'

    flags_update = []

    has_dot = False
    has_c = False
    has_o = False
    has_u = False

    for l in instr.name[3:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'O':
            has_o = True
        elif l == 'U':
            has_u = True
        elif l == 'W':
            pass
        else:
            assert False

    if has_u:
        op = 'udiv'
    else:
        op = 'sdiv'

    rvalue = ExprOp(op, ra, rb)

    over_expr = None
    if has_o:
        over_expr = ExprCond(rb, ExprInt(0, 1), ExprInt(1, 1))
        if not has_u:
            over_expr = over_expr | (ExprCond(ra ^ 0x80000000, ExprInt(0, 1),
                                              ExprInt(1, 1)) &
                                     ExprCond(rb ^ 0xFFFFFFFF, ExprInt(0, 1),
                                              ExprInt(1, 1)))
        flags_update.append(ExprAssign(XER_OV, over_expr))
        flags_update.append(ExprAssign(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    return ([ ExprAssign(rd, rvalue) ] + flags_update), []


def mn_do_eqv(ir, instr, ra, rs, rb):
    rvalue = ~(rs ^ rb)
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_exts(ir, instr, ra, rs):
    if instr.name[4] == 'B':
        size = 8
    elif instr.name[4] == 'H':
        size = 16
    else:
        assert False

    rvalue = rs[0:size].signExtend(32)
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def byte_swap(expr):
    nbytes = expr.size // 8
    lbytes = [ expr[i*8:i*8+8] for i in range(nbytes - 1, -1, -1) ]
    return ExprCompose(*lbytes)

def mn_do_load(ir, instr, arg1, arg2, arg3=None):
    assert instr.name[0] == 'L'

    ret = []

    if instr.name[1] == 'M':
        return mn_do_lmw(ir, instr, arg1, arg2)
    elif instr.name[1] == 'S':
        raise RuntimeError("LSWI, and LSWX need implementing")
    elif instr.name[1] == 'F':
        print("Warning, instruction %s implemented as NOP" % instr)
        return  [], []
    elif instr.name[1] == 'V':
        print("Warning, instruction %s implemented as NOP" % instr)
        return [], []

    size = {'B': 8, 'H': 16, 'W': 32}[instr.name[1]]

    has_a = False
    has_b = False
    has_u = False
    is_lwarx = False

    for l in instr.name[2:]:
        if l == 'A':
            has_a = True
        elif l == 'B':
            has_b = True
        elif l == 'U':
            has_u = True
        elif l == 'X' or l == 'Z':
            pass	# Taken care of earlier
        elif l == 'R' and not has_b:
            is_lwarx = True
        else:
            assert False

    if arg3 is None:
        assert isinstance(arg2, ExprMem)

        address = arg2.ptr
    else:
        address = arg2 + arg3

    src = ExprMem(address, size)

    if has_b:
        src = byte_swap(src)

    if has_a:
        src = src.signExtend(32)
    else:
        src = src.zeroExtend(32)

    ret.append(ExprAssign(arg1, src))
    if has_u:
        if arg3 is None:
            ret.append(ExprAssign(arg2.ptr.args[0], address))
        else:
            ret.append(ExprAssign(arg2, address))

    if is_lwarx:
        ret.append(ExprAssign(reserve, ExprInt(1, 1)))
        ret.append(ExprAssign(reserve_address, address))	# XXX should be the PA

    return ret, []

def mn_do_lmw(ir, instr, rd, src):
    ret = []
    address = src.ptr
    ri = int(rd.name[1:],10)
    i = 0
    while ri <= 31:
        ret.append(ExprAssign(all_regs_ids_byname["R%d" % ri],
                           ExprMem(address + ExprInt(i, 32), 32)))
        ri += 1
        i += 4

    return ret, []

def mn_do_lswi(ir, instr, rd, ra, nb):
    if nb == 0:
        nb = 32
    i = 32
    raise RuntimeError("%r not implemented" % instr)

def mn_do_lswx(ir, instr, rd, ra, nb):
    raise RuntimeError("%r not implemented" % instr)

def mn_do_mcrf(ir, instr, crfd, crfs):
    ret = []

    for bit in [ 'LT', 'GT', 'EQ', 'SO' ]:
        d = all_regs_ids_byname["%s_%s" % (crfd, bit)]
        s = all_regs_ids_byname["%s_%s" % (crfs, bit)]
        ret.append(ExprAssign(d, s))

    return ret, []

def mn_do_mcrxr(ir, instr, crfd):
    ret = []

    for (bit, val) in [ ('LT', XER_SO), ('GT', XER_OV), ('EQ', XER_CA),
                        ('SO', ExprInt(0, 1)) ]:
        ret.append(ExprAssign(all_regs_ids_byname["%s_%s" % (crfd, bit)], val))

    return ret, []

def mn_do_mfcr(ir, instr, rd):
    return ([ ExprAssign(rd, ExprCompose(*[ all_regs_ids_byname["CR%d_%s" % (i, b)]
                                        for i in range(7, -1, -1)
                                        for b in ['SO', 'EQ', 'GT', 'LT']]))],
            [])

@sbuild.parse
def mn_mfmsr(rd):
    rd = MSR

def mn_mfspr(ir, instr, arg1, arg2):
    sprid = int(arg2)
    gprid = int(arg1.name[1:])
    if sprid in spr_dict:
        return [ ExprAssign(arg1, spr_dict[sprid]) ], []
    elif sprid == 1:		# XER
        return [ ExprAssign(arg1, ExprCompose(XER_BC, ExprInt(0, 22),
                                           XER_CA, XER_OV, XER_SO)) ], []
    else:
        return [ ExprAssign(spr_access,
                         ExprInt(((sprid << SPR_ACCESS_SPR_OFF) |
                                    (gprid << SPR_ACCESS_GPR_OFF)), 32)),
                 ExprAssign(exception_flags, ExprInt(EXCEPT_SPR_ACCESS, 32)) ], []

def mn_mtcrf(ir, instr, crm, rs):
    ret = []

    for i in range(8):
        if int(crm) & (1 << (7 - i)):
            j = (28 - 4 * i) + 3
            for b in ['LT', 'GT', 'EQ', 'SO']:
                ret.append(ExprAssign(all_regs_ids_byname["CR%d_%s" % (i, b)],
                                   rs[j:j+1]))
                j -= 1

    return ret, []

def mn_mtmsr(ir, instr, rs):
    print("%08x: MSR assigned" % instr.offset)
    return [ ExprAssign(MSR, rs) ], []

def mn_mtspr(ir, instr, arg1, arg2):
    sprid = int(arg1)
    gprid = int(arg2.name[1:])
    if sprid in spr_dict:
        return [ ExprAssign(spr_dict[sprid], arg2) ], []
    elif sprid == 1:		# XER
        return [ ExprAssign(XER_SO, arg2[31:32]),
                 ExprAssign(XER_OV, arg2[30:31]),
                 ExprAssign(XER_CA, arg2[29:30]),
                 ExprAssign(XER_BC, arg2[0:7]) ], []
    else:
        return [ ExprAssign(spr_access,
                         ExprInt(((sprid << SPR_ACCESS_SPR_OFF) |
                                    (gprid << SPR_ACCESS_GPR_OFF) |
                                    SPR_ACCESS_IS_WRITE), 32)),
                 ExprAssign(exception_flags, ExprInt(EXCEPT_SPR_ACCESS, 32)) ], []

def mn_mtsr(ir, instr, sr, rs):
    srid = sr.arg
    return [ ExprAssign(sr_dict[srid], rs) ], []

# TODO
#def mn_mtsrin(ir, instr, rs, rb):
#    return [ ExprAssign(sr_dict[rb[0:3]], rs) ], []

def mn_mfsr(ir, instr, rd, sr):
    srid = sr.arg
    return [ ExprAssign(rd, sr_dict[srid]) ], []

# TODO
#def mn_mfsrin(ir, instr, rd, rb):
#    return [ ExprAssign(rd, sr_dict[rb[0:3]]) ], []

def mn_do_mul(ir, instr, rd, ra, arg2):
    variant = instr.name[3:]
    if variant[-1] == '.':
        variant = variant[:-2]

    if variant == 'HW':
        v1 = ra.signExtend(64)
        v2 = arg2.signExtend(64)
        shift = 32
    elif variant == 'HWU':
        v1 = ra.zeroExtend(64)
        v2 = arg2.zeroExtend(64)
        shift = 32
    else:
        v1 = ra
        v2 = arg2
        shift = 0

    rvalue = ExprOp('*', v1, v2)
    if shift != 0:
        rvalue = rvalue[shift : shift + 32]

    ret = [ ExprAssign(rd, rvalue) ]

    over_expr = None
    if variant[-1] == 'O':
        over_expr = ExprCond((rvalue.signExtend(64) ^
                              ExprOp('*', v1.signExtend(64),
                                     v2.signExtend(64))),
                             ExprInt(1, 1), ExprInt(0, 1))
        ret.append(ExprAssign(XER_OV, over_expr))
        ret.append(ExprAssign(XER_SO, XER_SO | over_expr))

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue, over_expr)

    return ret, []

def mn_do_nand(ir, instr, ra, rs, rb):
    rvalue = ~(rs & rb)
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_neg(ir, instr, rd, ra):
    rvalue = -ra
    ret = [ ExprAssign(rd, rvalue) ]
    has_o = False

    over_expr = None
    if instr.name[-1] == 'O' or instr.name[-2] == 'O':
        has_o = True
        over_expr = ExprCond(ra ^ ExprInt(0x80000000, 32),
                             ExprInt(0, 1), ExprInt(1, 1))
        ret.append(ExprAssign(XER_OV, over_expr))
        ret.append(ExprAssign(XER_SO, XER_SO | over_expr))

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue, over_expr)

    return ret, []

def mn_do_nor(ir, instr, ra, rs, rb):

    rvalue = ~(rs | rb)
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_or(ir, instr, ra, rs, arg2):
    if len(instr.name) > 2 and instr.name[2] == 'C':
        oarg = ~arg2
    else:
        oarg = arg2

    rvalue = rs | oarg
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_rfi(ir, instr):
    dest = ExprCompose(ExprInt(0, 2), SRR0[2:32])
    ret = [ ExprAssign(MSR, (MSR &
                          ~ExprInt(0b1111111101110011, 32) |
                          ExprCompose(SRR1[0:2], ExprInt(0, 2),
                                      SRR1[4:7], ExprInt(0, 1),
                                      SRR1[8:16], ExprInt(0, 16)))),
            ExprAssign(PC, dest),
            ExprAssign(ir.IRDst, dest) ]
    return ret, []

def mn_do_rotate(ir, instr, ra, rs, shift, mb, me):
    r = ExprOp('<<<', rs, shift)
    if mb <= me:
        m = ExprInt(((1 << (32 - mb)) - 1) & ~((1 << (32 - me - 1)) - 1), 32)
    else:
        m = ExprInt(((1 << (32 - mb)) - 1) | ~((1 << (32 - me - 1)) - 1), 32)
    rvalue = r & m
    if instr.name[0:6] == 'RLWIMI':
        rvalue = rvalue | (ra & ~m)

    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_slw(ir, instr, ra, rs, rb):

    rvalue = ExprCond(rb[5:6], ExprInt(0, 32),
                      ExprOp('<<', rs, rb & ExprInt(0b11111, 32)))
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_sraw(ir, instr, ra, rs, rb):
    rvalue = ExprCond(rb[5:6], ExprInt(0xFFFFFFFF, 32),
                      ExprOp('a>>', rs, rb & ExprInt(0b11111, 32)))
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    mask = ExprCond(rb[5:6], ExprInt(0xFFFFFFFF, 32),
                    (ExprInt(0xFFFFFFFF, 32) >>
                     (ExprInt(32, 32) - (rb & ExprInt(0b11111, 32)))))
    ret.append(ExprAssign(XER_CA, rs.msb() &
                       ExprCond(rs & mask, ExprInt(1, 1), ExprInt(0, 1))))

    return ret, []

def mn_do_srawi(ir, instr, ra, rs, imm):
    rvalue = ExprOp('a>>', rs, imm)
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    mask = ExprInt(0xFFFFFFFF >> (32 - int(imm)), 32)

    ret.append(ExprAssign(XER_CA, rs.msb() &
                       ExprCond(rs & mask, ExprInt(1, 1), ExprInt(0, 1))))

    return ret, []

def mn_do_srw(ir, instr, ra, rs, rb):
    rvalue = rs >> (rb & ExprInt(0b11111, 32))
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_do_stmw(ir, instr, rs, dest):
    ret = []
    address = dest.ptr
    ri = int(rs.name[1:],10)
    i = 0
    while ri <= 31:
        ret.append(ExprAssign(ExprMem(address + ExprInt(i,32), 32),
                           all_regs_ids_byname["R%d" % ri]))
        ri += 1
        i += 4

    return ret, []

def mn_do_store(ir, instr, arg1, arg2, arg3=None):
    assert instr.name[0:2] == 'ST'

    ret = []
    additional_ir = []

    if instr.name[2] == 'S':
        raise RuntimeError("STSWI, and STSWX need implementing")
    elif instr.name[2] == 'F':
        print("Warning, instruction %s implemented as NOP" % instr)
        return  [], []

    size = {'B': 8, 'H': 16, 'W': 32}[instr.name[2]]

    has_b = False
    has_u = False
    is_stwcx = False

    for l in instr.name[3:]:
        if l == 'B' or l == 'R':
            has_b = True
        elif l == 'U':
            has_u = True
        elif l == 'X' or l == 'Z':
            pass	# Taken care of earlier
        elif l == 'C' or l == '.':
            is_stwcx = True
        else:
            assert False

    if arg3 is None:
        assert isinstance(arg2, ExprMem)

        address = arg2.ptr
    else:
        address = arg2 + arg3

    dest = ExprMem(address, size)

    src = arg1[0:size]
    if has_b:
        src = byte_swap(src)

    ret.append(ExprAssign(dest, src))
    if has_u:
        if arg3 is None:
            ret.append(ExprAssign(arg2.ptr.args[0], address))
        else:
            ret.append(ExprAssign(arg2, address))

    if is_stwcx:
        loc_do = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
        loc_dont = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
        loc_next = ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)
        flags = [ ExprAssign(CR0_LT, ExprInt(0,1)),
                  ExprAssign(CR0_GT, ExprInt(0,1)),
                  ExprAssign(CR0_SO, XER_SO)]
        ret += flags
        ret.append(ExprAssign(CR0_EQ, ExprInt(1,1)))
        ret.append(ExprAssign(ir.IRDst, loc_next))
        dont = flags + [ ExprAssign(CR0_EQ, ExprInt(0,1)),
                         ExprAssign(ir.IRDst, loc_next) ]
        additional_ir = [ IRBlock(ir.loc_db, loc_do.loc_key, [ AssignBlock(ret) ]),
                          IRBlock(ir.loc_db, loc_dont.loc_key, [ AssignBlock(dont) ]) ]
        ret = [ ExprAssign(reserve, ExprInt(0, 1)),
                ExprAssign(ir.IRDst, ExprCond(reserve, loc_do, loc_dont)) ]

    return ret, additional_ir

def mn_do_sub(ir, instr, arg1, arg2, arg3):
    assert instr.name[0:4] == 'SUBF'

    flags_update = []

    has_dot = False
    has_c = False
    has_e = False
    has_o = False

    for l in instr.name[4:]:
        if l == '.':
            has_dot = True
        elif l == 'C':
            has_c = True
        elif l == 'E':
            has_e = True
        elif l == 'O':
            has_o = True
        elif l == 'I' or l == 'M' or l == 'S' or l == 'Z':
            pass	# Taken care of earlier
        else:
            assert False

    if has_e:
        arg3 = arg3 + XER_CA.zeroExtend(32)
        arg2 = arg2 + ExprInt(1, 32)

    rvalue = arg3 - arg2

    over_expr = None
    if has_o:
        msb1 = arg2.msb()
        msb2 = arg3.msb()
        msba = rvalue.msb()
        over_expr = (msb1 ^ msb2) & (msb1 ^ msba)
        flags_update.append(ExprAssign(XER_OV, over_expr))
        flags_update.append(ExprAssign(XER_SO, XER_SO | over_expr))

    if has_dot:
        flags_update += mn_compute_flags(rvalue, over_expr)

    if has_c or has_e:
        carry_expr = ((((arg3 ^ arg2) ^ rvalue) ^
                       ((arg3 ^ rvalue) & (arg3 ^ arg2))).msb())
        flags_update.append(ExprAssign(XER_CA, ~carry_expr))

    return ([ ExprAssign(arg1, rvalue) ] + flags_update), []

def mn_do_xor(ir, instr, ra, rs, rb):
    rvalue = rs ^ rb
    ret = [ ExprAssign(ra, rvalue) ]

    if instr.name[-1] == '.':
        ret += mn_compute_flags(rvalue)

    return ret, []

def mn_b(ir, instr, arg1, arg2 = None):
    if arg2 is not None:
        arg1 = arg2
    return [ ExprAssign(PC, arg1), ExprAssign(ir.IRDst, arg1) ], []

def mn_bl(ir, instr, arg1, arg2 = None):
    if arg2 is not None:
        arg1 = arg2
    dst = ir.get_next_instr(instr)
    return [ ExprAssign(LR, ExprLoc(dst, 32)),
             ExprAssign(PC, arg1),
             ExprAssign(ir.IRDst, arg1) ], []

def mn_get_condition(instr):
    bit = instr.additional_info.bi & 0b11
    cr = instr.args[0].name
    return all_regs_ids_byname[cr + '_' + ['LT', 'GT', 'EQ', 'SO'][bit]]

def mn_do_cond_branch(ir, instr, dest):
    bo = instr.additional_info.bo
    bi = instr.additional_info.bi
    ret = []

    if bo & 0b00100:
        ctr_cond = True
    else:
        ret.append(ExprAssign(CTR, CTR - ExprInt(1, 32)))
        ctr_cond = ExprCond(CTR ^ ExprInt(1, 32), ExprInt(1, 1), ExprInt(0, 1))
        if bo & 0b00010:
            ctr_cond = ~ctr_cond

    if (bo & 0b10000):
        cond_cond = True
    else:
        cond_cond = mn_get_condition(instr)
        if not (bo & 0b01000):
            cond_cond = ~cond_cond

    if ctr_cond != True or cond_cond != True:
        if ctr_cond != True:
            condition = ctr_cond
            if cond_cond != True:
                condition = condition & cond_cond
        else:
            condition = cond_cond
        dst = ir.get_next_instr(instr)
        dest_expr = ExprCond(condition, dest,
                             ExprLoc(dst, 32))
    else:
        dest_expr = dest

    if instr.name[-1] == 'L' or instr.name[-2:-1] == 'LA':
        dst = ir.get_next_instr(instr)
        ret.append(ExprAssign(LR, ExprLoc(dst, 32)))

    ret.append(ExprAssign(PC, dest_expr))
    ret.append(ExprAssign(ir.IRDst, dest_expr))

    return ret, []

def mn_do_nop_warn(ir, instr, *args):
    print("Warning, instruction %s implemented as NOP" % instr)
    return [], []

@sbuild.parse
def mn_cmp_signed(arg1, arg2, arg3):
    crf_dict[arg1]['LT'] = expr.ExprOp(expr.TOK_INF_SIGNED, arg2, arg3)
    crf_dict[arg1]['GT'] = expr.ExprOp(expr.TOK_INF_SIGNED, arg3, arg2)
    crf_dict[arg1]['EQ'] = expr.ExprOp(expr.TOK_EQUAL, arg2, arg3)
    crf_dict[arg1]['SO'] = XER_SO

@sbuild.parse
def mn_cmp_unsigned(arg1, arg2, arg3):
    crf_dict[arg1]['LT'] = expr.ExprOp(expr.TOK_INF_UNSIGNED, arg2, arg3)
    crf_dict[arg1]['GT'] = expr.ExprOp(expr.TOK_INF_UNSIGNED, arg3, arg2)
    crf_dict[arg1]['EQ'] = expr.ExprOp(expr.TOK_EQUAL, arg2, arg3)
    crf_dict[arg1]['SO'] = XER_SO

def mn_nop(ir, instr, *args):
    return [], []

@sbuild.parse
def mn_or(arg1, arg2, arg3):
    arg1 = arg2 | arg3

@sbuild.parse
def mn_assign(arg1, arg2):
    arg2 = arg1

def mn_stb(ir, instr, arg1, arg2):
    dest = ExprMem(arg2.arg, 8)
    return [ExprAssign(dest, ExprSlice(arg1, 0, 8))], []

@sbuild.parse
def mn_stwu(arg1, arg2):
    arg2 = arg1
    arg1 = arg2.arg

sem_dir = {
    'B': mn_b,
    'BA': mn_b,
    'BL': mn_bl,
    'BLA': mn_bl,
    'CMPLW': mn_cmp_unsigned,
    'CMPLWI': mn_cmp_unsigned,
    'CMPW': mn_cmp_signed,
    'CMPWI': mn_cmp_signed,
    'CNTLZW': mn_do_cntlzw,
    'CNTLZW.': mn_do_cntlzw,
    'ECIWX': mn_do_nop_warn,
    'ECOWX': mn_do_nop_warn,
    'EIEIO': mn_do_nop_warn,
    'EQV': mn_do_eqv,
    'EQV.': mn_do_eqv,
    'ICBI': mn_do_nop_warn,
    'ISYNC': mn_do_nop_warn,
    'MCRF': mn_do_mcrf,
    'MCRXR': mn_do_mcrxr,
    'MFCR': mn_do_mfcr,
    'MFFS': mn_do_nop_warn,
    'MFFS.': mn_do_nop_warn,
    'MFMSR': mn_mfmsr,
    'MFSPR': mn_mfspr,
    'MFSR': mn_mfsr,
    'MFSRIN': mn_do_nop_warn,
    'MTFSF': mn_do_nop_warn,
    'MTFSF.': mn_do_nop_warn,
    'MFTB': mn_mfspr,
    'MTCRF': mn_mtcrf,
    'MTMSR': mn_mtmsr,
    'MTSPR': mn_mtspr,
    'MTSR': mn_mtsr,
    'MTSRIN': mn_do_nop_warn,
    'MTVSCR': mn_do_nop_warn,
    'NAND': mn_do_nand,
    'NAND.': mn_do_nand,
    'NOR': mn_do_nor,
    'NOR.': mn_do_nor,
    'RFI': mn_do_rfi,
    'SC': mn_do_nop_warn,
    'SLW': mn_do_slw,
    'SLW.': mn_do_slw,
    'SRAW': mn_do_sraw,
    'SRAW.': mn_do_sraw,
    'SRAWI': mn_do_srawi,
    'SRAWI.': mn_do_srawi,
    'SRW': mn_do_srw,
    'SRW.': mn_do_srw,
    'SYNC': mn_do_nop_warn,
    'TLBIA': mn_do_nop_warn,
    'TLBIE': mn_do_nop_warn,
    'TLBSYNC': mn_do_nop_warn,
    'TW': mn_do_nop_warn,
    'TWI': mn_do_nop_warn,
}


class Lifter_PPC32b(Lifter):

    def __init__(self, loc_db):
        super(Lifter_PPC32b, self).__init__(mn_ppc, 'b', loc_db)
        self.pc = mn_ppc.getpc()
        self.sp = mn_ppc.getsp()
        self.IRDst = expr.ExprId('IRDst', 32)
        self.addrsize = 32

    def get_ir(self, instr):
        args = instr.args[:]
        if instr.name[0:5] in [ 'ADDIS', 'ORIS', 'XORIS', 'ANDIS' ]:
            args[2] = ExprInt(int(args[2]) << 16, 32)
        if instr.name[0:3] == 'ADD':
            if instr.name[0:4] == 'ADDZ':
                last_arg = ExprInt(0, 32)
            elif instr.name[0:4] == 'ADDM':
                last_arg = ExprInt(0xFFFFFFFF, 32)
            else:
                last_arg = args[2]
            instr_ir, extra_ir = mn_do_add(self, instr, args[0], args[1],
                                           last_arg)
        elif instr.name[0:3] == 'AND':
            instr_ir, extra_ir = mn_do_and(self, instr, *args)
        elif instr.additional_info.bo_bi_are_defined:
            name = instr.name
            if name[-1] == '+' or name[-1] == '-':
                name = name[0:-1]
            if name[-3:] == 'CTR' or name[-4:] == 'CTRL':
                arg1 = ExprCompose(ExprInt(0, 2), CTR[2:32])
            elif name[-2:] == 'LR' or name[-3:] == 'LRL':
                arg1 = ExprCompose(ExprInt(0, 2), LR[2:32])
            else:
                arg1 = args[1]
            instr_ir, extra_ir = mn_do_cond_branch(self, instr, arg1)
        elif instr.name[0:2] == 'CR':
            instr_ir, extra_ir = mn_do_cr(self, instr, *args)
        elif instr.name[0:3] == 'DCB':
            instr_ir, extra_ir = mn_do_nop_warn(self, instr, *args)
        elif instr.name[0:3] == 'DIV':
            instr_ir, extra_ir = mn_do_div(self, instr, *args)
        elif instr.name[0:4] == 'EXTS':
            instr_ir, extra_ir = mn_do_exts(self, instr, *args)
        elif instr.name[0] == 'L':
            instr_ir, extra_ir = mn_do_load(self, instr, *args)
        elif instr.name[0:3] == 'MUL':
            instr_ir, extra_ir = mn_do_mul(self, instr, *args)
        elif instr.name[0:3] == 'NEG':
            instr_ir, extra_ir = mn_do_neg(self, instr, *args)
        elif instr.name[0:2] == 'OR':
            instr_ir, extra_ir = mn_do_or(self, instr, *args)
        elif instr.name[0:2] == 'RL':
            instr_ir, extra_ir = mn_do_rotate(self, instr, args[0], args[1],
                                              args[2], int(args[3]),
                                              int(args[4]))
        elif instr.name == 'STMW':
            instr_ir, extra_ir = mn_do_stmw(self, instr, *args)
        elif instr.name[0:2] == 'ST':
            instr_ir, extra_ir = mn_do_store(self, instr, *args)
        elif instr.name[0:4] == 'SUBF':
            if instr.name[0:5] == 'SUBFZ':
                last_arg = ExprInt(0, 32)
            elif instr.name[0:5] == 'SUBFM':
                last_arg = ExprInt(0xFFFFFFFF, 32)
            else:
                last_arg = args[2]
            instr_ir, extra_ir = mn_do_sub(self, instr, args[0], args[1],
                                           last_arg)
        elif instr.name[0:3] == 'XOR':
            instr_ir, extra_ir = mn_do_xor(self, instr, *args)
        else:
            instr_ir, extra_ir = sem_dir[instr.name](self, instr, *args)

        return instr_ir, extra_ir

    def get_next_instr(self, instr):
        l = self.loc_db.get_or_create_offset_location(instr.offset  + 4)
        return l

    def get_next_break_loc_key(self, instr):
        l = self.loc_db.get_or_create_offset_location(instr.offset  + 4)
        return l
