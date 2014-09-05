from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.arch.mips32.arch import mn_mips32
from miasm2.arch.mips32.regs import *

def addiu(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b+c))
    return e, []

def lw(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return e, []

def sw(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return e, []

def jal(ir, instr, a):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(RA, n))
    return e, []

def jalr(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(b, n))
    return e, []

def bal(ir, instr, a):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    e.append(ExprAff(RA, n))
    return e, []

def l_b(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def lbu(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 8)
    e.append(ExprAff(a, b.zeroExtend(32)))
    return e, []

def lhu(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 16)
    e.append(ExprAff(a, b.zeroExtend(32)))
    return e, []

def beq(ir, instr, a, b, c):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a-b, n, c)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
     ]
    return e, []

def bgez(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a.msb(), n, b)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
     ]
    return e, []

def bne(ir, instr, a, b, c):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a-b, c, n)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
    ]
    return e, []

def lui(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCompose([(ExprInt16(0), 0, 16),
                                     (b[:16], 16, 32)])))
    return e, []

def nop(ir, instr):
    return [], []

def j(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    e.append(ExprAff(ir.IRDst, a))
    return e, []

def l_or(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b|c))
    return e, []

def nor(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, (b|c)^ExprInt32(0xFFFFFFFF)))
    return e, []

def l_and(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b&c))
    return e, []

def ext(ir, instr, a, b, c, d):
    e = []
    pos = int(c.arg)
    size = int(d.arg)
    e.append(ExprAff(a, b[pos:pos+size].zeroExtend(32)))
    return e, []

def mul(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('imul', b, c)))
    return e, []

def sltu(ir, instr, a, x, y):
    e = []
    e.append(ExprAff(a, (((x - y) ^ ((x ^ y) & ((x - y) ^ x))) ^ x ^ y).msb().zeroExtend(32)))
    return e, []

def slt(ir, instr, a, x, y):
    e = []
    e.append(ExprAff(a, ((x - y) ^ ((x ^ y) & ((x - y) ^ x))).zeroExtend(32)))
    return e, []

def l_sub(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b-c))
    return e, []

def sb(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 8)
    e.append(ExprAff(b, a[:8]))
    return e, []

def sh(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 16)
    e.append(ExprAff(b, a[:16]))
    return e, []

def movn(ir, instr, a, b, c):
    lbl_do = ExprId(ir.gen_label(), 32)
    lbl_skip = ExprId(ir.get_next_instr(instr), 32)
    e_do = []
    e_do.append(ExprAff(a, b))
    e_do.append(ExprAff(ir.IRDst, lbl_skip))
    e = []
    e.append(ExprAff(ir.IRDst, ExprCond(c, lbl_do, lbl_skip)))

    return e, [irbloc(lbl_do.name, [e_do], [])]

def movz(ir, instr, a, b, c):
    lbl_do = ExprId(ir.gen_label(), 32)
    lbl_skip = ExprId(ir.get_next_instr(instr), 32)
    e_do = []
    e_do.append(ExprAff(a, b))
    e_do.append(ExprAff(ir.IRDst, lbl_skip))
    e = []
    e.append(ExprAff(ir.IRDst, ExprCond(c, lbl_skip, lbl_do)))

    return e, [irbloc(lbl_do.name, [e_do], [])]

def srl(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b >> c))
    return e, []

def sra(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('a>>', b, c)))
    return e, []

def srav(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('a>>', b, c&ExprInt32(0x1F))))
    return e, []

def sll(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b<<c))
    return e, []

def srlv(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b >> (c & ExprInt32(0x1F))))
    return e, []

def sllv(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b << (c & ExprInt32(0x1F))))
    return e, []

def l_xor(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b^c))
    return e, []

def seb(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b[:8].signExtend(32)))
    return e, []

def bltz(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a.msb(), b, n)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
    ]
    return e, []

def blez(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    cond = ExprCond(a, ExprInt1(1), ExprInt1(0)) | a.msb()
    dst_o = ExprCond(cond, b, n)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
    ]
    return e, []

def bgtz(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    cond = ExprCond(a, ExprInt1(1), ExprInt1(0)) | a.msb()
    dst_o = ExprCond(cond, n, b)
    e = [ExprAff(PC, dst_o),
         ExprAff(ir.IRDst, dst_o)
     ]
    return e, []

def wsbh(ir, instr, a, b):
    e = [ExprAff(a, ExprCompose([(b[8:16],  0, 8)   ,
                                 (b[0:8]  , 8, 16)  ,
                                 (b[24:32], 16, 24),
                                 (b[16:24], 24, 32)]))]
    return e, []

def rotr(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('>>>', b, c)))
    return e, []

def add_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fadd', b, c)))
    return e, []

def sub_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fsub', b, c)))
    return e, []

def div_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fdiv', b, c)))
    return e, []

def mul_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fmul', b, c)))
    return e, []

def mov_d(ir, instr, a, b):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, b))
    return e, []

def mfc0(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return e, []

def mfc1(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return e, []

def mtc0(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return e, []

def mtc1(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return e, []

def tlbwi(ir, instr):
    # TODO XXX
    e = []
    return e, []

def tlbp(ir, instr):
    # TODO XXX
    e = []
    return e, []

def ins(ir, instr, a, b, c, d):
    e = []
    pos = int(c.arg)
    l = int(d.arg)

    my_slices = []
    if pos != 0:
        my_slices.append((a[:pos], 0, pos))
    if l != 0:
        my_slices.append((b[:l], pos, pos+l))
    if pos + l != 32:
        my_slices.append((a[pos+l:], pos+l, 32))
    r = ExprCompose(my_slices)
    e.append(ExprAff(a, r))
    return e, []


def lwc1(ir, instr, a, b):
    e = []
    src = ExprOp('mem_%.2d_to_single' % b.size, b)
    e.append(ExprAff(a, src))
    return e, []

def swc1(ir, instr, a, b):
    e = []
    src = ExprOp('single_to_mem_%.2d' % a.size, a)
    e.append(ExprAff(b, src))
    return e, []

def c_lt_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_lt', b, c)))
    return e, []

def c_eq_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_eq', b, c)))
    return e, []

def c_le_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_le', b, c)))
    return e, []

def bc1t(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a, b, n)
    e = [ExprAff(PC, dst_o)]
    e.append(ExprAff(ir.IRDst, dst_o))
    return e, []

def bc1f(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a, n, b)
    e = [ExprAff(PC, dst_o)]
    e.append(ExprAff(ir.IRDst, dst_o))
    return e, []

def cvt_d_w(ir, instr, a, b):
    e = []
    # TODO XXX
    e.append(ExprAff(a, ExprOp('flt_d_w', b)))
    return e, []

def mult(ir, instr, a, b):
    e = []
    size = a.size
    r = a.signExtend(size * 2) * b.signExtend(size * 2)

    e.append(ExprAff(R_LO, r[:32]))
    e.append(ExprAff(R_HI, r[32:]))
    return e, []

def mfhi(ir, instr, a):
    e = []
    e.append(ExprAff(a, R_HI))
    return e, []

def mflo(ir, instr, a):
    e = []
    e.append(ExprAff(a, R_LO))
    return e, []


mnemo_func = {
    "addiu": addiu,
    "addu": addiu,
    "lw" : lw,
    "sw" : sw,
    "sh" : sh,
    "sb" : sb,
    "jalr" : jalr,
    "jal" : jal,
    "bal" : bal,
    "b" : l_b,
    "lbu" : lbu,
    "lhu" : lhu,
    "beq" : beq,
    "bgez" : bgez,
    "bltz" : bltz,
    "bgtz" : bgtz,
    "bne" : bne,
    "lui" : lui,
    "nop" : nop,
    "j" : j,
    "jr" : j,
    "ori" : l_or,
    "or" : l_or,
    "nor" : nor,
    "and" : l_and,
    "andi" : l_and,
    "ext" : ext,
    "mul" : mul,
    "sltu" : sltu,
    "slt" : slt,
    "slti" : slt,
    "sltiu" : sltu,
    "subu" : l_sub,
    "movn" : movn,
    "movz" : movz,
    "srl" : srl,
    "sra" : sra,
    "srav" : srav,
    "sll" : sll,
    "srlv" : srlv,
    "sllv" : sllv,
    "xori" : l_xor,
    "xor" : l_xor,
    "seb" : seb,
    "bltz" : bltz,
    "blez" : blez,
    "wsbh" : wsbh,
    "rotr" : rotr,
    "mfc0" : mfc0,
    "mfc1" : mfc1,
    "mtc0" : mtc0,
    "mtc1" : mtc1,
    "tlbwi" : tlbwi,
    "tlbp" : tlbp,
    "ins" : ins,

    "add.d" : add_d,
    "sub.d" : sub_d,
    "div.d" : div_d,
    "mul.d" : mul_d,
    "mov.d" : mov_d,
    "lwc1" : lwc1,
    "swc1" : swc1,
    "c.lt.d" : c_lt_d,
    "c.eq.d" : c_eq_d,
    "c.le.d" : c_le_d,
    "bc1t" : bc1t,
    "bc1f" : bc1f,
    "cvt.d.w":cvt_d_w,
    "mult" : mult,

    "mfhi" : mfhi,
    "mflo" : mflo,

    }

def get_mnemo_expr(ir, instr, *args):
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir

class ir_mips32(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_mips32, None, symbol_pool)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()
        self.IRDst = ExprId('IRDst', 32)

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt32(instr.offset + 4)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt32(instr.offset + 4)}))
                    irs[i] = x
        return instr_ir, extra_ir

    def get_next_instr(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset  + 4)
        return l

    def get_next_break_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset  + 8)
        return l
    """
    def add_bloc(self, bloc, gen_pc_updt = False):
        c = None
        ir_blocs_all = []
        for l in bloc.lines:
            if c is None:
                # print 'new c'
                label = self.get_label(l)
                c = irbloc(label, [], [])
                ir_blocs_all.append(c)
                bloc_dst = None
            # print 'Translate', l
            dst, ir_bloc_cur, ir_blocs_extra = self.instr2ir(l)
            # print ir_bloc_cur
            # for xxx in ir_bloc_cur:
            #    print "\t", xxx
            assert((dst is None) or (bloc_dst is None))
            bloc_dst = dst
            #if bloc_dst is not None:
            #    c.dst = bloc_dst
            if dst is not None:
                ir_bloc_cur.append(ExprAff(PC_FETCH, dst))
                c.dst = PC_FETCH
            if gen_pc_updt is not False:
                self.gen_pc_update(c, l)

            c.irs.append(ir_bloc_cur)
            c.lines.append(l)
            if ir_blocs_extra:
                # print 'split'
                for b in ir_blocs_extra:
                    b.lines = [l] * len(b.irs)
                ir_blocs_all += ir_blocs_extra
                c = None
        self.post_add_bloc(bloc, ir_blocs_all)
        return ir_blocs_all
    """
