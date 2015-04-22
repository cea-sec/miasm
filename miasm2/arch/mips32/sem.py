import miasm2.expression.expression as m2_expr
from miasm2.ir.ir import ir, irbloc
from miasm2.arch.mips32.arch import mn_mips32
from miasm2.arch.mips32.regs import R_LO, R_HI, PC, RA
from miasm2.core.sembuilder import SemBuilder


# SemBuilder context
ctx = {"R_LO": R_LO,
       "R_HI": R_HI,
       "PC": PC,
       "RA": RA}
ctx.update(m2_expr.__dict__)
sbuild = SemBuilder(ctx)


@sbuild.parse
def addiu(Arg1, Arg2, Arg3):
    """Adds a register @Arg3 and a sign-extended immediate value @Arg2 and
    stores the result in a register @Arg1"""
    Arg1 = Arg2 + Arg3

@sbuild.parse
def lw(Arg1, Arg2):
    "A word is loaded into a register @Arg1 from the specified address @Arg2."
    Arg1 = Arg2

@sbuild.parse
def sw(Arg1, Arg2):
    "The contents of @Arg2 is stored at the specified address @Arg1."
    Arg2 = Arg1

@sbuild.parse
def jal(Arg1):
    "Jumps to the calculated address @Arg1 and stores the return address in $RA"
    PC = Arg1
    ir.IRDst = Arg1
    RA = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def jalr(Arg1, Arg2):
    """Jump to an address stored in a register @Arg1, and store the return
    address in another register @Arg2"""
    PC = Arg1
    ir.IRDst = Arg1
    Arg2 = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def bal(Arg1):
    PC = Arg1
    ir.IRDst = Arg1
    RA = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def l_b(Arg1):
    PC = Arg1
    ir.IRDst = Arg1

@sbuild.parse
def lbu(Arg1, Arg2):
    """A byte is loaded (unsigned extended) into a register @Arg1 from the
    specified address @Arg2."""
    Arg1 = mem8[Arg2.arg].zeroExtend(32)

@sbuild.parse
def lhu(Arg1, Arg2):
    """A word is loaded (unsigned extended) into a register @Arg1 from the
    specified address @Arg2."""
    Arg1 = mem16[Arg2.arg].zeroExtend(32)

@sbuild.parse
def lb(Arg1, Arg2):
    "A byte is loaded into a register @Arg1 from the specified address @Arg2."
    Arg1 = mem8[Arg2.arg].signExtend(32)

@sbuild.parse
def beq(Arg1, Arg2, Arg3):
    "Branches on @Arg3 if the quantities of two registers @Arg1, @Arg2 are eq"
    dst = ExprId(ir.get_next_break_label(instr)) if Arg1 - Arg2 else Arg3
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bgez(Arg1, Arg2):
    """Branches on @Arg2 if the quantities of register @Arg1 is greater than or
    equal to zero"""
    dst = ExprId(ir.get_next_break_label(instr)) if Arg1.msb() else Arg2
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bne(Arg1, Arg2, Arg3):
    """Branches on @Arg3 if the quantities of two registers @Arg1, @Arg2 are NOT
    equal"""
    dst = Arg3 if Arg1 - Arg2 else ExprId(ir.get_next_break_label(instr))
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def lui(Arg1, Arg2):
    """The immediate value @Arg2 is shifted left 16 bits and stored in the
    register @Arg1. The lower 16 bits are zeroes."""
    Arg1 = ExprCompose([(i16(0), 0, 16), (Arg2[:16], 16, 32)])

@sbuild.parse
def nop():
    """Do nothing"""

@sbuild.parse
def j(Arg1):
    """Jump to an address @Arg1"""
    PC = Arg1
    ir.IRDst = Arg1

@sbuild.parse
def l_or(Arg1, Arg2, Arg3):
    """Bitwise logical ors two registers @Arg2, @Arg3 and stores the result in a
    register @Arg1"""
    Arg1 = Arg2 | Arg3

@sbuild.parse
def nor(Arg1, Arg2, Arg3):
    """Bitwise logical Nors two registers @Arg2, @Arg3 and stores the result in
    a register @Arg1"""
    Arg1 = (Arg2 | Arg3) ^ i32(-1)

@sbuild.parse
def l_and(Arg1, Arg2, Arg3):
    """Bitwise logical ands two registers @Arg2, @Arg3 and stores the result in
    a register @Arg1"""
    Arg1 = Arg2 & Arg3

def ext(ir, instr, a, b, c, d):
    e = []
    pos = int(c.arg)
    size = int(d.arg)
    e.append(m2_expr.ExprAff(a, b[pos:pos+size].zeroExtend(32)))
    return e, []

def mul(ir, instr, a, b, c):
    """Multiplies @b by $c and stores the result in @a."""
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('imul', b, c)))
    return e, []

def sltu(ir, instr, a, x, y):
    """If @y is less than @x (unsigned), @a is set to one. It gets zero
    otherwise."""
    e = []
    value = (((x - y) ^ ((x ^ y) & ((x - y) ^ x))) ^ x ^ y).msb().zeroExtend(32)
    e.append(m2_expr.ExprAff(a, value))
    return e, []

def slt(ir, instr, a, x, y):
    """If @y is less than @x (signed), @a is set to one. It gets zero
    otherwise."""
    e = []
    value = ((x - y) ^ ((x ^ y) & ((x - y) ^ x))).zeroExtend(32)
    e.append(m2_expr.ExprAff(a, value))
    return e, []

def l_sub(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, b-c))
    return e, []

def sb(ir, instr, a, b):
    "The least significant byte of @a is stored at the specified address @b."
    e = []
    b = m2_expr.ExprMem(b.arg, 8)
    e.append(m2_expr.ExprAff(b, a[:8]))
    return e, []

def sh(ir, instr, a, b):
    e = []
    b = m2_expr.ExprMem(b.arg, 16)
    e.append(m2_expr.ExprAff(b, a[:16]))
    return e, []

def movn(ir, instr, a, b, c):
    lbl_do = m2_expr.ExprId(ir.gen_label(), 32)
    lbl_skip = m2_expr.ExprId(ir.get_next_instr(instr), 32)
    e_do = []
    e_do.append(m2_expr.ExprAff(a, b))
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e = []
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(c, lbl_do, lbl_skip)))

    return e, [irbloc(lbl_do.name, [e_do], [])]

def movz(ir, instr, a, b, c):
    lbl_do = m2_expr.ExprId(ir.gen_label(), 32)
    lbl_skip = m2_expr.ExprId(ir.get_next_instr(instr), 32)
    e_do = []
    e_do.append(m2_expr.ExprAff(a, b))
    e_do.append(m2_expr.ExprAff(ir.IRDst, lbl_skip))
    e = []
    e.append(m2_expr.ExprAff(ir.IRDst, m2_expr.ExprCond(c, lbl_skip, lbl_do)))

    return e, [irbloc(lbl_do.name, [e_do], [])]

def srl(ir, instr, a, b, c):
    """Shifts a register value @b right by the shift amount @c and places the
    value in the destination register @a. Zeroes are shifted in."""
    e = []
    e.append(m2_expr.ExprAff(a, b >> c))
    return e, []

def sra(ir, instr, a, b, c):
    """Shifts a register value @b right by the shift amount @c and places the
    value in the destination register @a. The sign bit is shifted in."""
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('a>>', b, c)))
    return e, []

def srav(ir, instr, a, b, c):
    e = []
    value = m2_expr.ExprOp('a>>', b, c&m2_expr.ExprInt32(0x1F))
    e.append(m2_expr.ExprAff(a, value))
    return e, []

def sll(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, b<<c))
    return e, []

def srlv(ir, instr, a, b, c):
    """Shifts a register value @b right by the amount specified in @c and places
    the value in the destination register @a. Zeroes are shifted in."""
    e = []
    e.append(m2_expr.ExprAff(a, b >> (c & m2_expr.ExprInt32(0x1F))))
    return e, []

def sllv(ir, instr, a, b, c):
    """Shifts a register value @b left by the amount specified in @c and places
    the value in the destination register @a. Zeroes are shifted in."""
    e = []
    e.append(m2_expr.ExprAff(a, b << (c & m2_expr.ExprInt32(0x1F))))
    return e, []

def l_xor(ir, instr, a, b, c):
    """Exclusive ors two registers @b, @c and stores the result in a register
    @c"""
    e = []
    e.append(m2_expr.ExprAff(a, b^c))
    return e, []

def seb(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, b[:8].signExtend(32)))
    return e, []

def seh(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, b[:16].signExtend(32)))
    return e, []

def bltz(ir, instr, a, b):
    """Branches on @b if the register @a is less than zero"""
    e = []
    n = m2_expr.ExprId(ir.get_next_break_label(instr))
    dst_o = m2_expr.ExprCond(a.msb(), b, n)
    e = [m2_expr.ExprAff(PC, dst_o),
         m2_expr.ExprAff(ir.IRDst, dst_o)
    ]
    return e, []

def blez(ir, instr, a, b):
    """Branches on @b if the register @a is less than or equal to zero"""
    e = []
    n = m2_expr.ExprId(ir.get_next_break_label(instr))
    cond = m2_expr.ExprCond(a, m2_expr.ExprInt1(1),
                            m2_expr.ExprInt1(0)) | a.msb()
    dst_o = m2_expr.ExprCond(cond, b, n)
    e = [m2_expr.ExprAff(PC, dst_o),
         m2_expr.ExprAff(ir.IRDst, dst_o)
    ]
    return e, []

def bgtz(ir, instr, a, b):
    """Branches on @b if the register @a is greater than zero"""
    e = []
    n = m2_expr.ExprId(ir.get_next_break_label(instr))
    cond = m2_expr.ExprCond(a, m2_expr.ExprInt1(1),
                            m2_expr.ExprInt1(0)) | a.msb()
    dst_o = m2_expr.ExprCond(cond, n, b)
    e = [m2_expr.ExprAff(PC, dst_o),
         m2_expr.ExprAff(ir.IRDst, dst_o)
     ]
    return e, []

def wsbh(ir, instr, a, b):
    e = [m2_expr.ExprAff(a, m2_expr.ExprCompose([(b[8:16],  0, 8),
                                 (b[0:8]  , 8, 16),
                                 (b[24:32], 16, 24),
                                 (b[16:24], 24, 32)]))]
    return e, []

def rotr(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('>>>', b, c)))
    return e, []

def add_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fadd', b, c)))
    return e, []

def sub_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fsub', b, c)))
    return e, []

def div_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fdiv', b, c)))
    return e, []

def mul_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fmul', b, c)))
    return e, []

def mov_d(ir, instr, a, b):
    # XXX TODO check
    e = []
    e.append(m2_expr.ExprAff(a, b))
    return e, []

def mfc0(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, b))
    return e, []

def mfc1(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(a, b))
    return e, []

def mtc0(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(b, a))
    return e, []

def mtc1(ir, instr, a, b):
    e = []
    e.append(m2_expr.ExprAff(b, a))
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
    r = m2_expr.ExprCompose(my_slices)
    e.append(m2_expr.ExprAff(a, r))
    return e, []


def lwc1(ir, instr, a, b):
    e = []
    src = m2_expr.ExprOp('mem_%.2d_to_single' % b.size, b)
    e.append(m2_expr.ExprAff(a, src))
    return e, []

def swc1(ir, instr, a, b):
    e = []
    src = m2_expr.ExprOp('single_to_mem_%.2d' % a.size, a)
    e.append(m2_expr.ExprAff(b, src))
    return e, []

def c_lt_d(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fcomp_lt', b, c)))
    return e, []

def c_eq_d(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fcomp_eq', b, c)))
    return e, []

def c_le_d(ir, instr, a, b, c):
    e = []
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('fcomp_le', b, c)))
    return e, []

def bc1t(ir, instr, a, b):
    e = []
    n = m2_expr.ExprId(ir.get_next_break_label(instr))
    dst_o = m2_expr.ExprCond(a, b, n)
    e = [m2_expr.ExprAff(PC, dst_o)]
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []

def bc1f(ir, instr, a, b):
    e = []
    n = m2_expr.ExprId(ir.get_next_break_label(instr))
    dst_o = m2_expr.ExprCond(a, n, b)
    e = [m2_expr.ExprAff(PC, dst_o)]
    e.append(m2_expr.ExprAff(ir.IRDst, dst_o))
    return e, []

def cvt_d_w(ir, instr, a, b):
    e = []
    # TODO XXX
    e.append(m2_expr.ExprAff(a, m2_expr.ExprOp('flt_d_w', b)))
    return e, []

def mult(ir, instr, a, b):
    """Multiplies (signed) @a by @b and stores the result in $R_HI:$R_LO"""
    e = []
    size = a.size
    r = a.signExtend(size * 2) * b.signExtend(size * 2)

    e.append(m2_expr.ExprAff(R_LO, r[:32]))
    e.append(m2_expr.ExprAff(R_HI, r[32:]))
    return e, []

def multu(ir, instr, a, b):
    """Multiplies (unsigned) @a by @b and stores the result in $R_HI:$R_LO"""
    e = []
    size = a.size
    r = a.zeroExtend(size * 2) * b.zeroExtend(size * 2)

    e.append(m2_expr.ExprAff(R_LO, r[:32]))
    e.append(m2_expr.ExprAff(R_HI, r[32:]))
    return e, []

def mfhi(ir, instr, a):
    "The contents of register $R_HI are moved to the specified register @a."
    e = []
    e.append(m2_expr.ExprAff(a, R_HI))
    return e, []

def mflo(ir, instr, a):
    "The contents of register R_LO are moved to the specified register @a."
    e = []
    e.append(m2_expr.ExprAff(a, R_LO))
    return e, []

def di(ir, instr, a):
    return [], []

def ei(ir, instr, a):
    return [], []

def ehb(ir, instr, a):
    return [], []

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
    "lb" : lb,
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
    "seh" : seh,
    "bltz" : bltz,
    "blez" : blez,
    "wsbh" : wsbh,
    "rotr" : rotr,
    # "mfc0" : mfc0,
    # "mfc1" : mfc1,
    # "mtc0" : mtc0,
    # "mtc1" : mtc1,
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
    "multu" : multu,

    "mfhi" : mfhi,
    "mflo" : mflo,

    "di" : di,
    "ei" : ei,
    "ehb" : ehb,

    }

def get_mnemo_expr(ir, instr, *args):
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir

class ir_mips32l(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_mips32, 'l', symbol_pool)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()
        self.IRDst = m2_expr.ExprId('IRDst', 32)

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        for i, x in enumerate(instr_ir):
            x = m2_expr.ExprAff(x.dst, x.src.replace_expr(
                {self.pc: m2_expr.ExprInt32(instr.offset + 4)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = m2_expr.ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: m2_expr.ExprInt32(instr.offset + 4)}))
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
                ir_bloc_cur.append(m2_expr.ExprAff(PC_FETCH, dst))
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

class ir_mips32b(ir_mips32l):
    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_mips32, 'b', symbol_pool)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()
        self.IRDst = m2_expr.ExprId('IRDst', 32)
