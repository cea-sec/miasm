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

@sbuild.parse
def ext(a, b, c, d):
    pos = int(c.arg)
    size = int(d.arg)
    a = b[pos:pos + size].zeroExtend(32)

@sbuild.parse
def mul(a, b, c):
    """Multiplies @b by $c and stores the result in @a."""
    a = 'imul'(b, c)

@sbuild.parse
def sltu(a, x, y):
    """If @y is less than @x (unsigned), @a is set to one. It gets zero
    otherwise."""
    a = (((x - y) ^ ((x ^ y) & ((x - y) ^ x))) ^ x ^ y).msb().zeroExtend(32)

@sbuild.parse
def slt(a, x, y):
    """If @y is less than @x (signed), @a is set to one. It gets zero
    otherwise."""
    a = ((x - y) ^ ((x ^ y) & ((x - y) ^ x))).zeroExtend(32)

@sbuild.parse
def l_sub(a, b, c):
    a = b - c

@sbuild.parse
def sb(a, b):
    "The least significant byte of @a is stored at the specified address @b."
    mem8[b.arg] = a[:8]

@sbuild.parse
def sh(a, b):
    mem16[b.arg] = a[:16]

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

@sbuild.parse
def srl(a, b, c):
    """Shifts a register value @b right by the shift amount @c and places the
    value in the destination register @a. Zeroes are shifted in."""
    a = b >> c

@sbuild.parse
def sra(a, b, c):
    """Shifts a register value @b right by the shift amount @c and places the
    value in the destination register @a. The sign bit is shifted in."""
    a = 'a>>'(b, c)

@sbuild.parse
def srav(a, b, c):
    a = 'a>>'(b, c & i32(0x1F))

@sbuild.parse
def sll(a, b, c):
    a = b << c

@sbuild.parse
def srlv(a, b, c):
    """Shifts a register value @b right by the amount specified in @c and places
    the value in the destination register @a. Zeroes are shifted in."""
    a = b >> (c & i32(0x1F))

@sbuild.parse
def sllv(a, b, c):
    """Shifts a register value @b left by the amount specified in @c and places
    the value in the destination register @a. Zeroes are shifted in."""
    a = b << (c & i32(0x1F))

@sbuild.parse
def l_xor(a, b, c):
    """Exclusive ors two registers @b, @c and stores the result in a register
    @c"""
    a = b ^ c

@sbuild.parse
def seb(a, b):
    a = b[:8].signExtend(32)

@sbuild.parse
def seh(a, b):
    a = b[:16].signExtend(32)

@sbuild.parse
def bltz(a, b):
    """Branches on @b if the register @a is less than zero"""
    dst_o = b if a.msb() else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def blez(a, b):
    """Branches on @b if the register @a is less than or equal to zero"""
    cond = (i1(1) if a else i1(0)) | a.msb()
    dst_o = b if cond else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bgtz(a, b):
    """Branches on @b if the register @a is greater than zero"""
    cond = (i1(1) if a else i1(0)) | a.msb()
    dst_o = ExprId(ir.get_next_break_label(instr)) if cond else b
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def wsbh(a, b):
    a = ExprCompose([(b[8:16],  0, 8),
                     (b[0:8]  , 8, 16),
                     (b[24:32], 16, 24),
                     (b[16:24], 24, 32)])

@sbuild.parse
def rotr(a, b, c):
    a = '>>>'(b, c)

@sbuild.parse
def add_d(a, b, c):
    # XXX TODO check
    a = 'fadd'(b, c)

@sbuild.parse
def sub_d(a, b, c):
    # XXX TODO check
    a = 'fsub'(b, c)

@sbuild.parse
def div_d(a, b, c):
    # XXX TODO check
    a = 'fdiv'(b, c)

@sbuild.parse
def mul_d(a, b, c):
    # XXX TODO check
    a = 'fmul'(b, c)

@sbuild.parse
def mov_d(a, b):
    # XXX TODO check
    a = b

@sbuild.parse
def mfc0(a, b):
    a = b

@sbuild.parse
def mfc1(a, b):
    a = b

@sbuild.parse
def mtc0(a, b):
    b = a

@sbuild.parse
def mtc1(a, b):
    b = a

@sbuild.parse
def tlbwi():
    "TODO XXX"

@sbuild.parse
def tlbp():
    "TODO XXX"

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


@sbuild.parse
def lwc1(a, b):
    a = ('mem_%.2d_to_single' % b.size)(b)

@sbuild.parse
def swc1(a, b):
    b = ('single_to_mem_%.2d' % a.size)(a)

@sbuild.parse
def c_lt_d(a, b, c):
    a = 'fcomp_lt'(b, c)

@sbuild.parse
def c_eq_d(a, b, c):
    a = 'fcomp_eq'(b, c)

@sbuild.parse
def c_le_d(a, b, c):
    a = 'fcomp_le'(b, c)

@sbuild.parse
def bc1t(a, b):
    dst_o = b if a else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bc1f(a, b):
    dst_o = ExprId(ir.get_next_break_label(instr)) if a else b
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def cvt_d_w(a, b):
    # TODO XXX
    a = 'flt_d_w'(b)

@sbuild.parse
def mult(a, b):
    """Multiplies (signed) @a by @b and stores the result in $R_HI:$R_LO"""
    size = a.size
    result = a.signExtend(size * 2) * b.signExtend(size * 2)
    R_LO = result[:32]
    R_HI = result[32:]

@sbuild.parse
def multu(a, b):
    """Multiplies (unsigned) @a by @b and stores the result in $R_HI:$R_LO"""
    size = a.size
    result = a.zeroExtend(size * 2) * b.zeroExtend(size * 2)
    R_LO = result[:32]
    R_HI = result[32:]

@sbuild.parse
def mfhi(a):
    "The contents of register $R_HI are moved to the specified register @a."
    a = R_HI

@sbuild.parse
def mflo(a):
    "The contents of register R_LO are moved to the specified register @a."
    a = R_LO

@sbuild.parse
def di(a):
    "NOP"

@sbuild.parse
def ei(a):
    "NOP"

@sbuild.parse
def ehb(a):
    "NOP"

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
