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
def addiu(arg1, arg2, arg3):
    """Adds a register @arg3 and a sign-extended immediate value @arg2 and
    stores the result in a register @arg1"""
    arg1 = arg2 + arg3

@sbuild.parse
def lw(arg1, arg2):
    "A word is loaded into a register @arg1 from the specified address @arg2."
    arg1 = arg2

@sbuild.parse
def sw(arg1, arg2):
    "The contents of @arg2 is stored at the specified address @arg1."
    arg2 = arg1

@sbuild.parse
def jal(arg1):
    "Jumps to the calculated address @arg1 and stores the return address in $RA"
    PC = arg1
    ir.IRDst = arg1
    RA = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def jalr(arg1, arg2):
    """Jump to an address stored in a register @arg1, and store the return
    address in another register @arg2"""
    PC = arg1
    ir.IRDst = arg1
    arg2 = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def bal(arg1):
    PC = arg1
    ir.IRDst = arg1
    RA = ExprId(ir.get_next_break_label(instr))

@sbuild.parse
def l_b(arg1):
    PC = arg1
    ir.IRDst = arg1

@sbuild.parse
def lbu(arg1, arg2):
    """A byte is loaded (unsigned extended) into a register @arg1 from the
    specified address @arg2."""
    arg1 = mem8[arg2.arg].zeroExtend(32)

@sbuild.parse
def lhu(arg1, arg2):
    """A word is loaded (unsigned extended) into a register @arg1 from the
    specified address @arg2."""
    arg1 = mem16[arg2.arg].zeroExtend(32)

@sbuild.parse
def lb(arg1, arg2):
    "A byte is loaded into a register @arg1 from the specified address @arg2."
    arg1 = mem8[arg2.arg].signExtend(32)

@sbuild.parse
def beq(arg1, arg2, arg3):
    "Branches on @arg3 if the quantities of two registers @arg1, @arg2 are eq"
    dst = ExprId(ir.get_next_break_label(instr)) if arg1 - arg2 else arg3
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bgez(arg1, arg2):
    """Branches on @arg2 if the quantities of register @arg1 is greater than or
    equal to zero"""
    dst = ExprId(ir.get_next_break_label(instr)) if arg1.msb() else arg2
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bne(arg1, arg2, arg3):
    """Branches on @arg3 if the quantities of two registers @arg1, @arg2 are NOT
    equal"""
    dst = arg3 if arg1 - arg2 else ExprId(ir.get_next_break_label(instr))
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def lui(arg1, arg2):
    """The immediate value @arg2 is shifted left 16 bits and stored in the
    register @arg1. The lower 16 bits are zeroes."""
    arg1 = ExprCompose([(i16(0), 0, 16), (arg2[:16], 16, 32)])

@sbuild.parse
def nop():
    """Do nothing"""

@sbuild.parse
def j(arg1):
    """Jump to an address @arg1"""
    PC = arg1
    ir.IRDst = arg1

@sbuild.parse
def l_or(arg1, arg2, arg3):
    """Bitwise logical ors two registers @arg2, @arg3 and stores the result in a
    register @arg1"""
    arg1 = arg2 | arg3

@sbuild.parse
def nor(arg1, arg2, arg3):
    """Bitwise logical Nors two registers @arg2, @arg3 and stores the result in
    a register @arg1"""
    arg1 = (arg2 | arg3) ^ i32(-1)

@sbuild.parse
def l_and(arg1, arg2, arg3):
    """Bitwise logical ands two registers @arg2, @arg3 and stores the result in
    a register @arg1"""
    arg1 = arg2 & arg3

@sbuild.parse
def ext(arg1, arg2, arg3, arg4):
    pos = int(arg3.arg)
    size = int(arg4.arg)
    arg1 = arg2[pos:pos + size].zeroExtend(32)

@sbuild.parse
def mul(arg1, arg2, arg3):
    """Multiplies @arg2 by $arg3 and stores the result in @arg1."""
    arg1 = 'imul'(arg2, arg3)

@sbuild.parse
def sltu(arg1, arg2, arg3):
    """If @arg3 is less than @arg2 (unsigned), @arg1 is set to one. It gets zero
    otherwise."""
    arg1 = (((arg2 - arg3) ^ ((arg2 ^ arg3) & ((arg2 - arg3) ^ arg2))) ^ arg2 ^ arg3).msb().zeroExtend(32)

@sbuild.parse
def slt(arg1, arg2, arg3):
    """If @arg3 is less than @arg2 (signed), @arg1 is set to one. It gets zero
    otherwise."""
    arg1 = ((arg2 - arg3) ^ ((arg2 ^ arg3) & ((arg2 - arg3) ^ arg2))).zeroExtend(32)

@sbuild.parse
def l_sub(arg1, arg2, arg3):
    arg1 = arg2 - arg3

@sbuild.parse
def sb(arg1, arg2):
    """The least significant byte of @arg1 is stored at the specified address
    @arg2."""
    mem8[arg2.arg] = arg1[:8]

@sbuild.parse
def sh(arg1, arg2):
    mem16[arg2.arg] = arg1[:16]

@sbuild.parse
def movn(arg1, arg2, arg3):
    if arg3:
        arg1 = arg2

@sbuild.parse
def movz(arg1, arg2, arg3):
    if not arg3:
        arg1 = arg2

@sbuild.parse
def srl(arg1, arg2, arg3):
    """Shifts arg1 register value @arg2 right by the shift amount @arg3 and
    places the value in the destination register @arg1.
    Zeroes are shifted in."""
    arg1 = arg2 >> arg3

@sbuild.parse
def sra(arg1, arg2, arg3):
    """Shifts arg1 register value @arg2 right by the shift amount @arg3 and
    places the value in the destination register @arg1. The sign bit is shifted
    in."""
    arg1 = 'a>>'(arg2, arg3)

@sbuild.parse
def srav(arg1, arg2, arg3):
    arg1 = 'a>>'(arg2, arg3 & i32(0x1F))

@sbuild.parse
def sll(arg1, arg2, arg3):
    arg1 = arg2 << arg3

@sbuild.parse
def srlv(arg1, arg2, arg3):
    """Shifts a register value @arg2 right by the amount specified in @arg3 and
    places the value in the destination register @arg1.
    Zeroes are shifted in."""
    arg1 = arg2 >> (arg3 & i32(0x1F))

@sbuild.parse
def sllv(arg1, arg2, arg3):
    """Shifts a register value @arg2 left by the amount specified in @arg3 and
    places the value in the destination register @arg1.
    Zeroes are shifted in."""
    arg1 = arg2 << (arg3 & i32(0x1F))

@sbuild.parse
def l_xor(arg1, arg2, arg3):
    """Exclusive ors two registers @arg2, @arg3 and stores the result in a
    register @arg3"""
    arg1 = arg2 ^ arg3

@sbuild.parse
def seb(arg1, arg2):
    arg1 = arg2[:8].signExtend(32)

@sbuild.parse
def seh(arg1, arg2):
    arg1 = arg2[:16].signExtend(32)

@sbuild.parse
def bltz(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is less than zero"""
    dst_o = arg2 if arg1.msb() else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def blez(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is less than or equal to zero"""
    cond = (i1(1) if arg1 else i1(0)) | arg1.msb()
    dst_o = arg2 if cond else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bgtz(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is greater than zero"""
    cond = (i1(1) if arg1 else i1(0)) | arg1.msb()
    dst_o = ExprId(ir.get_next_break_label(instr)) if cond else arg2
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def wsbh(arg1, arg2):
    arg1 = ExprCompose([(arg2[8:16],  0, 8),
                        (arg2[0:8]  , 8, 16),
                        (arg2[24:32], 16, 24),
                        (arg2[16:24], 24, 32)])

@sbuild.parse
def rotr(arg1, arg2, arg3):
    arg1 = '>>>'(arg2, arg3)

@sbuild.parse
def add_d(arg1, arg2, arg3):
    # XXX TODO check
    arg1 = 'fadd'(arg2, arg3)

@sbuild.parse
def sub_d(arg1, arg2, arg3):
    # XXX TODO check
    arg1 = 'fsub'(arg2, arg3)

@sbuild.parse
def div_d(arg1, arg2, arg3):
    # XXX TODO check
    arg1 = 'fdiv'(arg2, arg3)

@sbuild.parse
def mul_d(arg1, arg2, arg3):
    # XXX TODO check
    arg1 = 'fmul'(arg2, arg3)

@sbuild.parse
def mov_d(arg1, arg2):
    # XXX TODO check
    arg1 = arg2

@sbuild.parse
def mfc0(arg1, arg2):
    arg1 = arg2

@sbuild.parse
def mfc1(arg1, arg2):
    arg1 = arg2

@sbuild.parse
def mtc0(arg1, arg2):
    arg2 = arg1

@sbuild.parse
def mtc1(arg1, arg2):
    arg2 = arg1

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
def lwc1(arg1, arg2):
    arg1 = ('mem_%.2d_to_single' % arg2.size)(arg2)

@sbuild.parse
def swc1(arg1, arg2):
    arg2 = ('single_to_mem_%.2d' % arg1.size)(arg1)

@sbuild.parse
def c_lt_d(arg1, arg2, arg3):
    arg1 = 'fcomp_lt'(arg2, arg3)

@sbuild.parse
def c_eq_d(arg1, arg2, arg3):
    arg1 = 'fcomp_eq'(arg2, arg3)

@sbuild.parse
def c_le_d(arg1, arg2, arg3):
    arg1 = 'fcomp_le'(arg2, arg3)

@sbuild.parse
def bc1t(arg1, arg2):
    dst_o = arg2 if arg1 else ExprId(ir.get_next_break_label(instr))
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bc1f(arg1, arg2):
    dst_o = ExprId(ir.get_next_break_label(instr)) if arg1 else arg2
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def cvt_d_w(arg1, arg2):
    # TODO XXX
    arg1 = 'flt_d_w'(arg2)

@sbuild.parse
def mult(arg1, arg2):
    """Multiplies (signed) @arg1 by @arg2 and stores the result in $R_HI:$R_LO"""
    size = arg1.size
    result = arg1.signExtend(size * 2) * arg2.signExtend(size * 2)
    R_LO = result[:32]
    R_HI = result[32:]

@sbuild.parse
def multu(arg1, arg2):
    """Multiplies (unsigned) @arg1 by @arg2 and stores the result in $R_HI:$R_LO"""
    size = arg1.size
    result = arg1.zeroExtend(size * 2) * arg2.zeroExtend(size * 2)
    R_LO = result[:32]
    R_HI = result[32:]

@sbuild.parse
def mfhi(arg1):
    "The contents of register $R_HI are moved to the specified register @arg1."
    arg1 = R_HI

@sbuild.parse
def mflo(arg1):
    "The contents of register R_LO are moved to the specified register @arg1."
    arg1 = R_LO

@sbuild.parse
def di(arg1):
    "NOP"

@sbuild.parse
def ei(arg1):
    "NOP"

@sbuild.parse
def ehb(arg1):
    "NOP"

mnemo_func = sbuild.functions
mnemo_func.update({
        'add.d': add_d,
        'addu': addiu,
        'and': l_and,
        'andi': l_and,
        'b': l_b,
        'c.eq.d': c_eq_d,
        'c.le.d': c_le_d,
        'c.lt.d': c_lt_d,
        'cvt.d.w': cvt_d_w,
        'div.d': div_d,
        'ins': ins,
        'jr': j,
        'mov.d': mov_d,
        'mul.d': mul_d,
        'or': l_or,
        'ori': l_or,
        'slti': slt,
        'sltiu': sltu,
        'sub.d': sub_d,
        'subu': l_sub,
        'xor': l_xor,
        'xori': l_xor,
})

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
