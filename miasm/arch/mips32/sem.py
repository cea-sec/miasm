import miasm.expression.expression as m2_expr
from miasm.ir.ir import Lifter, IRBlock, AssignBlock
from miasm.arch.mips32.arch import mn_mips32
from miasm.arch.mips32.regs import R_LO, R_HI, PC, RA, ZERO, exception_flags
from miasm.core.sembuilder import SemBuilder
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_SOFT_BP, EXCEPT_SYSCALL


# SemBuilder context
ctx = {
    "R_LO": R_LO,
    "R_HI": R_HI,
    "PC": PC,
    "RA": RA,
    "m2_expr": m2_expr
}

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
    RA = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), RA.size)

@sbuild.parse
def jalr(arg1, arg2):
    """Jump to an address stored in a register @arg1, and store the return
    address in another register @arg2"""
    PC = arg1
    ir.IRDst = arg1
    arg2 = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), arg2.size)

@sbuild.parse
def bal(arg1):
    PC = arg1
    ir.IRDst = arg1
    RA = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), RA.size)

@sbuild.parse
def l_b(arg1):
    PC = arg1
    ir.IRDst = arg1

@sbuild.parse
def lbu(arg1, arg2):
    """A byte is loaded (unsigned extended) into a register @arg1 from the
    specified address @arg2."""
    arg1 = m2_expr.ExprMem(arg2.ptr, 8).zeroExtend(32)

@sbuild.parse
def lh(arg1, arg2):
    """A word is loaded into a register @arg1 from the
    specified address @arg2."""
    arg1 = m2_expr.ExprMem(arg2.ptr, 16).signExtend(32)

@sbuild.parse
def lhu(arg1, arg2):
    """A word is loaded (unsigned extended) into a register @arg1 from the
    specified address @arg2."""
    arg1 = m2_expr.ExprMem(arg2.ptr, 16).zeroExtend(32)

@sbuild.parse
def lb(arg1, arg2):
    "A byte is loaded into a register @arg1 from the specified address @arg2."
    arg1 = m2_expr.ExprMem(arg2.ptr, 8).signExtend(32)

@sbuild.parse
def ll(arg1, arg2):
    "To load a word from memory for an atomic read-modify-write"
    arg1 = arg2

@sbuild.parse
def beq(arg1, arg2, arg3):
    "Branches on @arg3 if the quantities of two registers @arg1, @arg2 are eq"
    dst = arg3 if m2_expr.ExprOp(m2_expr.TOK_EQUAL, arg1, arg2) else m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size)
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def beql(arg1, arg2, arg3):
    "Branches on @arg3 if the quantities of two registers @arg1, @arg2 are eq"
    dst = arg3 if m2_expr.ExprOp(m2_expr.TOK_EQUAL, arg1, arg2) else m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size)
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bgez(arg1, arg2):
    """Branches on @arg2 if the quantities of register @arg1 is greater than or
    equal to zero"""
    dst = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size) if m2_expr.ExprOp(m2_expr.TOK_INF_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size)) else arg2
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bgezl(arg1, arg2):
    """Branches on @arg2 if the quantities of register @arg1 is greater than or
    equal to zero"""
    dst = m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size) if m2_expr.ExprOp(m2_expr.TOK_INF_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size)) else arg2
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bne(arg1, arg2, arg3):
    """Branches on @arg3 if the quantities of two registers @arg1, @arg2 are NOT
    equal"""
    dst = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size) if m2_expr.ExprOp(m2_expr.TOK_EQUAL, arg1, arg2) else arg3
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bnel(arg1, arg2, arg3):
    """Branches on @arg3 if the quantities of two registers @arg1, @arg2 are NOT
    equal"""
    dst = m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size) if m2_expr.ExprOp(m2_expr.TOK_EQUAL, arg1, arg2) else arg3
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def lui(arg1, arg2):
    """The immediate value @arg2 is shifted left 16 bits and stored in the
    register @arg1. The lower 16 bits are zeroes."""
    arg1 = m2_expr.ExprCompose(i16(0), arg2[:16])

@sbuild.parse
def nop():
    """Do nothing"""

@sbuild.parse
def sync(arg1):
    """Synchronize Shared Memory"""

@sbuild.parse
def pref(arg1, arg2):
    """To move data between memory and cache"""

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
    pos = int(arg3)
    size = int(arg4)
    arg1 = arg2[pos:pos + size].zeroExtend(32)

@sbuild.parse
def mul(arg1, arg2, arg3):
    """Multiplies @arg2 by $arg3 and stores the result in @arg1."""
    arg1 = 'imul'(arg2, arg3)

@sbuild.parse
def sltu(arg1, arg2, arg3):
    """If @arg2 is less than @arg3 (unsigned), @arg1 is set to one. It gets zero
    otherwise."""
    arg1 = m2_expr.ExprCond(
        m2_expr.ExprOp(m2_expr.TOK_INF_UNSIGNED, arg2, arg3),
        m2_expr.ExprInt(1, arg1.size),
        m2_expr.ExprInt(0, arg1.size)
    )

@sbuild.parse
def slt(arg1, arg2, arg3):
    """If @arg2 is less than @arg3 (signed), @arg1 is set to one. It gets zero
    otherwise."""
    arg1 = m2_expr.ExprCond(
        m2_expr.ExprOp(m2_expr.TOK_INF_SIGNED, arg2, arg3),
        m2_expr.ExprInt(1, arg1.size),
        m2_expr.ExprInt(0, arg1.size)
    )


@sbuild.parse
def l_sub(arg1, arg2, arg3):
    arg1 = arg2 - arg3

def sb(ir, instr, arg1, arg2):
    """The least significant byte of @arg1 is stored at the specified address
    @arg2."""
    e = []
    e.append(m2_expr.ExprAssign(m2_expr.ExprMem(arg2.ptr, 8), arg1[:8]))
    return e, []

def sh(ir, instr, arg1, arg2):
    e = []
    e.append(m2_expr.ExprAssign(m2_expr.ExprMem(arg2.ptr, 16), arg1[:16]))
    return e, []

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
    dst_o = arg2 if m2_expr.ExprOp(m2_expr.TOK_INF_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size)) else m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bltzl(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is less than zero"""
    dst_o = arg2 if m2_expr.ExprOp(m2_expr.TOK_INF_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size)) else m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def blez(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is less than or equal to zero"""
    cond = m2_expr.ExprOp(m2_expr.TOK_INF_EQUAL_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size))
    dst_o = arg2 if cond else m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def blezl(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is less than or equal to zero"""
    cond = m2_expr.ExprOp(m2_expr.TOK_INF_EQUAL_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size))
    dst_o = arg2 if cond else m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bgtz(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is greater than zero"""
    cond =  m2_expr.ExprOp(m2_expr.TOK_INF_EQUAL_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size))
    dst_o = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size) if cond else arg2
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bgtzl(arg1, arg2):
    """Branches on @arg2 if the register @arg1 is greater than zero"""
    cond =  m2_expr.ExprOp(m2_expr.TOK_INF_EQUAL_SIGNED, arg1, m2_expr.ExprInt(0, arg1.size))
    dst_o = m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size) if cond else arg2
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def wsbh(arg1, arg2):
    arg1 = m2_expr.ExprCompose(arg2[8:16], arg2[0:8], arg2[24:32], arg2[16:24])

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

@sbuild.parse
def tlbwr():
    "TODO XXX"

@sbuild.parse
def tlbr():
    "TODO XXX"

def break_(ir, instr):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(EXCEPT_SOFT_BP, 32)))
    return e, []

def syscall(ir, instr, code):
    e = []
    e.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(EXCEPT_SYSCALL, 32)))
    return e, []

def ins(ir, instr, a, b, c, d):
    e = []
    pos = int(c)
    l = int(d)

    my_slices = []
    if pos != 0:
        my_slices.append(a[:pos])
    if l != 0:
        my_slices.append(b[:l])
    if pos + l != 32:
        my_slices.append(a[pos+l:])
    r = m2_expr.ExprCompose(*my_slices)
    e.append(m2_expr.ExprAssign(a, r))
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
    dst_o = arg2 if arg1 else m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bc1tl(arg1, arg2):
    dst_o = arg2 if arg1 else m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size)
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bc1f(arg1, arg2):
    dst_o = m2_expr.ExprLoc(ir.get_next_break_loc_key(instr), ir.IRDst.size) if arg1 else arg2
    PC = dst_o
    ir.IRDst = dst_o

@sbuild.parse
def bc1fl(arg1, arg2):
    dst_o = m2_expr.ExprLoc(ir.get_next_delay_loc_key(instr), ir.IRDst.size) if arg1 else arg2
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
def div(arg1, arg2):
    """Divide (signed) @arg1 by @arg2 and stores the remaining/result in $R_HI/$R_LO"""
    R_LO = m2_expr.ExprOp('sdiv' ,arg1, arg2)
    R_HI = m2_expr.ExprOp('smod', arg1, arg2)

@sbuild.parse
def divu(arg1, arg2):
    """Divide (unsigned) @arg1 by @arg2 and stores the remaining/result in $R_HI/$R_LO"""
    R_LO = m2_expr.ExprOp('udiv', arg1, arg2)
    R_HI = m2_expr.ExprOp('umod', arg1, arg2)

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

@sbuild.parse
def sc(arg1, arg2):
    arg2 = arg1;
    arg1 = m2_expr.ExprInt(0x1, 32)

@sbuild.parse
def mthi(arg1):
    R_HI = arg1

@sbuild.parse
def mtlo(arg1):
    R_LOW = arg1

def clz(ir, instr, rs, rd):
    e = []
    e.append(m2_expr.ExprAssign(rd, m2_expr.ExprOp('cntleadzeros', rs)))
    return e, []

def teq(ir, instr, arg1, arg2):
    e = []

    loc_except, loc_except_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    do_except = []
    do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_except = IRBlock(ir.loc_db, loc_except, [AssignBlock(do_except, instr)])

    cond = arg1 - arg2


    e = []
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(cond, loc_next_expr, loc_except_expr)))

    return e, [blk_except]

def tne(ir, instr, arg1, arg2):
    e = []

    loc_except, loc_except_expr = ir.gen_loc_key_and_expr(ir.IRDst.size)
    loc_next = ir.get_next_loc_key(instr)
    loc_next_expr = m2_expr.ExprLoc(loc_next, ir.IRDst.size)

    do_except = []
    do_except.append(m2_expr.ExprAssign(exception_flags, m2_expr.ExprInt(
        EXCEPT_DIV_BY_ZERO, exception_flags.size)))
    do_except.append(m2_expr.ExprAssign(ir.IRDst, loc_next_expr))
    blk_except = IRBlock(ir.loc_db, loc_except, [AssignBlock(do_except, instr)])

    cond = arg1 ^ arg2


    e = []
    e.append(m2_expr.ExprAssign(ir.IRDst,
                             m2_expr.ExprCond(cond, loc_next_expr, loc_except_expr)))

    return e, [blk_except]


mnemo_func = sbuild.functions
mnemo_func.update(
    {
        'add.d': add_d,
        'addu': addiu,
        'addi': addiu,
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
        'clz': clz,
        'teq': teq,
        'tne': tne,
        'break': break_,
        'sb': sb,
        'sh': sh,
        'syscall': syscall,
    }
)

def get_mnemo_expr(ir, instr, *args):
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir

class Lifter_Mips32l(Lifter):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_mips32, 'l', loc_db)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()
        self.IRDst = m2_expr.ExprId('IRDst', 32)
        self.addrsize = 32

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        fixed_regs = {
            self.pc: m2_expr.ExprInt(instr.offset + 4, 32),
            ZERO: m2_expr.ExprInt(0, 32)
        }

        instr_ir = [m2_expr.ExprAssign(expr.dst, expr.src.replace_expr(fixed_regs))
                    for expr in instr_ir]

        new_extra_ir = [irblock.modify_exprs(mod_src=lambda expr: expr.replace_expr(fixed_regs))
                        for irblock in extra_ir]
        return instr_ir, new_extra_ir

    def get_next_instr(self, instr):
        return self.loc_db.get_or_create_offset_location(instr.offset  + 4)

    def get_next_break_loc_key(self, instr):
        return self.loc_db.get_or_create_offset_location(instr.offset  + 8)

    def get_next_delay_loc_key(self, instr):
        return self.loc_db.get_or_create_offset_location(instr.offset + 16)

class Lifter_Mips32b(Lifter_Mips32l):
    def __init__(self, loc_db):
        self.addrsize = 32
        Lifter.__init__(self, mn_mips32, 'b', loc_db)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()
        self.IRDst = m2_expr.ExprId('IRDst', 32)
