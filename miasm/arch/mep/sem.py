# Toshiba MeP-c4 - miasm instructions side effects
# Guillaume Valadon <guillaume@valadon.net>

from miasm.core.sembuilder import SemBuilder
from miasm.ir.ir import Lifter
from miasm.arch.mep.arch import mn_mep
from miasm.arch.mep.regs import PC, SP, LP, SAR, TP, RPB, RPE, RPC, EPC, NPC, \
    take_jmp, in_erepeat
from miasm.arch.mep.regs import EXC, HI, LO, PSW, DEPC, DBG
from miasm.expression.expression import ExprId, ExprInt, ExprOp, TOK_EQUAL
from miasm.expression.expression import ExprAssign, ExprCond, ExprMem
from miasm.core.cpu import sign_ext
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO

from miasm.arch.mep.regs import exception_flags


def compute_s_inf(arg1, arg2):
    """Signed comparison operator"""
    return ((arg1 - arg2) ^ ((arg1 ^ arg2) & ((arg1 - arg2) ^ arg1))).msb()

def compute_u_inf(x, y):
    """Unsigned comparison operator"""
    result = (((x - y) ^ ((x ^ y) & ((x - y) ^ x))) ^ x ^ y).msb()
    return result

def i8(value):
    return ExprInt(value, 8)

def i32(value):
    return ExprInt(value, 32)


# SemBuilder context
ctx = {"PC": PC, "SP": SP, "LP": LP, "SAR": SAR, "TP": TP,
       "RPB": RPB, "RPE": RPE, "RPC": RPC, "EPC": EPC, "NPC": NPC,
       "EXC": EXC, "HI": HI, "LO": LO, "PSW": PSW, "DEPC": DEPC, "DBG": DBG,
       "exception_flags": exception_flags, "compute_s_inf": compute_s_inf,
       "compute_u_inf": compute_u_inf, "take_jmp": take_jmp,
       "in_erepeat": in_erepeat, "EXCEPT_DIV_BY_ZERO": EXCEPT_DIV_BY_ZERO}
sbuild = SemBuilder(ctx)


# Functions used to get an instruction IR
manual_functions = dict()


@sbuild.parse
def mep_nop():
    """Dummy instruction"""


@sbuild.parse
def mep_nop_2_args(arg1, arg2):
    """Dummy instruction with two arguments"""


### Load/Store instructions

# Register indirect addressing mode

def sb(ir, instr, reg_src, deref_dst):
    """SB - Store Byte into memory"""

    # MemByte(Rm31..0) <- Rn7..0
    # MemByte((ZeroExt(disp7)+TP)31..0)) <- Rn7..0
    # MemByte((SignExt(disp16)+Rm)31..0) <- Rn7..0
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr, 8), reg_src[:8]))
    return e, []

manual_functions["sb"] = sb


def sh(ir, instr, reg_src, deref_dst):
    """SH - Store Halfword into memory"""

    # MemHword(Rm31..1||0) <- Rn15..0
    # MemHword((ZeroExt((disp7)6..1||0)+TP)31..1||0)) <- Rn15..0
    # MemHword((SignExt(disp16)+Rm)31..1||0) <- Rn15..0
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr & i32(0xFFFFFFFE), 16), reg_src[:16]))
    return e, []

manual_functions["sh"] = sh


def sw(ir, instr, reg_src, deref_dst):
    """SW - Store Word into memory"""

    # MemWord(Rm31..2||00) <- Rn31..0
    # MemWord((ZeroExt((disp7)6..2||00)+SP)31..2||00)) <- Rn31..0
    # MemWord((ZeroExt((disp7)6..2||00)+TP)31..2||00)) <- Rn31..0
    # MemWord((SignExt(disp16)+Rm)31..2||00) <- Rn31..0
    # MemWord(ZeroExt((abs24)23..2||00)) - Rn31..0
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr & i32(0xFFFFFFFC), 32), reg_src))
    return e, []

manual_functions["sw"] = sw

# Without the sembuilder
#def sw(ir, instr, reg_src, deref_reg_or_imm, deref_reg=None):
#    """SW - store Word into memory.
#
#       Note: there are three variants to get the memory address:
#            - from a register
#            - relatively to SP
#            - relatively to TP"""
#
#    if isinstance(deref_reg_or_imm, ExprMem):
#        # MemWord(Rm31..2||00) <- Rn31..0
#        dst = deref_reg_or_imm
#
#    elif isinstance(deref_reg_or_imm, ExprInt) and deref_reg:
#        # MemWord((ZeroExt((disp7)6..2||00)+SP)31..2||00)) <- Rn31..0
#        # MemWord((ZeroExt((disp7)6..2||00)+TP)31..2||00)) <- Rn31..0
#
#        imm = deref_reg_or_imm.zeroExtend(32)
#        dst = ExprMem(ExprOp("+", imm, deref_reg.arg))
#
#    return [ExprAssign(dst, reg_src)], []


def lb(ir, instr, reg_dst, deref_dst):
    """LB - Load Byte from memory"""

    # Rn <- SignExt(MemByte(Rm31..0))
    # Rn <- SignExt(MemByte((ZeroExt(disp7)+TP)31..0))
    # Rn <- SignExt(MemByte((SignExt(disp16)+Rm)31..0)
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_dst.ptr, 8).signExtend(32)))
    return e, []

manual_functions["lb"] = lb


def lh(ir, instr, reg_dst, deref_dst):
    """LH - Load Halfword from memory"""

    # Rn <- SignExt(MemHword(Rm31..1||0))
    # Rn <- SignExt(MemHword((ZeroExt((disp7)6..1||0)+TP)31..1||0)
    # Rn <- SignExt(MemHword((SignExt(disp16)+Rm)31..1||0))
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_dst.ptr & i32(0xFFFFFFFE), 16).signExtend(32)))
    return e, []

manual_functions["lh"] = lh

def lw(ir, instr, reg_dst, deref_dst):
    """LW - Load Word from memory"""

    # Rn <- MemWord(Rm31..2||00)
    # Rn <- MemWord((ZeroExt((disp7)6..2||00)+TP)31..2||00)
    # Rn <- MemWord((SignExt(disp16)+Rm)31..2||00)
    # Rn <- MemWord(ZeroExt((abs24)23..2||00))
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_dst.ptr & i32(0xFFFFFFFC), 32)))
    return e, []

manual_functions["lw"] = lw


def lbu(ir, instr, reg_dst, deref_dst):
    """LBU - Load an unsigned Byte from memory"""

    # Rn <- ZeroExt(MemByte(Rm31..0))
    # Rn <- ZeroExt(MemByte((ZeroExt(disp7)+TP)31..0))
    # Rn <- ZeroExt(MemByte((SignExt(disp16)+Rm)31..0))
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_dst.ptr, 8).zeroExtend(32)))
    return e, []

manual_functions["lbu"] = lbu


def lhu(ir, instr, reg_dst, deref_dst):
    """LHU - Load an unsigned Halfword from memory"""

    # Rn <- ZeroExt(MemHword(Rm31..1||0))
    # Rn <- ZeroExt(MemHword((SignExt(disp16)+Rm)31..1||0))
    # Rn <- ZeroExt(MemHword((ZeroExt((disp7)6..1||0)+TP)31..1||0))
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_dst.ptr & i32(0xFFFFFFFE), 16).zeroExtend(32)))
    return e, []

manual_functions["lhu"] = lhu



### Byte/Halfword extension instructions

@sbuild.parse
def extb(reg):
    """EXTB - Sign extend a byte"""

    # Rn <- SignExt(Rn7..0)
    reg = reg[:8].signExtend(32)


@sbuild.parse
def exth(reg):
    """EXTH - Sign extend a word"""

    # Rn <- ZeroExt(Rn15..0)
    reg = reg[:16].signExtend(32)


@sbuild.parse
def extub(reg):
    """EXUTB - Zero extend a byte"""

    # Rn <- SignExt(Rn7..0)
    reg = reg[:8].zeroExtend(32)


@sbuild.parse
def extuh(reg):
    """EXTUH - Zero extend a word"""

    # Rn <- ZeroExt(Rn15..0)
    reg = reg[:16].zeroExtend(32)


### Shift amount manipulation instructions

#@sbuild.parse
#def ssarb(deref_reg):


### Move instructions

@sbuild.parse
def mov(reg, value):
    """MOV - Copy 'value' to a register. The three alternatives are handled."""

    # Rn <- Rm
    # Rn <- SignExt(imm8)
    # Rn <- SignExt(imm16)
    reg = value.signExtend(32)


@sbuild.parse
def movu(reg, value):
    """MOV - Copy 'value' to a register. The two alternatives are handled."""

    # Rn[0-7] <- ZeroExt(imm24)
    # Rn <- ZeroExt(imm16)
    reg = value.zeroExtend(32)


@sbuild.parse
def movh(reg, imm16):
    """MOVH - Copy a shifted imm16 to a register."""

    # Rn <- imm16 <<16
    reg = imm16.zeroExtend(32) << i32(16)


### Arithmetic instructions

def add3(ir, instr, reg_dst, reg_src, reg_or_imm):
    """ADD3 - Add two register and store the result to a register, or
              add a register and an immediate and store the result to a register"""

    if isinstance(reg_or_imm, ExprId):
        # Rl <- Rn + Rm
        result = ExprOp("+", reg_src, reg_or_imm)
    else:
        # Rn <- Rm + SignExt(imm16)
        value = int(reg_or_imm)
        result = ExprOp("+", reg_src, ExprInt(value, 32))

    return [ExprAssign(reg_dst, result)], []

manual_functions["add3"] = add3


@sbuild.parse
def add(arg1, arg2):
    """ADD - Add a register and an immediate."""

    # Rn <- Rn + SignExt(imm6)
    arg1 = arg1 + arg2.signExtend(32)


@sbuild.parse
def advck3(r0, rn, rm):
    """ADVCK3 - Check addition overflow."""

    # if(Overflow(Rn+Rm)) R0<-1 else R0<-0 (Signed)
    r0 = i32(1) if compute_u_inf(i64(0xFFFFFFFF), rn.zeroExtend(64) + rm.zeroExtend(64)) else i32(0)


@sbuild.parse
def sub(reg1, reg2):
    """SUB - Subtract one register to another."""

    # Rn <- Rn - Rm
    reg1 = reg1 - reg2


def sbvck3(ir, instr, r0, rn, rm):
    """SBVCK3 - Check subtraction overflow"""

    # if(Overflow(Rn-Rm)) R0<-1 else R0<-0 (Signed)

    # Subtract registers
    reg_sub = ExprOp("+", rn, rm)

    # Get the register storing the highest value
    max_rn_rm = ExprCond(ExprOp(">", rn, rm), rn, rm)

    # Check for an overflow
    overflow_test = ExprOp(">", reg_sub, max_rn_rm)

    # Return the result
    condition = ExprCond(overflow_test, ExprInt(1, 32), ExprInt(0, 32))
    return [ExprAssign(r0, condition)], []

manual_functions["sbvck3"] = sbvck3


@sbuild.parse
def neg(reg1, reg2):
    """NEG - Negate one register."""

    # Rn <- - Rm
    reg1 = - reg2


@sbuild.parse
def slt3(r0, rn, rm_or_imm5):
    """SLT3 - Set on less than (signed)."""

    # if (Rn<Rm) R0<-1 else R0<-0 (Signed)
    # if (Rn<ZeroExt(imm5)) R0<-1 else R0<-0(Signed)
    r0 = i32(1) if compute_s_inf(rn, rm_or_imm5.signExtend(32)) else i32(0)

if False:
    rm_ext = rm_or_imm5

    # Mask sign bits
    sign_mask = i32(0x80000000)
    sign_rn = rn & sign_mask
    sign_rm = rm_ext & sign_mask

    # Check if both numbers are positive or negative
    are_both_neg = sign_rn & sign_rm
    are_both_pos = ~(sign_rn & sign_rm) >> i32(31)

    # rn is positive and rm negative, return 1
    r0_mixed = i32(1) if sign_rn else i32(0)

    # rn & rm are both positives, test and return 1 or 0
    r0_pos = (i32(1) if "<"(rn, rm_ext) else i32(0)) if are_both_pos else r0_mixed

    # rn & rm are both negatives, test and return 0 or 1
    r0 = (i32(0) if "<"(rn, rm_ext) else i32(1)) if are_both_neg else r0_pos


@sbuild.parse
def sltu3(r0, rn, rm_or_imm5):
    """SLTU3 - Set on less than (unsigned)."""

    # if (Rn<Rm) R0<-1 else R0<-0 (Unsigned)
    # if (Rn<ZeroExt(imm5)) R0<-1 else R0<-0(Unsigned)
    r0 = i32(1) if compute_u_inf(rn, rm_or_imm5) else i32(0)


@sbuild.parse
def sl1ad3(r0, rn, rm):
    """SL1AD3 - Shift a register one bit left, then add another one."""

    # R0 <- (Rn<<1) + Rm
    r0 = (rn << i32(1)) + rm


@sbuild.parse
def sl2ad3(r0, rn, rm):
    """SL2AD3 - Shift a register two bits left, then add another one."""

    # R0 <- (Rn<<2) + Rm
    r0 = (rn << i32(2)) + rm


### Logical instructions

@sbuild.parse
def logical_or(rn, rm):
    """OR - Logical OR between two registers."""

    # Rn <- Rn or Rm
    rn = rn | rm

manual_functions["or"] = logical_or


@sbuild.parse
def logical_and(rn, rm):
    """AND - Logical AND between two registers."""

    # Rn <- Rn and Rm
    rn = rn & rm

manual_functions["and"] = logical_and


@sbuild.parse
def xor(rn, rm):
    """XOR - Logical XOR between two registers."""

    # Rn <- Rn xor Rm
    rn = rn ^ rm


@sbuild.parse
def nor(rn, rm):
    """NOR - Logical NOR between two registers."""

    # Rn <- Rn nor Rm
    rn = ~ (rn | rm)


@sbuild.parse
def or3(rn, rm, imm16):
    """OR3 - Logical OR between a register and an immediate"""

    # Rn <- Rm or ZeroExt(imm16)
    rn = rm | imm16


@sbuild.parse
def and3(rn, rm, imm16):
    """AND3 - Logical AND between a register and an immediate"""

    # Rn <- Rm and ZeroExt(imm16)
    rn = rm & imm16


@sbuild.parse
def xor3(rn, rm, imm16):
    """XOR3 - Logical XOR between a register and an immediate"""

    # Rn <- Rm xor ZeroExt(imm16)
    rn = rm ^ imm16


### Shift instruction

@sbuild.parse
def sra(rn, rm_or_imm5):
    """SRA - Shift Right signed"""

    # Rn <- (Signed) Rn >> Rm4..0
    # Rn <- (Signed) Rn >> imm5

    # Unsigned result
    shift_u = rn >> rm_or_imm5

    # Signed result
    shift_mask = i32(32) - rm_or_imm5
    mask = (i32(0xFFFFFFFF) >> shift_mask) << shift_mask
    shift_s = shift_u | mask

    rn = shift_s if rn.msb() else shift_u


@sbuild.parse
def srl(rn, rm_or_imm5):
    """SRL - Shift Right unsigned."""

    # Rn <- (Unsigned) Rn >> Rm4..0
    # Rn <- (Unsigned) Rn >> imm5
    rn = rn >> rm_or_imm5


@sbuild.parse
def sll(rn, rm_or_imm5):
    """SLL - Shift Left unsigned."""

    # Rn <- (Unsigned) Rn >> Rm4..0
    # Rn <- (Unsigned) Rn << imm5
    rn = rn << rm_or_imm5


@sbuild.parse
def sll3(r0, rn, imm5):
    """SLL3 - Shift Left unsigned, with 3 arguments."""

    # R0 <- (Unsigned) Rn << imm5
    r0 = rn << imm5


@sbuild.parse
def fsft(rn, rm):
    """FSFT - Funnel shift."""

    # Rn <- ((Rn||Rm)<<SAR5..0)63..32
    # Note: lowest Rm bits are discarded

    sar = SAR[:5].zeroExtend(32)
    tmp_rn = rn << sar  # Shift Rn
    tmp_rm = rm >> (i32(32) - sar)  # Shift Rm in the reverse order
    rn = tmp_rn | tmp_rm  # Concatenate registers


## Branch/Jump instructions

@sbuild.parse
def bra(disp12):
    """BRA - Branch to an address."""

    # PC <- PC + SignExt((disp12)11..1||0)
    dst = disp12
    PC = dst
    take_jmp = ExprInt(1, 32)
    ir.IRDst = dst


@sbuild.parse
def beqz(reg_test, disp8):
    """BEQZ - Branch if the register stores zero."""

    # if(Rn==0) PC <- PC +SignExt((disp8)7..1||0)
    dst = ExprLoc(ir.get_next_break_loc_key(instr), 32) if reg_test else disp8
    take_jmp = ExprInt(0, 32) if reg_test else ExprInt(1, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def bnez(reg_test, disp8):
    """BNEZ - Branch if the register does not store zero."""

    # if(Rn!=0) PC <- PC + SignExt((disp8)7..1||0)
    dst = disp8 if reg_test else ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32) if reg_test else ExprInt(0, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def beqi(reg_test, imm4, disp16):
    """BEQI - Branch if the register stores imm4."""

    # if(Rn==ZeroExt(imm4)) PC <- PC +SignExt((disp17)16..1||0)
    dst = ExprLoc(ir.get_next_break_loc_key(instr), 32) if (reg_test - imm4) else disp16
    take_jmp = ExprInt(0, 32) if (reg_test - imm4) else ExprInt(1, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def bnei(reg_test, imm4, disp16):
    """BNEI - Branch if the register does not store imm4."""

    # if(Rn!=ZeroExt(imm4)) PC <- PC+SignExt((disp17)16..1||0)
    dst = disp16 if (reg_test - imm4) else ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32) if (reg_test - imm4) else ExprInt(0, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def blti(reg_test, imm4, disp16):
    """BLTI - Branch if the register is lower than imm4."""

    # if(Rn< ZeroExt(imm4)) PC <- PC +SignExt((disp17)16..1||0) - (Signed comparison)
    dst = disp16 if compute_s_inf(reg_test, imm4) else ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32) if compute_s_inf(reg_test, imm4) else ExprInt(0, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def bgei(reg_test, imm4, disp16):
    """BGEI - Branch if the register is greater or equal to imm4."""

    # if(Rn>=ZeroExt(imm4)) PC <- PC +SignExt((disp17)16..1||0) - (Signed comparison)
    cond = i32(1) if ExprOp(TOK_EQUAL, reg_test, imm4) else compute_s_inf(imm4, reg_test).zeroExtend(32)
    dst = disp16 if cond else ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32) if cond else ExprInt(0, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def beq(rn, rm, disp16):
    """BEQ - Branch if the two registers are equal."""

    # if(Rn==Rm) PC <- PC +SignExt((disp17)16..1||0)
    dst = ExprLoc(ir.get_next_break_loc_key(instr), 32) if (rn - rm) else disp16
    take_jmp = ExprInt(0, 32) if (rn - rm) else ExprInt(1, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def bne(rn, rm, disp16):
    """BNE - Branch if the two registers are not equal."""

    # if(Rn!=Rm) PC <- PC +SignExt((disp17)16..1||0)
    dst = disp16 if (rn - rm) else ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32) if (rn - rm) else ExprInt(0, 32)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def bsr(disp):
    """BSR - Branch to an address, and store the return address."""

    # 16-bit variant: LP <- PC + 2; PC <- PC +SignExt((disp12)11..1||0)
    # 32-bit variant: LP <- PC + 4; PC <- PC +SignExt((disp24)23..1||0)

    # Set LP
    LP = ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32)

    # Set PC according to the immediate size
    dst = disp
    PC = dst
    ir.IRDst = dst


def jmp(ir, instr, reg_or_imm):
    """JMP - Change PC to a register content or an immediate.
       Note: the behavior in VLIW mode is not implemented"""

    take_jmp = ExprInt(1, 32)

    if isinstance(reg_or_imm, ExprId):
        # PC <- Rm31..1||0
        new_PC = ExprAssign(PC, reg_or_imm)
    else:
        # PC <- PC31..28||0000||(target24)23..1||0
        new_PC = ExprAssign(PC, ExprOp("+", ExprOp("&", PC, ExprInt(0xF0000000, 32)), reg_or_imm))

    return [new_PC, ExprAssign(ir.IRDst, new_PC)], []

manual_functions["jmp"] = jmp


@sbuild.parse
def jsr(reg):
    """JSR - Jump to the register, and store the return address."""

    # LP <- PC + 2; PC <- Rm31..1||0
    LP = ExprLoc(ir.get_next_break_loc_key(instr), 32)
    take_jmp = ExprInt(1, 32)
    PC = reg
    ir.IRDst = reg


@sbuild.parse
def ret():
    """RET - Return from a function call.
       Note: the behavior in VLIW mode is not implemented"""

    # PC <- LP31..1||0
    dst = LP
    PC = dst
    ir.IRDst = dst


# Repeat instructions

@sbuild.parse
def repeat(rn, disp17):
    """REPEAT - This instruction repeats an instruction block. It sets the RPB,
       RPE and RPC control registers."""

    # RPB <- pc+4 // Repeat Begin
    RPB = PC + i32(4)
    # RPE <- pc+SignExt((disp17)16..1||0)) // Repeat End
    RPE = PC + i32(int(disp17) & 0xFFFFFFFE)
    # RPC <- Rn
    RPC = rn
    in_erepeat = ExprInt(0, 32)


@sbuild.parse
def erepeat(disp17):
    """EREPEAT - This instruction repeats an instruction block. It sets the RPB
       and RPE control registers. To distinguish from the repeat instruction,
       the least significant bit in the RPE register (ELR) is set to 1."""

    # RPB <- pc+4 // Repeat Begin
    RPB = PC + i32(4)
    # RPE <- pc+SignExt((disp17)16..1||1)) (EREPEAT)
    RPE = PC + i32(int(disp17) + 1)
    # RPC <- undefined
    in_erepeat = ExprInt(1, 32)


## Control Instructions

@sbuild.parse
def stc(reg, control_reg):
    """STC - Copy a general-purpose register into a control register."""

    # ControlReg(imm5) <- Rn
    control_reg = reg


@sbuild.parse
def ldc(reg, control_reg):
    """LDC - Copy a control register into a general-purpose register."""

    # Rn <- ControlReg(imm5)
    reg = control_reg


@sbuild.parse
def di():
    """DI - Disable Interrupt"""

    # PSW.IEC<-0
    PSW = PSW & i32(0xFFFFFFFE)  # PSW.IEC: bit 0


@sbuild.parse
def ei():
    """EI - Enable Interrupt"""

    # PSW.IEC<-1
    PSW = PSW ^ i32(0b1)  # PSW.IEC: bit 0


@sbuild.parse
def reti():
    """RETI - Return from the exception/interrupt handler.
       Note: the behavior in VLIW mode is not implemented"""

    #if (PSW.NMI==1) {
    #   PC <- NPC31..1 || 0; PSW.NMI<-0;
    #} else {
    #   PC <- EPC31..1 || 0;
    #   PSW.UMC <- PSW.UMP; PSW.IEC <- PSW.IEP
    #}

    # PSW.NMI == bit 9
    NMI_mask = i32(1 << 9)

    # PSW.UMP == bit 3
    # PSW.IEP == bit 1
    UMP_IEP_mask = i32((1 << 3) ^ (1 << 1))

    # PSW.UMC == bit 2
    # PSW.IEC == bit 0
    UMC_IEC_mask = (PSW & UMP_IEP_mask) >> i32(1)

    # Get PSW.NMI
    PSW_NMI = (PSW & NMI_mask) >> i32(9)

    # Set PC
    dst = NPC & i32(0xFFFFFFFE) if PSW_NMI else EPC & i32(0xFFFFFFFE)
    PC = dst

    # Set flags
    PSW = PSW ^ NMI_mask if PSW_NMI else PSW ^ UMC_IEC_mask

    ir.IRDst = dst


@sbuild.parse
def swi(imm2):
    """SWI - Software Interrupt"""

    # if(imm2==0) EXC.SIP0 <- 1
    # else if (imm2==1) EXC.SIP1 <- 1
    # else if (imm2==2) EXC.SIP2 <- 1
    # else if (imm2==3) EXC.SIP3 <- 1

    # EXC.SIP0 == bit 4
    # EXC.SIP1 == bit 5
    # EXC.SIP2 == bit 6
    # EXC.SIP3 == bit 7

    EXC = EXC ^ (i32(1) << (i32(4) + imm2))


# Note: the following instructions can't be implemented
manual_functions["halt"] = mep_nop
manual_functions["sleep"] = mep_nop
manual_functions["break"] = mep_nop
manual_functions["syncm"] = mep_nop
manual_functions["stcb"] = mep_nop_2_args
manual_functions["ldcb"] = mep_nop_2_args


### Bit manipulation instruction option

def bsetm(ir, instr, rm_deref, imm3):
    """BSETM - Bit Set Memory"""

    # MemByte(Rm) <- MemByte(Rm) or (1<<imm3)
    e = []
    e.append(ExprAssign(ExprMem(rm_deref.ptr, 8), ExprOp("|", ExprMem(rm_deref.ptr, 8), (i8(1) << imm3[:8]))))
    return e, []

manual_functions["bsetm"] = bsetm


def bclrm(ir, instr, rm_deref, imm3):
    """BCLRM - Bit Clear Memory"""

    # MemByte(Rm) <- MemByte(Rm) and ~(1<<imm3)
    e = []
    shift = ExprOp("<<", i8(1), imm3[:8])
    e.append(ExprAssign(ExprMem(rm_deref.ptr, 8), ExprOp("&", ExprMem(rm_deref.ptr, 8), shift.__invert__())))
    return e, []

manual_functions["bclrm"] = bclrm


def bnotm(ir, instr, rm_deref, imm3):
    """BNOTM - Bit Not Memory"""

    # MemByte(Rm) <- MemByte(Rm) xor (1<<imm3)
    e = []
    e.append(ExprAssign(ExprMem(rm_deref.ptr, 8), ExprOp("^", ExprMem(rm_deref.ptr, 8), (i8(1) << imm3[:8]))))
    return e, []

manual_functions["bnotm"] = bnotm


def btstm(ir, instr, r0, rm_deref, imm3):
    """BTSTM - Bit Test Memory"""

    # R0 <- ZeroExt( MemByte(Rm) and (1<<imm3) )
    e = []
    e.append(ExprAssign(r0, ExprOp("&", ExprMem(rm_deref.ptr, 8), i8(1) << imm3[:8]).zeroExtend(32)))
    return e, []

manual_functions["btstm"] = btstm


def tas(ir, instr, rn, rm_deref):
    """TAS - Load And Set"""

    # temp <- Rm; Rn <- ZeroExt(MemByte(temp)); MemByte(temp) <- 1
    e = []
    temp = rm_deref
    e.append(ExprAssign(rn, ExprMem(temp.ptr, 8).zeroExtend(32)))
    e.append(ExprAssign(ExprMem(temp.ptr, 8),  i8(1)))
    return e, []

manual_functions["tas"] = tas


### Data cache option

# Note: the following instruction can't be implemented
manual_functions["cache"] = mep_nop_2_args


### 32-bit multiply instruction option

@sbuild.parse
def mul(rn, rm):
    """MUL - Signed 32-bit multiplication"""

    # HI||LO <- Rn * Rm (Signed)
    result = rn.signExtend(64) * rm.signExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]


@sbuild.parse
def mulu(rn, rm):
    """MUL - Unsigned 32-bit multiplication"""

    # HI||LO <- Rn * Rm (Unsigned)
    result = rn.zeroExtend(64) * rm.zeroExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[0:32]


@sbuild.parse
def mulr(rn, rm):
    """MULR - Signed 32-bit multiplication & store LO in Rn"""

    # HI||LO <- Rn * Rm; Rn <- LO (Signed)
    result = rn.signExtend(64) * rm.signExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]
    rn = result[:32]


@sbuild.parse
def mulru(rn, rm):
    """MULRU - Unsigned 32-bit multiplication & store LO in Rn"""

    # HI||LO <- Rn * Rm; Rn <- LO (Unsigned)
    result = rn.zeroExtend(64) * rm.zeroExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]
    rn = result[:32]


@sbuild.parse
def madd(rn, rm):
    """MADD - Signed 32-bit multiplication, adding results to HI & LO registers"""

    # HI||LO <- HI||LO + Rn*Rm (Signed)
    result = (HI << i32(32)).signExtend(64) + LO.signExtend(64) + rn.signExtend(64) * rm.signExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]


@sbuild.parse
def maddu(rn, rm):
    """MADDU - Unsigned 32-bit multiplication, adding results to HI & LO registers"""

    # HI||LO <- HI||LO + Rn*Rm (Unsigned)
    result = (HI << i32(32)).zeroExtend(64) + LO.zeroExtend(64) + rn.zeroExtend(64) * rm.zeroExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]


@sbuild.parse
def maddr(rn, rm):
    """MADDR - Signed 32-bit multiplication, adding results to HI & LO registers & storing LO in Rn"""

    # HI||LO <- HI||LO + Rn*Rm; Rn <- LO (Signed)
    result = (HI << i32(32)).signExtend(64) + LO.signExtend(64) + rn.signExtend(64) * rm.signExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]
    rn = result[:32]


@sbuild.parse
def maddru(rn, rm):
    """MADDRU - Unsigned 32-bit multiplication, adding results to HI & LO registers & storing LO in Rn"""

    # HI||LO <- HI||LO + Rn*Rm; Rn <- LO (Unsigned)
    result = (HI << i32(32)).zeroExtend(64) + LO.zeroExtend(64) + rn.zeroExtend(64) * rm.zeroExtend(64)  # expand registers size
    HI = result[32:64]
    LO = result[:32]
    rn = result[:32]


### 32-bit divide instruction option

@sbuild.parse
def div(rn, rm):
    """DIV - Signed division"""

    # LO <- Rn / Rm, HI <- Rn % Rm (Signed)

    # Mask sign bits
    sign_mask = i32(0x80000000)
    sign_rn = rn & sign_mask
    sign_rm = rm & sign_mask

    # Check if both numbers are positive or negative
    are_both_neg = sign_rn & sign_rm
    are_both_pos = ExprCond(
        are_both_neg - sign_mask,
        ExprInt(0, are_both_neg.size),
        ExprInt(1, are_both_neg.size)
    )


    # Invert both numbers
    rn_inv = ~rn + i32(1)
    rm_inv = ~rm + i32(1)

    # Used to delay the arithmetic computations
    tmp_rm = rm if rm else i32(1)
    tmp_rm_inv = rm_inv if rm_inv else i32(1)

    # Results if only rn, or rm is negative
    LO_rn_neg = (~(rn_inv // tmp_rm) + i32(1)) if sign_rn else (~(rn // tmp_rm_inv) + i32(1))
    HI_rn_neg = (~(rn_inv % tmp_rm) + i32(1)) if sign_rn else (~(rn % tmp_rm_inv) + i32(1))

    # Results if both numbers are positive
    LO_pos = rn // tmp_rm if are_both_pos else LO_rn_neg
    HI_pos = rn % tmp_rm if are_both_pos else HI_rn_neg

    # Results if both numbers are negative
    LO_neg = rn_inv // tmp_rm_inv if are_both_neg else LO_pos
    HI_neg = rn_inv % tmp_rm_inv if are_both_neg else HI_pos

    # Results if rm is equal to zero
    LO = LO_neg if rm else LO
    HI = HI_neg if rm else HI

    exception_flags = i32(0) if rm else i32(EXCEPT_DIV_BY_ZERO)


@sbuild.parse
def divu(rn, rm):
    """DIVU - Unsigned division"""

    # LO <- Rn / Rm, HI <- Rn % Rm (Unsigned)

    tmp_rm = rm if rm else i32(1)  # used to delay the arithmetic computations
    LO = rn // tmp_rm if rm else LO
    HI = rn % tmp_rm if rm else HI

    exception_flags = i32(0) if rm else i32(EXCEPT_DIV_BY_ZERO)


### Debug function option

@sbuild.parse
def dret():
    """DRET - Debug Exception Return"""

    # PC <- DEPC; DBG.DM <- 0
    PC = DEPC
    DBG = DBG & i32(0xFFFFBFFF)  # DBG.DM: bit 15


@sbuild.parse
def dbreak():
    """DBREAK - Debug break"""

    # The DBG.DBP bit becomes 1
    DBG = DBG ^ i32(0b10)  # DBG.DBP: bit 2


### Leading zero instruction option

@sbuild.parse
def ldz(rn, rm):
    """LDZ - Count Leading Zeroes

       Note: this implementation is readable, yet slow. Each bit are tested
       individually, and the results are propagated to other bits.

       Here is the commented implementation for 4-bit integers:
       rm = 0b0001

       # Invert the value
       reversed_rm = ~rm
      -> reversed_rm = 0b1110

       # Test bits individually
       b3 = (reversed_rm & i32(2**3)) >> i32(3) if reversed_rm else i32(0)
      -> b3 = (0b1110 & 0b1000 >> 3) = 1

       b2 = (reversed_rm & i32(2**2)) >> i32(2) if b3 else i32(0)
      -> b2 = (0b1110 & 0b0100 >> 2) = 1

       b1 = (reversed_rm & i32(2**1)) >> i32(1) if b2 else i32(0)
      -> b1 = (0b1110 & 0b0010 >> 1) = 1

       b0 = (reversed_rm & i32(2**0)) >> i32(0) if b1 else i32(0)
      -> b0 = (0b1110 & 0b0001 >> 0) = 0

       # Sum all partial results
       rn = b3 + b2 + b1 + b0
      -> rn = 1 + 1 + 1 + 0 = 3
    """

    # Rn <- LeadingZeroDetect(Rm)

    # Invert the value
    reversed_rm = ~rm

    # Test bits individually
    b31 = (reversed_rm & i32(2**31)) >> i32(31) if reversed_rm else i32(0)
    b30 = (reversed_rm & i32(2**30)) >> i32(30) if b31 else i32(0)
    b29 = (reversed_rm & i32(2**29)) >> i32(29) if b30 else i32(0)
    b28 = (reversed_rm & i32(2**28)) >> i32(28) if b29 else i32(0)
    b27 = (reversed_rm & i32(2**27)) >> i32(27) if b28 else i32(0)
    b26 = (reversed_rm & i32(2**26)) >> i32(26) if b27 else i32(0)
    b25 = (reversed_rm & i32(2**25)) >> i32(25) if b26 else i32(0)
    b24 = (reversed_rm & i32(2**24)) >> i32(24) if b25 else i32(0)
    b23 = (reversed_rm & i32(2**23)) >> i32(23) if b24 else i32(0)
    b22 = (reversed_rm & i32(2**22)) >> i32(22) if b23 else i32(0)
    b21 = (reversed_rm & i32(2**21)) >> i32(21) if b22 else i32(0)
    b20 = (reversed_rm & i32(2**20)) >> i32(20) if b21 else i32(0)
    b19 = (reversed_rm & i32(2**19)) >> i32(19) if b20 else i32(0)
    b18 = (reversed_rm & i32(2**18)) >> i32(18) if b19 else i32(0)
    b17 = (reversed_rm & i32(2**17)) >> i32(17) if b18 else i32(0)
    b16 = (reversed_rm & i32(2**16)) >> i32(16) if b17 else i32(0)
    b15 = (reversed_rm & i32(2**15)) >> i32(15) if b16 else i32(0)
    b14 = (reversed_rm & i32(2**14)) >> i32(14) if b15 else i32(0)
    b13 = (reversed_rm & i32(2**13)) >> i32(13) if b14 else i32(0)
    b12 = (reversed_rm & i32(2**12)) >> i32(12) if b13 else i32(0)
    b11 = (reversed_rm & i32(2**11)) >> i32(11) if b12 else i32(0)
    b10 = (reversed_rm & i32(2**10)) >> i32(10) if b11 else i32(0)
    b09 = (reversed_rm & i32(2 ** 9)) >> i32(9) if b10 else i32(0)
    b08 = (reversed_rm & i32(2 ** 8)) >> i32(8) if b09 else i32(0)
    b07 = (reversed_rm & i32(2 ** 7)) >> i32(7) if b08 else i32(0)
    b06 = (reversed_rm & i32(2 ** 6)) >> i32(6) if b07 else i32(0)
    b05 = (reversed_rm & i32(2 ** 5)) >> i32(5) if b06 else i32(0)
    b04 = (reversed_rm & i32(2 ** 4)) >> i32(4) if b05 else i32(0)
    b03 = (reversed_rm & i32(2 ** 3)) >> i32(3) if b04 else i32(0)
    b02 = (reversed_rm & i32(2 ** 2)) >> i32(2) if b03 else i32(0)
    b01 = (reversed_rm & i32(2 ** 1)) >> i32(1) if b02 else i32(0)
    b00 = (reversed_rm & i32(2 ** 0)) >> i32(0) if b01 else i32(0)

    # Sum all partial results
    rn = b31 + b30 + b29 + b28 + b27 + b26 + b25 + b24 + b23 + b22 + b21 + b20 \
        + b19 + b18 + b17 + b16 + b15 + b14 + b13 + b12 + b11 + b10 + b09 + b08 \
        + b07 + b06 + b05 + b04 + b03 + b02 + b01 + b00


### Coprocessor option

# Note: these instructions are implemented when needed

# SWCP - Store Word to memory from a coprocessor register
#        MemWord(Rm31..2||00) <- CRn 31..0
manual_functions["swcp"] = sw


# LWCP - Load Word from memory to a coprocessor register
#        CRn <- MemWord(Rm31..2||00)
manual_functions["lwcp"] = lw


def smcp(ir, instr, reg_src, deref_dst):
    """SMCP - Store Word to memory from a coprocessor register"""

    # MemDword(Rm31..3||000) <- CRn
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr & i32(0xFFFFFFF8), 32), reg_src))
    return e, []

manual_functions["smcp"] = smcp


def lmcp(ir, instr, reg_dst, deref_src):
    """LMCP - Load Word from memory to a coprocessor register"""

    # CRn <- MemDword(Rm31..3||000)
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_src.ptr & i32(0xFFFFFFF8), 32)))
    return e, []

manual_functions["lmcp"] = lmcp


def swcpi(ir, instr, reg_src, deref_dst):
    """SWCPI - Store Word to memory, and increment the address"""

    # MemWord(Rm31..2||00) <- CRn 31..0; Rm<-Rm+4
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr & i32(0xFFFFFFFC), 32), reg_src))
    e.append(ExprAssign(deref_dst.ptr, deref_dst.ptr + i32(4)))
    return e, []

manual_functions["swcpi"] = swcpi


def lwcpi(ir, instr, reg_dst, deref_src):
    """LWCPI - Load Word from memory, and increment the address"""

    # CRn <- MemWord(Rm31..2||00); Rm<-Rm+4
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_src.ptr & i32(0xFFFFFFFC), 32)))
    e.append(ExprAssign(deref_src.ptr, deref_src.ptr + i32(4)))
    return e, []

manual_functions["lwcpi"] = lwcpi

def smcpi(ir, instr, reg_src, deref_dst):
    """SMCPI - Store Word to memory, and increment the address"""

    # MemDword(Rm31..3||000) <- CRn; Rm<-Rm+8
    e = []
    e.append(ExprAssign(ExprMem(deref_dst.ptr & i32(0xFFFFFFF8), 32), reg_src))
    e.append(ExprAssign(deref_dst.ptr, deref_dst.ptr + i32(8)))
    return e, []

manual_functions["smcpi"] = smcpi


def lmcpi(ir, instr, reg_dst, deref_src):
    """LMCPI - Load Word from memory, and increment the address"""

    # CRn <- MemDword(Rm31..3||000); Rm<-Rm+8
    e = []
    e.append(ExprAssign(reg_dst, ExprMem(deref_src.ptr & i32(0xFFFFFFFC), 32)))
    e.append(ExprAssign(deref_src.ptr, deref_src.ptr + i32(8)))
    return e, []

manual_functions["lmcpi"] = lmcpi


### IR MeP definitions

def get_mnemo_expr(ir, instr, *args):
    """Simplify getting the IR from a miasm instruction."""

    if instr.name.lower() in sbuild.functions:
        mnemo_func = sbuild.functions[instr.name.lower()]
    else:
        mnemo_func = manual_functions[instr.name.lower()]

    ir, extra_ir = mnemo_func(ir, instr, *args)
    return ir, extra_ir


class Lifter_MEPb(Lifter):
    """Toshiba MeP miasm IR - Big Endian

       It transforms an instructon into an IR.
    """

    addrsize = 32

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_mep, "b", loc_db)
        self.pc = mn_mep.getpc()
        self.sp = mn_mep.getsp()
        self.IRDst = ExprId("IRDst", 32)

    def get_ir(self, instr):
        """Get the IR from a miasm instruction."""

        instr_ir, extra_ir = get_mnemo_expr(self, instr, *instr.args)

        return instr_ir, extra_ir

    def get_next_break_loc_key(self, instr):
        """Returns a new label that identifies where the instruction is going.

           Note: it eases linking IR blocks
        """

        l = self.loc_db.get_or_create_offset_location(instr.offset + instr.l)
        return l


class Lifter_MEPl(Lifter_MEPb):
    """Toshiba MeP miasm IR - Little Endian"""

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_mep, "l", loc_db)
        self.pc = mn_mep.getpc()
        self.sp = mn_mep.getsp()
        self.IRDst = ExprId("IRDst", 32)
