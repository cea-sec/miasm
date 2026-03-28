from builtins import range
from future.utils import viewitems

from miasm.expression.expression import ExprId, ExprInt, ExprLoc, ExprMem, \
    ExprCond, ExprCompose, ExprOp, ExprAssign
from miasm.ir.ir import Lifter, IRBlock, AssignBlock
from miasm.arch.riscv.arch import mn_riscv
from miasm.arch.riscv.regs import *
from miasm.core.sembuilder import SemBuilder
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_INT_XX

# System register for riscv64
system_regs = {
    # User-level
    0x000: USTATUS,
    0x004: UIE,
    0x005: UTVEC,
    0x040: USCRATCH,
    0x041: UEPC,
    0x042: UCAUSE,
    0x043: UTVAL,
    0x044: UIP,

    # Supervisor-level
    0x100: SSTATUS,
    0x104: SIE,
    0x105: STVEC,
    0x140: SSCRATCH,
    0x141: SEPC,
    0x142: SCAUSE,
    0x143: STVAL,
    0x144: SIP,
    0x180: SATP,

    # Machine-level
    0x300: MSTATUS,
    0x301: MISA,
    0x304: MIE,
    0x305: MTVEC,
    0x340: MSCRATCH,
    0x341: MEPC,
    0x342: MCAUSE,
    0x343: MTVAL,
    0x344: MIP,

    # hart info
    0xF11: MVENDORID,
    0xF12: MARCHID,
    0xF13: MIMPID,
    0xF14: MHARTID,
}

# SemBuilder context
ctx = {
    "PC": PC,
    "ExprId": ExprId,
    "exception_flags": exception_flags,
    "interrupt_num": interrupt_num,
    "EXCEPT_DIV_BY_ZERO": EXCEPT_DIV_BY_ZERO,
    "EXCEPT_INT_XX": EXCEPT_INT_XX,
}

sbuild = SemBuilder(ctx)


# instruction definition ##############

@sbuild.parse
def add(rd, rs1, rs2):
    rd = rs1 + rs2

@sbuild.parse
def sub(rd, rs1, rs2):
    rd = rs1 - rs2

@sbuild.parse
def xor(rd, rs1, rs2):
    rd = rs1 ^ rs2

@sbuild.parse
def or_(rd, rs1, rs2):
    rd = rs1 | rs2

@sbuild.parse
def and_(rd, rs1, rs2):
    rd = rs1 & rs2

@sbuild.parse
def sll(rd, rs1, rs2):
    sh = rs2 & ExprInt(rs1.size - 1, rs1.size)
    rd = rs1 << sh

@sbuild.parse
def srl(rd, rs1, rs2):
    sh = rs2 & ExprInt(rs1.size - 1, rs1.size)
    rd = rs1 >> sh

@sbuild.parse
def sra(rd, rs1, rs2):
    sh = rs2 & ExprInt(rs1.size - 1, rs1.size)
    tmp = rs1.signExtend(rs1.size * 2)
    rd = (tmp >> sh).zeroExtend(rd.size)

@sbuild.parse
def addi(rd, rs1, imm):
    rd = rs1 + imm.signExtend(rs1.size)

@sbuild.parse
def andi(rd, rs1, imm):
    rd = rs1 & imm.zeroExtend(rs1.size)

@sbuild.parse
def slt(rd, rs1, rs2):
    rd = ExprCond(
        ExprOp("<", rs1, rs2),
        ExprInt(1, rd.size),
        ExprInt(0, rd.size),
    )

@sbuild.parse
def sltu(rd, rs1, rs2):
    rd = ExprCond(
        ExprOp("u<", rs1, rs2),
        ExprInt(1, rd.size),
        ExprInt(0, rd.size),
    )

@sbuild.parse
def slti(rd, rs1, imm):
    tmp = imm.signExtend(rs1.size)
    rd = ExprCond(
        ExprOp("<", rs1, tmp),
        ExprInt(1, rd.size),
        ExprInt(0, rd.size),
    )

@sbuild.parse
def sltiu(rd, rs1, imm):
    tmp = imm.signExtend(rs1.size)
    rd = ExprCond(
        ExprOp("u<", rs1, tmp),
        ExprInt(1, rd.size),
        ExprInt(0, rd.size),
    )

@sbuild.parse
def xori(rd, rs1, imm):
    rd = rs1 ^ imm

@sbuild.parse
def ori(rd, rs1, imm):
    rd = rs1 | imm

@sbuild.parse
def beq(rs1, rs2, target):
    cond = ExprOp("==", rs1, rs2)

    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)

    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bne(rs1, rs2, target):
    cond = ExprOp("!=", rs1, rs2)
    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)
    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def blt(rs1, rs2, target):
    cond = ExprOp("<", rs1, rs2)
    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)
    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bge(rs1, rs2, target):
    cond = ExprOp(">=", rs1, rs2)
    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)
    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bltu(rs1, rs2, target):
    cond = ExprOp("u<", rs1, rs2)
    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)
    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def bgeu(rs1, rs2, target):
    cond = ExprOp("u>=", rs1, rs2)
    fallthrough = ExprLoc(ir.get_next_loc_key(instr), PC.size)
    dst = ExprCond(cond, target, fallthrough)

    PC = dst
    ir.IRDst = dst

@sbuild.parse
def jalr(rd, rs1, imm):
    ret_addr = ExprInt(instr.offset + instr.l, PC.size)
    rd = ret_addr

    dst = rs1 + imm.signExtend(rs1.size)
    PC = dst
    ir.IRDst = dst

@sbuild.parse
def lui(rd, imm):
    rd = imm << ExprInt(12, imm.size)

@sbuild.parse
def auipc(rd, imm):
    rd = PC + (imm << ExprInt(12, imm.size))


@sbuild.parse
def ret(rd):
    PC = rd
    ir.IRDst = rd

def jal(ir, instr, rd, target):
    e = []
    ret_addr = ExprInt(instr.offset + instr.l, PC.size)
    e.append(ExprAssign(rd, ret_addr))
    e.append(ExprAssign(PC, target))
    ir.IRDst = target
    return e, []

def _load(ir, instr, rd, rs1, imm, size, signed):
    e = []
    addr = rs1 + imm.signExtend(rs1.size)
    mem = ExprMem(addr, size)

    if signed:
        val = mem.signExtend(rd.size)
    else:
        val = mem.zeroExtend(rd.size)

    e.append(ExprAssign(rd, val))
    return e, []

def lb(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 8, True)

def lh(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 16, True)

def lw(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 32, True)

def ld(ir, instr, rd, rs1, imm):
    e = []
    addr = rs1 + imm.signExtend(rs1.size)
    e.append(ExprAssign(rd, ExprMem(addr, rd.size)))
    return e, []

def lbu(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 8, False)

def lhu(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 16, False)

def lwu(ir, instr, rd, rs1, imm):
    return _load(ir, instr, rd, rs1, imm, 32, False)

def _store(ir, instr, rs1, rs2, imm, size):
    e = []
    addr = rs1 + imm.signExtend(rs1.size)
    if size < rs2.size:
        data = rs2[:size]
    else:
        data = rs2
    e.append(ExprAssign(ExprMem(addr, size), data))
    return e, []

def sb(ir, instr, rs1, rs2, imm):
    return _store(ir, instr, rs1, rs2, imm, 8)

def sh(ir, instr, rs1, rs2, imm):
    return _store(ir, instr, rs1, rs2, imm, 16)

def sw(ir, instr, rs1, rs2, imm):
    return _store(ir, instr, rs1, rs2, imm, 32)

def sd(ir, instr, rs1, rs2, imm):
    return _store(ir, instr, rs1, rs2, imm, 64)

# system-level instr
# TODO: add more instr for system-level instr

mnemo_func = sbuild.functions
mnemo_func.update({
    "and": and_,
    "or": or_,
    "jal": jal,
    "lb": lb,
    "lh": lh,
    "lw": lw,
    "ld": ld,
    "lbu": lbu,
    "lhu": lhu,
    "lwu": lwu,
    "sb": sb,
    "sh": sh,
    "sw": sw,
    "sd": sd,
})


def get_mnemo_expr(ir, instr, *args):
    if not instr.name.lower() in mnemo_func:
        raise NotImplementedError('unknown mnemo %s' % instr)
    instr_ir, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr_ir, extra_ir

class riscvinfo(object):
    mode = "riscv"
    # offset


class Lifter_Riscv64(Lifter):

    def __init__(self, loc_db):
        # TODO: support 32 bits mode
        Lifter.__init__(self, mn_riscv, 64, loc_db)
        self.pc = PC
        self.sp = X2
        self.IRDst = ExprId('IRDst', 64)
        self.addrsize = 64

    def get_ir(self, instr):
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *instr.args)
        self.mod_pc(instr, instr_ir, extra_ir)
        instr_ir, extra_ir = self.del_dst_zr(instr, instr_ir, extra_ir)
        return instr_ir, extra_ir

    def expraff_fix_regs_for_mode(self, e):
        dst = e.dst
        src = e.src
        return ExprAssign(dst, src)

    def irbloc_fix_regs_for_mode(self, irblock, mode=64):
        irs = []
        for assignblk in irblock:
            new_assignblk = dict(assignblk)
            for dst, src in viewitems(assignblk):
                del(new_assignblk[dst])
                new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.loc_db, irblock.loc_key, irs)

    def mod_pc(self, instr, instr_ir, extra_ir):
        "Replace PC by the instruction's offset"
        cur_offset = ExprInt(instr.offset, 64)
        pc_fixed = {self.pc: cur_offset}
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = ExprAssign(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))


    def del_dst_zr(self, instr, instr_ir, extra_ir):
        "Writes to x0 (zero register) are discarded"
        # riscv: ZERO=>X0
        regs_to_fix = [X0]

        instr_ir = [expr for expr in instr_ir if expr.dst not in regs_to_fix]

        new_irblocks = []
        for irblock in extra_ir:
            irs = []
            for assignblk in irblock:
                new_dsts = {
                    dst: src for dst, src in viewitems(assignblk)
                    if dst not in regs_to_fix
                }
                irs.append(AssignBlock(new_dsts, assignblk.instr))
            new_irblocks.append(IRBlock(self.loc_db, irblock.loc_key, irs))

        return instr_ir, new_irblocks

# TODO: implement CSR access functions
def get_csr_reg(csr):
    if not csr.is_int():
        raise NotImplementedError("CSR must be an immediate in IR, got %r" % (csr,))
    csr_num = int(csr)
    if csr_num not in system_regs:
        raise NotImplementedError("Unknown CSR 0x%03x" % csr_num)
    return system_regs[csr_num]