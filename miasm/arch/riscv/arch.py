#-*- coding:utf-8 -*-

from __future__ import print_function
from builtins import range
import re

from future.utils import viewitems

from miasm.core import utils
from miasm.expression.expression import *
from pyparsing import *
from miasm.core.cpu import *
from collections import defaultdict
import miasm.arch.riscv.regs as regs_module
from miasm.arch.riscv.regs import *
from miasm.core.asm_ast import AstNode, AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html
from miasm.core.utils import BRACKET_O, BRACKET_C


log = logging.getLogger("riscv_arch")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

gpregs_64 = (xregs_info.parser)

gpregs_info = {64: xregs_info, }

BRCOND = ["BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU"]

CALL = ["JAL", "JALR"]

# TODO: support 32-bit mode
XLEN64 = 64


class riscv_gpreg_noarg(reg_noarg):
    parser = gpregs_64
    gpregs_info = gpregs_info

    def decode(self, v):
        # TODO: support 32-bit mode
        size = XLEN64
        self.expr = self.gpregs_info[size].expr[v & 0x1F]
        return True

    def encode(self):
        if not self.expr.size in self.gpregs_info:
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True
    
class riscv_arg(m_arg):
    def asm_ast_to_expr(self, value, loc_db, size_hint=None, fixed_size=None):
        if size_hint is None:
            # TODO: support 32-bit mode
            size_hint = XLEN64
        if fixed_size is None:
            fixed_size = set()

        if isinstance(value, AstId):
            if value.name in all_regs_ids_byname:
                reg = all_regs_ids_byname[value.name]
                fixed_size.add(reg.size)
                return reg

            if isinstance(value.name, ExprId):
                fixed_size.add(value.name.size)
                return value.name

            loc_key = loc_db.get_or_create_name_location(value.name)
            return m2_expr.ExprLoc(loc_key, size_hint)

        if isinstance(value, AstInt):
            assert size_hint is not None
            return m2_expr.ExprInt(value.value, size_hint)

        if isinstance(value, AstOp):
            args = [self.asm_ast_to_expr(arg, loc_db, None, fixed_size)
                    for arg in value.args]

            if len(fixed_size) == 0:
                pass
            elif len(fixed_size) == 1:
                size = list(fixed_size)[0]
                args = [self.asm_ast_to_expr(arg, loc_db, size, fixed_size)
                        for arg in value.args]
            else:
                raise ValueError("Size conflict")

            return m2_expr.ExprOp(value.op, *args)

        return None

class riscv_imm_I(imm_noarg, riscv_arg):
    parser = base_expr
    intsize = XLEN64

    def decode(self, v):
        v &= self.lmask
        if v & (1 << (self.l - 1)):
            v -= 1 << self.l
        self.expr = m2_expr.ExprInt(v, self.intsize)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        v = int(self.expr)
        if v < -(1 << (self.l - 1)) or v >= (1 << (self.l - 1)):
            return False
        self.value = v & self.lmask
        return True

class riscv_imm_S(imm_noarg, riscv_arg):
    """
    S-type store imm[11:0] = {imm[11:5], imm[4:0]}, sign-extended
    """
    parser = base_expr
    intsize = XLEN64

    def decode(self, v):
        # v = imm[4:0]
        lo = v & self.lmask
        hi = self.parent.imm_S_hi.value

        imm12 = (hi << 5) | lo

        if imm12 & (1 << 11):
            imm12 -= 1 << 12

        self.expr = m2_expr.ExprInt(imm12, self.intsize)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False

        v = int(self.expr)
        if v < -(1 << 11) or v >= (1 << 11):
            return False

        imm12 = v & 0xFFF
        lo = imm12 & 0x1F
        hi = (imm12 >> 5) & 0x7F

        self.parent.imm_S_hi.value = hi
        self.value = lo
        return True

class riscv_imm_B(imm_noarg, riscv_arg):
    """
    B-type branch offset
    """
    parser = base_expr
    intsize = XLEN64

    def decode(self, v):
        # imm[11]
        bit11    = v & 0x1
        bit12    = self.parent.b_imm_12.value
        bits10_5 = self.parent.b_imm_10_5.value
        bits4_1  = self.parent.b_imm_4_1.value

        imm = (bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1)

        # 13-bit sign-extend
        if imm & (1 << 12):
            imm -= 1 << 13

        self.expr = m2_expr.ExprInt(imm, self.intsize)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False

        imm = int(self.expr)

        # RISC-V B-type offset must 2 Bytes aligned
        if imm & 1:
            return False

        if imm < -(1 << 12) or imm >= (1 << 12):
            return False

        imm &= (1 << 13) - 1  # 13 bits

        bit12    = (imm >> 12) & 0x1
        bit11    = (imm >> 11) & 0x1
        bits10_5 = (imm >> 5)  & 0x3F
        bits4_1  = (imm >> 1)  & 0xF

        self.parent.b_imm_12.value   = bit12
        self.parent.b_imm_10_5.value = bits10_5
        self.parent.b_imm_4_1.value  = bits4_1
        self.value = bit11 # imm[11]
        return True


class riscv_imm_U(imm_noarg, riscv_arg):
    """
    U-type imm[31:12]
    """
    parser = base_expr
    intsize = XLEN64

    def decode(self, v):
        v &= self.lmask
        if v & (1 << 19):
            v -= 1 << 20
        self.expr = m2_expr.ExprInt(v, self.intsize)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False

        val = int(self.expr)
        if val < -(1 << 19) or val >= (1 << 19):
            return False

        self.value = val & self.lmask
        return True


class riscv_imm_J(imm_noarg, riscv_arg):
    """
    J-type JAL offset: imm[20|10:1|11|19:12] << 1, sign-extended
    """
    parser = base_expr
    intsize = XLEN64

    def decode(self, v):
        bits19_12 = v & self.lmask

        bit20     = self.parent.j_imm_20.value
        bits10_1  = self.parent.j_imm_10_1.value
        bit11     = self.parent.j_imm_11.value

        imm = (bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1)

        if imm & (1 << 20):
            imm -= 1 << 21

        self.expr = m2_expr.ExprInt(imm, self.intsize)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False

        imm = int(self.expr)

        if imm & 1:
            return False

        if imm < -(1 << 20) or imm >= (1 << 20):
            return False

        imm &= (1 << 21) - 1

        bit20     = (imm >> 20) & 0x1
        bits19_12 = (imm >> 12) & 0xFF
        bit11     = (imm >> 11) & 0x1
        bits10_1  = (imm >> 1)  & 0x3FF

        self.parent.j_imm_20.value   = bit20
        self.parent.j_imm_10_1.value = bits10_1
        self.parent.j_imm_11.value   = bit11
        self.value                   = bits19_12
        return True

class riscv_gpreg(riscv_gpreg_noarg, riscv_arg):
    pass

class additional_info(object):

    def __init__(self):
        self.except_on_instr = False

class instruction_riscv(instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_riscv, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int():
            return str(expr)

        if expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)

        if isinstance(expr, m2_expr.ExprOp) and expr.op == "+":
            base, off = expr.args
            if off.is_int():
                return "%s(%s)" % (off, base)
            return "%s + %s" % (base, off)

        if isinstance(expr, m2_expr.ExprOp):
            return "%s(%s)" % (expr.op, ", ".join(str(a) for a in expr.args))

        raise NotImplementedError("bad op %r" % (expr,))

    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int() or expr.is_loc():
            return color_expr_html(expr, loc_db)

        if isinstance(expr, m2_expr.ExprOp) and expr.op == "+":
            base, off = expr.args
            if off.is_int():
                return "%s(%s)" % (
                    color_expr_html(off, loc_db),
                    color_expr_html(base, loc_db),
                )
            return "%s + %s" % (
                color_expr_html(base, loc_db),
                color_expr_html(off, loc_db),
            )

        if isinstance(expr, m2_expr.ExprOp):
            args_html = ", ".join(color_expr_html(a, loc_db) for a in expr.args)
            return "%s(%s)" % (
                utils.set_html_text_color(expr.op, utils.COLOR_OP),
                args_html,
            )

        raise NotImplementedError("bad op %r" % (expr,))

    def splitflow(self):
        if self.name in BRCOND:
            return True

        if self.name == "JAL":
            return True

        if self.name == "JALR":
            rd = self.args[0]

            if rd != X0:
                return True

            return False

        return False


    def dstflow(self):
        if self.name in BRCOND:
            return True

        if self.name == "JAL":
            return True

        if self.name == "JALR":
            rd = self.args[0]

            if rd != X0:
                return True

            return False

        return False
    
    def dstflow2label(self, loc_db):
        index = self.mnemo_flow_to_dst_index(self.name)
        expr = self.args[index]

        if not expr.is_int():
            return
        
        addr = (int(expr) + self.offset) & int(expr.mask)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[index] = m2_expr.ExprLoc(loc_key, expr.size)

    def mnemo_flow_to_dst_index(self, name):
        if self.name in BRCOND:
            return 2

        elif self.name in ["JAL"]:
            return len(self.args) - 1

        elif self.name in ["JALR"]:
            return 1

        else:
            return 0

    def getdstflow(self, loc_db):
        index = self.mnemo_flow_to_dst_index(self.name)
        return [self.args[index]]


    def breakflow(self):
        return self.name in (
            BRCOND
            + CALL
            + ["RET", "ECALL", "EBREAK", "MRET", "SRET", "URET"]
        )

    def is_subcall(self):
        return self.name in CALL

class mn_riscv(cls_mn):
    name = "riscv"
    regs = regs_module
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    bintree = {}
    delayslot = 0
    # TODO: support 32-bit mode, however RISC-V is mostly 64-bit now.
    pc = {64: PC}
    sp = {64: X2}
    instruction = instruction_riscv
    max_instruction_len = 4

    @classmethod
    def getpc(cls, attrib=None):
        return PC

    @classmethod
    def getsp(cls, attrib=None):
        return X2

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def check_mnemo(cls, fields):
        pass

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        l = sum(x.l for x in fields)
        # RISC-V only has 16-bit and 32-bit instructions
        if l not in (16, 32):
            raise ValueError(f"Invalid RISC-V instruction length: {l}")
        return fields
    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

def riscvop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_riscv,), dct)

# general regs
rd  = bs(l=5, cls=(riscv_gpreg,), fname="rd")
rs1 = bs(l=5, cls=(riscv_gpreg,), fname="rs1")
rs2 = bs(l=5, cls=(riscv_gpreg,), fname="rs2")

# I-type imm[11:0]
imm_I = bs(l=12, cls=(riscv_imm_I,), fname="imm_I")

# S-type imm[11:5] | imm[4:0]
imm_S_hi = bs(l=7, fname="imm_S_hi")
imm_S    = bs(l=5, cls=(riscv_imm_S,), fname="imm_S")

# B-type imm[12|10:5|4:1|11] merge to b_imm
b_imm_12   = bs(l=1, fname="b_imm_12")
b_imm_10_5 = bs(l=6, fname="b_imm_10_5")
b_imm_4_1  = bs(l=4, fname="b_imm_4_1")
b_imm      = bs(l=1, cls=(riscv_imm_B,), fname="b_imm")


# U-type imm[31:12] << 12
u_imm = bs(l=20, cls=(riscv_imm_U,), fname="u_imm")

# J-type JAL offset
j_imm_20    = bs(l=1, fname="j_imm_20")
j_imm_10_1  = bs(l=10, fname="j_imm_10_1")
j_imm_11    = bs(l=1, fname="j_imm_11")
j_imm       = bs(l=8, cls=(riscv_imm_J,), fname="j_imm")


# R-type integer ALU
riscvop("add",  [bs("0000000"), rs2, rs1, bs("000"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("sub",  [bs("0100000"), rs2, rs1, bs("000"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("and",  [bs("0000000"), rs2, rs1, bs("111"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("or",   [bs("0000000"), rs2, rs1, bs("110"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("xor",  [bs("0000000"), rs2, rs1, bs("100"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("sll",  [bs("0000000"), rs2, rs1, bs("001"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("srl",  [bs("0000000"), rs2, rs1, bs("101"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("sra",  [bs("0100000"), rs2, rs1, bs("101"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("slt",  [bs("0000000"), rs2, rs1, bs("010"), rd, bs("0110011")], [rd, rs1, rs2])
riscvop("sltu", [bs("0000000"), rs2, rs1, bs("011"), rd, bs("0110011")], [rd, rs1, rs2])

# I-type ALU imm
# NOP: addi x0, x0, x0
riscvop("addi",  [imm_I, rs1, bs("000"), rd, bs("0010011")], [rd, rs1, imm_I])
riscvop("slti",  [imm_I, rs1, bs("010"), rd, bs("0010011")], [rd, rs1, imm_I])
riscvop("sltiu", [imm_I, rs1, bs("011"), rd, bs("0010011")], [rd, rs1, imm_I])
riscvop("xori",  [imm_I, rs1, bs("100"), rd, bs("0010011")], [rd, rs1, imm_I])
riscvop("ori",   [imm_I, rs1, bs("110"), rd, bs("0010011")], [rd, rs1, imm_I])
riscvop("andi",  [imm_I, rs1, bs("111"), rd, bs("0010011")], [rd, rs1, imm_I])

# I-type LOAD
riscvop("lb",  [imm_I, rs1, bs("000"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("lh",  [imm_I, rs1, bs("001"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("lw",  [imm_I, rs1, bs("010"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("ld",  [imm_I, rs1, bs("011"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("lbu",[imm_I, rs1, bs("100"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("lhu",[imm_I, rs1, bs("101"), rd, bs("0000011")], [rd, rs1, imm_I])
riscvop("lwu",[imm_I, rs1, bs("110"), rd, bs("0000011")], [rd, rs1, imm_I])
# JALR (it approach to I-Type)
riscvop("jalr", [imm_I, rs1, bs("000"), rd, bs("1100111")], [rd, rs1, imm_I])

# S-type STORE
riscvop("sb", [imm_S_hi, rs2, rs1, bs("000"), imm_S, bs("0100011")], [rs2, rs1, imm_S])
riscvop("sh", [imm_S_hi, rs2, rs1, bs("001"), imm_S, bs("0100011")], [rs2, rs1, imm_S])
riscvop("sw", [imm_S_hi, rs2, rs1, bs("010"), imm_S, bs("0100011")], [rs2, rs1, imm_S])
riscvop("sd", [imm_S_hi, rs2, rs1, bs("011"), imm_S, bs("0100011")], [rs2, rs1, imm_S])

# B-type BRCOND
riscvop("beq", [b_imm_12, b_imm_10_5, rs2, rs1, bs("000"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])
riscvop("bne", [b_imm_12, b_imm_10_5, rs2, rs1, bs("001"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])
riscvop("blt", [b_imm_12, b_imm_10_5, rs2, rs1, bs("100"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])
riscvop("bge", [b_imm_12, b_imm_10_5, rs2, rs1, bs("101"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])
riscvop("bltu", [b_imm_12, b_imm_10_5, rs2, rs1, bs("110"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])
riscvop("bgeu", [b_imm_12, b_imm_10_5, rs2, rs1, bs("111"), b_imm_4_1, b_imm, bs("1100011")], [rs1, rs2, b_imm])

# U-type (LUI / AUIPC)
riscvop("lui",   [u_imm, rd, bs("0110111")], [rd, u_imm])
riscvop("auipc", [u_imm, rd, bs("0010111")], [rd, u_imm])

# J-type JAL
riscvop("jal", [j_imm_20, j_imm_10_1, j_imm_11, j_imm, rd, bs("1101111")], [rd, j_imm])