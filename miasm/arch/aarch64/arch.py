#-*- coding:utf-8 -*-

from builtins import range
from future.utils import viewitems, viewvalues

import logging
from pyparsing import *
from miasm.expression import expression as m2_expr
from miasm.core.cpu import *
from collections import defaultdict
from miasm.core.bin_stream import bin_stream
from miasm.arch.aarch64 import regs as regs_module
from miasm.arch.aarch64.regs import *
from miasm.core.cpu import log as log_cpu
from miasm.core.modint import mod_size2int
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html
from miasm.core import utils

log = logging.getLogger("aarch64dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

# refs from A_e_armv8_arm.pdf

# log_cpu.setLevel(logging.DEBUG)


replace_regs = {
    W0: X0[:32],
    W1: X1[:32],
    W2: X2[:32],
    W3: X3[:32],
    W4: X4[:32],
    W5: X5[:32],
    W6: X6[:32],
    W7: X7[:32],
    W8: X8[:32],
    W9: X9[:32],

    W10: X10[:32],
    W11: X11[:32],
    W12: X12[:32],
    W13: X13[:32],
    W14: X14[:32],
    W15: X15[:32],
    W16: X16[:32],
    W17: X17[:32],
    W18: X18[:32],
    W19: X19[:32],

    W20: X20[:32],
    W21: X21[:32],
    W22: X22[:32],
    W23: X23[:32],
    W24: X24[:32],
    W25: X25[:32],
    W26: X26[:32],
    W27: X27[:32],
    W28: X28[:32],
    W29: X29[:32],

    W30: LR[:32],

    WSP: SP[:32],

    WZR: m2_expr.ExprInt(0, 32),
    XZR: m2_expr.ExprInt(0, 64),

}




shift2expr_dct = {'LSL': '<<', 'LSR': '>>', 'ASR': 'a>>', 'ROR': '>>>'}
shift_str = ["LSL", "LSR", "ASR", "ROR"]
shift_expr = ["<<", ">>", "a>>", '>>>']


def cb_shift(tokens):
    return shift2expr_dct[tokens[0]]


def cb_extreg(tokens):
    return tokens[0]


def cb_shiftreg(tokens):
    if len(tokens) == 1:
        return tokens[0]
    elif len(tokens) == 3:
        result = AstOp(tokens[1], tokens[0], tokens[2])
        return result
    else:
        raise ValueError('bad string')


def cb_shift_sc(tokens):
    if len(tokens) == 1:
        return tokens[0]
    elif len(tokens) == 3:
        if tokens[1] != '<<':
            raise ValueError('bad op')
        result = AstOp("slice_at", tokens[0], tokens[2])
        return result
    else:
        raise ValueError('bad string')


def cb_extend(tokens):
    if len(tokens) == 1:
        return tokens[0]
    result = AstOp(tokens[1], tokens[0], tokens[2])
    return result


def cb_deref_pc_off(tokens):
    if len(tokens) == 2 and tokens[0] == "PC":
        result = AstOp('preinc', AstId(ExprId('PC', 64)), tokens[1])
        return result
    raise ValueError('bad string')

def cb_deref_pc_nooff(tokens):
    if len(tokens) == 1 and tokens[0] == "PC":
        result = AstOp('preinc', AstId(PC))
        return result
    raise ValueError('bad string')

all_binaryop_lsl_t = literal_list(shift_str).setParseAction(cb_shift)

all_binaryop_shiftleft_t = literal_list(["LSL"]).setParseAction(cb_shift)

extend_lst = ['UXTB', 'UXTH', 'UXTW', 'UXTX', 'SXTB', 'SXTH', 'SXTW', 'SXTX']
extend2_lst = ['UXTW', 'LSL', 'SXTW', 'SXTX']

all_extend_t = literal_list(extend_lst).setParseAction(cb_extreg)
all_extend2_t = literal_list(extend2_lst).setParseAction(cb_extreg)


gpregz32_extend = (gpregsz32_info.parser + Optional(all_extend_t + base_expr)).setParseAction(cb_extend)
gpregz64_extend = (gpregsz64_info.parser + Optional(all_extend_t + base_expr)).setParseAction(cb_extend)


shift32_off = (gpregsz32_info.parser + Optional(all_binaryop_lsl_t + base_expr)).setParseAction(cb_shiftreg)
shift64_off = (gpregsz64_info.parser + Optional(all_binaryop_lsl_t + base_expr)).setParseAction(cb_shiftreg)


shiftimm_imm_sc = (base_expr + all_binaryop_shiftleft_t + base_expr).setParseAction(cb_shift_sc)

shiftimm_off_sc = shiftimm_imm_sc | base_expr


shift_off = (shift32_off | shift64_off)
reg_ext_off = (gpregz32_extend | gpregz64_extend)

gpregs_32_64 = (gpregs32_info.parser | gpregs64_info.parser)
gpregsz_32_64 = (gpregsz32_info.parser | gpregsz64_info.parser | base_expr)

gpregs_32_64_nosp = (gpregs32_nosp_info.parser | gpregs64_nosp_info.parser)


simdregs = (simd08_info.parser | simd16_info.parser | simd32_info.parser | simd64_info.parser)
simdregs_h = (simd32_info.parser | simd64_info.parser | simd128_info.parser)

simdregs_h_zero = (simd32_info.parser | simd64_info.parser | simd128_info.parser | base_expr)


gpregs_info = {32: gpregs32_info,
               64: gpregs64_info}
gpregsz_info = {32: gpregsz32_info,
                64: gpregsz64_info}


gpregs_nosp_info = {
    32: gpregs32_nosp_info,
    64: gpregs64_nosp_info
}

simds_info = {8: simd08_info,
              16: simd16_info,
              32: simd32_info,
              64: simd64_info,
              128: simd128_info}



def cb_deref_nooff(t):
    # XXX default
    result = AstOp("preinc", t[0], AstInt(0))
    return result


def cb_deref_post(t):
    assert len(t) == 2
    if isinstance(t[1], AstId) and isinstance(t[1].name, ExprId):
        return
    result = AstOp("postinc", *t)
    return result


def cb_deref_pre(t):
    assert len(t) == 2
    if isinstance(t[1], AstId) and isinstance(t[1].name, ExprId):
        return
    result = AstOp("preinc", *t)
    return result


def cb_deref_pre_wb(t):
    assert len(t) == 2
    if isinstance(t[1], AstId) and isinstance(t[1].name, ExprId):
        return
    result = AstOp("preinc_wb", *t)
    return result


LBRACK = Suppress("[")
RBRACK = Suppress("]")
COMMA = Suppress(",")
POSTINC = Suppress("!")

deref_nooff = (LBRACK + gpregs64_info.parser + RBRACK).setParseAction(cb_deref_nooff)
deref_off_post = (LBRACK + gpregs64_info.parser + RBRACK + COMMA + base_expr).setParseAction(cb_deref_post)
deref_off_pre = (LBRACK + gpregs64_info.parser + COMMA + base_expr + RBRACK).setParseAction(cb_deref_pre)
deref_off_pre_wb = (LBRACK + gpregs64_info.parser + COMMA + base_expr + RBRACK + POSTINC).setParseAction(cb_deref_pre_wb)

deref = (deref_off_post | deref_off_pre_wb | deref_off_pre | deref_nooff)


deref_pc_off = (LBRACK + Literal("PC") + COMMA + base_expr + RBRACK).setParseAction(cb_deref_pc_off)
deref_pc_nooff = (LBRACK + Literal("PC") + RBRACK).setParseAction(cb_deref_pc_nooff)

deref_pc = (deref_pc_off | deref_pc_nooff)

def cb_deref_ext2op(t):
    if len(t) == 4:
        result = AstOp('segm', t[0], AstOp(t[2], t[1], t[3]))
        return result
    elif len(t) == 2:
        result = AstOp('segm', *t)
        return result

    raise ValueError("cad deref")

deref_ext2 = (LBRACK + gpregs_32_64 + COMMA + gpregs_32_64 + Optional(all_extend2_t + base_expr) + RBRACK).setParseAction(cb_deref_ext2op)


class additional_info(object):

    def __init__(self):
        self.except_on_instr = False
        self.lnk = None
        self.cond = None

CONDS = [
    'EQ', 'NE', 'CS', 'CC',
    'MI', 'PL', 'VS', 'VC',
    'HI', 'LS', 'GE', 'LT',
    'GT', 'LE', 'AL', 'NV']

CONDS_INV = [
    'NE', 'EQ', 'CC', 'CS',
    'PL', 'MI', 'VC', 'VS',
    'LS', 'HI', 'LT', 'GE',
    'LE', 'GT', 'NV', 'AL']

BRCOND = ['B.' + cond for cond in CONDS] + ['CBZ', 'CBNZ', 'TBZ', 'TBNZ']

# for conditional selec
conds_expr, _, conds_info = gen_regs(CONDS, {})
conds_inv_expr, _, conds_inv_info = gen_regs(CONDS_INV, {})



class aarch64_arg(m_arg):
    def asm_ast_to_expr(self, value, loc_db, size_hint=None, fixed_size=None):
        if size_hint is None:
            size_hint = 64
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
            if value.op == "segm":
                segm = self.asm_ast_to_expr(value.args[0], loc_db)
                ptr = self.asm_ast_to_expr(value.args[1], loc_db, None, fixed_size)
                return m2_expr.ExprOp('segm', segm, ptr)

            args = [self.asm_ast_to_expr(arg, loc_db, None, fixed_size) for arg in value.args]
            if len(fixed_size) == 0:
                # No fixed size
                pass
            elif len(fixed_size) == 1:
                # One fixed size, regen all
                size = list(fixed_size)[0]
                args = [self.asm_ast_to_expr(arg, loc_db, size, fixed_size) for arg in value.args]
            else:
                raise ValueError("Size conflict")

            return m2_expr.ExprOp(value.op, *args)
        return None


class instruction_aarch64(instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_aarch64, self).__init__(*args, **kargs)

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        wb = False
        if expr.is_id() or expr.is_int():
            return str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)
        elif isinstance(expr, m2_expr.ExprOp) and expr.op in shift_expr:
            op_str = shift_str[shift_expr.index(expr.op)]
            return "%s %s %s" % (expr.args[0], op_str, expr.args[1])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "slice_at":
            return "%s LSL %s" % (expr.args[0], expr.args[1])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op in extend_lst:
            op_str = expr.op
            return "%s %s %s" % (expr.args[0], op_str, expr.args[1])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "postinc":
            if int(expr.args[1]) != 0:
                return "[%s], %s" % (expr.args[0], expr.args[1])
            else:
                return "[%s]" % (expr.args[0])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "preinc_wb":
            if int(expr.args[1]) != 0:
                return "[%s, %s]!" % (expr.args[0], expr.args[1])
            else:
                return "[%s]" % (expr.args[0])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "preinc":
            if len(expr.args) == 1:
                return "[%s]" % (expr.args[0])
            elif not isinstance(expr.args[1], m2_expr.ExprInt) or int(expr.args[1]) != 0:
                return "[%s, %s]" % (expr.args[0], expr.args[1])
            else:
                return "[%s]" % (expr.args[0])
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == 'segm':
            arg = expr.args[1]
            if isinstance(arg, m2_expr.ExprId):
                arg = str(arg)
            elif arg.op == 'LSL' and int(arg.args[1]) == 0:
                arg = str(arg.args[0])
            else:
                arg = "%s %s %s" % (arg.args[0], arg.op, arg.args[1])
            return '[%s, %s]' % (expr.args[0], arg)

        else:
            raise NotImplementedError("bad op")

    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        wb = False
        if expr.is_id() or expr.is_int() or expr.is_loc():
            return color_expr_html(expr, loc_db)
        elif isinstance(expr, m2_expr.ExprOp) and expr.op in shift_expr:
            op_str = shift_str[shift_expr.index(expr.op)]
            return "%s %s %s" % (
                color_expr_html(expr.args[0], loc_db),
                utils.set_html_text_color(op_str, utils.COLOR_OP),
                color_expr_html(expr.args[1], loc_db)
            )
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "slice_at":
            return "%s LSL %s" % (
                color_expr_html(expr.args[0], loc_db),
                color_expr_html(expr.args[1], loc_db)
            )
        elif isinstance(expr, m2_expr.ExprOp) and expr.op in extend_lst:
            op_str = expr.op
            return "%s %s %s" % (
                color_expr_html(expr.args[0], loc_db),
                op_str,
                color_expr_html(expr.args[1], loc_db)
            )
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "postinc":
            if int(expr.args[1]) != 0:
                return "[%s], %s" % (
                    color_expr_html(expr.args[0], loc_db),
                    color_expr_html(expr.args[1], loc_db)
                )
            else:
                return "[%s]" % (color_expr_html(expr.args[0], loc_db))
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "preinc_wb":
            if int(expr.args[1]) != 0:
                return "[%s, %s]!" % (
                    color_expr_html(expr.args[0], loc_db),
                    color_expr_html(expr.args[1], loc_db)
                )
            else:
                return "[%s]" % (color_expr_html(expr.args[0], loc_db))
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == "preinc":
            if len(expr.args) == 1:
                return "[%s]" % (color_expr_html(expr.args[0], loc_db))
            elif not isinstance(expr.args[1], m2_expr.ExprInt) or int(expr.args[1]) != 0:
                return "[%s, %s]" % (
                    color_expr_html(expr.args[0], loc_db),
                    color_expr_html(expr.args[1], loc_db)
                )
            else:
                return "[%s]" % color_expr_html(expr.args[0], loc_db)
        elif isinstance(expr, m2_expr.ExprOp) and expr.op == 'segm':
            arg = expr.args[1]
            if isinstance(arg, m2_expr.ExprId):
                arg = str(arg)
            elif arg.op == 'LSL' and int(arg.args[1]) == 0:
                arg = str(arg.args[0])
            else:
                arg = "%s %s %s" % (
                    color_expr_html(arg.args[0], loc_db),
                    utils.set_html_text_color(arg.op, utils.COLOR_OP),
                    color_expr_html(arg.args[1], loc_db)
                )
            return '[%s, %s]' % (color_expr_html(expr.args[0], loc_db), arg)

        else:
            raise NotImplementedError("bad op")

    def dstflow(self):
        return self.name in BRCOND + ["B", "BL", "BR", "BLR"]

    def mnemo_flow_to_dst_index(self, name):
        if self.name in ['CBZ', 'CBNZ']:
            return 1
        elif self.name in ['TBZ', 'TBNZ']:
            return 2
        else:
            return 0

    def dstflow2label(self, loc_db):
        index = self.mnemo_flow_to_dst_index(self.name)
        expr = self.args[index]
        if not expr.is_int():
            return
        addr = (int(expr) + self.offset) & int(expr.mask)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[index] = m2_expr.ExprLoc(loc_key, expr.size)

    def breakflow(self):
        return self.name in BRCOND + ["BR", "BLR", "RET", "ERET", "DRPS", "B", "BL"]

    def is_subcall(self):
        return self.name in ["BLR", "BL"]

    def getdstflow(self, loc_db):
        index = self.mnemo_flow_to_dst_index(self.name)
        return [self.args[index]]

    def splitflow(self):
        return self.name in BRCOND + ["BLR", "BL"]

    def get_symbol_size(self, symbol, loc_db):
        return 64

    def fixDstOffset(self):
        index = self.mnemo_flow_to_dst_index(self.name)
        e = self.args[index]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, m2_expr.ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = (int(e) - self.offset) & int(e.mask)
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[index] = m2_expr.ExprInt(int(off), 64)



class mn_aarch64(cls_mn):
    delayslot = 0
    name = "aarch64"
    regs = regs_module
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = {'l': PC, 'b': PC}
    sp = {'l': SP, 'b': SP}
    instruction = instruction_aarch64
    max_instruction_len = 4
    alignment = 4

    @classmethod
    def getpc(cls, attrib=None):
        return PC

    @classmethod
    def getsp(cls, attrib=None):
        return SP

    def additional_info(self):
        info = additional_info()
        info.lnk = False
        if hasattr(self, "lnk"):
            info.lnk = self.lnk.value != 0
        return info

    @classmethod
    def getbits(cls, bs, attrib, start, n):
        if not n:
            return 0
        o = 0
        if n > bs.getlen() * 8:
            raise ValueError('not enough bits %r %r' % (n, len(bs.bin) * 8))
        while n:
            offset = start // 8
            n_offset = cls.endian_offset(attrib, offset)
            c = cls.getbytes(bs, n_offset, 1)
            if not c:
                raise IOError
            c = ord(c)
            r = 8 - start % 8
            c &= (1 << r) - 1
            l = min(r, n)
            c >>= (r - l)
            o <<= l
            o |= c
            n -= l
            start += l
        return o

    @classmethod
    def endian_offset(cls, attrib, offset):
        if attrib == "l":
            return (offset & ~3) + 3 - offset % 4
        elif attrib == "b":
            return offset
        else:
            raise NotImplementedError('bad attrib')

    @classmethod
    def check_mnemo(cls, fields):
        l = sum([x.l for x in fields])
        assert l == 32, "len %r" % l

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        l = sum([x.l for x in fields])
        if l == 32:
            return fields
        return fields

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_aarch64, self).value(mode)
        if mode == 'l':
            return [x[::-1] for x in v]
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')

    def get_symbol_size(self, symbol, loc_db, mode):
        return 32

    def reset_class(self):
        super(mn_aarch64, self).reset_class()
        if hasattr(self, "sf"):
            self.sf.value = None


def aarch64op(name, fields, args=None, alias=False):
    dct = {"fields": fields, "alias":alias}
    if args is not None:
        dct['args'] = args
    type(name, (mn_aarch64,), dct)


class aarch64_gpreg_noarg(reg_noarg):
    parser = gpregs_32_64
    gpregs_info = gpregs_info

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = self.gpregs_info[size].expr[v]
        return True

    def encode(self):
        if not test_set_sf(self.parent, self.expr.size):
            return False
        if not self.expr.size in self.gpregs_info:
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True

class aarch64_gpreg_noarg_nosp(aarch64_gpreg_noarg):
    parser = gpregs_32_64_nosp
    gpregs_info = gpregs_nosp_info

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        if v >= len(self.gpregs_info[size].expr):
            return False
        self.expr = self.gpregs_info[size].expr[v]
        return True

    def encode(self):
        if not test_set_sf(self.parent, self.expr.size):
            return False
        if not self.expr.size in self.gpregs_info:
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        if self.expr not in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True


class aarch64_simdreg(reg_noarg, aarch64_arg):
    parser = simdregs
    simd_size = [8, 16, 32, 64]

    def decode(self, v):
        if self.parent.size.value > len(self.simd_size):
            return False
        size = self.simd_size[self.parent.size.value]
        self.expr = simds_info[size].expr[v]
        return True

    def encode(self):
        if not self.expr.size in self.simd_size:
            return False
        if not self.expr in simds_info[self.expr.size].expr:
            return False
        self.value = simds_info[self.expr.size].expr.index(self.expr)
        self.parent.size.value = self.simd_size.index(self.expr.size)
        return True


class aarch64_simdreg_h(aarch64_simdreg):
    parser = simdregs_h
    simd_size = [32, 64, 128]


class aarch64_simdreg_32_64(aarch64_simdreg):
    parser = simdregs_h
    simd_size = [32, 64]


class aarch64_simdreg_32_64_zero(aarch64_simdreg_32_64):
    parser = simdregs_h_zero

    def decode(self, v):
        if v == 0 and self.parent.opc.value == 1:
            size = 64 if self.parent.size.value else 32
            self.expr = m2_expr.ExprInt(0, size)
            return True
        else:
            return super(aarch64_simdreg_32_64_zero, self).decode(v)

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            self.parent.opc.value = 1
            self.value = 0
            return True
        else:
            self.parent.opc.value = 0
            return super(aarch64_simdreg_32_64_zero, self).encode()


class aarch64_gpreg_isf(reg_noarg, aarch64_arg):
    parser = gpregs_32_64

    def decode(self, v):
        size = 32 if self.parent.sf.value else 64
        self.expr = gpregs_info[size].expr[v]
        return True

    def encode(self):
        if not self.expr in gpregs_info[self.expr.size].expr:
            return False
        self.value = gpregs_info[self.expr.size].expr.index(self.expr)
        self.parent.sf.value = 1 if self.expr.size == 32 else 0
        return True


class aarch64_gpreg(aarch64_gpreg_noarg, aarch64_arg):
    pass


class aarch64_gpreg_n1(aarch64_gpreg):

    def decode(self, v):
        if v == 0b11111:
            return False
        return super(aarch64_gpreg_n1, self).decode(v)

    def encode(self):
        super(aarch64_gpreg_n1, self).encode()
        return self.value != 0b11111


class aarch64_gpregz(aarch64_gpreg_noarg, aarch64_arg):
    parser = gpregsz_32_64
    gpregs_info = gpregsz_info


class aarch64_gpreg0(bsi, aarch64_arg):
    parser = gpregsz_32_64
    gpregs_info = gpregsz_info

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        if v == 0x1F:
            self.expr = m2_expr.ExprInt(0, size)
        else:
            self.expr = self.gpregs_info[size].expr[v]
        return True

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            if int(self.expr) == 0:
                self.value = 0x1F
                return True
            return False
        if not self.expr.size in self.gpregs_info:
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        if not self.expr in self.gpregs_info[self.expr.size].expr:
            return False
        self.value = self.gpregs_info[self.expr.size].expr.index(self.expr)
        return True


class aarch64_crreg(reg_noarg, aarch64_arg):
    reg_info = cr_info
    parser = reg_info.parser


class aarch64_gpreg32_nodec(bsi):
    reg_info = gpregs32_info


class aarch64_gpreg64_nodec(bsi):
    reg_info = gpregs64_info


class aarch64_gpreg32_noarg(reg_noarg):
    reg_info = gpregs32_info
    parser = reg_info.parser


class aarch64_gpreg32(aarch64_gpreg32_noarg, aarch64_arg):
    reg_info = gpregs32_info
    parser = reg_info.parser


class aarch64_gpreg64_noarg(reg_noarg):
    reg_info = gpregs64_info
    parser = reg_info.parser


class aarch64_gpreg64(reg_noarg, aarch64_arg):
    reg_info = gpregs64_info
    parser = reg_info.parser


class aarch64_gpregz32_noarg(reg_noarg):
    reg_info = gpregsz32_info
    parser = reg_info.parser


class aarch64_gpregz32(aarch64_gpreg32_noarg, aarch64_arg):
    reg_info = gpregsz32_info
    parser = reg_info.parser


class aarch64_gpregz64_noarg(reg_noarg):
    reg_info = gpregsz64_info
    parser = reg_info.parser


class aarch64_gpregz64(reg_noarg, aarch64_arg):
    reg_info = gpregsz64_info
    parser = reg_info.parser


class aarch64_simd08_noarg(reg_noarg):
    reg_info = simd08_info
    parser = reg_info.parser


class aarch64_simd08(aarch64_simd08_noarg, aarch64_arg):
    reg_info = simd08_info
    parser = reg_info.parser


class aarch64_simd16_noarg(reg_noarg):
    reg_info = simd16_info
    parser = reg_info.parser


class aarch64_simd16(aarch64_simd16_noarg, aarch64_arg):
    reg_info = simd16_info
    parser = reg_info.parser


class aarch64_simd32_noarg(reg_noarg):
    reg_info = simd32_info
    parser = reg_info.parser


class aarch64_simd32(aarch64_simd32_noarg, aarch64_arg):
    reg_info = simd32_info
    parser = reg_info.parser


class aarch64_simd64_noarg(reg_noarg):
    reg_info = simd64_info
    parser = reg_info.parser


class aarch64_simd64(aarch64_simd64_noarg, aarch64_arg):
    reg_info = simd64_info
    parser = reg_info.parser


class aarch64_simd128_noarg(reg_noarg):
    reg_info = simd128_info
    parser = reg_info.parser


class aarch64_simd128(aarch64_simd128_noarg, aarch64_arg):
    reg_info = simd128_info
    parser = reg_info.parser


class aarch64_imm_32(imm_noarg, aarch64_arg):
    parser = base_expr


class aarch64_imm_64(aarch64_imm_32):
    parser = base_expr


class aarch64_int64_noarg(int32_noarg):
    parser = base_expr
    intsize = 64
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: m2_expr.ExprInt(
        sign_ext(x, self.l, self.intsize), 64)


class aarch64_uint64_noarg(imm_noarg):
    parser = base_expr
    intsize = 64
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: m2_expr.ExprInt(x, 64)


class aarch64_uint64(aarch64_uint64_noarg, aarch64_arg):
    parser = base_expr


def set_imm_to_size(size, expr):
    if size == expr.size:
        return expr
    if size > expr.size:
        expr = m2_expr.ExprInt(int(expr), size)
    else:
        if int(expr) > (1 << size) - 1:
            return None
        expr = m2_expr.ExprInt(int(expr), size)
    return expr


class aarch64_imm_sf(imm_noarg):
    parser = base_expr

    def fromstring(self, text, loc_db, parser_result=None):
        start, stop = super(aarch64_imm_sf, self).fromstring(text, loc_db, parser_result)
        if start is None:
            return start, stop
        size = self.parent.args[0].expr.size
        if self.expr in gpregs64_info.expr + gpregs32_info.expr:
            return None, None
        if isinstance(self.expr, m2_expr.ExprOp):
            return False
        expr = set_imm_to_size(size, self.expr)
        if expr is None:
            return None, None
        self.expr = expr
        return start, stop

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = int(self.expr)
        if value >= 1 << self.l:
            return False
        self.value = value
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = m2_expr.ExprInt(v, size)
        return True


class aarch64_imm_sft(aarch64_imm_sf, aarch64_arg):

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = int(self.expr)
        if value < 1 << self.l:
            self.parent.shift.value = 0
        else:
            if value & 0xFFF:
                return False
            value >>= 12
            if value >= 1 << self.l:
                return False
            self.parent.shift.value = 1
        self.value = value
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        if self.parent.shift.value == 0:
            self.expr = m2_expr.ExprInt(v, size)
        elif self.parent.shift.value == 1:
            self.expr = m2_expr.ExprInt(v << 12, size)
        else:
            return False
        return True

OPTION2SIZE = [32, 32, 32, 64,
               32, 32, 32, 64]


class aarch64_gpreg_ext(reg_noarg, aarch64_arg):
    parser = reg_ext_off

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        if self.expr.op not in extend_lst:
            return False
        reg, amount = self.expr.args

        if not reg in gpregsz_info[self.expr.size].expr:
            return False
        self.value = gpregsz_info[self.expr.size].expr.index(reg)
        option = extend_lst.index(self.expr.op)
        if self.expr.size != OPTION2SIZE[option]:
            if not test_set_sf(self.parent, self.expr.size):
                return False
        self.parent.option.value = option
        self.parent.imm.value = int(amount)
        return True

    def decode(self, v):
        if self.parent.sf.value == 0:
            size = 64 if self.parent.sf.value else 32
        else:
            size = OPTION2SIZE[self.parent.option.value]
        reg = gpregsz_info[size].expr[v]

        self.expr = m2_expr.ExprOp(extend_lst[self.parent.option.value],
                           reg, m2_expr.ExprInt(self.parent.imm.value, reg.size))
        return True

EXT2_OP = {
    0b010: 'UXTW',
    0b011: 'LSL',
    0b110: 'SXTW',
    0b111: 'SXTX'
}

EXT2_OP_INV = dict((value, key) for key, value in viewitems(EXT2_OP))


class aarch64_gpreg_ext2(reg_noarg, aarch64_arg):
    parser = deref_ext2

    def get_size(self):
        return self.parent.size.value

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        if len(self.expr.args) != 2:
            return False
        arg0, arg1 = self.expr.args
        if (self.expr.is_op("preinc") and arg0.is_id() and arg1.is_id()):
            self.parent.shift.value = 0
            self.parent.rn.value = self.parent.rn.reg_info.expr.index(arg0)
            self.value = gpregs_info[arg1.size].expr.index(arg1)
            self.parent.option.value = 0b011
            return True
        if not (isinstance(self.expr, m2_expr.ExprOp) and self.expr.op == 'segm'):
            return False
        if not arg0 in self.parent.rn.reg_info.expr:
            return False
        self.parent.rn.value = self.parent.rn.reg_info.expr.index(arg0)
        is_reg = False
        self.parent.shift.value = 0
        if isinstance(arg1, m2_expr.ExprId):
            reg = arg1
            self.parent.option.value = 0b011
            is_reg = True
        elif isinstance(arg1, m2_expr.ExprOp) and arg1.op in viewvalues(EXT2_OP):
            reg = arg1.args[0]
        else:
            return False
        if not (reg.size in gpregs_info and
                reg in gpregs_info[reg.size].expr):
            return False
        self.value = gpregs_info[reg.size].expr.index(reg)
        if is_reg:
            return True
        if not (isinstance(arg1.args[1], m2_expr.ExprInt)):
            return False
        if arg1.op not in EXT2_OP_INV:
            return False
        self.parent.option.value = EXT2_OP_INV[arg1.op]
        if int(arg1.args[1]) == 0:
            self.parent.shift.value = 0
            return True

        if int(arg1.args[1]) != self.get_size():
            return False

        self.parent.shift.value = 1

        return True

    def decode(self, v):
        opt = self.parent.option.value
        if opt in [0, 1, 4, 5]:
            return False
        elif opt in [2, 6]:
            reg_expr = gpregsz32_info.expr
        elif opt in [3, 7]:
            reg_expr = gpregsz64_info.expr
        arg = reg_expr[v]

        if opt in EXT2_OP:
            if self.parent.shift.value == 1:
                arg = m2_expr.ExprOp(EXT2_OP[opt], arg,
                             m2_expr.ExprInt(self.get_size(), arg.size))
            else:
                arg = m2_expr.ExprOp(EXT2_OP[opt], arg,
                             m2_expr.ExprInt(0, arg.size))

        reg = self.parent.rn.reg_info.expr[self.parent.rn.value]
        self.expr = m2_expr.ExprOp('segm', reg, arg)
        return True


class aarch64_gpreg_ext2_128(aarch64_gpreg_ext2):

    def get_size(self):
        return 4


def test_set_sf(parent, size):
    if not hasattr(parent, 'sf'):
        return False
    if parent.sf.value == None:
        parent.sf.value = 1 if size == 64 else 0
        return True
    psize = 64 if parent.sf.value else 32
    return psize == size


class aarch64_gpreg_sftimm(reg_noarg, aarch64_arg):
    reg_info = gpregsz_info
    parser = shift_off

    def encode(self):
        size = self.expr.size
        if not test_set_sf(self.parent, size):
            return False
        if isinstance(self.expr, m2_expr.ExprId):
            if not size in gpregs_info:
                return False
            if not self.expr in self.reg_info[size].expr:
                return False
            self.parent.shift.value = 0
            self.parent.imm.value = 0
            self.value = self.reg_info[size].expr.index(self.expr)
            return True

        if not isinstance(self.expr, m2_expr.ExprOp):
            return False
        if not self.expr.op in shift_expr:
            return False
        args = self.expr.args
        if not args[0] in self.reg_info[size].expr:
            return False
        if not isinstance(args[1], m2_expr.ExprInt):
            return False
        self.parent.shift.value = shift_expr.index(self.expr.op)
        self.parent.imm.value = int(args[1])
        self.value = self.reg_info[size].expr.index(args[0])
        return True

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        e = self.reg_info[size].expr[v]
        amount = self.parent.imm.value
        if amount != 0:
            e = m2_expr.ExprOp(
                shift_expr[self.parent.shift.value], e, m2_expr.ExprInt(amount, e.size))
        self.expr = e
        return True


def ror(value, amount, size):
    mask = (1 << size) - 1
    return ((value >> amount) | (value << (size - amount))) & mask


def rol(value, amount, size):
    mask = (1 << size) - 1
    return ((value << amount) | (value >> (size - amount)) & mask)

# This implementation is inspired from ARM ISA v8.2
# Exact Reference name:
# "ARM Architecture Reference Manual ARMv8, for ARMv8-A architecture profile"

class ReservedValue(Exception):
    """Reserved Value, should not happen"""
    pass

class NotEncodable(Exception):
    """Instruction is not encodable"""
    pass

class bits(object):
    """Stand for ARM ASL 'bits' type, ie. a bit vector"""

    __slots__ = ["size", "value"]

    def __init__(self, size, value):
        """Instantiate a bitvector of size @size with value @value"""
        value = int(value)
        self.size = int(size)
        if value & self.mask != value:
            raise ValueError(
                "Value %r is too large for %r bits (mask %r)",
                value,
                size,
                self.mask
            )
        self.value = value

    def concat_left(self, other_bits):
        """Return a new bits instance for @other_bits . self"""
        return bits(self.size + other_bits.size,
                    self.value | (other_bits.value << self.size))

    @property
    def mask(self):
        return (1 << self.size) - 1

    def __invert__(self):
        return bits(self.size, self.value ^ self.mask)

    def __int__(self):
        return self.value

    def __and__(self, other_bits):
        assert other_bits.size == self.size
        return bits(self.size, self.value & other_bits.value)

    def __eq__(self, other_bits):
        return all((self.size == other_bits.size,
                    self.value == other_bits.value))

    def __getitem__(self, info):
        if isinstance(info, slice):
            start = info.start if info.start else 0
            stop = info.stop if info.stop else self.value
            if info.step is not None:
                raise RuntimeError("Not implemented")
            mask = (1 << stop) - 1
            return bits(stop - start,
                        (self.value >> start) & mask)
        else:
            raise RuntimeError("Not implemented")

    @property
    def pop_count(self):
        "Population count: number of bit set"
        count = 0
        value = self.value
        while (value > 0):
            if value & 1 == 1:
                count += 1
            value >>= 1
        return count

    def __str__(self):
        return "'%s'" % "".join('1' if self.value & (1 << i) else '0'
                                for i in reversed(range(self.size)))

# From J1-6035
def HighestSetBit(x):
    for i in reversed(range(x.size)):
        if x.value & (1 << i):
            return i
    return - 1

# From J1-6037
def Ones(N):
    return bits(N, (1 << N) - 1)

# From J1-6038
def ROR(x, shift):
    if shift == 0:
        return x
    return bits(x.size, ror(UInt(x), shift, x.size))

# From J1-6038
def Replicate(x, N):
    assert N % x.size == 0
    new = x
    while new.size < N:
        new = new.concat_left(x)
    return new

# From J1-6039
def UInt(x):
    return int(x)

# From J1-6039
def ZeroExtend(x, N):
    assert N >= x.size
    return bits(N, x.value)

# From J1-5906
def DecodeBitMasks(M, immN, imms, immr, immediate):
    """
    @M: 32 or 64
    @immN: 1-bit
    @imms: 6-bit
    @immr: 6-bit
    @immediate: boolean
    """
    len_ = HighestSetBit((~imms).concat_left(immN))
    if len_ < 1:
        raise ReservedValue()
    assert M >= (1 << len_)

    levels = ZeroExtend(Ones(len_), 6)

    if immediate and (imms & levels) == levels:
        raise ReservedValue()
    S = UInt(imms & levels);
    R = UInt(immr & levels);

    esize = 1 << len_
    welem = ZeroExtend(Ones(S + 1), esize)
    wmask = Replicate(ROR(welem, R), M)

    # For now, 'tmask' is unused:
    #
    # diff = S - R;
    # d = UInt(bits(len_, diff))
    # telem = ZeroExtend(Ones(d + 1), esize)
    # tmask = Replicate(telem, M)

    return wmask, None

# EncodeBitMasks doesn't have any equivalent in ARM ASL shared functions
# This implementation "reverses" DecodeBitMasks flow
def EncodeBitMasks(wmask):
    # Find replicate
    M = wmask.size
    for i in range(1, M + 1):
        if M % i != 0:
            continue
        if wmask == Replicate(wmask[:i], M):
            break
    else:
        raise NotEncodable

    # Find ROR value: welem is only '1's
    welem_after_ror = wmask[:i]
    esize = welem_after_ror.size
    S = welem_after_ror.pop_count - 1
    welem = ZeroExtend(Ones(S + 1), esize)
    for i in range(welem_after_ror.size):
        if ROR(welem, i) == welem_after_ror:
            break
    else:
        raise NotEncodable
    R = i

    # Find len value
    for i in range(M):
        if (1 << i) == esize:
            break
    else:
        raise NotEncodable
    len_ = i
    levels = ZeroExtend(Ones(len_), 6)
    levels = UInt(levels)

    if len_ == 6:
        # N = 1
        immn = 1
        imms = S
    else:
        # N = 0, NOT(imms) have to be considered
        immn = 0
        mask = (1 << ((6 - len_ - 1))) - 1
        mask <<= (len_ + 1)
        imms = S | mask
    immr = R
    return immr, imms, immn


class aarch64_imm_nsr(aarch64_imm_sf, aarch64_arg):
    parser = base_expr

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        bitmask, _ = DecodeBitMasks(size,
                                    bits(1, self.parent.immn.value),
                                    bits(6, v),
                                    bits(6, self.parent.immr.value),
                                    True
        )
        self.expr = m2_expr.ExprInt(UInt(bitmask),
                                    size)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        if not test_set_sf(self.parent, self.expr.size):
            return False
        value = int(self.expr)
        if value == 0:
            return False

        try:
            immr, imms, immn = EncodeBitMasks(bits(self.expr.size, value))
        except NotEncodable:
            return False
        self.parent.immr.value = immr
        self.parent.immn.value = immn
        self.value = imms
        return True


class aarch64_pcoff(aarch64_imm_32):
    parser = base_expr


class aarch64_immhip_page(aarch64_imm_32):
    parser = base_expr

    def decode(self, v):
        v = ((v << 2) | self.parent.immlo.value) << 12
        v = sign_ext(v, 33, 64)
        self.expr = m2_expr.ExprInt(v, 64)
        return True

    def encode(self):
        v = int(self.expr)
        if v & (1 << 63):
            v &= (1 << 33) - 1
        if v & 0xfff:
            return False
        v >>= 12
        self.parent.immlo.value = v & 3
        v >>= 2
        self.value = v
        return True


class aarch64_immhi_page(aarch64_imm_32):
    parser = base_expr

    def decode(self, v):
        v = ((v << 2) | self.parent.immlo.value)
        v = sign_ext(v, 21, 64)
        self.expr = m2_expr.ExprInt(v, 64)
        return True

    def encode(self):
        v = int(self.expr)
        if v & (1 << 63):
            v &= (1 << 33) - 1
        self.parent.immlo.value = v & 3
        v >>= 2
        if v > (1 << 19) - 1:
            return False
        self.value = v & ((1 << 19) - 1)
        return True


class aarch64_imm_hw(aarch64_arg):
    parser = base_expr
    shift_op = '<<'

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        self.expr = m2_expr.ExprInt(v << (16 * self.parent.hw.value), size)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        size = self.parent.args[0].expr.size
        if set_imm_to_size(size, self.expr) is None:
            return False
        value = int(self.expr)
        mask = (1 << size) - 1
        for i in range(size // 16):
            if ((0xffff << (i * 16)) ^ mask) & value:
                continue
            self.parent.hw.value = i
            self.value = value >> (i * 16)
            return True
        return False


class aarch64_imm_hw_sc(aarch64_arg):
    parser = shiftimm_off_sc
    shift_op = 'slice_at'

    def decode(self, v):
        size = 64 if self.parent.sf.value else 32
        expr = m2_expr.ExprInt(v, size)
        amount = m2_expr.ExprInt(16 * self.parent.hw.value, size)
        if self.parent.hw.value:
            self.expr = m2_expr.ExprOp(self.shift_op, expr,  amount)
        else:
            self.expr = expr
        return True

    def encode(self):
        if isinstance(self.expr, m2_expr.ExprInt):
            if int(self.expr) > 0xFFFF:
                return False
            self.value = int(self.expr)
            self.parent.hw.value = 0
            return True

        if not (isinstance(self.expr, m2_expr.ExprOp) and
                self.expr.op == self.shift_op and
                len(self.expr.args) == 2 and
                isinstance(self.expr.args[0], m2_expr.ExprInt) and
                isinstance(self.expr.args[1], m2_expr.ExprInt)):
            return False
        if set_imm_to_size(self.parent.args[0].expr.size, self.expr.args[0]) is None:
            return False
        if set_imm_to_size(self.parent.args[0].expr.size, self.expr.args[1]) is None:
            return False
        arg, amount = [int(arg) for arg in self.expr.args]
        if arg > 0xFFFF:
            return False
        if amount % 16 or amount // 16 > 4:
            return False
        self.value = arg
        self.parent.hw.value = amount // 16
        return True


class aarch64_offs(imm_noarg, aarch64_arg):
    parser = base_expr

    def decode(self, v):
        v = v & self.lmask
        v = (v << 2)
        v = sign_ext(v, (self.l + 2), 64)
        self.expr = m2_expr.ExprInt(v, 64)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        v = int(self.expr)
        if v & (1 << 63):
            v &= (1 << (self.l + 2)) - 1
        self.value = v >> 2
        return True



class aarch64_offs_pc(imm_noarg, aarch64_arg):
    parser = deref_pc

    def decode(self, v):
        v = v & self.lmask
        v = (v << 2)
        v = sign_ext(v, (self.l + 2), 64)
        self.expr = m2_expr.ExprOp("preinc", PC, m2_expr.ExprInt(v, 64))
        return True

    def encode(self):
        if not self.expr.is_op('preinc'):
            return False
        if self.expr.args == (PC,):
            v = 0
        elif (len(self.expr.args) == 2 and
              self.expr.args[0] == PC and
              self.expr.args[1].is_int()):
            v = int(self.expr.args[1])
        else:
            return None
        if v & (1 << 63):
            v &= (1 << (self.l + 2)) - 1
        self.value = v >> 2
        return True



def set_mem_off(parent, imm):
    if hasattr(parent, 'simm'):
        mask = (1 << parent.simm.l) - 1
        if imm != sign_ext(imm & mask, parent.simm.l, 64):
            return False
        parent.simm.value = imm & mask
    elif hasattr(parent, 'uimm'):
        mask = (1 << parent.uimm.l) - 1
        if imm > mask:
            return False
        parent.uimm.value = imm
    else:
        raise ValueError('unknown imm')
    return True


def get_size(parent):
    if not hasattr(parent, "size"):
        return 0
    if hasattr(parent.size, "amount"):
        size = parent.size.amount
    else:
        size = parent.size.value
    return size


class aarch64_deref(aarch64_arg):
    parser = deref

    def decode_w_size(self, off):
        return off

    def encode_w_size(self, off):
        return off

    def get_postpre(self, parent):
        if hasattr(self.parent, "postpre"):
            if self.parent.postpre.value == 0:
                op = 'postinc'
            else:
                op = 'preinc_wb'
        else:
            op = 'preinc'
        return op

    def decode(self, v):
        reg = gpregs64_info.expr[v]
        off = int(self.parent.imm.expr)
        op = self.get_postpre(self.parent)
        off = self.decode_w_size(off)
        self.expr = m2_expr.ExprOp(op, reg, m2_expr.ExprInt(off, 64))
        return True

    def encode(self):
        expr = self.expr
        if not isinstance(expr, m2_expr.ExprOp):
            return False
        if not expr.op in ['postinc', 'preinc_wb', 'preinc']:
            return False
        if hasattr(self.parent, "postpre"):
            if expr.op == 'postinc':
                self.parent.postpre.value = 0
            else:
                self.parent.postpre.value = 1
        if len(expr.args) != 2:
            return False
        reg, off = expr.args
        if not reg in gpregs64_info.expr:
            return False
        if not isinstance(off, m2_expr.ExprInt):
            return False
        imm = int(off)
        imm = self.encode_w_size(imm)
        if imm is False:
            return False
        self.parent.imm.expr = m2_expr.ExprInt(imm, 64)
        if not self.parent.imm.encode():
            return False
        self.value = gpregs64_info.expr.index(reg)
        return True


class aarch64_deref_size(aarch64_deref):

    def decode_w_size(self, off):
        size = get_size(self.parent)
        return off << size

    def encode_w_size(self, off):
        size = get_size(self.parent)
        if size:
            if off & ((1 << size) - 1):
                return False
            off >>= size
        return off


class aarch64_deref_nooff(aarch64_deref):
    parser = deref_nooff

    def decode(self, v):
        reg = gpregs64_info.expr[v]
        self.expr = m2_expr.ExprOp('preinc', reg)
        return True

    def encode(self):
        expr = self.expr
        if not isinstance(expr, m2_expr.ExprOp):
            return False
        if expr.op != 'preinc':
            return False
        if len(expr.args) == 1:
            reg = expr.args[0]
        elif len(expr.args) == 2:
            reg, off = expr.args
            if not isinstance(off, m2_expr.ExprInt):
                return False
            if int(off) != 0:
                return False
        else:
            return False

        if not reg in gpregs64_info.expr:
            return False
        self.value = gpregs64_info.expr.index(reg)
        return True


class aarch64_sf_scale(aarch64_deref):
    size2scale = {32: 2, 64: 3}

    def decode_w_size(self, off):
        size = 2 + self.parent.sf.value
        return off << size

    def encode_w_size(self, off):
        size = self.parent.args[0].expr.size
        if not size in self.size2scale:
            return False
        scale = self.size2scale[size]
        off = int(mod_size2int[size](off) >> scale)
        return off


class aarch64_sd_scale(aarch64_sf_scale):
    size2scale = {32: 2, 64: 3, 128: 4}

    def decode_w_size(self, off):
        size = 2 + self.parent.size.value
        return off << size


class aarch64_eq(bsi):

    def decode(self, v):
        return getattr(self.parent, self.ref).value == v

    def encode(self):
        self.value = getattr(self.parent, self.ref).value
        return True
modf = bs_mod_name(l=1, fname='modf', mn_mod=['', 'S'])
sf = bs(l=1, fname='sf', order=-1)


class aarch64_cond_arg(reg_noarg, aarch64_arg):
    reg_info = conds_info
    parser = reg_info.parser


class aarch64_cond_inv_arg(reg_noarg, aarch64_arg):
    reg_info = conds_inv_info
    parser = reg_info.parser


class aarch64_b40(aarch64_arg):
    parser = base_expr

    def decode(self, v):
        self.expr = m2_expr.ExprInt(
            (self.parent.sf.value << self.l) | v, self.parent.rt.expr.size)
        return True

    def encode(self):
        if not isinstance(self.expr, m2_expr.ExprInt):
            return False
        size = self.parent.args[0].expr.size
        value = int(self.expr)
        self.value = value & self.lmask
        if self.parent.sf.value is None:
            self.parent.sf.value = value >> self.l
            return True
        else:
            return value >> self.l == self.parent.sf.value


shift = bs(l=2, fname='shift')

shiftb = bs(l=1, fname='shift', order=-1)


rn64_v = bs(l=5, cls=(aarch64_gpreg64_nodec,), fname='rn', order=-1)

rn = bs(l=5, cls=(aarch64_gpreg,), fname="rn")
rs = bs(l=5, cls=(aarch64_gpreg,), fname="rs")
rm = bs(l=5, cls=(aarch64_gpreg,), fname="rm")
rd = bs(l=5, cls=(aarch64_gpreg,), fname="rd")
ra = bs(l=5, cls=(aarch64_gpregz,), fname="ra")
rt = bs(l=5, cls=(aarch64_gpregz,), fname="rt")
rt2 = bs(l=5, cls=(aarch64_gpregz,), fname="rt2")
rn0 = bs(l=5, cls=(aarch64_gpreg0,), fname="rn")

rmz = bs(l=5, cls=(aarch64_gpregz,), fname="rm")
rnz = bs(l=5, cls=(aarch64_gpregz,), fname="rn")
rdz = bs(l=5, cls=(aarch64_gpregz,), fname="rd")

rd_nosp = bs(l=5, cls=(aarch64_gpreg_noarg_nosp, aarch64_arg), fname="rd")


rn_n1 = bs(l=5, cls=(aarch64_gpreg_n1,), fname="rn")
rm_n1 = bs(l=5, cls=(aarch64_gpreg_n1,), fname="rm")


rn_na = bs(l=5, cls=(aarch64_gpreg_noarg,), fname="rn", order=-1)
rn32_na = bs(l=5, cls=(aarch64_gpreg32_noarg,), fname="rn", order=-1)
rn64_na = bs(l=5, cls=(aarch64_gpreg64_noarg,), fname="rn", order=-1)

sd1 = bs(l=5, cls=(aarch64_simdreg_h,), fname="rt")
sd2 = bs(l=5, cls=(aarch64_simdreg_h,), fname="rt2")

sdn_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rn")
sdd_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rd")
sdm_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="rm")
sda_32_64 = bs(l=5, cls=(aarch64_simdreg_32_64,), fname="ra")


sdm_32_64_zero = bs(l=5, cls=(aarch64_simdreg_32_64_zero,), fname="rm")

crn = bs(l=4, cls=(aarch64_crreg,), fname="crn")
crm = bs(l=4, cls=(aarch64_crreg,), fname="crm")


rn64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rn")
rs64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rs")
rm64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rm")
rd64 = bs(l=5, cls=(aarch64_gpreg64,), fname="rd")
rt64 = bs(l=5, cls=(aarch64_gpregz64,), fname="rt")
ra64 = bs(l=5, cls=(aarch64_gpregz64,), fname="ra")

rn32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rn")
rm32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rm")
rd32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rd")
rs32 = bs(l=5, cls=(aarch64_gpreg32,), fname="rs")

sd08 = bs(l=5, cls=(aarch64_simd08,), fname="rd")
sd16 = bs(l=5, cls=(aarch64_simd16,), fname="rd")
sd32 = bs(l=5, cls=(aarch64_simd32,), fname="rd")
sd64 = bs(l=5, cls=(aarch64_simd64,), fname="rd")
sd128 = bs(l=5, cls=(aarch64_simd128,), fname="rd")

sn08 = bs(l=5, cls=(aarch64_simd08,), fname="rn")
sn16 = bs(l=5, cls=(aarch64_simd16,), fname="rn")
sn32 = bs(l=5, cls=(aarch64_simd32,), fname="rn")
sn64 = bs(l=5, cls=(aarch64_simd64,), fname="rn")
sn128 = bs(l=5, cls=(aarch64_simd128,), fname="rn")


rt32 = bs(l=5, cls=(aarch64_gpregz32,), fname="rt")

rt_isf = bs(l=5, cls=(aarch64_gpreg_isf,), fname="rt")

rn64_deref = bs(l=5, cls=(aarch64_deref,), fname="rn")
rn64_deref_sz = bs(l=5, cls=(aarch64_deref_size,), fname="rn")
rn64_deref_sf = bs(l=5, cls=(aarch64_sf_scale,), fname="rn")
rn64_deref_sd = bs(l=5, cls=(aarch64_sd_scale,), fname="rn")

rn64_deref_nooff = bs(l=5, cls=(aarch64_deref_nooff,), fname="rn")

imm_sft_12 = bs(l=12, cls=(aarch64_imm_sft,))

# imm32_3 = bs(l=3, cls=(aarch64_imm_32,))
imm32_3 = bs(l=3, fname="imm")
imm6 = bs(l=6, fname="imm", order=-1)
imm3 = bs(l=3, fname="imm", order=-1)
simm6 = bs(l=6, cls=(aarch64_int64_noarg, aarch64_arg), fname="imm", order=-1)
simm9 = bs(l=9, cls=(aarch64_int64_noarg,), fname="imm", order=-1)
simm7 = bs(l=7, cls=(aarch64_int64_noarg,), fname="imm", order=-1)
nzcv = bs(l=4, cls=(aarch64_uint64_noarg, aarch64_arg), fname="nzcv", order=-1)
uimm4 = bs(l=4, cls=(aarch64_uint64_noarg, aarch64_arg), fname="imm", order=-1)
uimm5 = bs(l=5, cls=(aarch64_uint64_noarg, aarch64_arg), fname="imm", order=-1)
uimm6 = bs(l=6, cls=(aarch64_uint64_noarg, aarch64_arg), fname="imm", order=-1)
uimm12 = bs(l=12, cls=(aarch64_uint64_noarg,), fname="imm", order=-1)
uimm16 = bs(l=16, cls=(aarch64_uint64_noarg, aarch64_arg), fname="imm", order=-1)
uimm7 = bs(l=7, cls=(aarch64_uint64_noarg,), fname="imm", order=-1)

uimm8 = bs(l=8, cls=(aarch64_uint64,), fname="imm", order=-1)

class op0_value(aarch64_uint64):
    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        v += 2
        e = self.int2expr(v)
        if not e:
            return False
        self.expr = e
        return True

    def encode(self):
        v = self.expr2int(self.expr)
        if v is None:
            return False
        v -= 2
        v = self.encodeval(v)
        if v is False:
            return False
        self.value = v
        return True

op0 = bs(l=1, cls=(op0_value, aarch64_arg), fname="op0")
op1 = bs(l=3, cls=(aarch64_uint64, aarch64_arg), fname="op1")
op2 = bs(l=3, cls=(aarch64_uint64, aarch64_arg), fname="op2")


imm16 = bs(l=16, fname="imm", order=-1)


immlo = bs(l=2, fname='immlo')
immhip = bs(l=19, cls=(aarch64_immhip_page,))
immhi = bs(l=19, cls=(aarch64_immhi_page,))

option = bs(l=3, fname='option', order=-1)


rm_ext = bs(l=5, cls=(aarch64_gpreg_ext,), fname="rm")
rm_sft = bs(l=5, cls=(aarch64_gpreg_sftimm,), fname="rm")

rm_ext2 = bs(l=5, cls=(aarch64_gpreg_ext2,), fname="rm")
rm_ext2_128 = bs(l=5, cls=(aarch64_gpreg_ext2_128,), fname="rm")


imms = bs(l=6, cls=(aarch64_imm_nsr,), fname='imms')
immr = bs(l=6, fname='immr')
immn = bs(l=1, fname='immn')


imm16_hw = bs(l=16, cls=(aarch64_imm_hw,), fname='imm')
imm16_hw_sc = bs(l=16, cls=(aarch64_imm_hw_sc,), fname='imm')
hw = bs(l=2, fname='hw')


a_imms = bs(l=6, cls=(aarch64_imm_sf, aarch64_arg), fname="imm1", order=-1)
a_immr = bs(l=6, cls=(aarch64_imm_sf, aarch64_arg), fname="imm1", order=-1)



adsu_name = {'ADD': 0, 'SUB': 1}
bs_adsu_name = bs_name(l=1, name=adsu_name)


offs19 = bs(l=19, cls=(aarch64_offs,), fname='off')
offs19pc = bs(l=19, cls=(aarch64_offs_pc,), fname='off')

offs26 = bs(l=26, cls=(aarch64_offs,), fname='off')
offs14 = bs(l=14, cls=(aarch64_offs,), fname='off')

b40 = bs(l=5, cls=(aarch64_b40,), fname='b40', order=1)

sdsize1 = bs(l=1, fname="size")

sdsize = bs(l=2, fname="size")
opsize = bs(l=2, fname="size")
sd = bs(l=5, cls=(aarch64_simdreg,), fname='sd')

opc = bs(l=1, fname='opc', order=-1)

# add/sub (imm)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('10001'), shift, imm_sft_12, rn, rd], [rd, rn, imm_sft_12])
aarch64op("cmp", [sf, bs('1'), bs('1'), bs('10001'), shift, imm_sft_12, rn, bs('11111')], [rn, imm_sft_12], alias=True)
aarch64op("cmn", [sf, bs('0'), bs('1'), bs('10001'), shift, imm_sft_12, rn, bs('11111')], [rn, imm_sft_12], alias=True)

aarch64op("adrp", [bs('1'), immlo, bs('10000'), immhip, rd64], [rd64, immhip])
aarch64op("adr",  [bs('0'), immlo, bs('10000'), immhi, rd64], [rd64, immhi])

# add/sub (reg shift)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('01011'), shift, bs('0'), rm_sft, imm6, rn, rd_nosp], [rd_nosp, rn, rm_sft])
aarch64op("CMN", [sf, bs('0'), bs('1'), bs('01011'), shift, bs('0'), rm_sft, imm6, rn, bs('11111')], [rn, rm_sft])

aarch64op("cmp", [sf, bs('1'), bs('1'), bs('01011'), shift, bs('0'), rm_sft, imm6, rn, bs('11111')], [rn, rm_sft], alias=True)
# add/sub (reg ext)
aarch64op("addsub", [sf, bs_adsu_name, modf, bs('01011'), bs('00'), bs('1'), rm_ext, option, imm3, rn, rd], [rd, rn, rm_ext])
#aarch64op("cmp",    [sf, bs('1'), bs('1'), bs('01011'), bs('00'), bs('1'), rm_ext, option, imm3, rn, bs('11111')], [rn, rm_ext], alias=True)


aarch64op("neg", [sf, bs('1'), modf, bs('01011'), shift, bs('0'), rm_sft, imm6, bs('11111'), rd], [rd, rm_sft], alias=True)


logic_name = {'AND': 0, 'ORR': 1, 'EOR': 2}
bs_logic_name = bs_name(l=2, name=logic_name)
# logical (imm)
aarch64op("logic", [sf, bs_logic_name, bs('100100'), immn, immr, imms, rn0, rd], [rd, rn0, imms])
# ANDS
aarch64op("ands", [sf, bs('11'), bs('100100'), immn, immr, imms, rn0, rdz], [rdz, rn0, imms])
aarch64op("tst",  [sf, bs('11'), bs('100100'), immn, immr, imms, rn0, bs('11111')], [rn0, imms], alias=True)


# bitfield move p.149
logicbf_name = {'SBFM': 0b00, 'BFM': 0b01, 'UBFM': 0b10}
bs_logicbf_name = bs_name(l=2, name=logicbf_name)
aarch64op("logic", [sf, bs_logicbf_name, bs('100110'), bs(l=1, cls=(aarch64_eq,), ref="sf"), a_immr, a_imms, rn, rd], [rd, rn, a_immr, a_imms])


# logical (reg shift)
aarch64op("and",  [sf, bs('00'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("bic",  [sf, bs('00'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("orr",  [sf, bs('01'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("orn",  [sf, bs('01'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("mvn",  [sf, bs('01'), bs('01010'), shift, bs('1'), rm_sft, imm6, bs('11111'), rd], [rd, rm_sft], alias=True)
aarch64op("eor",  [sf, bs('10'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("eon",  [sf, bs('10'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("ands", [sf, bs('11'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])
aarch64op("tst",  [sf, bs('11'), bs('01010'), shift, bs('0'), rm_sft, imm6, rn, bs('11111')], [rn, rm_sft], alias=True)
aarch64op("bics", [sf, bs('11'), bs('01010'), shift, bs('1'), rm_sft, imm6, rn, rd], [rd, rn, rm_sft])

# move reg
aarch64op("mov",  [sf, bs('01'), bs('01010'), bs('00'), bs('0'), rmz, bs('000000'), bs('11111'), rd], [rd, rmz], alias=True)


aarch64op("adc", [sf, bs('00'), bs('11010000'), rm, bs('000000'), rn, rd], [rd, rn, rm])
aarch64op("adcs", [sf, bs('01'), bs('11010000'), rm, bs('000000'), rn, rd], [rd, rn, rm])


aarch64op("sbc", [sf, bs('10'), bs('11010000'), rm, bs('000000'), rn, rd], [rd, rn, rm])
aarch64op("sbcs", [sf, bs('11'), bs('11010000'), rm, bs('000000'), rn, rd], [rd, rn, rm])



bcond = bs_mod_name(l=4, fname='cond', mn_mod=['EQ', 'NE', 'CS', 'CC',
                                               'MI', 'PL', 'VS', 'VC',
                                               'HI', 'LS', 'GE', 'LT',
                                               'GT', 'LE', 'AL', 'NV'])

cond_arg = bs(l=4, cls=(aarch64_cond_arg,), fname="cond")
cond_inv_arg = bs(l=4, cls=(aarch64_cond_inv_arg,), fname="cond")
# unconditional branch (ret)
aarch64op("br", [bs('1101011'), bs('0000'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("blr", [bs('1101011'), bs('0001'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("ret", [bs('1101011'), bs('0010'), bs('11111'), bs('000000'), rn64, bs('00000')], [rn64])
aarch64op("eret", [bs('1101011'), bs('0100'), bs('11111'), bs('000000'), bs('11111'), bs('00000')])
aarch64op("drps", [bs('1101011'), bs('0101'), bs('11111'), bs('000000'), bs('11111'), bs('00000')])

# unconditional branch (imm)
aarch64op("b",  [bs('0'), bs('00101'), offs26], [offs26])
aarch64op("bl", [bs('1'), bs('00101'), offs26], [offs26])


post_pre = bs(l=1, order=-1, fname='postpre')

# conditional compare (imm) p.158
ccmp_name = {'CCMN': 0, 'CCMP': 1}
bs_ccmp_name = bs_name(l=1, name=ccmp_name)
aarch64op("condcmp", [sf, bs_ccmp_name, bs('1'), bs('11010010'), uimm5, cond_arg, bs('1'), bs('0'), rn, bs('0'), nzcv], [rn, uimm5, nzcv, cond_arg])
aarch64op("condcmp", [sf, bs_ccmp_name, bs('1'), bs('11010010'), rm, cond_arg, bs('0'), bs('0'), rn, bs('0'), nzcv], [rn, rm, nzcv, cond_arg])

ldst_b_name = {'STRB': 0, 'LDRB': 1}
bs_ldst_b_name = bs_name(l=1, name=ldst_b_name)
ldst_name = {'STR': 0, 'LDR': 1}
bs_ldst_name = bs_name(l=1, name=ldst_name)
ldst_h_name = {'STRH': 0, 'LDRH': 1}
bs_ldst_h_name = bs_name(l=1, name=ldst_h_name)

ldst_tb_name = {'STTRB': 0, 'LDTRB': 1}
bs_ldst_tb_name = bs_name(l=1, name=ldst_tb_name)

ldst_th_name = {'STTRH': 0, 'LDTRH': 1}
bs_ldst_th_name = bs_name(l=1, name=ldst_th_name)

ldst_ub_name = {'STURB': 0, 'LDURB': 1}
bs_ldst_ub_name = bs_name(l=1, name=ldst_ub_name)
ldst_u_name = {'STUR': 0, 'LDUR': 1}
bs_ldst_u_name = bs_name(l=1, name=ldst_u_name)

ldst_t_name = {'STTR': 0, 'LDTR': 1}
bs_ldst_st_name = bs_name(l=1, name=ldst_t_name)

ldst_1u_name = {'STUR': 0b0, 'LDUR': 0b1}
bs_ldst_1u_name = bs_name(l=1, name=ldst_1u_name)

ldst_uh_name = {'STURH': 0, 'LDURH': 1}
bs_ldst_uh_name = bs_name(l=1, name=ldst_uh_name)


ldst_sw_name = {'STRSW': 0, 'LDRSW': 1}
bs_ldst_sw_name = bs_name(l=1, name=ldst_sw_name)

# load/store register (imm post index)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_b_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldrsb",  [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldrsh",  [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldst",   [bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_h_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldst",   [bs('10'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldrsw",  [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldst",   [bs('11'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, rt64], [rt64, rn64_deref ])

aarch64op("ldst",   [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_name, bs('0'), simm9, post_pre, bs('1'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store register (unsigned imm)
aarch64op("ldst",   [bs('00', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_b_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldrsb",  [bs('00', fname="size"), bs('111'), bs('0'), bs('01'), bs('1'), sf, uimm12, rn64_deref_sz, rt_isf], [rt_isf, rn64_deref_sz ])
aarch64op("ldrsh",  [bs('01', fname="size"), bs('111'), bs('0'), bs('01'), bs('1'), sf, uimm12, rn64_deref_sz, rt_isf], [rt_isf, rn64_deref_sz ])
aarch64op("ldst",   [bs('01', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_h_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldst",   [bs('10', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, rt32], [rt32, rn64_deref_sz ])
aarch64op("ldrsw",  [bs('10', fname="size"), bs('111'), bs('0'), bs('01'), bs('10'), uimm12, rn64_deref_sz, rt64], [rt64, rn64_deref_sz ])
aarch64op("ldst",   [bs('11', fname="size"), bs('111'), bs('0'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, rt64], [rt64, rn64_deref_sz ])

aarch64op("ldst",   [sdsize, bs('111'), bs('1'), bs('01'), bs('0'), bs_ldst_name, uimm12, rn64_deref_sz, sd], [sd, rn64_deref_sz ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('01'), bs('1', fname='size', amount=4), bs_ldst_name, uimm12, rn64_deref_sz, sd128], [sd128, rn64_deref_sz ])

# load/store register (unp)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_tb_name, bs('0'), simm9, bs('10'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldtrsb", [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('10'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldtrsh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('10'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldsttrh",[bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_th_name, bs('0'), simm9, bs('10'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldtrsw", [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, bs('10'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldstt",  [bs('1'), sf, bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, rt], [rt, rn64_deref ])

aarch64op("ldstt",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_st_name, bs('0'), simm9, bs('10'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store register (unscaled imm)
aarch64op("ldst",   [bs('00'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_ub_name, bs('0'), simm9, bs('00'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldursb", [bs('00'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('00'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldstuh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_uh_name, bs('0'), simm9, bs('00'), rn64_deref, rt32], [rt32, rn64_deref ])
aarch64op("ldursh", [bs('01'), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('0'), simm9, bs('00'), rn64_deref, rt_isf], [rt_isf, rn64_deref ])
aarch64op("ldursw", [bs('10'), bs('111'), bs('0'), bs('00'), bs('10'), bs('0'), simm9, bs('00'), rn64_deref, rt64], [rt64, rn64_deref ])
aarch64op("ldst",   [bs('1'), sf, bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_u_name, bs('0'), simm9, bs('00'), rn64_deref, rt], [rt, rn64_deref ])

aarch64op("ldstu",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_u_name, bs('0'), simm9, bs('00'), rn64_deref, sd], [sd, rn64_deref ])
aarch64op("ldst",   [bs('00'), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_1u_name, bs('0'), simm9, bs('00'), rn64_deref, sd128], [sd128, rn64_deref ])

# load/store (register) p.728

aarch64op("ldstrb",[bs('00', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_b_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldstrh",[bs('01', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_h_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldrsb", [bs('00', fname="size"), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt_isf], [rt_isf, rm_ext2])

aarch64op("ldrsh", [bs('01', fname="size"), bs('111'), bs('0'), bs('00'), bs('1'), sf, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt_isf], [rt_isf, rm_ext2])

aarch64op("ldst",  [sdsize, bs('111'), bs('1'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, sd], [sd, rm_ext2])
aarch64op("ldst",  [bs('00', fname="size"), bs('111'), bs('1'), bs('00'), bs('1'), bs_ldst_name, bs('1'), rm_ext2_128, option, shiftb, bs('10'), rn64_v, sd128], [sd128, rm_ext2_128])

aarch64op("str",   [bs('10', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt32], [rt32, rm_ext2])

aarch64op("ldrsw", [bs('10', fname="size"), bs('111'), bs('0'), bs('00'), bs('10'), bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt64], [rt64, rm_ext2])

aarch64op("ldst",  [bs('11', fname="size"), bs('111'), bs('0'), bs('00'), bs('0'), bs_ldst_name, bs('1'), rm_ext2, option, shiftb, bs('10'), rn64_v, rt64], [rt64, rm_ext2])

# load/store literal p.137
aarch64op("ldr",  [bs('0'), sf, bs('011'), bs('0'), bs('00'), offs19pc, rt], [rt, offs19pc])
aarch64op("ldrsw",  [bs('10'), bs('011'), bs('0'), bs('00'), offs19pc, rt64], [rt64, offs19pc])

# load/store simd literal p.142
aarch64op("ldr",  [sdsize, bs('011'), bs('1'), bs('00'), offs19pc, sd1], [sd1, offs19pc])


# move wide p.203
movwide_name = {'MOVN': 0b00, 'MOVZ': 0b10}
bs_movwide_name = bs_name(l=2, name=movwide_name)
# mov wide (imm)
aarch64op("mov", [sf, bs_movwide_name, bs('100101'), hw, imm16_hw, rd], [rd, imm16_hw])
aarch64op("movk", [sf, bs('11'), bs('100101'), hw, imm16_hw_sc, rd], [rd, imm16_hw_sc])

# stp/ldp p.139
ldstp_name = {'STP': 0b0, 'LDP': 0b1}
bs_ldstp_name = bs_name(l=1, name=ldstp_name)
aarch64op("ldstp", [sf, bs('0'), bs('101'), bs('0'), bs('0'), post_pre, bs('1'), bs_ldstp_name, simm7, rt2, rn64_deref_sf, rt], [rt, rt2, rn64_deref_sf])
aarch64op("ldstp", [sf, bs('0'), bs('101'), bs('0'), bs('0'), bs('1'), bs('0'), bs_ldstp_name, simm7, rt2, rn64_deref_sf, rt], [rt, rt2, rn64_deref_sf])

aarch64op("ldstp", [sdsize, bs('101'), bs('1'), bs('0'), post_pre, bs('1'), bs_ldstp_name, simm7, sd2, rn64_deref_sd, sd1], [sd1, sd2, rn64_deref_sd])
aarch64op("ldstp", [sdsize, bs('101'), bs('1'), bs('0'), bs('1'), bs('0'), bs_ldstp_name, simm7, sd2, rn64_deref_sd, sd1], [sd1, sd2, rn64_deref_sd])


# data process p.207
datap0_name = {'RBIT': 0b000000, 'REV16': 0b000001,
              'REV': 0b000010,
              'CLZ': 0b000100, 'CLS': 0b000101}
bs_datap0_name = bs_name(l=6, name=datap0_name)
aarch64op("ldstp", [bs('0', fname='sf'), bs('1'), modf, bs('11010110'), bs('00000'), bs_datap0_name, rn, rd])
datap1_name = {'RBIT': 0b000000, 'REV16': 0b000001,
               'REV32': 0b000010, 'REV': 0b000011,
              'CLZ': 0b000100, 'CLS': 0b000101}
bs_datap1_name = bs_name(l=6, name=datap1_name)
aarch64op("ldstp", [bs('1', fname='sf'), bs('1'), modf, bs('11010110'), bs('00000'), bs_datap1_name, rn, rd])


# conditional branch p.132
aarch64op("b.",   [bs('0101010'), bs('0'), offs19, bs('0'), bcond], [offs19])
aarch64op("cbnz", [sf, bs('011010'), bs('1'), offs19, rt], [rt, offs19])
aarch64op("cbz",  [sf, bs('011010'), bs('0'), offs19, rt], [rt, offs19])
aarch64op("tbnz", [sf, bs('011011'), bs('1'), b40, offs14, rt], [rt, b40, offs14])
aarch64op("tbz",  [sf, bs('011011'), bs('0'), b40, offs14, rt], [rt, b40, offs14])


# fmov register p.160
aarch64op("fmov",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('00'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
# fmov scalar imm p.160
aarch64op("fmov",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), uimm8, bs('100'), bs('00000'), sdd_32_64], [sdd_32_64, uimm8])
# floating point comparison p.164
aarch64op("fcmp",  [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64_zero, bs('00'), bs('1000'), sdn_32_64, bs('0'), opc, bs('000')], [sdn_32_64, sdm_32_64_zero])
aarch64op("fcmpe", [bs('000'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64_zero, bs('00'), bs('1000'), sdn_32_64, bs('1'), opc, bs('000')], [sdn_32_64, sdm_32_64_zero])
# floating point convert p.161
aarch64op("fcvtas",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('100'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])
aarch64op("fcvtzu",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('11'), bs('001'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])
aarch64op("fcvtzs",[sf, bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('11'), bs('000'), bs('000000'), sdn_32_64, rd], [rd, sdn_32_64])

aarch64op("fcvt",  [bs('000'), bs('11110'), bs('11'), bs('1'), bs('0001'), bs('00'), bs('10000'), sn16, sd32], [sd32, sn16])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('11'), bs('1'), bs('0001'), bs('01'), bs('10000'), sn16, sd64], [sd64, sn16])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('00'), bs('1'), bs('0001'), bs('11'), bs('10000'), sn32, sd16], [sd16, sn32])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('00'), bs('1'), bs('0001'), bs('01'), bs('10000'), sn32, sd64], [sd64, sn32])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('01'), bs('1'), bs('0001'), bs('11'), bs('10000'), sn64, sd16], [sd16, sn64])
aarch64op("fcvt",  [bs('000'), bs('11110'), bs('01'), bs('1'), bs('0001'), bs('00'), bs('10000'), sn64, sd32], [sd32, sn64])



swapargs = bs_swapargs(l=1, fname="swap", mn_mod=list(range(1 << 1)))

aarch64op("fmov",  [bs('0'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('110'), bs('000000'), sn32, rd32], [rd32, sn32])
aarch64op("fmov",  [bs('0'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('111'), bs('000000'), rn32, sd32], [sd32, rn32])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('00'), bs('1'), bs('00'), bs('110'), bs('000000'), sd32, rd32], [rd32, sd32])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('01'), bs('1'), bs('00'), bs('111'), bs('000000'), rd64, sd64], [sd64, rd64])
aarch64op("fmov",  [bs('1'), bs('00'), bs('11110'), bs('01'), bs('1'), bs('00'), bs('110'), bs('000000'), sd64, rd64], [rd64, sd64])



# floating point arith p.163
aarch64op("fsub",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('001'), bs('1'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fadd",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('001'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fdiv",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('000'), bs('1'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fmul",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('000'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])
aarch64op("fnmul", [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('100'), bs('0'), bs('10'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64])

aarch64op("fabs",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('01'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
aarch64op("fneg",  [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('10'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])
aarch64op("fsqrt", [bs('0'), bs('00'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('0000'), bs('11'), bs('10000'), sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64])


# floating point multiply add p.163
aarch64op("fmadd", [bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('0'), sdm_32_64, bs('0'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fmsub", [bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('0'), sdm_32_64, bs('1'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fnmadd",[bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('0'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])
aarch64op("fnmsub",[bs('0'), bs('00'), bs('11111'), bs('0'), sdsize1, bs('1'), sdm_32_64, bs('1'), sda_32_64, sdn_32_64, sdd_32_64], [sdd_32_64, sdn_32_64, sdm_32_64, sda_32_64])

# conversion float integer p.235
aarch64op("scvtf", [sf, bs('0'), bs('0'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('010'), bs('000000'), rn, sdd_32_64], [sdd_32_64, rn])
aarch64op("ucvtf", [sf, bs('0'), bs('0'), bs('11110'), bs('0'), sdsize1, bs('1'), bs('00'), bs('011'), bs('000000'), rn, sdd_32_64], [sdd_32_64, rn])



# conditional select p.158
aarch64op("csel",  [sf, bs('0'), bs('0'), bs('11010100'), rmz, cond_arg, bs('00'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csinc", [sf, bs('0'), bs('0'), bs('11010100'), rmz, cond_arg, bs('01'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csinv", [sf, bs('1'), bs('0'), bs('11010100'), rmz, cond_arg, bs('00'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("csneg", [sf, bs('1'), bs('0'), bs('11010100'), rmz, cond_arg, bs('01'), rnz, rd], [rd, rnz, rmz, cond_arg])
aarch64op("cset",  [sf, bs('0'), bs('0'), bs('11010100'), bs('11111'), cond_inv_arg, bs('01'), bs('11111'), rd], [rd, cond_inv_arg], alias=True)
aarch64op("csetm", [sf, bs('1'), bs('0'), bs('11010100'), bs('11111'), cond_inv_arg, bs('00'), bs('11111'), rd], [rd, cond_inv_arg], alias=True)


# multiply p.156
aarch64op("madd",  [sf, bs('00'), bs('11011'), bs('000'), rm, bs('0'), ra, rn, rd], [rd, rn, rm, ra])
aarch64op("msub",  [sf, bs('00'), bs('11011'), bs('000'), rm, bs('1'), ra, rn, rd], [rd, rn, rm, ra])

aarch64op("umulh", [bs('1'), bs('00'), bs('11011'), bs('110'), rm64, bs('0'), bs('11111'), rn64, rd64], [rd64, rn64, rm64])
aarch64op("smulh", [bs('1'), bs('00'), bs('11011'), bs('010'), rm64, bs('0'), bs('11111'), rn64, rd64], [rd64, rn64, rm64])

aarch64op("smaddl",[bs('1'), bs('00'), bs('11011'), bs('001'), rm32, bs('0'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])
aarch64op("umaddl",[bs('1'), bs('00'), bs('11011'), bs('101'), rm32, bs('0'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])

aarch64op("smsubl",[bs('1'), bs('00'), bs('11011'), bs('001'), rm32, bs('1'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])
aarch64op("umsubl",[bs('1'), bs('00'), bs('11011'), bs('101'), rm32, bs('1'), ra64, rn32, rd64], [rd64, rn32, rm32, ra64])

# division p.156
aarch64op("sdiv", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('00001'), bs('1'), rn, rd], [rd, rn, rm])
aarch64op("udiv", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('00001'), bs('0'), rn, rd], [rd, rn, rm])


# extract register p.150
aarch64op("extr", [sf, bs('00100111'), bs(l=1, cls=(aarch64_eq,), ref="sf"), bs('0'), rm, uimm6, rn, rd], [rd, rn, rm, uimm6])

# shift reg p.155
shiftr_name = {'LSL': 0b00, 'LSR': 0b01, 'ASR': 0b10, 'ROR': 0b11}
bs_shiftr_name = bs_name(l=2, name=shiftr_name)

aarch64op("shiftr", [sf, bs('0'), bs('0'), bs('11010110'), rm, bs('0010'), bs_shiftr_name, rn, rd], [rd, rn, rm])

#
aarch64op("NOP", [bs('11010101000000110010000000011111')])

# exception p.133
aarch64op("brk", [bs('11010100'), bs('001'), uimm16, bs('000'), bs('00')], [uimm16])
aarch64op("hlt", [bs('11010100'), bs('010'), uimm16, bs('000'), bs('00')], [uimm16])
aarch64op("svc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('01')], [uimm16])
aarch64op("hvc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('10')], [uimm16])
aarch64op("smc", [bs('11010100'), bs('000'), uimm16, bs('000'), bs('11')], [uimm16])

# msr p.631
msr_name = {'MSR': 0b0, 'MRS': 0b1}
bs_msr_name = bs_name(l=1, name=msr_name)
aarch64op("mrs", [bs('1101010100'), bs('1'), bs('1'), op0, op1, crn, crm, op2, rt64], [rt64, op0, op1, crn, crm, op2])
aarch64op("msr", [bs('1101010100'), bs('0'), bs('1'), op0, op1, crn, crm, op2, rt64], [op0, op1, crn, crm, op2, rt64])


# load/store exclusive p.140
aarch64op("stxr", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt], [rs32, rt, rn64_deref_nooff])
aarch64op("ldxr", [bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])


aarch64op("stxrb", [bs('0'), bs('0'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("ldxrb", [bs('0'), bs('0'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])

aarch64op("stxrb", [bs('0'), bs('1'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("ldxrh", [bs('0'), bs('1'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('0'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])

aarch64op("stxp", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('1'), rs32, bs('0'), rt2, rn64_deref_nooff, rt], [rs32, rt, rt2, rn64_deref_nooff])
aarch64op("ldxp", [bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('1'), bs('11111'), bs('0'), rt2, rn64_deref_nooff, rt], [rt, rt2, rn64_deref_nooff])

# load acquire/store release p.141
aarch64op("ldar", [bs('1'), sf, bs('001000'), bs('1'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldarb",[bs('0'), bs('0'), bs('001000'), bs('1'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])
aarch64op("ldarh",[bs('0'), bs('1'), bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldaxp",[bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('1'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("ldaxr",[bs('1'), sf, bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])

aarch64op("stlr", [bs('1'), sf, bs('001000'), bs('1'), bs('0'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt], [rt, rn64_deref_nooff])
aarch64op("stlrb",[bs('0'), bs('0'), bs('001000'), bs('1'), bs('0'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])
aarch64op("stlrh",[bs('0'), bs('1'), bs('001000'), bs('1'), bs('0'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])

aarch64op("stlxr", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt], [rs32, rt, rn64_deref_nooff])
aarch64op("stlxrb",[bs('0'), bs('0'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("stlxrh",[bs('0'), bs('1'), bs('001000'), bs('0'), bs('0'), bs('0'), rs32, bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rs32, rt32, rn64_deref_nooff])
aarch64op("stlxp", [bs('1'), sf, bs('001000'), bs('0'), bs('0'), bs('1'), rs32, bs('1'), rt2, rn64_deref_nooff, rt], [rs32, rt, rt2, rn64_deref_nooff])


# barriers p.135
aarch64op("dsb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('00'), bs('11111')], [crm])
aarch64op("dmb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('01'), bs('11111')], [crm])
aarch64op("isb", [bs('1101010100'), bs('0000110011'), crm, bs('1'), bs('10'), bs('11111')], [crm])
aarch64op("ic",  [bs('1101010100'), bs('0'), bs('01'), op1, bs('0111'), crm, op2, rt64], [op1, crm, op2, rt64])
aarch64op('clrex', [bs('1101010100'), bs('0'), bs('00'), bs('011'), bs('0011'), uimm4, bs('010'), bs('11111')], [uimm4])
aarch64op("tlbi", [bs('1101010100'), bs('0'), bs('01'), op1, bs('1000'), crm, op2, rt64], [op1, crm, op2, rt64])
aarch64op('yield', [bs('1101010100'), bs('0'), bs('00'), bs('011'), bs('0010'), bs('0000'), bs('001'), bs('11111')], [])


stacctype = bs_mod_name(l=1, fname='order', mn_mod=['', 'L'])
ltacctype = bs_mod_name(l=1, fname='order', mn_mod=['', 'A'])


aarch64op("casp",   [bs('0'), sf, bs('001000'), bs('0'), ltacctype, bs('1'), rs, stacctype, bs('11111'), rn64_deref_nooff, rt], [rs, rt, rn64_deref_nooff])
aarch64op("ldaxrb", [bs('00'),  bs('001000'), bs('0'), bs('1'), bs('0'), bs('11111'), bs('1'), bs('11111'), rn64_deref_nooff, rt32], [rt32, rn64_deref_nooff])
