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
import miasm.arch.x86.regs as regs_module
from miasm.arch.x86.regs import *
from miasm.core.asm_ast import AstNode, AstInt, AstId, AstMem, AstOp
from miasm.ir.ir import color_expr_html


log = logging.getLogger("x86_arch")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

conditional_branch = ["JO", "JNO", "JB", "JAE",
                      "JZ", "JNZ", "JBE", "JA",
                      "JS", "JNS", "JPE", "JNP",
                      #"L", "NL", "NG", "G"]
                      "JL", "JGE", "JLE", "JG",
                      "JCXZ", "JECXZ", "JRCXZ"]

unconditional_branch = ['JMP', 'JMPF']

f_isad = "AD"
f_s08 = "S08"
f_u08 = "U08"
f_s16 = "S16"
f_u16 = "U16"
f_s32 = "S32"
f_u32 = "U32"
f_s64 = "S64"
f_u64 = "U64"
f_imm = 'IMM'

f_imm2size = {f_s08: 8, f_s16: 16, f_s32: 32, f_s64: 64,
              f_u08: 8, f_u16: 16, f_u32: 32, f_u64: 64}


size2gpregs = {8: gpregs08, 16: gpregs16,
               32: gpregs32, 64: gpregs64}


replace_regs64 = {
    AL: RAX[:8], CL: RCX[:8], DL: RDX[:8], BL: RBX[:8],
    AH: RAX[8:16], CH: RCX[8:16], DH: RDX[8:16], BH: RBX[8:16],
    SPL: RSP[0:8], BPL: RBP[0:8], SIL: RSI[0:8], DIL: RDI[0:8],
    R8B: R8[0:8], R9B: R9[0:8], R10B: R10[0:8], R11B: R11[0:8],
    R12B: R12[0:8], R13B: R13[0:8], R14B: R14[0:8], R15B: R15[0:8],

    AX: RAX[:16], CX: RCX[:16], DX: RDX[:16], BX: RBX[:16],
    SP: RSP[:16], BP: RBP[:16], SI: RSI[:16], DI: RDI[:16],
    R8W:  R8[:16], R9W:  R9[:16], R10W: R10[:16], R11W: R11[:16],
    R12W: R12[:16], R13W: R13[:16], R14W: R14[:16], R15W: R15[:16],

    EAX: RAX[:32], ECX: RCX[:32], EDX: RDX[:32], EBX: RBX[:32],
    ESP: RSP[:32], EBP: RBP[:32], ESI: RSI[:32], EDI: RDI[:32],
    R8D: R8[:32], R9D: R9[:32], R10D: R10[:32], R11D: R11[:32],
    R12D: R12[:32], R13D: R13[:32], R14D: R14[:32], R15D: R15[:32],

    IP: RIP[:16], EIP: RIP[:32],

    ExprId("ST", 64): float_st0,
    ExprId("ST(0)", 64): float_st0,
    ExprId("ST(1)", 64): float_st1,
    ExprId("ST(2)", 64): float_st2,
    ExprId("ST(3)", 64): float_st3,
    ExprId("ST(4)", 64): float_st4,
    ExprId("ST(5)", 64): float_st5,
    ExprId("ST(6)", 64): float_st6,
    ExprId("ST(7)", 64): float_st7,

}

replace_regs32 = {
    AL: EAX[:8],   CL: ECX[:8],   DL: EDX[:8],   BL: EBX[:8],
    AH: EAX[8:16], CH: ECX[8:16], DH: EDX[8:16], BH: EBX[8:16],

    AX: EAX[:16], CX: ECX[:16], DX: EDX[:16], BX: EBX[:16],
    SP: ESP[:16], BP: EBP[:16], SI: ESI[:16], DI: EDI[:16],

    IP: EIP[:16],


    ExprId("ST", 64): float_st0,
    ExprId("ST(0)", 64): float_st0,
    ExprId("ST(1)", 64): float_st1,
    ExprId("ST(2)", 64): float_st2,
    ExprId("ST(3)", 64): float_st3,
    ExprId("ST(4)", 64): float_st4,
    ExprId("ST(5)", 64): float_st5,
    ExprId("ST(6)", 64): float_st6,
    ExprId("ST(7)", 64): float_st7,

}

replace_regs16 = {
    AL: AX[:8],   CL: CX[:8],   DL: DX[:8],   BL: BX[:8],
    AH: AX[8:16], CH: CX[8:16], DH: DX[8:16], BH: BX[8:16],

    AX: AX[:16],  CX: CX[:16],  DX: DX[:16],  BX: BX[:16],
    SP: SP[:16],  BP: BP[:16],  SI: SI[:16],  DI: DI[:16],


    ExprId("ST", 64): float_st0,
    ExprId("ST(0)", 64): float_st0,
    ExprId("ST(1)", 64): float_st1,
    ExprId("ST(2)", 64): float_st2,
    ExprId("ST(3)", 64): float_st3,
    ExprId("ST(4)", 64): float_st4,
    ExprId("ST(5)", 64): float_st5,
    ExprId("ST(6)", 64): float_st6,
    ExprId("ST(7)", 64): float_st7,

}

replace_regs = {16: replace_regs16,
                32: replace_regs32,
                64: replace_regs64}


segm2enc = {CS: 1, SS: 2, DS: 3, ES: 4, FS: 5, GS: 6}
enc2segm = dict((value, key) for key, value in viewitems(segm2enc))

segm_info = reg_info_dct(enc2segm)



enc2crx = {
    0: cr0,
    1: cr1,
    2: cr2,
    3: cr3,
    4: cr4,
    5: cr5,
    6: cr6,
    7: cr7,
}

crx_info = reg_info_dct(enc2crx)


enc2drx = {
    0: dr0,
    1: dr1,
    2: dr2,
    3: dr3,
    4: dr4,
    5: dr5,
    6: dr6,
    7: dr7,
}

drx_info = reg_info_dct(enc2drx)



# parser helper ###########
PLUS = Suppress("+")
MULT = Suppress("*")

COLON = Suppress(":")


LBRACK = Suppress("[")
RBRACK = Suppress("]")


gpreg = (
    gpregs08.parser |
    gpregs08_64.parser |
    gpregs16.parser |
    gpregs32.parser |
    gpregs64.parser |
    gpregs_xmm.parser |
    gpregs_mm.parser |
    gpregs_bnd.parser
)


def is_op_segm(expr):
    """Returns True if is ExprOp and op == 'segm'"""
    return expr.is_op('segm')

def is_mem_segm(expr):
    """Returns True if is ExprMem and ptr is_op_segm"""
    return expr.is_mem() and is_op_segm(expr.ptr)


def cb_deref_segmoff(tokens):
    assert len(tokens) == 2
    return AstOp('segm', tokens[0], tokens[1])


def cb_deref_base_expr(tokens):
    tokens = tokens[0]
    assert isinstance(tokens, AstNode)
    addr = tokens
    return addr


deref_mem_ad = (LBRACK + base_expr + RBRACK).setParseAction(cb_deref_base_expr)

deref_ptr = (base_expr + COLON + base_expr).setParseAction(cb_deref_segmoff)


PTR = Suppress('PTR')

FAR = Suppress('FAR')


BYTE = Literal('BYTE')
WORD = Literal('WORD')
DWORD = Literal('DWORD')
QWORD = Literal('QWORD')
TBYTE = Literal('TBYTE')
XMMWORD = Literal('XMMWORD')

MEMPREFIX2SIZE = {'BYTE': 8, 'WORD': 16, 'DWORD': 32,
                  'QWORD': 64, 'TBYTE': 80, 'XMMWORD': 128}

SIZE2MEMPREFIX = dict((value, key) for key, value in viewitems(MEMPREFIX2SIZE))

def cb_deref_mem(tokens):
    if len(tokens) == 2:
        s, ptr = tokens
        assert isinstance(ptr, AstNode)
        return AstMem(ptr, MEMPREFIX2SIZE[s])
    elif len(tokens) == 3:
        s, segm, ptr = tokens
        return AstMem(AstOp('segm', segm, ptr), MEMPREFIX2SIZE[s])
    raise ValueError('len(tokens) > 3')

mem_size = (BYTE | DWORD | QWORD | WORD | TBYTE | XMMWORD)
deref_mem = (mem_size + PTR + Optional((base_expr + COLON))+ deref_mem_ad).setParseAction(cb_deref_mem)


rmarg = (
    gpregs08.parser |
    gpregs08_64.parser |
    gpregs16.parser |
    gpregs32.parser |
    gpregs64.parser |
    gpregs_mm.parser |
    gpregs_xmm.parser |
    gpregs_bnd.parser
)

rmarg |= deref_mem


mem_far = FAR + deref_mem


cl_or_imm = r08_ecx.parser
cl_or_imm |= base_expr



class x86_arg(m_arg):
    def asm_ast_to_expr(self, value, loc_db, size_hint=None, fixed_size=None):
        if size_hint is None:
            size_hint = self.parent.mode
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
            if value.name in MEMPREFIX2SIZE:
                return None
            if value.name in ["FAR"]:
                return None

            loc_key = loc_db.get_or_create_name_location(value.name)
            return ExprLoc(loc_key, size_hint)
        if isinstance(value, AstOp):
            # First pass to retrieve fixed_size
            if value.op == "segm":
                segm = self.asm_ast_to_expr(value.args[0], loc_db)
                ptr = self.asm_ast_to_expr(value.args[1], loc_db, None, fixed_size)
                return ExprOp('segm', segm, ptr)
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
            if None in args:
                return None
            return ExprOp(value.op, *args)
        if isinstance(value, AstInt):
            if 1 << size_hint < value.value:
                size_hint *= 2
            return ExprInt(value.value, size_hint)
        if isinstance(value, AstMem):
            fixed_size.add(value.size)
            ptr = self.asm_ast_to_expr(value.ptr, loc_db, None, set())
            if ptr is None:
                return None
            return ExprMem(ptr, value.size)
        return None

class r_al(reg_noarg, x86_arg):
    reg_info = r08_eax
    parser = reg_info.parser


class r_ax(reg_noarg, x86_arg):
    reg_info = r16_eax
    parser = reg_info.parser


class r_dx(reg_noarg, x86_arg):
    reg_info = r16_edx
    parser = reg_info.parser


class r_eax(reg_noarg, x86_arg):
    reg_info = r32_eax
    parser = reg_info.parser


class r_rax(reg_noarg, x86_arg):
    reg_info = r64_eax
    parser = reg_info.parser


class r_cl(reg_noarg, x86_arg):
    reg_info = r08_ecx
    parser = reg_info.parser


invmode = {16: 32, 32: 16}


def opmode_prefix(mode):
    size, opmode, admode = mode
    if size in [16, 32]:
        if opmode:
            return invmode[size]
        else:
            return size
    elif size == 64:
        if opmode:
            return 16
        else:
            return 32
    raise NotImplementedError('not fully functional')


def admode_prefix(mode):
    size, opmode, admode = mode
    if size in [16, 32]:
        if admode:
            return invmode[size]
        else:
            return size
    elif size == 64:
        return 64
    raise NotImplementedError('not fully functional')


def v_opmode_info(size, opmode, rex_w, stk):
    if size in [16, 32]:
        if opmode:
            return invmode[size]
        else:
            return size
    elif size == 64:
        # Rex has the maximum priority
        # Then opmode
        # Then stacker
        if rex_w == 1:
            return 64
        elif opmode == 1:
            return 16
        elif stk:
            return 64
        else:
            return 32


def v_opmode(p):
    stk = hasattr(p, 'stk')
    return v_opmode_info(p.mode, p.opmode, p.rex_w.value, stk)


def v_admode_info(size, admode):
    if size in [16, 32]:
        if admode:
            return invmode[size]
        else:
            return size
    elif size == 64:
        if admode == 1:
            return 32
        return 64


def v_admode(p):
    return v_admode_info(p.mode, p.admode)


def offsize(p):
    if p.opmode:
        return 16
    else:
        return p.mode


def get_prefix(s):
    g = re.search('(\S+)(\s+)', s)
    if not g:
        return None, s
    prefix, b = g.groups()
    return prefix, s[len(prefix) + len(b):]


repeat_mn = ["INS", "OUTS",
             "MOVSB", "MOVSW", "MOVSD", "MOVSQ",
             "SCASB", "SCASW", "SCASD", "SCASQ",
             "LODSB", "LODSW", "LODSD", "LODSQ",
             "STOSB", "STOSW", "STOSD", "STOSQ",
             "CMPSB", "CMPSW", "CMPSD", "CMPSQ",
             ]


class group(object):

    def __init__(self):
        self.value = None


class additional_info(object):

    def __init__(self):
        self.except_on_instr = False
        self.g1 = group()
        self.g2 = group()
        self.vopmode = None
        self.stk = False
        self.v_opmode = None
        self.v_admode = None
        self.prefixed = b''


class instruction_x86(instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_x86, self).__init__(*args, **kargs)

    def v_opmode(self):
        return self.additional_info.v_opmode

    def v_admode(self):
        return self.additional_info.v_admode

    def dstflow(self):
        if self.name in conditional_branch + unconditional_branch:
            return True
        if self.name.startswith('LOOP'):
            return True
        return self.name in ['CALL']

    def dstflow2label(self, loc_db):
        if self.additional_info.g1.value & 14 and self.name in repeat_mn:
            return
        expr = self.args[0]
        if not expr.is_int():
            return
        addr = (int(expr) + int(self.offset)) & int(expr.mask)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[0] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        if self.name in conditional_branch + unconditional_branch:
            return True
        if self.name.startswith('LOOP'):
            return True
        if self.name.startswith('RET'):
            return True
        if self.name.startswith('INT'):
            return True
        if self.name.startswith('SYS'):
            return True
        return self.name in ['CALL', 'HLT', 'IRET', 'IRETD', 'IRETQ', 'ICEBP', 'UD2']

    def splitflow(self):
        if self.name in conditional_branch:
            return True
        if self.name in unconditional_branch:
            return False
        if self.name.startswith('LOOP'):
            return True
        if self.name.startswith('INT'):
            return True
        if self.name.startswith('SYS'):
            return True
        return self.name in ['CALL']

    def setdstflow(self, a):
        return

    def is_subcall(self):
        return self.name in ['CALL']

    def getdstflow(self, loc_db):
        if self.additional_info.g1.value & 14 and self.name in repeat_mn:
            addr = int(self.offset)
            loc_key = loc_db.get_or_create_offset_location(addr)
            return [ExprLoc(loc_key, self.v_opmode())]
        return [self.args[0]]

    def get_symbol_size(self, symbol, loc_db):
        return self.mode

    def fixDstOffset(self):
        expr = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(expr, ExprInt):
            log.warning('dynamic dst %r', expr)
            return
        self.args[0] = ExprInt(int(expr) - self.offset, self.mode)

    def get_info(self, c):
        self.additional_info.g1.value = c.g1.value
        self.additional_info.g2.value = c.g2.value
        self.additional_info.stk = hasattr(c, 'stk')
        self.additional_info.v_opmode = c.v_opmode()
        self.additional_info.v_admode = c.v_admode()
        self.additional_info.prefix = c.prefix
        self.additional_info.prefixed = getattr(c, "prefixed", b"")

    def __str__(self):
        return self.to_string()

    def to_string(self, loc_db=None):
        o = super(instruction_x86, self).to_string(loc_db)
        if self.additional_info.g1.value & 1:
            o = "LOCK %s" % o
        if self.additional_info.g1.value & 2:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF2":
                o = "REPNE %s" % o
        if self.additional_info.g1.value & 8:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF3":
                o = "REP %s" % o
        elif self.additional_info.g1.value & 4:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF3":
                o = "REPE %s" % o
        return o

    def to_html(self, loc_db=None):
        o = super(instruction_x86, self).to_html(loc_db)
        if self.additional_info.g1.value & 1:
            text =  utils.set_html_text_color("LOCK", utils.COLOR_MNEMO)
            o = "%s %s" % (text, o)
        if self.additional_info.g1.value & 2:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF2":
                text =  utils.set_html_text_color("REPNE", utils.COLOR_MNEMO)
                o = "%s %s" % (text, o)
        if self.additional_info.g1.value & 8:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF3":
                text =  utils.set_html_text_color("REP", utils.COLOR_MNEMO)
                o = "%s %s" % (text, o)
        elif self.additional_info.g1.value & 4:
            if getattr(self.additional_info.prefixed, 'default', b"") != b"\xF3":
                text =  utils.set_html_text_color("REPE", utils.COLOR_MNEMO)
                o = "%s %s" % (text, o)
        return o


    def get_args_expr(self):
        args = []
        for a in self.args:
            a = a.replace_expr(replace_regs[self.mode])
            args.append(a)
        return args

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int():
            o = str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                o = loc_db.pretty_str(expr.loc_key)
            else:
                o = str(expr)
        elif ((isinstance(expr, ExprOp) and expr.op == 'far' and
               isinstance(expr.args[0], ExprMem)) or
              isinstance(expr, ExprMem)):
            if isinstance(expr, ExprOp):
                prefix, expr = "FAR ", expr.args[0]
            else:
                prefix = ""
            sz = SIZE2MEMPREFIX[expr.size]
            segm = ""
            if is_mem_segm(expr):
                segm = "%s:" % expr.ptr.args[0]
                expr = expr.ptr.args[1]
            else:
                expr = expr.ptr
            if isinstance(expr, ExprOp):
                s = str(expr).replace('(', '').replace(')', '')
            else:
                s = str(expr)
            o = prefix + sz + ' PTR %s[%s]' % (segm, s)
        elif isinstance(expr, ExprOp) and expr.op == 'segm':
            o = "%s:%s" % (expr.args[0], expr.args[1])
        else:
            raise ValueError('check this %r' % expr)
        return "%s" % o


    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int() or expr.is_loc():
            o = color_expr_html(expr, loc_db)
        elif ((isinstance(expr, ExprOp) and expr.op == 'far' and
               isinstance(expr.args[0], ExprMem)) or
              isinstance(expr, ExprMem)):
            if isinstance(expr, ExprOp):
                prefix, expr = "FAR ", expr.args[0]
            else:
                prefix = ""
            sz = SIZE2MEMPREFIX[expr.size]
            sz =  '<font color="%s">%s</font>' % (utils.COLOR_MEM, sz)
            segm = ""
            if is_mem_segm(expr):
                segm = "%s:" % expr.ptr.args[0]
                expr = expr.ptr.args[1]
            else:
                expr = expr.ptr
            if isinstance(expr, ExprOp):
                s = color_expr_html(expr, loc_db)#.replace('(', '').replace(')', '')
            else:
                s = color_expr_html(expr, loc_db)
            o = prefix + sz + ' PTR %s[%s]' % (segm, s)
        elif isinstance(expr, ExprOp) and expr.op == 'segm':
            o = "%s:%s" % (
                color_expr_html(expr.args[0], loc_db),
                color_expr_html(expr.args[1], loc_db)
            )
        else:
            raise ValueError('check this %r' % expr)
        return "%s" % o



class mn_x86(cls_mn):
    name = "x86"
    prefix_op_size = False
    prefix_ad_size = False
    regs = regs_module
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    bintree = {}
    num = 0
    delayslot = 0
    pc = {16: IP, 32: EIP, 64: RIP}
    sp = {16: SP, 32: ESP, 64: RSP}
    instruction = instruction_x86
    max_instruction_len = 15

    @classmethod
    def getpc(cls, attrib):
        return cls.pc[attrib]

    @classmethod
    def getsp(cls, attrib):
        return cls.sp[attrib]

    def v_opmode(self):
        if hasattr(self, 'stk'):
            stk = 1
        else:
            stk = 0
        return v_opmode_info(self.mode, self.opmode, self.rex_w.value, stk)

    def v_admode(self):
        size, opmode, admode = self.mode, self.opmode, self.admode
        if size in [16, 32]:
            if admode:
                return invmode[size]
            else:
                return size
        elif size == 64:
            if admode == 1:
                return 32
            return 64

    def additional_info(self):
        info = additional_info()
        info.g1.value = self.g1.value
        info.g2.value = self.g2.value
        info.stk = hasattr(self, 'stk')
        info.v_opmode = self.v_opmode()
        info.prefixed = b""
        if hasattr(self, 'prefixed'):
            info.prefixed = self.prefixed.default
        return info

    @classmethod
    def check_mnemo(cls, fields):
        pass

    @classmethod
    def getmn(cls, name):
        return name.upper()

    @classmethod
    def mod_fields(cls, fields):
        prefix = [d_g1, d_g2, d_rex_p, d_rex_w, d_rex_r, d_rex_x, d_rex_b]
        return prefix + fields

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    @classmethod
    def fromstring(cls, text, loc_db, mode):
        pref = 0
        prefix, new_s = get_prefix(text)
        if prefix == "LOCK":
            pref |= 1
            text = new_s
        elif prefix == "REPNE" or prefix == "REPNZ":
            pref |= 2
            text = new_s
        elif prefix == "REPE" or prefix == "REPZ":
            pref |= 4
            text = new_s
        elif prefix == "REP":
            pref |= 8
            text = new_s
        c = super(mn_x86, cls).fromstring(text, loc_db, mode)
        c.additional_info.g1.value = pref
        return c

    @classmethod
    def pre_dis(cls, v, mode, offset):
        offset_o = offset
        pre_dis_info = {'opmode': 0,
                        'admode': 0,
                        'g1': 0,
                        'g2': 0,
                        'rex_p': 0,
                        'rex_w': 0,
                        'rex_r': 0,
                        'rex_x': 0,
                        'rex_b': 0,
                        'prefix': b"",
                        'prefixed': b"",
                        }
        while True:
            c = v.getbytes(offset)
            if c == b'\x66':
                pre_dis_info['opmode'] = 1
            elif c == b'\x67':
                pre_dis_info['admode'] = 1
            elif c == b'\xf0':
                pre_dis_info['g1'] = 1
            elif c == b'\xf2':
                pre_dis_info['g1'] = 2
            elif c == b'\xf3':
                pre_dis_info['g1'] = 12

            elif c == b'\x2e':
                pre_dis_info['g2'] = 1
            elif c == b'\x36':
                pre_dis_info['g2'] = 2
            elif c == b'\x3e':
                pre_dis_info['g2'] = 3
            elif c == b'\x26':
                pre_dis_info['g2'] = 4
            elif c == b'\x64':
                pre_dis_info['g2'] = 5
            elif c == b'\x65':
                pre_dis_info['g2'] = 6

            else:
                break
            pre_dis_info['prefix'] += c
            offset += 1
        rex_prefixes = b'@ABCDEFGHIJKLMNO'
        if mode == 64 and c in rex_prefixes:
            while c in rex_prefixes:
                # multiple REX prefixes case - use last REX prefix
                x = ord(c)
                offset += 1
                c = v.getbytes(offset)
            pre_dis_info['rex_p'] = 1
            pre_dis_info['rex_w'] = (x >> 3) & 1
            pre_dis_info['rex_r'] = (x >> 2) & 1
            pre_dis_info['rex_x'] = (x >> 1) & 1
            pre_dis_info['rex_b'] = (x >> 0) & 1
        elif pre_dis_info.get('g1', None) == 12 and c in [b'\xa6', b'\xa7', b'\xae', b'\xaf']:
            pre_dis_info['g1'] = 4
        return pre_dis_info, v, mode, offset, offset - offset_o

    @classmethod
    def get_cls_instance(cls, cc, mode, infos=None):
        for opmode in [0, 1]:
            for admode in [0, 1]:
                c = cc()
                c.init_class()

                c.reset_class()
                c.add_pre_dis_info()
                c.dup_info(infos)
                c.mode = mode
                c.opmode = opmode
                c.admode = admode

                if not hasattr(c, 'stk') and hasattr(c, "fopmode") and c.fopmode.mode == 64:
                    c.rex_w.value = 1
                yield c

    def post_dis(self):
        if self.g2.value:
            for a in self.args:
                if not isinstance(a.expr, ExprMem):
                    continue
                m = a.expr
                a.expr = ExprMem(
                    ExprOp('segm', enc2segm[self.g2.value], m.ptr), m.size)
        return self

    def dup_info(self, infos):
        if infos is not None:
            self.g1.value = infos.g1.value
            self.g2.value = infos.g2.value

    def reset_class(self):
        super(mn_x86, self).reset_class()
        if hasattr(self, "opmode"):
            del(self.opmode)
        if hasattr(self, "admode"):
            del(self.admode)

    def add_pre_dis_info(self, pre_dis_info=None):
        if pre_dis_info is None:
            return True
        if hasattr(self, "prefixed") and self.prefixed.default == b"\x66":
            pre_dis_info['opmode'] = 0
        self.opmode = pre_dis_info['opmode']
        self.admode = pre_dis_info['admode']

        if hasattr(self, 'no_xmm_pref') and\
                pre_dis_info['prefix'] and\
                pre_dis_info['prefix'][-1] in b'\x66\xf2\xf3':
            return False
        if (hasattr(self, "prefixed") and
            not pre_dis_info['prefix'].endswith(self.prefixed.default)):
            return False
        if (self.rex_w.value is not None and
            self.rex_w.value != pre_dis_info['rex_w']):
            return False
        else:
            self.rex_w.value = pre_dis_info['rex_w']
        self.rex_r.value = pre_dis_info['rex_r']
        self.rex_b.value = pre_dis_info['rex_b']
        self.rex_x.value = pre_dis_info['rex_x']
        self.rex_p.value = pre_dis_info['rex_p']

        if hasattr(self, 'no_rex') and\
           (self.rex_r.value or self.rex_b.value or
            self.rex_x.value or self.rex_p.value):
            return False


        self.g1.value = pre_dis_info['g1']
        self.g2.value = pre_dis_info['g2']
        self.prefix = pre_dis_info['prefix']
        return True

    def post_asm(self, v):
        return v


    def gen_prefix(self):
        v = b""
        rex = 0x40
        if self.g1.value is None:
            self.g1.value = 0
        if self.g2.value is None:
            self.g2.value = 0

        if self.rex_w.value:
            rex |= 0x8
        if self.rex_r.value:
            rex |= 0x4
        if self.rex_x.value:
            rex |= 0x2
        if self.rex_b.value:
            rex |= 0x1
        if rex != 0x40 or self.rex_p.value == 1:
            v = utils.int_to_byte(rex) + v
            if hasattr(self, 'no_rex'):
                return None

        if hasattr(self, 'prefixed'):
            v = self.prefixed.default + v

        if self.g1.value & 1:
            v = b"\xf0" + v
        if self.g1.value & 2:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = b"\xf2" + v
        if self.g1.value & 12:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = b"\xf3" + v
        if self.g2.value:
            v = {
                1: b'\x2e',
                2: b'\x36',
                3: b'\x3e',
                4: b'\x26',
                5: b'\x64',
                6: b'\x65'
            }[self.g2.value] + v
        # mode prefix
        if hasattr(self, "admode") and self.admode:
            v = b"\x67" + v

        if hasattr(self, "opmode") and self.opmode:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = b"\x66" + v
        return v

    def encodefields(self, decoded):
        v = super(mn_x86, self).encodefields(decoded)
        prefix = self.gen_prefix()
        if prefix is None:
            return None
        return prefix + v

    def getnextflow(self, loc_db):
        raise NotImplementedError('not fully functional')

    def ir_pre_instruction(self):
        return [ExprAssign(mRIP[self.mode],
            ExprInt(self.offset + self.l, mRIP[self.mode].size))]

    @classmethod
    def filter_asm_candidates(cls, instr, candidates):

        cand_same_mode = []
        cand_diff_mode = []
        out = []
        for c, v in candidates:
            if (hasattr(c, 'no_xmm_pref') and
                (c.g1.value & 2 or c.g1.value & 4 or c.g1.value & 8 or c.opmode)):
                continue
            if hasattr(c, "fopmode") and v_opmode(c) != c.fopmode.mode:
                continue
            if hasattr(c, "fadmode") and v_admode(c) != c.fadmode.mode:
                continue
            # relative dstflow must not have opmode set
            # (assign IP instead of EIP for instance)
            if (instr.dstflow() and
                instr.name not in ["JCXZ", "JECXZ", "JRCXZ"] and
                len(instr.args) == 1 and
                    isinstance(instr.args[0], ExprInt) and c.opmode):
                continue

            out.append((c, v))
        candidates = out
        for c, v in candidates:
            if v_opmode(c) == instr.mode:
                cand_same_mode += v
        for c, v in candidates:
            if v_opmode(c) != instr.mode:
                cand_diff_mode += v
        cand_same_mode.sort(key=len)
        cand_diff_mode.sort(key=len)
        return cand_same_mode + cand_diff_mode


class bs_modname_size(bs_divert):
    prio = 1

    def divert(self, i, candidates):
        out = []
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            fopmode = opmode_prefix(
                (dct['mode'], dct['opmode'], dct['admode']))
            mode = dct['mode']
            size, opmode, admode = dct['mode'], dct['opmode'], dct['admode']
            # no mode64 exinstance in name means no 64bit version of mnemo
            if mode == 64:
                if mode in self.args['name']:
                    nfields = fields[:]
                    f, i = getfieldindexby_name(nfields, 'rex_w')
                    f = bs("1", l=0, cls=(bs_fbit,), fname="rex_w")
                    osize = v_opmode_info(size, opmode, 1, 0)
                    nfields[i] = f
                    nfields = nfields[:-1]
                    ndct = dict(dct)
                    if osize in self.args['name']:
                        ndct['name'] = self.args['name'][osize]
                        out.append((cls, ndct['name'], bases, ndct, nfields))

                    nfields = fields[:]
                    nfields = nfields[:-1]
                    f, i = getfieldindexby_name(nfields, 'rex_w')
                    f = bs("0", l=0, cls=(bs_fbit,), fname="rex_w")
                    osize = v_opmode_info(size, opmode, 0, 0)
                    nfields[i] = f
                    ndct = dict(dct)
                    if osize in self.args['name']:
                        ndct['name'] = self.args['name'][osize]
                        out.append((cls, ndct['name'], bases, ndct, nfields))
            else:
                l = opmode_prefix((dct['mode'], dct['opmode'], dct['admode']))
                osize = v_opmode_info(size, opmode, None, 0)
                nfields = fields[:-1]
                ndct = dict(dct)
                if osize in self.args['name']:
                    ndct['name'] = self.args['name'][osize]
                    out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


class bs_modname_jecx(bs_divert):
    prio = 1

    def divert(self, i, candidates):
        out = []
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            fopmode = opmode_prefix(
                (dct['mode'], dct['opmode'], dct['admode']))
            mode = dct['mode']
            size, opmode, admode = dct['mode'], dct['opmode'], dct['admode']

            nfields = fields[:]
            nfields = nfields[:-1]
            args = dict(self.args)
            ndct = dict(dct)
            if mode == 64:
                if admode:
                    ndct['name'] = "JECXZ"
                else:
                    ndct['name'] = "JRCXZ"
            elif mode == 32:
                if admode:
                    ndct['name'] = "JCXZ"
                else:
                    ndct['name'] = "JECXZ"
            elif mode == 16:
                if admode:
                    ndct['name'] = "JECXZ"
                else:
                    ndct['name'] = "JCXZ"
            else:
                raise ValueError('unhandled mode')
            out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


class bs_modname_mode(bs_divert):
    prio = 1

    def divert(self, i, candidates):
        out = []
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            fopmode = opmode_prefix(
                (dct['mode'], dct['opmode'], dct['admode']))
            size, opmode, admode = dct['mode'], dct['opmode'], dct['admode']

            mode = dct['mode']
            l = opmode_prefix((dct['mode'], dct['opmode'], dct['admode']))
            osize = v_opmode_info(size, opmode, None, 0)
            nfields = fields[:-1]
            args = dict(self.args)
            ndct = dict(dct)
            if mode == 64 or osize == 32:
                ndct['name'] = self.args['name'][mode]
            else:
                ndct['name'] = self.args['name'][16]
            out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


class x86_imm(imm_noarg):
    parser = base_expr

    def decodeval(self, v):
        return swap_uint(self.l, v)

    def encodeval(self, v):
        return swap_uint(self.l, v)


class x86_imm_fix_08(imm_noarg):
    parser = base_expr
    intsize = 8
    intmask = (1 << intsize) - 1

    def decodeval(self, v):
        return self.ival

    def encode(self):
        v = self.expr2int(self.expr)
        if v != self.ival:
            return False
        self.value = 0
        return True


class x86_08(x86_imm):
    intsize = 8
    intmask = (1 << intsize) - 1


class x86_16(x86_imm):
    intsize = 16
    intmask = (1 << intsize) - 1


class x86_32(x86_imm):
    intsize = 32
    intmask = (1 << intsize) - 1


class x86_64(x86_imm):
    intsize = 64
    intmask = (1 << intsize) - 1


class x86_08_ne(x86_imm):
    intsize = 8
    intmask = (1 << intsize) - 1

    def encode(self):
        return True

    def decode(self, v):
        v = swap_uint(self.l, v)
        p = self.parent
        admode = p.v_admode()
        value = sign_ext(v, self.intsize, admode)
        self.expr = ExprInt(value, admode)
        return True


class x86_16_ne(x86_08_ne):
    intsize = 16
    intmask = (1 << intsize) - 1


class x86_32_ne(x86_08_ne):
    intsize = 32
    intmask = (1 << intsize) - 1


class x86_64_ne(x86_08_ne):
    intsize = 64
    intmask = (1 << intsize) - 1


class x86_s08to16(x86_imm):
    in_size = 8
    out_size = 16

    def myexpr(self, x):
        return ExprInt(x, 16)

    def int2expr(self, v):
        return self.myexpr(v)

    def expr2int(self, e):
        if not isinstance(e, ExprInt):
            return None
        v = int(e)
        if v & ~((1 << self.l) - 1) != 0:
            return None
        return v

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if self.parent.v_opmode() == 64:
            self.expr = ExprInt(sign_ext(v, self.in_size, 64), 64)
        else:
            if (1 << (self.l - 1)) & v:
                v = sign_ext(v, self.l, self.out_size)
            self.expr = self.myexpr(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        opmode = self.parent.v_opmode()

        out_size = self.out_size
        if opmode != self.out_size:
            if opmode == 32 and self.out_size == 64:
                out_size = opmode
                if v == sign_ext(
                    int(v & ((1 << self.in_size) - 1)), self.in_size, out_size):
                    pass
                else:
                    # test with rex_w
                    self.parent.rex_w.value = 1
                    opmode = self.parent.v_opmode()
                    out_size = opmode
                    if (v != sign_ext(
                        int(v & ((1 << self.in_size) - 1)),
                        self.in_size, out_size)):
                        return False
        if v != sign_ext(
            int(v & ((1 << self.in_size) - 1)), self.in_size, out_size):
            return False
        v = self.encodeval(v)
        self.value = (v & 0xffffffff) & self.lmask
        return True

    def decodeval(self, v):
        return swap_uint(self.l, v)

    def encodeval(self, v):
        return swap_sint(self.l, v)


class x86_s08to32(x86_s08to16):
    in_size = 8
    out_size = 32

    def myexpr(self, x):
        return ExprInt(x, 32)

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if self.parent.rex_w.value == 1:
            v = ExprInt(sign_ext(v, self.in_size, 64), 64)
        else:
            v = ExprInt(sign_ext(v, self.in_size, 32), 32)

        self.expr = v
        return True


class x86_s08to64(x86_s08to32):
    in_size = 8
    out_size = 64

    def myexpr(self, x):
        return ExprInt(x, 64)


class x86_s32to64(x86_s08to32):
    in_size = 32
    out_size = 64

    def myexpr(self, x):
        return ExprInt(x, 64)


class bs_eax(x86_arg):
    reg_info = r_eax_all
    rindex = 0
    parser = reg_info.parser

    def decode(self, v):
        p = self.parent
        expr = None
        if hasattr(p, 'w8') and p.w8.value == 0:
            expr = regs08_expr[self.rindex]
        else:
            expr = size2gpregs[p.v_opmode()].expr[self.rindex]
        self.expr = expr
        return True

    def encode(self):
        self.value = 0
        p = self.parent
        expr = self.expr
        osize = p.v_opmode()
        if hasattr(p, 'w8'):
            if p.w8.value is None:
                # XXX TODO: priority in w8 erase?
                if expr.size == 8:
                    p.w8.value = 0
                else:
                    p.w8.value = 1
        if hasattr(p, 'w8') and p.w8.value == 0:
            return expr == regs08_expr[self.rindex]
        elif p.mode in [16, 32]:
            return expr == size2gpregs[osize].expr[self.rindex]
        elif p.mode == 64:
            if expr == size2gpregs[64].expr[self.rindex]:
                p.rex_w.value = 1
                return True
            elif expr == size2gpregs[osize].expr[self.rindex]:
                return True
            return False
        return False

class bs_seg(x86_arg):
    reg_info = r_eax_all
    rindex = 0
    parser = reg_info.parser

    def decode(self, v):
        self.expr = self.reg_info.expr[0]
        return True

    def encode(self):
        self.value = 0
        return self.expr == self.reg_info.expr[0]


class bs_edx(bs_eax):
    reg_info = r_edx_all
    rindex = 2
    parser = reg_info.parser


class bs_st(bs_eax):
    reg_info = r_st_all
    rindex = 0
    parser = reg_info.parser


class bs_cs(bs_seg):
    reg_info = r_cs_all
    rindex = 0
    parser = reg_info.parser


class bs_ds(bs_seg):
    reg_info = r_ds_all
    rindex = 0
    parser = reg_info.parser


class bs_es(bs_seg):
    reg_info = r_es_all
    rindex = 0
    parser = reg_info.parser


class bs_ss(bs_seg):
    reg_info = r_ss_all
    rindex = 0
    parser = reg_info.parser


class bs_fs(bs_seg):
    reg_info = r_fs_all
    rindex = 0
    parser = reg_info.parser


class bs_gs(bs_seg):
    reg_info = r_gs_all
    rindex = 0
    parser = reg_info.parser


class x86_reg_st(reg_noarg, x86_arg):
    reg_info = r_st_all
    parser = reg_info.parser


class bs_sib_scale(bs_divert):
    bsname = "sib_scale"

    def divert(self, i, candidates):
        out = []
        done = False
        for cls, name, bases, dct, fields in candidates:
            if (not (admode_prefix(
                (dct['mode'], dct['opmode'], dct['admode'])) != 16 and
                'rm' in dct and dct['rm'] == 0b100 and
                'mod' in dct and dct['mod'] != 0b11)):
                ndct = dict(dct)
                nfields = fields[:]
                nfields[i] = None
                ndct[self.args['fname']] = None
                out.append((cls, ndct['name'], bases, ndct, nfields))
                continue

            nfields = fields[:]
            args = dict(self.args)
            ndct = dict(dct)
            f = bs(**args)
            nfields[i] = f
            ndct[self.args['fname']] = None
            out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


class bs_sib_index(bs_sib_scale):
    pass


class bs_sib_base(bs_sib_scale):
    pass


class bs_disp(bs_divert):

    def divert(self, i, candidates):
        out = []
        done = False
        for cls, name, bases, dct, fields in candidates:
            ndct = dict(dct)
            nfields = fields[:]
            if (admode_prefix(
                (dct['mode'], dct['opmode'], dct['admode'])) == 16):
                if 'mod' in dct and dct['mod'] == 0b00 and \
                        'rm' in dct and dct['rm'] == 0b110:
                    nfields[i] = bs(
                        l=16, cls=(x86_16_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue
                elif 'mod' in dct and dct['mod'] == 0b01:
                    nfields[i] = bs(
                        l=8, cls=(x86_08_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue
                elif 'mod' in dct and dct['mod'] == 0b10:
                    nfields[i] = bs(
                        l=16, cls=(x86_16_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue
            else:
                if 'mod' in dct and dct['mod'] == 0b00 and \
                        'rm' in dct and dct['rm'] == 0b101:
                    nfields[i] = bs(
                        l=32, cls=(x86_32_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue
                elif 'mod' in dct and dct['mod'] == 0b01:
                    nfields[i] = bs(
                        l=8, cls=(x86_08_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue
                elif 'mod' in dct and dct['mod'] == 0b10:
                    nfields[i] = bs(
                        l=32, cls=(x86_32_ne,), fname=self.args['fname'])
                    ndct[self.args['fname']] = True
                    out.append((cls, ndct['name'], bases, ndct, nfields))
                    continue

            nfields[i] = None
            ndct[self.args['fname']] = None
            out.append((cls, ndct['name'], bases, ndct, nfields))
        return out


def getmodrm(c):
    return (c >> 6) & 3, (c >> 3) & 7, c & 7


def setmodrm(mod, re, rm):
    return ((mod & 3) << 6) | ((re & 7) << 3) | (rm & 7)


def sib(c):
    return modrm(c)

db_afs_64 = []
sib_64_s08_ebp = []


def gen_modrm_form():
    global db_afs_64, sib_64_s08_ebp
    ebp = 5

    sib_s08_ebp = [{f_isad: True} for i in range(0x100)]
    sib_u32_ebp = [{f_isad: True} for i in range(0x100)]
    sib_u32 = [{f_isad: True} for i in range(0x100)]

    sib_u64 = []
    for rex_x in range(2):
        o = []
        for rex_b in range(2):
            x = [{f_isad: True} for i in range(0x100)]
            o.append(x)
        sib_u64.append(o)

    sib_u64_ebp = []
    for rex_x in range(2):
        o = []
        for rex_b in range(2):
            x = [{f_isad: True} for i in range(0x100)]
            o.append(x)
        sib_u64_ebp.append(o)

    sib_64_s08_ebp = []
    for rex_x in range(2):
        o = []
        for rex_b in range(2):
            x = [{f_isad: True} for i in range(0x100)]
            o.append(x)
        sib_64_s08_ebp.append(o)

    for sib_rez in [sib_s08_ebp,
                    sib_u32_ebp,
                    sib_u32,
                    sib_64_s08_ebp,
                    sib_u64_ebp,
                    sib_u64,
                    ]:
        for index in range(0x100):
            ss, i, b = getmodrm(index)

            if b == 0b101:
                if sib_rez == sib_s08_ebp:
                    sib_rez[index][f_imm] = f_s08
                    sib_rez[index][ebp] = 1
                elif sib_rez == sib_u32_ebp:
                    sib_rez[index][f_imm] = f_u32
                    sib_rez[index][ebp] = 1
                elif sib_rez == sib_u32:
                    sib_rez[index][f_imm] = f_u32
                elif sib_rez == sib_u64_ebp:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                            sib_rez[rex_x][rex_b][index][ebp + 8 * rex_b] = 1
                elif sib_rez == sib_u64:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                elif sib_rez == sib_64_s08_ebp:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_s08
                            sib_rez[rex_x][rex_b][index][ebp + 8 * rex_b] = 1

            else:
                if sib_rez == sib_s08_ebp:
                    sib_rez[index][b] = 1
                    sib_rez[index][f_imm] = f_s08
                elif sib_rez == sib_u32_ebp:
                    sib_rez[index][b] = 1
                    sib_rez[index][f_imm] = f_u32
                elif sib_rez == sib_u32:
                    sib_rez[index][b] = 1
                elif sib_rez == sib_u64_ebp:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][b + 8 * rex_b] = 1
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                elif sib_rez == sib_u64:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][b + 8 * rex_b] = 1
                elif sib_rez == sib_64_s08_ebp:
                    for rex_b in range(2):
                        for rex_x in range(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_s08
                            sib_rez[rex_x][rex_b][index][b + 8 * rex_b] = 1

            if i == 0b100 and sib_rez in [sib_s08_ebp, sib_u32_ebp, sib_u32]:
                continue

            if sib_rez in [sib_s08_ebp, sib_u32_ebp, sib_u32]:
                tmp = i
                if not tmp in sib_rez[index]:
                    sib_rez[index][tmp] = 0  # 1 << ss
                sib_rez[index][tmp] += 1 << ss
            else:
                for rex_b in range(2):
                    for rex_x in range(2):
                        tmp = i + 8 * rex_x
                        if i == 0b100 and rex_x == 0:
                            continue
                        if not tmp in sib_rez[rex_x][rex_b][index]:
                            sib_rez[rex_x][rex_b][index][tmp] = 0  # 1 << ss
                        sib_rez[rex_x][rex_b][index][tmp] += 1 << ss

    # 32bit
    db_afs_32 = [None for i in range(0x100)]
    for i in range(0x100):
        index = i
        mod, re, rm = getmodrm(i)

        if mod == 0b00:
            if rm == 0b100:
                db_afs_32[index] = sib_u32
            elif rm == 0b101:
                db_afs_32[index] = {f_isad: True, f_imm: f_u32}
            else:
                db_afs_32[index] = {f_isad: True, rm: 1}
        elif mod == 0b01:
            if rm == 0b100:
                db_afs_32[index] = sib_s08_ebp
                continue
            tmp = {f_isad: True, rm: 1, f_imm: f_s08}
            db_afs_32[index] = tmp

        elif mod == 0b10:
            if rm == 0b100:
                db_afs_32[index] = sib_u32_ebp
            else:
                db_afs_32[index] = {f_isad: True, rm: 1, f_imm: f_u32}
        elif mod == 0b11:
            db_afs_32[index] = {f_isad: False, rm: 1}

    # 64bit
    db_afs_64 = [None for i in range(0x400)]
    for i in range(0x400):
        index = i
        rex_x = (index >> 9) & 1
        rex_b = (index >> 8) & 1
        mod, re, rm = getmodrm(i & 0xff)

        if mod == 0b00:
            if rm == 0b100:
                db_afs_64[i] = sib_u64[rex_x][rex_b]
            elif rm == 0b101:
                db_afs_64[i] = {f_isad: True, f_imm: f_u32, 16: 1}
            else:
                db_afs_64[i] = {f_isad: True, rm + 8 * rex_b: 1}
        elif mod == 0b01:
            if rm == 0b100:
                db_afs_64[i] = sib_64_s08_ebp[rex_x][rex_b]
                continue
            tmp = {f_isad: True, rm + 8 * rex_b: 1, f_imm: f_s08}
            db_afs_64[i] = tmp

        elif mod == 0b10:
            if rm == 0b100:
                db_afs_64[i] = sib_u64_ebp[rex_x][rex_b]
            else:
                db_afs_64[i] = {f_isad: True, rm + 8 * rex_b: 1, f_imm: f_u32}
        elif mod == 0b11:
            db_afs_64[i] = {f_isad: False, rm + 8 * rex_b: 1}

    # 16bit
    db_afs_16 = [None for i in range(0x100)]
    _si = 6
    _di = 7
    _bx = 3
    _bp = 5
    for i in range(0x100):
        index = i
        mod, re, rm = getmodrm(i)

        if mod == 0b00:
            if rm == 0b100:
                db_afs_16[index] = {f_isad: True, _si: 1}
            elif rm == 0b101:
                db_afs_16[index] = {f_isad: True, _di: 1}
            elif rm == 0b110:
                db_afs_16[index] = {
                    f_isad: True, f_imm: f_u16}  # {f_isad:True,_bp:1}
            elif rm == 0b111:
                db_afs_16[index] = {f_isad: True, _bx: 1}
            else:
                db_afs_16[index] = {f_isad: True,
                         [_si, _di][rm % 2]: 1,
                    [_bx, _bp][(rm >> 1) % 2]: 1}
        elif mod in [0b01, 0b10]:
            if mod == 0b01:
                my_imm = f_s08
            else:
                my_imm = f_u16

            if rm == 0b100:
                db_afs_16[index] = {f_isad: True, _si: 1, f_imm: my_imm}
            elif rm == 0b101:
                db_afs_16[index] = {f_isad: True, _di: 1, f_imm: my_imm}
            elif rm == 0b110:
                db_afs_16[index] = {f_isad: True, _bp: 1, f_imm: my_imm}
            elif rm == 0b111:
                db_afs_16[index] = {f_isad: True, _bx: 1, f_imm: my_imm}
            else:
                db_afs_16[index] = {f_isad: True,
                         [_si, _di][rm % 2]: 1,
                    [_bx, _bp][(rm >> 1) % 2]: 1,
                    f_imm: my_imm}

        elif mod == 0b11:
            db_afs_16[index] = {f_isad: False, rm: 1}

    byte2modrm = {}
    byte2modrm[16] = db_afs_16
    byte2modrm[32] = db_afs_32
    byte2modrm[64] = db_afs_64

    modrm2byte = {16: defaultdict(list),
                  32: defaultdict(list),
                  64: defaultdict(list),
                  }
    for size, db_afs in viewitems(byte2modrm):
        for i, modrm in enumerate(db_afs):
            if not isinstance(modrm, list):
                # We only need sort for determinism
                modrm = tuple(sorted(viewitems(modrm), key=str))
                modrm2byte[size][modrm].append(i)
                continue
            for j, modrm_f in enumerate(modrm):
                # We only need sort for determinism
                modrm_f = tuple(sorted(viewitems(modrm_f), key=str))
                modrm2byte[size][modrm_f].append((i, j))

    return byte2modrm, modrm2byte

byte2modrm, modrm2byte = gen_modrm_form()


# ret is modr; ret is displacement
def exprfindmod(e, o=None):
    if o is None:
        o = {}
    if isinstance(e, ExprInt):
        return e
    if isinstance(e, ExprId):
        i = size2gpregs[e.size].expr.index(e)
        o[i] = 1
        return None
    elif isinstance(e, ExprOp):
        out = None
        if e.op == '+':
            for a in e.args:
                r = exprfindmod(a, o)
                if out and r:
                    raise ValueError('multiple displacement!')
                out = r
            return out
        elif e.op == "*":
            mul = int(e.args[1])
            a = e.args[0]
            i = size2gpregs[a.size].expr.index(a)
            o[i] = mul
        else:
            raise ValueError('bad op')
    return None

def test_addr_size(ptr, size):
    if isinstance(ptr, ExprInt):
        return int(ptr) < (1 << size)
    else:
        return ptr.size == size

SIZE2XMMREG = {64:gpregs_mm,
               128:gpregs_xmm}
SIZE2BNDREG = {64:gpregs_mm,
               128:gpregs_bnd}

def parse_mem(expr, parent, w8, sx=0, xmm=0, mm=0, bnd=0):
    dct_expr = {}
    opmode = parent.v_opmode()
    if is_mem_segm(expr) and expr.ptr.args[0].is_int():
        return None, None, False

    if is_mem_segm(expr):
        segm = expr.ptr.args[0]
        ptr = expr.ptr.args[1]
    else:
        segm = None
        ptr = expr.ptr

    dct_expr[f_isad] = True
    ad_size = ptr.size
    admode = parent.v_admode()
    if not test_addr_size(ptr, admode):
        return None, None, False

    if (w8 == 1 and expr.size != opmode and not sx and
        not (hasattr(parent, 'sd') or hasattr(parent, 'wd'))):
        return None, None, False

    if hasattr(parent, 'wd'):
        if expr.size == 16:
            parent.wd.value = 1
        elif expr.size == 32:
            pass
        else:
            return None, None, False

    if (not isinstance(ptr, ExprInt) and
        parent.mode == 64 and
        ptr.size == 32 and
        parent.admode != 1):
        return None, None, False
    dct_expr = {f_isad: True}
    disp = exprfindmod(ptr, dct_expr)
    out = []
    if disp is None:
        # add 0 disp
        disp = ExprInt(0, 32)
    if disp is not None:
        for signed, encoding, cast_size in [(True, f_s08, 8),
                                           (True, f_s16, 16),
                                           (True, f_s32, 32),
                                           (False, f_u08, 8),
                                           (False, f_u16, 16),
                                           (False, f_u32, 32)]:
            value = ExprInt(int(disp), cast_size)
            if admode < value.size:
                if signed:
                    if int(disp) != sign_ext(int(value), admode, disp.size):
                        continue
                else:
                    if int(disp) != int(value):
                        continue
            else:
                if int(disp) != sign_ext(int(value), value.size, admode):
                    continue
            x1 = dict(dct_expr)
            x1[f_imm] = (encoding, value)
            out.append(x1)
    else:
        out = [dct_expr]
    return out, segm, True

def expr2modrm(expr, parent, w8, sx=0, xmm=0, mm=0, bnd=0):
    dct_expr = {f_isad : False}

    if mm or xmm or bnd:
        if mm and expr.size != 64:
            return None, None, False
        elif xmm and expr.size != 128:
            return None, None, False
        elif bnd and expr.size != 128:
            return None, None, False

        if isinstance(expr, ExprId):
            if bnd:
                size2reg = SIZE2BNDREG
            else:
                size2reg = SIZE2XMMREG
            selreg = size2reg[expr.size]
            if not expr in selreg.expr:
                return None, None, False
            i = selreg.expr.index(expr)
            dct_expr[i] = 1
            return [dct_expr], None, True
        else:
            return parse_mem(expr, parent, w8, sx, xmm, mm)

    elif expr.size == 64 and expr not in gpregs_mm.expr:
        if hasattr(parent, 'sd'):
            parent.sd.value = 1
        elif hasattr(parent, 'wd'):
            pass
        elif hasattr(parent, 'stk'):
            pass
        else:
            parent.rex_w.value = 1
    opmode = parent.v_opmode()
    if sx == 1:
        opmode = 16
    if sx == 2:
        opmode = 32
    if expr.size == 8 and w8 != 0:
        return None, None, False

    if w8 == 0 and expr.size != 8:
        return None, None, False

    if not isinstance(expr, ExprMem):
        dct_expr[f_isad] = False
        if xmm:
            if expr in gpregs_xmm.expr:
                i = gpregs_xmm.expr.index(expr)
                dct_expr[i] = 1
                return [dct_expr], None, True
            else:
                return None, None, False
        if bnd:
            if expr in gpregs_bnd.expr:
                i = gpregs_bnd.expr.index(expr)
                dct_expr[i] = 1
                return [dct_expr], None, True
            else:
                return None, None, False
        if mm:
            if expr in gpregs_mm.expr:
                i = gpregs_mm.expr.index(expr)
                dct_expr[i] = 1
                return [dct_expr], None, True
            else:
                return None, None, False
        if w8 == 0:
            if parent.mode == 64 and expr in gpregs08_64.expr:
                r = gpregs08_64
                parent.rex_p.value = 1
            else:
                parent.rex_p.value = 0
                parent.rex_x.value = 0
                r = size2gpregs[8]
            if not expr in r.expr:
                return None, None, False
            i = r.expr.index(expr)
            dct_expr[i] = 1
            return [dct_expr], None, True
        if opmode != expr.size:
            return None, None, False
        if not expr in size2gpregs[opmode].expr:
            return None, None, False
        i = size2gpregs[opmode].expr.index(expr)
        if i > 7:
            if parent.mode != 64:
                return None, None, False
        dct_expr[i] = 1
        return [dct_expr], None, True
    return parse_mem(expr, parent, w8, sx, xmm, mm, bnd)

def modrm2expr(modrm, parent, w8, sx=0, xmm=0, mm=0, bnd=0):
    o = []
    if not modrm[f_isad]:
        modrm_k = [key for key, value in viewitems(modrm) if value == 1]
        if len(modrm_k) != 1:
            raise ValueError('strange reg encoding %r' % modrm)
        modrm_k = modrm_k[0]
        if w8 == 0:
            opmode = 8
        elif sx == 1:
            opmode = 16
        elif sx == 2:
            opmode = 32
        else:
            opmode = parent.v_opmode()
        if xmm:
            expr = gpregs_xmm.expr[modrm_k]
        elif mm:
            expr = gpregs_mm.expr[modrm_k]
        elif bnd:
            expr = gpregs_bnd.expr[modrm_k]
        elif opmode == 8 and (parent.v_opmode() == 64 or parent.rex_p.value == 1):
            expr = gpregs08_64.expr[modrm_k]
        else:
            expr = size2gpregs[opmode].expr[modrm_k]
        return expr
    admode = parent.v_admode()
    opmode = parent.v_opmode()
    for modrm_k, scale in viewitems(modrm):
        if isinstance(modrm_k, int):
            expr = size2gpregs[admode].expr[modrm_k]
            if scale != 1:
                expr = ExprInt(scale, admode) * expr
            o.append(expr)
    if f_imm in modrm:
        if parent.disp.value is None:
            return None
        o.append(ExprInt(int(parent.disp.expr), admode))
    if len(o) == 1:
        expr = o[0]
    else:
        expr = ExprOp('+', *o)
    if w8 == 0:
        opmode = 8
    elif sx == 1:
        opmode = 16
    elif sx == 2:
        opmode = 32
    if xmm:
        opmode = 128
    elif mm:
        opmode = 64
    elif bnd:
        opmode = 128

    expr = ExprMem(expr, size=opmode)
    return expr


class x86_rm_arg(x86_arg):
    parser = rmarg

    def fromstring(self, text, loc_db, parser_result=None):
        start, stop = super(x86_rm_arg, self).fromstring(text, loc_db, parser_result)
        p = self.parent
        if start is None:
            return None, None
        return start, stop

    def get_modrm(self):
        p = self.parent
        admode = p.v_admode()

        if not admode in [16, 32, 64]:
            raise ValueError('strange admode %r', admode)
        v = setmodrm(p.mod.value, 0, p.rm.value)
        v |= p.rex_b.value << 8
        v |= p.rex_x.value << 9
        if p.mode == 64:
            # XXXx to check
            admode = 64

        xx = byte2modrm[admode][v]
        if isinstance(xx, list):
            if not p.sib_scale:
                return False
            v = setmodrm(p.sib_scale.value,
                         p.sib_index.value,
                         p.sib_base.value)
            xx = xx[v]
        return xx

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        self.expr = modrm2expr(xx, p, 1)
        return self.expr is not None

    def gen_cand(self, v_cand, admode):
        if not admode in modrm2byte:
            # XXX TODO: 64bit
            return
        if not v_cand:
            return

        p = self.parent
        o_rex_x = p.rex_x.value
        o_rex_b = p.rex_b.value
        # add candidate without 0 imm
        new_v_cand = []
        moddd = False
        for v in v_cand:
            new_v_cand.append(v)
            if f_imm in v and int(v[f_imm][1]) == 0:
                v = dict(v)
                del(v[f_imm])
                new_v_cand.append(v)
                moddd = True

        v_cand = new_v_cand

        out_c = []
        for v in v_cand:
            disp = None
            # patch value in modrm
            if f_imm in v:
                size, disp = v[f_imm]
                disp = int(disp)

                v[f_imm] = size
            vo = v
            # We only need sort for determinism
            v = tuple(sorted(viewitems(v), key=str))
            admode = 64 if p.mode == 64 else admode
            if not v in modrm2byte[admode]:
                continue
            xx = modrm2byte[admode][v]

            # default case
            for x in xx:
                if type(x) == tuple:
                    modrm, sib = x
                else:
                    modrm = x
                    sib = None

                # 16 bit cannot have sib
                if sib is not None and admode == 16:
                    continue
                rex = modrm >> 8  # 0# XXX HACK REM temporary REX modrm>>8
                if rex and admode != 64:
                    continue

                p.rex_x.value = (rex >> 1) & 1
                p.rex_b.value = rex & 1

                if o_rex_x is not None and p.rex_x.value != o_rex_x:
                    continue
                if o_rex_b is not None and p.rex_b.value != o_rex_b:
                    continue

                mod, re, rm = getmodrm(modrm)
                # check re on parent
                if re != p.reg.value:
                    continue

                if sib is not None:
                    s_scale, s_index, s_base = getmodrm(sib)
                else:
                    s_scale, s_index, s_base = None, None, None

                p.mod.value = mod
                p.rm.value = rm
                p.sib_scale.value = s_scale
                p.sib_index.value = s_index
                p.sib_base.value = s_base
                p.disp.value = disp
                if disp is not None:
                    p.disp.l = f_imm2size[vo[f_imm]]

                yield True

        return

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        admode = p.v_admode()
        mode = self.expr.size
        v_cand, segm, ok = expr2modrm(self.expr, p, 1)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, admode):
            yield x

class x86_rm_mem(x86_rm_arg):
    def fromstring(self, text, loc_db, parser_result=None):
        self.expr = None
        start, stop = super(x86_rm_mem, self).fromstring(text, loc_db, parser_result)
        if not isinstance(self.expr, ExprMem):
            return None, None
        return start, stop


class x86_rm_mem_far(x86_rm_arg):
    parser = mem_far
    def fromstring(self, text, loc_db, parser_result=None):
        self.expr = None
        start, stop = super(x86_rm_mem_far, self).fromstring(text, loc_db, parser_result)
        if not isinstance(self.expr, ExprMem):
            return None, None
        self.expr = ExprOp('far', self.expr)
        return start, stop

    def decode(self, v):
        ret = super(x86_rm_mem_far, self).decode(v)
        if not ret:
            return ret
        if isinstance(self.expr, m2_expr.ExprMem):
            self.expr = ExprOp('far', self.expr)
        return True

    def encode(self):
        if not (isinstance(self.expr, m2_expr.ExprOp) and
                self.expr.op == 'far'):
            return

        expr = self.expr.args[0]
        if isinstance(expr, ExprInt):
            return
        p = self.parent
        admode = p.v_admode()
        mode = expr.size
        v_cand, segm, ok = expr2modrm(expr, p, 1)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, admode):
            yield x

class x86_rm_w8(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        self.expr = modrm2expr(xx, p, p.w8.value)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        if p.w8.value is None:
            if self.expr.size == 8:
                p.w8.value = 0
            else:
                p.w8.value = 1

        v_cand, segm, ok = expr2modrm(self.expr, p, p.w8.value)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_sx(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        self.expr = modrm2expr(xx, p, p.w8.value, 1)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        if p.w8.value is None:
            if self.expr.size == 8:
                p.w8.value = 0
            else:
                p.w8.value = 1
        v_cand, segm, ok = expr2modrm(self.expr, p, p.w8.value, 1)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_sxd(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        self.expr = modrm2expr(xx, p, 1, 2)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        v_cand, segm, ok = expr2modrm(self.expr, p, 1, 2)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_sd(x86_rm_arg):
    out_size = 64
    def get_s_value(self):
        return self.parent.sd.value
    def set_s_value(self, value):
        self.parent.sd.value = value

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        expr = modrm2expr(xx, p, 1)
        if not isinstance(expr, ExprMem):
            return False
        if self.get_s_value() == 0:
            expr = ExprMem(expr.ptr, 32)
        else:
            expr = ExprMem(expr.ptr, self.out_size)
        self.expr = expr
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        if not self.expr.size in [32, 64]:
            return
        self.set_s_value(0)
        v_cand, segm, ok = expr2modrm(self.expr, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_wd(x86_rm_sd):
    out_size = 16
    def get_s_value(self):
        return self.parent.wd.value
    def set_s_value(self, value):
        self.parent.wd.value = value

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        p.wd.value = 0
        v_cand, segm, ok = expr2modrm(self.expr, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_08(x86_rm_arg):
    msize = 8

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        expr = modrm2expr(xx, p, 0)
        if not isinstance(expr, ExprMem):
            self.expr = expr
            return True
        self.expr = ExprMem(expr.ptr, self.msize)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        v_cand, segm, ok = expr2modrm(self.expr, p, 0, 0, 0, 0)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x

class x86_rm_reg_m08(x86_rm_arg):
    msize = 8

    def decode(self, v):
        ret = x86_rm_arg.decode(self, v)
        if not ret:
            return ret
        if not isinstance(self.expr, ExprMem):
            return True
        self.expr = ExprMem(self.expr.ptr, self.msize)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        if isinstance(self.expr, ExprMem):
            expr = ExprMem(self.expr.ptr, 32)
        else:
            expr = self.expr
        v_cand, segm, ok = expr2modrm(expr, p, 1, 0, 0, 0)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x

class x86_rm_reg_m16(x86_rm_reg_m08):
    msize = 16

class x86_rm_m64(x86_rm_arg):
    msize = 64

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        expr = modrm2expr(xx, p, 1)
        if not isinstance(expr, ExprMem):
            return False
        self.expr = ExprMem(expr.ptr, self.msize)
        return self.expr is not None

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        p = self.parent
        v_cand, segm, ok = expr2modrm(self.expr, p, 0, 0, 0, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m80(x86_rm_m64):
    msize = 80

    def encode(self):
        if isinstance(self.expr, ExprInt):
            return
        if not isinstance(self.expr, ExprMem) or self.expr.size != self.msize:
            return
        p = self.parent
        mode = p.mode
        if mode == 64:
            mode = 32
        self.expr = ExprMem(self.expr.ptr, mode)
        v_cand, segm, ok = expr2modrm(self.expr, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m08(x86_rm_arg):
    msize = 8

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        self.expr = modrm2expr(xx, p, 0)
        return self.expr is not None

    def encode(self):
        if self.expr.size != 8:
            return
        p = self.parent
        mode = p.mode
        v_cand, segm, ok = expr2modrm(self.expr, p, 0)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m16(x86_rm_m80):
    msize = 16


class x86_rm_mm(x86_rm_m80):
    msize = 64
    is_mm = True
    is_xmm = False
    is_bnd = False

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        expr = modrm2expr(xx, p, 0, 0, self.is_xmm, self.is_mm, self.is_bnd)
        if isinstance(expr, ExprMem):
            if self.msize is None:
                return False
            if expr.size != self.msize:
                expr = ExprMem(expr.ptr, self.msize)
        self.expr = expr
        return True


    def encode(self):
        expr = self.expr
        if isinstance(expr, ExprInt):
            return
        if isinstance(expr, ExprMem) and expr.size != self.msize:
            return
        p = self.parent
        mode = p.mode
        if mode == 64:
            mode = 32
        if isinstance(expr, ExprMem):
            if self.is_xmm:
                expr = ExprMem(expr.ptr, 128)
            elif self.is_mm:
                expr = ExprMem(expr.ptr, 64)

        v_cand, segm, ok = expr2modrm(expr, p, 0, 0, self.is_xmm, self.is_mm,
                                      self.is_bnd)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_mm_m64(x86_rm_mm):
    msize = 64
    is_mm = True
    is_xmm = False

class x86_rm_xmm(x86_rm_mm):
    msize = 128
    is_mm = False
    is_xmm = True


class x86_rm_xmm_m32(x86_rm_mm):
    msize = 32
    is_mm = False
    is_xmm = True

class x86_rm_xmm_m64(x86_rm_mm):
    msize = 64
    is_mm = False
    is_xmm = True

class x86_rm_xmm_m128(x86_rm_mm):
    msize = 128
    is_mm = False
    is_xmm = True


class x86_rm_xmm_reg(x86_rm_mm):
    msize = None
    is_mm = False
    is_xmm = True

class x86_rm_mm_reg(x86_rm_mm):
    msize = None
    is_mm = True
    is_xmm = False


class x86_rm_bnd(x86_rm_mm):
    msize = 128
    is_mm = False
    is_xmm = False
    is_bnd = True


class x86_rm_bnd_reg(x86_rm_mm):
    msize = None
    is_mm = False
    is_xmm = False
    is_bnd = True


class x86_rm_bnd_m64(x86_rm_mm):
    msize = 64
    is_mm = False
    is_xmm = False
    is_bnd = True


class x86_rm_bnd_m128(x86_rm_mm):
    msize = 128
    is_mm = False
    is_xmm = False
    is_bnd = True


class x86_rm_reg_noarg(object):
    prio = default_prio + 1

    parser = gpreg

    def fromstring(self, text, loc_db, parser_result=None):
        if not hasattr(self.parent, 'sx') and hasattr(self.parent, "w8"):
            self.parent.w8.value = 1
        if parser_result:
            result, start, stop = parser_result[self.parser]
            if result == [None]:
                return None, None
            self.expr = result
            if self.expr.size == 8:
                if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                    return None, None
                self.parent.w8.value = 0
            return start, stop
        try:
            result, start, stop = next(self.parser.scanString(text))
        except StopIteration:
            return None, None
        expr = self.asm_ast_to_expr(result[0], loc_db)
        if expr is None:
            return None, None

        self.expr = expr
        if self.expr.size == 0:
            if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                return None, None
            self.parent.w8.value = 0

        return start, stop

    def getrexsize(self):
        return self.parent.rex_r.value

    def setrexsize(self, v):
        self.parent.rex_r.value = v

    def decode(self, v):
        v = v & self.lmask
        p = self.parent
        opmode = p.v_opmode()
        if not hasattr(p, 'sx') and (hasattr(p, 'w8') and p.w8.value == 0):
            opmode = 8
        r = size2gpregs[opmode]
        if p.mode == 64 and self.getrexsize():
            v |= 0x8
        if p.v_opmode() == 64 or p.rex_p.value == 1:
            if not hasattr(p, 'sx') and (hasattr(p, 'w8') and p.w8.value == 0):
                r = gpregs08_64
            elif p.rex_r.value == 1:
                v |= 8
        self.expr = r.expr[v]
        return True

    def encode(self):
        if not isinstance(self.expr, ExprId):
            return False
        if self.expr in gpregs64.expr and not hasattr(self.parent, 'stk'):
            self.parent.rex_w.value = 1
        opmode = self.parent.v_opmode()
        if not hasattr(self.parent, 'sx') and hasattr(self.parent, 'w8'):
            self.parent.w8.value = 1
        if self.expr.size == 8:
            if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                return False
            self.parent.w8.value = 0
            opmode = 8
        r = size2gpregs[opmode]
        if self.expr in r.expr:
            i = r.expr.index(self.expr)
        elif (opmode == 8 and self.parent.mode == 64 and
            self.expr in gpregs08_64.expr):
            i = gpregs08_64.expr.index(self.expr)
            self.parent.rex_p.value = 1
        else:
            log.debug("cannot encode reg %r", self.expr)
            return False
        if self.parent.v_opmode() == 64:
            if i > 7:
                self.setrexsize(1)
                i -= 8
        elif self.parent.mode == 64 and i > 7:
            i -= 8
            self.setrexsize(1)
        self.value = i
        return True


class x86_rm_reg_mm(x86_rm_reg_noarg, x86_arg):
    selreg = gpregs_mm
    def decode(self, v):
        if self.parent.mode == 64 and self.getrexsize():
            v |= 0x8
        self.expr = self.selreg.expr[v]
        return True

    def encode(self):
        if not isinstance(self.expr, ExprId):
            return False
        if self.expr not in self.selreg.expr:
            return False
        i = self.selreg.expr.index(self.expr)
        if self.parent.mode == 64 and i > 7:
            i -= 8
            self.setrexsize(1)
        self.value = i
        return True

class x86_rm_reg_xmm(x86_rm_reg_mm):
    selreg = gpregs_xmm

class x86_rm_reg_bnd(x86_rm_reg_mm):
    selreg = gpregs_bnd

class x86_rm_reg(x86_rm_reg_noarg, x86_arg):
    pass


class x86_reg(x86_rm_reg):

    def getrexsize(self):
        return self.parent.rex_b.value

    def setrexsize(self, v):
        self.parent.rex_b.value = v


class x86_reg_modrm(x86_rm_reg):

    def getrexsize(self):
        return self.parent.rex_r.value

    def setrexsize(self, v):
        self.parent.rex_r.value = v



class x86_reg_noarg(x86_rm_reg_noarg):

    def getrexsize(self):
        return self.parent.rex_b.value

    def setrexsize(self, v):
        self.parent.rex_b.value = v


class x86_rm_segm(reg_noarg, x86_arg):
    prio = default_prio + 1
    reg_info = segmreg
    parser = reg_info.parser


class x86_rm_cr(reg_noarg, x86_arg):
    prio = default_prio + 1
    reg_info = crregs
    parser = reg_info.parser


class x86_rm_dr(reg_noarg, x86_arg):
    prio = default_prio + 1
    reg_info = drregs
    parser = reg_info.parser


class x86_rm_flt(reg_noarg, x86_arg):
    prio = default_prio + 1
    reg_info = fltregs
    parser = reg_info.parser


class bs_fbit(bsi):

    def decode(self, v):
        # value already decoded in pre_dis_info
        return True


class bs_cl1(bsi, x86_arg):
    parser = cl_or_imm

    def decode(self, v):
        if v == 1:
            self.expr = regs08_expr[1]
        else:
            self.expr = ExprInt(1, 8)
        return True

    def encode(self):
        if self.expr == regs08_expr[1]:
            self.value = 1
        elif isinstance(self.expr, ExprInt) and int(self.expr) == 1:
            self.value = 0
        else:
            return False
        return True


def sib_cond(cls, mode, v):
    if admode_prefix((mode, v["opmode"], v["admode"])) == 16:
        return None
    if v['mod'] == 0b11:
        return None
    elif v['rm'] == 0b100:
        return cls.ll
    else:
        return None
    return v['rm'] == 0b100


class bs_cond_scale(bs_cond):
    # cond must return field len
    ll = 2

    @classmethod
    def flen(cls, mode, v):
        return sib_cond(cls, mode, v)

    def encode(self):
        if self.value is None:
            self.value = 0
            self.l = 0
            return True
        return super(bs_cond_scale, self).encode()

    def decode(self, v):
        self.value = v
        return True


class bs_cond_index(bs_cond_scale):
    ll = 3

    @classmethod
    def flen(cls, mode, v):
        return sib_cond(cls, mode, v)


class bs_cond_disp(bs_cond):
    # cond must return field len

    @classmethod
    def flen(cls, mode, v):
        if admode_prefix((mode, v['opmode'], v['admode'])) == 16:
            if v['mod'] == 0b00:
                if v['rm'] == 0b110:
                    return 16
                else:
                    return None
            elif v['mod'] == 0b01:
                return 8
            elif v['mod'] == 0b10:
                return 16
            return None
        # 32, 64
        if 'sib_base' in v and v['sib_base'] == 0b101:
            if v['mod'] == 0b00:
                return 32
            elif v['mod'] == 0b01:
                return 8
            elif v['mod'] == 0b10:
                return 32
            else:
                return None

        if v['mod'] == 0b00:
            if v['rm'] == 0b101:
                return 32
            else:
                return None
        elif v['mod'] == 0b01:
            return 8
        elif v['mod'] == 0b10:
            return 32
        else:
            return None

    def encode(self):
        if self.value is None:
            self.value = 0
            self.l = 0
            return True
        self.value = swap_uint(self.l, self.value)
        return True

    def decode(self, v):
        admode = self.parent.v_admode()
        v = swap_uint(self.l, v)
        self.value = v
        v = sign_ext(v, self.l, admode)
        v = ExprInt(v, admode)
        self.expr = v
        return True


class bs_cond_imm(bs_cond_scale, x86_arg):
    parser = base_expr
    max_size = 32

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            expr, start, stop = parser_result[self.parser]
        else:
            try:
                expr, start, stop = next(self.parser.scanString(text))
            except StopIteration:
                expr = None
        self.expr = expr

        if len(self.parent.args) > 1:
            l = self.parent.args[0].expr.size
        else:
            l = self.parent.v_opmode()
        if isinstance(self.expr, ExprInt):
            v = int(self.expr)
            mask = ((1 << l) - 1)
            self.expr = ExprInt(v & mask, l)

        if self.expr is None:
            log.debug('cannot fromstring int %r', text)
            return None, None
        return start, stop

    @classmethod
    def flen(cls, mode, v):
        if 'w8' not in v or v['w8'] == 1:
            if 'se' in v and v['se'] == 1:
                return 8
            else:
                osize = v_opmode_info(mode, v['opmode'], v['rex_w'], 0)
                osize = min(osize, cls.max_size)
                return osize
        return 8

    def getmaxlen(self):
        return 32

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return
        arg0_expr = self.parent.args[0].expr
        self.parent.rex_w.value = 0
        # special case for push
        if len(self.parent.args) == 1:
            v = int(self.expr)
            l = self.parent.v_opmode()
            l = min(l, self.max_size)

            self.l = l
            mask = ((1 << self.l) - 1)
            if v != sign_ext(v & mask, self.l, l):
                return
            self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
            yield True
            return

        # assume 2 args; use first arg to guess op size
        if arg0_expr.size == 64:
            self.parent.rex_w.value = 1

        l = self.parent.v_opmode()
        v = int(self.expr)
        if arg0_expr.size == 8:
            if not hasattr(self.parent, 'w8'):
                return
            self.parent.w8.value = 0
            l = 8
            if hasattr(self.parent, 'se'):
                self.parent.se.value = 0
        elif hasattr(self.parent, 'se'):
            if hasattr(self.parent, 'w8'):
                self.parent.w8.value = 1
            # try to generate signed extended version
            if v == sign_ext(v & 0xFF, 8, arg0_expr.size):
                self.parent.se.value = 1
                self.l = 8
                self.value = v & 0xFF
                yield True
            self.parent.se.value = 0
        else:
            if hasattr(self.parent, 'w8'):
                self.parent.w8.value = 1
        if l == 64:
            self.l = self.getmaxlen()
        else:
            self.l = l

        mask = ((1 << self.l) - 1)
        if v != sign_ext(v & mask, self.l, l):
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        v = swap_uint(self.l, v)
        self.value = v
        l_out = opmode
        if hasattr(self.parent, 'w8') and self.parent.w8.value == 0:
            l_out = 8
        v = sign_ext(v, self.l, l_out)
        self.expr = ExprInt(v, l_out)
        return True


class bs_cond_imm64(bs_cond_imm):
    max_size = 64

    def getmaxlen(self):
        return 64

    @classmethod
    def flen(cls, mode, v):
        if 'w8' not in v or v['w8'] == 1:
            if 'se' in v and v['se'] == 1:
                return 8
            else:
                osize = v_opmode_info(mode, v['opmode'], v['rex_w'], 0)
                return osize
        else:
            return 8


class bs_rel_off(bs_cond_imm):
    parser = base_expr

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            expr, start, stop = parser_result[self.parser]
        else:
            try:
                expr, start, stop = next(self.parser.scanString(text))
            except StopIteration:
                expr = None
        self.expr = expr
        l = self.parent.mode
        if isinstance(self.expr, ExprInt):
            v = int(self.expr)
            mask = ((1 << l) - 1)
            self.expr = ExprInt(v & mask, l)
        return start, stop

    @classmethod
    def flen(cls, mode, v):
        osize = v_opmode_info(mode, v['opmode'], v['rex_w'], 0)
        if osize == 16:
            return 16
        else:
            return 32

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return
        arg0_expr = self.parent.args[0].expr
        if self.l == 0:
            l = self.parent.v_opmode()
            self.l = l
        l = offsize(self.parent)
        prefix = self.parent.gen_prefix()
        parent_len = len(prefix) * 8 + self.parent.l + self.l
        assert(parent_len % 8 == 0)

        v = int(self.expr) - parent_len // 8
        if prefix is None:
            return
        mask = ((1 << self.l) - 1)
        if self.l > l:
            return
        if v != sign_ext(v & mask, self.l, l):
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        v = swap_uint(self.l, v)
        size = offsize(self.parent)
        v = sign_ext(v, self.l, size)
        v += self.parent.l
        self.expr = ExprInt(v, size)
        return True

class bs_s08(bs_rel_off):
    parser = base_expr

    @classmethod
    def flen(cls, mode, v):
        return 8

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return
        arg0_expr = self.parent.args[0].expr
        if self.l != 0:
            l = self.l
        else:
            l = self.parent.v_opmode()
            self.l = l
        l = offsize(self.parent)
        v = int(self.expr)
        mask = ((1 << self.l) - 1)
        if self.l > l:
            return
        if v != sign_ext(v & mask, self.l, l):
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        v = swap_uint(self.l, v)
        size = offsize(self.parent)
        v = sign_ext(v, self.l, size)
        self.expr = ExprInt(v, size)
        return True


class bs_rel_off08(bs_rel_off):

    @classmethod
    def flen(cls, mode, v):
        return 8


class bs_moff(bsi):

    @classmethod
    def flen(cls, mode, v):
        osize = v_opmode_info(mode, v['opmode'], v['rex_w'], 0)
        if osize == 16:
            return 16
        else:
            return 32

    def encode(self):
        if not hasattr(self.parent, "mseg"):
            return
        m = self.parent.mseg.expr
        if not (isinstance(m, ExprOp) and m.op == 'segm'):
            return
        if not isinstance(m.args[1], ExprInt):
            return
        l = self.parent.v_opmode()
        if l == 16:
            self.l = 16
        else:
            self.l = 32
        v = int(m.args[1])
        mask = ((1 << self.l) - 1)
        if v != sign_ext(v & mask, self.l, l):
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        if opmode == 64:
            return False
        v = swap_uint(self.l, v)
        self.value = v
        v = sign_ext(v, self.l, opmode)
        self.expr = ExprInt(v, opmode)
        return True


class bs_movoff(x86_arg):
    parser = deref_mem

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            if e is None:
                return None, None
            if not isinstance(e, ExprMem):
                return None, None
            self.expr = e
            if self.expr is None:
                return None, None
            return start, stop
        try:
            v, start, stop = next(self.parser.scanString(text))
        except StopIteration:
            return None, None
        if not isinstance(e, ExprMem):
            return None, None
        self.expr = v[0]
        if self.expr is None:
            log.debug('cannot fromstring int %r', text)
            return None, None
        return start, stop

    @classmethod
    def flen(cls, mode, v):
        if mode == 64:
            if v['admode']:
                return 32
            else:
                return 64
        asize = v_admode_info(mode, v['admode'])
        return asize

    def encode(self):
        p = self.parent
        if not isinstance(self.expr, ExprMem) or not isinstance(self.expr.ptr, ExprInt):
            return
        self.l = p.v_admode()
        v = int(self.expr.ptr)
        mask = ((1 << self.l) - 1)
        if v != mask & v:
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        if self.parent.mode == 64:
            if self.parent.admode == 1:
                l = 32
            else:
                l = 64
        else:
            l = self.parent.v_admode()
        v = swap_uint(self.l, v)
        self.value = v
        v = sign_ext(v, self.l, l)
        v = ExprInt(v, l)
        size = self.parent.v_opmode()
        if self.parent.w8.value == 0:
            size = 8
        self.expr = ExprMem(v, size)
        return True


class bs_msegoff(x86_arg):
    parser = deref_ptr

    def fromstring(self, text, loc_db, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            if e is None:
                return None, None
            self.expr = e
            if self.expr is None:
                return None, None
            return start, stop
        try:
            v, start, stop = next(self.parser.scanString(text))
        except StopIteration:
            return None, None
        self.expr = v[0]
        if self.expr is None:
            log.debug('cannot fromstring int %r', text)
            return None, None
        return start, stop

    def encode(self):
        if not (isinstance(self.expr, ExprOp) and self.expr.op == 'segm'):
            return
        if not isinstance(self.expr.args[0], ExprInt):
            return
        if not isinstance(self.expr.args[1], ExprInt):
            return
        l = self.parent.v_opmode()
        v = int(self.expr.args[0])
        mask = ((1 << self.l) - 1)
        if v != sign_ext(v & mask, self.l, l):
            return
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        v = swap_uint(self.l, v)
        self.value = v
        v = ExprInt(v, 16)
        self.expr = ExprOp('segm', v, self.parent.off.expr)
        return True


d_rex_p = bs(l=0, cls=(bs_fbit,), fname="rex_p")
d_rex_w = bs(l=0, cls=(bs_fbit,), fname="rex_w")
d_rex_r = bs(l=0, cls=(bs_fbit,), fname="rex_r")
d_rex_x = bs(l=0, cls=(bs_fbit,), fname="rex_x")
d_rex_b = bs(l=0, cls=(bs_fbit,), fname="rex_b")

d_g1 = bs(l=0, cls=(bs_fbit,), fname="g1")
d_g2 = bs(l=0, cls=(bs_fbit,), fname="g2")


d_cl1 = bs(l=1, cls=(bs_cl1,), fname="cl1")


w8 = bs(l=1, fname="w8")
se = bs(l=1, fname="se")

sx = bs(l=0, fname="sx")
sxd = bs(l=0, fname="sx")


xmmreg = bs(l=0, fname="xmmreg")
mmreg = bs(l=0, fname="mmreg")

pref_f2 = bs(l=0, fname="prefixed", default=b"\xf2")
pref_f3 = bs(l=0, fname="prefixed", default=b"\xf3")
pref_66 = bs(l=0, fname="prefixed", default=b"\x66")
no_xmm_pref = bs(l=0, fname="no_xmm_pref")

no_rex = bs(l=0, fname="no_rex")

sib_scale = bs(l=2, cls=(bs_cond_scale,), fname = "sib_scale")
sib_index = bs(l=3, cls=(bs_cond_index,), fname = "sib_index")
sib_base = bs(l=3, cls=(bs_cond_index,), fname = "sib_base")

disp = bs(l=0, cls=(bs_cond_disp,), fname = "disp")

s08 = bs(l=8, cls=(bs_s08, ))

u08 = bs(l=8, cls=(x86_08, x86_arg))
u07 = bs(l=7, cls=(x86_08, x86_arg))
u16 = bs(l=16, cls=(x86_16, x86_arg))
u32 = bs(l=32, cls=(x86_32, x86_arg))
s3264 = bs(l=32, cls=(x86_s32to64, x86_arg))

u08_3 = bs(l=0, cls=(x86_imm_fix_08, x86_arg), ival = 3)

d0 = bs("000", fname='reg')
d1 = bs("001", fname='reg')
d2 = bs("010", fname='reg')
d3 = bs("011", fname='reg')
d4 = bs("100", fname='reg')
d5 = bs("101", fname='reg')
d6 = bs("110", fname='reg')
d7 = bs("111", fname='reg')

sd = bs(l=1, fname="sd")
wd = bs(l=1, fname="wd")

stk = bs(l=0, fname="stk")


class field_size(object):
    prio = default_prio

    def __init__(self, d=None):
        if d is None:
            d = {}
        self.d = d

    def get(self, opm, adm=None):
        return self.d[opm]

class bs_mem(object):
    def encode(self):
        return self.value != 0b11

    def decode(self, v):
        self.value = v
        return v != 0b11

class bs_reg(object):
    def encode(self):
        return self.value == 0b11

    def decode(self, v):
        self.value = v
        return v == 0b11

d_imm64 = bs(l=0, fname="imm64")

d_eax = bs(l=0, cls=(bs_eax, ), fname='eax')
d_edx = bs(l=0, cls=(bs_edx, ), fname='edx')
d_st = bs(l=0, cls=(x86_reg_st, ), fname='st')
d_imm = bs(l=0, cls=(bs_cond_imm,), fname="imm")
d_imm64 = bs(l=0, cls=(bs_cond_imm64,), fname="imm")
d_ax = bs(l=0, cls=(r_ax, ), fname='ax')
d_dx = bs(l=0, cls=(r_dx, ), fname='dx')
d_cl = bs(l=0, cls=(r_cl, ), fname='cl')

d_cs = bs(l=0, cls=(bs_cs, ), fname='cs')
d_ds = bs(l=0, cls=(bs_ds, ), fname='ds')
d_es = bs(l=0, cls=(bs_es, ), fname='es')
d_ss = bs(l=0, cls=(bs_ss, ), fname='ss')
d_fs = bs(l=0, cls=(bs_fs, ), fname='fs')
d_gs = bs(l=0, cls=(bs_gs, ), fname='gs')

# Offset must be decoded in last position to have final instruction len
rel_off = bs(l=0, cls=(bs_rel_off,), fname="off", order=-1)
# Offset must be decoded in last position to have final instruction len
rel_off08 = bs(l=8, cls=(bs_rel_off08,), fname="off", order=-1)
moff = bs(l=0, cls=(bs_moff,), fname="off")
msegoff = bs(l=16, cls=(bs_msegoff,), fname="mseg")
movoff = bs(l=0, cls=(bs_movoff,), fname="off")
mod = bs(l=2, fname="mod")
mod_mem = bs(l=2, cls=(bs_mem,), fname="mod")
mod_reg = bs(l=2, cls=(bs_reg,), fname="mod")

rmreg = bs(l=3, cls=(x86_rm_reg, ), order =1, fname = "reg")
reg = bs(l=3, cls=(x86_reg, ), order =1, fname = "reg")

reg_modrm = bs(l=3, cls=(x86_reg_modrm, ), order =1, fname = "reg")


regnoarg = bs(l=3, default_val="000", order=1, fname="reg")
segm = bs(l=3, cls=(x86_rm_segm, ), order =1, fname = "reg")
crreg = bs(l=3, cls=(x86_rm_cr, ), order =1, fname = "reg")
drreg = bs(l=3, cls=(x86_rm_dr, ), order =1, fname = "reg")


mm_reg = bs(l=3, cls=(x86_rm_reg_mm, ), order =1, fname = "reg")
xmm_reg = bs(l=3, cls=(x86_rm_reg_xmm, ), order =1, fname = "reg")
bnd_reg = bs(l=3, cls=(x86_rm_reg_bnd, ), order =1, fname = "reg")


fltreg = bs(l=3, cls=(x86_rm_flt, ), order =1, fname = "reg")

rm = bs(l=3, fname="rm")

rm_arg = bs(l=0, cls=(x86_rm_arg,), fname='rmarg')
rm_arg_w8 = bs(l=0, cls=(x86_rm_w8,), fname='rmarg')
rm_arg_sx = bs(l=0, cls=(x86_rm_sx,), fname='rmarg')
rm_arg_sxd = bs(l=0, cls=(x86_rm_sxd,), fname='rmarg')
rm_arg_sd = bs(l=0, cls=(x86_rm_sd,), fname='rmarg')
rm_arg_wd = bs(l=0, cls=(x86_rm_wd,), fname='rmarg')
rm_arg_08 = bs(l=0, cls=(x86_rm_08,), fname='rmarg')
rm_arg_reg_m08 = bs(l=0, cls=(x86_rm_reg_m08,), fname='rmarg')
rm_arg_reg_m16 = bs(l=0, cls=(x86_rm_reg_m16,), fname='rmarg')
rm_arg_m08 = bs(l=0, cls=(x86_rm_m08,), fname='rmarg')
rm_arg_m64 = bs(l=0, cls=(x86_rm_m64,), fname='rmarg')
rm_arg_m80 = bs(l=0, cls=(x86_rm_m80,), fname='rmarg')
rm_arg_m16 = bs(l=0, cls=(x86_rm_m16,), fname='rmarg')

rm_mem = bs(l=0, cls=(x86_rm_mem,), fname='rmarg')
rm_mem_far = bs(l=0, cls=(x86_rm_mem_far,), fname='rmarg')

rm_arg_mm = bs(l=0, cls=(x86_rm_mm,), fname='rmarg')
rm_arg_mm_m64 = bs(l=0, cls=(x86_rm_mm_m64,), fname='rmarg')
rm_arg_mm_reg = bs(l=0, cls=(x86_rm_mm_reg,), fname='rmarg')

rm_arg_xmm = bs(l=0, cls=(x86_rm_xmm,), fname='rmarg')
rm_arg_xmm_m32 = bs(l=0, cls=(x86_rm_xmm_m32,), fname='rmarg')
rm_arg_xmm_m64 = bs(l=0, cls=(x86_rm_xmm_m64,), fname='rmarg')
rm_arg_xmm_m128 = bs(l=0, cls=(x86_rm_xmm_m128,), fname='rmarg')
rm_arg_xmm_reg = bs(l=0, cls=(x86_rm_xmm_reg,), fname='rmarg')

rm_arg_bnd = bs(l=0, cls=(x86_rm_bnd,), fname='rmarg')
rm_arg_bnd_m64 = bs(l=0, cls=(x86_rm_bnd_m64,), fname='rmarg')
rm_arg_bnd_m128 = bs(l=0, cls=(x86_rm_bnd_m128,), fname='rmarg')
rm_arg_bnd_reg = bs(l=0, cls=(x86_rm_bnd_reg,), fname='rmarg')


swapargs = bs_swapargs(l=1, fname="swap", mn_mod=list(range(1 << 1)))


class bs_op_mode(bsi):

    def decode(self, v):
        opmode = self.parent.v_opmode()
        return opmode == self.mode


class bs_ad_mode(bsi):

    def decode(self, v):
        admode = self.parent.v_admode()
        return admode == self.mode


class bs_op_mode_no64(bsi):

    def encode(self):
        if self.parent.mode == 64:
            return False
        return super(bs_op_mode_no64, self).encode()

    def decode(self, v):
        if self.parent.mode == 64:
            return False
        opmode = self.parent.v_opmode()
        return opmode == self.mode


class bs_op_mode64(bsi):
    def encode(self):
        if self.parent.mode != 64:
            return False
        return super(bs_op_mode64, self).encode()

    def decode(self, v):
        if self.parent.mode != 64:
            return False
        return True

class bs_op_modeno64(bsi):
    def encode(self):
        if self.parent.mode == 64:
            return False
        return super(bs_op_modeno64, self).encode()

    def decode(self, v):
        if self.parent.mode == 64:
            return False
        return True



bs_opmode16 = bs(l=0, cls=(bs_op_mode,), mode = 16, fname="fopmode")
bs_opmode32 = bs(l=0, cls=(bs_op_mode,), mode = 32, fname="fopmode")
bs_opmode64 = bs(l=0, cls=(bs_op_mode,), mode = 64, fname="fopmode")


bs_admode16 = bs(l=0, cls=(bs_ad_mode,), mode = 16, fname="fadmode")
bs_admode32 = bs(l=0, cls=(bs_ad_mode,), mode = 32, fname="fadmode")
bs_admode64 = bs(l=0, cls=(bs_ad_mode,), mode = 64, fname="fadmode")

bs_opmode16_no64 = bs(l=0, cls=(bs_op_mode_no64,), mode = 16, fname="fopmode")
bs_opmode32_no64 = bs(l=0, cls=(bs_op_mode_no64,), mode = 32, fname="fopmode")

bs_mode64 = bs(l=0, cls=(bs_op_mode64,))
bs_modeno64 = bs(l=0, cls=(bs_op_modeno64,))


cond_list = ["O", "NO", "B", "AE",
             "Z", "NZ", "BE", "A",
             "S", "NS", "PE", "NP",
             #"L", "NL", "NG", "G"]
             "L", "GE", "LE", "G"]
cond = bs_mod_name(l=4, fname='cond', mn_mod=cond_list)


def rmmod(r, rm_arg_x=rm_arg, modrm=mod):
    return [modrm, r, rm, sib_scale, sib_index, sib_base, disp, rm_arg_x]

#
# mode | reg | rm #
#

#
# scale | index | base #
#

#
# Prefix | REX prefix | Opcode | mod/rm | sib | displacement | immediate #
#


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_x86,), dct)
"""
class ia32_aaa(mn_x86):
    fields = [bs8(0x37)]
"""
addop("aaa", [bs8(0x37)])
addop("aas", [bs8(0x3F)])
addop("aad", [bs8(0xd5), u08])
addop("aam", [bs8(0xd4), u08])

addop("adc", [bs("0001010"), w8, d_eax, d_imm])
addop("adc", [bs("100000"), se, w8] + rmmod(d2, rm_arg_w8) + [d_imm])
addop("adc", [bs("000100"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("add", [bs("0000010"), w8, d_eax, d_imm])
addop("add", [bs("100000"), se, w8] + rmmod(d0, rm_arg_w8) + [d_imm])
addop("add", [bs("000000"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("and", [bs("0010010"), w8, d_eax, d_imm])
addop("and", [bs("100000"), se, w8] + rmmod(d4, rm_arg_w8) + [d_imm])
addop("and", [bs("001000"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("bndmov", [bs8(0x0f), bs8(0x1a), pref_66, bs_modeno64] +
      rmmod(bnd_reg, rm_arg_bnd_m64), [bnd_reg, rm_arg_bnd_m64])
addop("bndmov", [bs8(0x0f), bs8(0x1a), pref_66, bs_mode64] +
      rmmod(bnd_reg, rm_arg_bnd_m128), [bnd_reg, rm_arg_bnd_m128])
addop("bndmov", [bs8(0x0f), bs8(0x1b), pref_66, bs_modeno64] +
      rmmod(bnd_reg, rm_arg_bnd_m64), [rm_arg_bnd_m64, bnd_reg])
addop("bndmov", [bs8(0x0f), bs8(0x1b), pref_66, bs_mode64] +
      rmmod(bnd_reg, rm_arg_bnd_m128), [rm_arg_bnd_m128, bnd_reg])



addop("bsf", [bs8(0x0f), bs8(0xbc)] + rmmod(rmreg))
addop("bsr", [bs8(0x0f), bs8(0xbd), mod,
    rmreg, rm, sib_scale, sib_index, sib_base, disp, rm_arg])

addop("bswap", [bs8(0x0f), bs('11001'), reg])

addop("bt", [bs8(0x0f), bs8(0xa3)] + rmmod(rmreg), [rm_arg, rmreg])
addop("bt", [bs8(0x0f), bs8(0xba)] + rmmod(d4) + [u08])
addop("btc", [bs8(0x0f), bs8(0xbb)] + rmmod(rmreg), [rm_arg, rmreg])
addop("btc", [bs8(0x0f), bs8(0xba)] + rmmod(d7) + [u08])


addop("btr", [bs8(0x0f), bs8(0xb3)] + rmmod(rmreg), [rm_arg, rmreg])
addop("btr", [bs8(0x0f), bs8(0xba)] + rmmod(d6) + [u08])
addop("bts", [bs8(0x0f), bs8(0xab)] + rmmod(rmreg), [rm_arg, rmreg])
addop("bts", [bs8(0x0f), bs8(0xba)] + rmmod(d5) + [u08])

addop("call", [bs8(0xe8), rel_off])
addop("call", [bs8(0xff), stk] + rmmod(d2))
addop("call", [bs8(0xff), stk] + rmmod(d3, rm_arg_x=rm_mem_far, modrm=mod_mem))
addop("call", [bs8(0x9a), bs_modeno64, moff, msegoff])


addop("cbw", [bs8(0x98), bs_opmode16])
addop("cwde", [bs8(0x98), bs_opmode32])
addop("cdqe", [bs8(0x98), bs_opmode64])

addop("clc", [bs8(0xf8)])
addop("cld", [bs8(0xfc)])
addop("cli", [bs8(0xfa)])
addop("clts", [bs8(0x0f), bs8(0x06)])
addop("cmc", [bs8(0xf5)])

addop("cmov", [bs8(0x0f), bs('0100'), cond] + rmmod(rmreg))

addop("cmp", [bs("0011110"), w8, d_eax, d_imm])
addop("cmp", [bs("100000"), se, w8] + rmmod(d7, rm_arg_w8) + [d_imm])
addop("cmp", [bs("001110"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])


addop("cmpsb", [bs8(0xa6)])
addop("cmpsw", [bs8(0xa7), bs_opmode16])
addop("cmpsd", [bs8(0xa7), bs_opmode32])
addop("cmpsq", [bs8(0xa7), bs_opmode64])

addop("cmpxchg", [bs8(0x0f), bs('1011000'), w8]
      + rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("cmpxchg8b", [bs8(0x0f), bs8(0xc7), bs_opmode16] + rmmod(d1, rm_arg_m64))
addop("cmpxchg8b", [bs8(0x0f), bs8(0xc7), bs_opmode32] + rmmod(d1, rm_arg_m64))
addop("cmpxchg16b", [bs8(0x0f), bs8(0xc7), bs_opmode64] + rmmod(d1, rm_arg_xmm_m128))

# XXX TODO CMPXCHG8/16

addop("comiss", [bs8(0x0f), bs8(0x2f), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm_m32), [xmm_reg, rm_arg_xmm_m32])
addop("comisd", [bs8(0x0f), bs8(0x2f), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m64), [xmm_reg, rm_arg_xmm_m64])

addop("cpuid", [bs8(0x0f), bs8(0xa2)])

addop("cwd", [bs8(0x99), bs_opmode16])
addop("cdq", [bs8(0x99), bs_opmode32])
addop("cqo", [bs8(0x99), bs_opmode64])


addop("daa", [bs8(0x27)])
addop("das", [bs8(0x2f)])
addop("dec", [bs('1111111'), w8] + rmmod(d1, rm_arg_w8))
addop("dec", [bs('01001'), reg, bs_modeno64])
addop("div", [bs('1111011'), w8] + rmmod(d6, rm_arg_w8))
addop("enter", [bs8(0xc8), u16, u08])

# float #####
addop("fwait", [bs8(0x9b)])

addop("f2xm1", [bs8(0xd9), bs8(0xf0)])
addop("fabs", [bs8(0xd9), bs8(0xe1)])

addop("fadd", [bs("11011"), sd, bs("00")] + rmmod(d0, rm_arg_sd))
addop("fadd", [bs("11011"), swapargs, bs("00"),
      bs("11000"), d_st, fltreg], [d_st, fltreg])
addop("faddp", [bs8(0xde), bs("11000"), fltreg, d_st])
addop("fiadd", [bs("11011"), wd, bs("10")] + rmmod(d0, rm_arg_wd))

addop("fbld", [bs8(0xdf)] + rmmod(d4, rm_arg_m80))
addop("fbldp", [bs8(0xdf)] + rmmod(d6, rm_arg_m80))
addop("fchs", [bs8(0xd9), bs8(0xe0)])
# addop("fclex", [bs8(0x9b), bs8(0xdb), bs8(0xe2)])
addop("fnclex", [bs8(0xdb), bs8(0xe2)])

addop("fcmovb", [bs8(0xda), bs("11000"), d_st, fltreg])
addop("fcmove", [bs8(0xda), bs("11001"), d_st, fltreg])
addop("fcmovbe", [bs8(0xda), bs("11010"), d_st, fltreg])
addop("fcmovu", [bs8(0xda), bs("11011"), d_st, fltreg])
addop("fcmovnb", [bs8(0xdb), bs("11000"), d_st, fltreg])
addop("fcmovne", [bs8(0xdb), bs("11001"), d_st, fltreg])
addop("fcmovnbe", [bs8(0xdb), bs("11010"), d_st, fltreg])
addop("fcmovnu", [bs8(0xdb), bs("11011"), d_st, fltreg])

addop("fcom", [bs("11011"), sd, bs("00")] + rmmod(d2, rm_arg_sd))
addop("fcom", [bs("11011"), swapargs, bs("00"),
      bs("11010"), d_st, fltreg], [d_st, fltreg])
addop("fcomp", [bs("11011"), sd, bs("00")] + rmmod(d3, rm_arg_sd))
addop("fcomp",
      [bs("11011"), swapargs, bs("00"), bs("11011"),
      d_st, fltreg], [d_st, fltreg])
addop("fcompp", [bs8(0xde), bs8(0xd9)])

addop("fcomi", [bs8(0xdb), bs("11110"), d_st, fltreg])
addop("fcomip", [bs8(0xdf), bs("11110"), d_st, fltreg])
addop("fucomi", [bs8(0xdb), bs("11101"), d_st, fltreg])
addop("fucomip", [bs8(0xdf), bs("11101"), d_st, fltreg])

addop("fcos", [bs8(0xd9), bs8(0xff)])
addop("fdecstp", [bs8(0xd9), bs8(0xf6)])


addop("fdiv", [bs("11011"), sd, bs("00")] + rmmod(d6, rm_arg_sd))
addop("fdiv", [bs8(0xd8), bs("11110"), d_st, fltreg])
addop("fdiv", [bs8(0xdc), bs("11111"), fltreg, d_st])
addop("fdivp", [bs8(0xde), bs("11111"), fltreg, d_st])
addop("fidiv", [bs("11011"), wd, bs("10")] + rmmod(d6, rm_arg_wd))

addop("fdivr", [bs("11011"), sd, bs("00")] + rmmod(d7, rm_arg_sd))
addop("fdivr", [bs8(0xd8), bs("11111"), d_st, fltreg])
addop("fdivr", [bs8(0xdc), bs("11110"), fltreg, d_st])
addop("fdivrp", [bs8(0xde), bs("11110"), fltreg, d_st])
addop("fidivr", [bs("11011"), wd, bs("10")] + rmmod(d7, rm_arg_wd))

addop("ffree", [bs8(0xdd), bs("11000"), fltreg])
addop("ficom", [bs("11011"), wd, bs("10")] + rmmod(d2, rm_arg_wd))
addop("ficomp", [bs("11011"), wd, bs("10")] + rmmod(d3, rm_arg_wd))
addop("fild", [bs("11011"), wd, bs("11")] + rmmod(d0, rm_arg_wd))
addop("fild", [bs8(0xdf)] + rmmod(d5, rm_arg_m64))

addop("fincstp", [bs8(0xd9), bs8(0xf7)])

# addop("finit", [bs8(0x9b), bs8(0xdb), bs8(0xe3)])
addop("fninit", [bs8(0xdb), bs8(0xe3)])

addop("fist", [bs("11011"), wd, bs("11")] + rmmod(d2, rm_arg_wd))
addop("fistp", [bs("11011"), wd, bs("11")] + rmmod(d3, rm_arg_wd))
addop("fistp", [bs8(0xdf)] + rmmod(d7, rm_arg_m64))

addop("fisttp", [bs("11011"), wd, bs("11")] + rmmod(d1, rm_arg_wd))
addop("fisttp", [bs8(0xdd)] + rmmod(d1, rm_arg_m64))

addop("fld", [bs("11011"), sd, bs("01")] + rmmod(d0, rm_arg_sd))
addop("fld", [bs8(0xdb)] + rmmod(d5, rm_arg_m80))
addop("fld", [bs8(0xd9), bs("11000"), fltreg])

addop("fld1", [bs8(0xd9), bs8(0xe8)])
addop("fldl2t", [bs8(0xd9), bs8(0xe9)])
addop("fldl2e", [bs8(0xd9), bs8(0xea)])
addop("fldpi", [bs8(0xd9), bs8(0xeb)])
addop("fldlg2", [bs8(0xd9), bs8(0xec)])
addop("fldln2", [bs8(0xd9), bs8(0xed)])
addop("fldz", [bs8(0xd9), bs8(0xee)])

addop("fldcw", [bs8(0xd9)] + rmmod(d5, rm_arg_m16))
addop("fldenv", [bs8(0xd9)] + rmmod(d4, rm_arg_m80))  # XXX TODO: m14?

addop("fmul", [bs("11011"), sd, bs("00")] + rmmod(d1, rm_arg_sd))
addop("fmul", [bs("11011"), swapargs, bs("00"),
      bs("11001"), d_st, fltreg], [d_st, fltreg])
addop("fmulp", [bs8(0xde), bs("11001"), fltreg, d_st])
addop("fimul", [bs("11011"), wd, bs("10")] + rmmod(d1, rm_arg_wd))

addop("fnop", [bs8(0xd9), bs8(0xd0)])
addop("fpatan", [bs8(0xd9), bs8(0xf3)])
addop("fprem", [bs8(0xd9), bs8(0xf8)])
addop("fprem1", [bs8(0xd9), bs8(0xf5)])
addop("fptan", [bs8(0xd9), bs8(0xf2)])
addop("frndint", [bs8(0xd9), bs8(0xfc)])
addop("frstor", [bs8(0xdd)] + rmmod(d4, rm_arg_m80))  # XXX TODO: m94 ?
# addop("fsave", [bs8(0x9b), bs8(0xdd)] + rmmod(d6, rm_arg_m80)) # XXX
# TODO: m94 ?
addop("fnsave", [bs8(0xdd)] + rmmod(d6, rm_arg_m80))  # XXX TODO: m94 ?

addop("fscale", [bs8(0xd9), bs8(0xfd)])
addop("fsin", [bs8(0xd9), bs8(0xfe)])
addop("fsincos", [bs8(0xd9), bs8(0xfb)])
addop("fsqrt", [bs8(0xd9), bs8(0xfa)])

addop("fst", [bs("11011"), sd, bs("01")] + rmmod(d2, rm_arg_sd))
addop("fst", [bs8(0xdd), bs("11010"), fltreg])
addop("fstp", [bs("11011"), sd, bs("01")] + rmmod(d3, rm_arg_sd))
addop("fstp", [bs8(0xdb)] + rmmod(d7, rm_arg_m80))
addop("fstp", [bs8(0xdd), bs("11011"), fltreg])

# addop("fstcw", [bs8(0x9b), bs8(0xd9)] + rmmod(d7, rm_arg_m16))
addop("fnstcw", [bs8(0xd9)] + rmmod(d7, rm_arg_m16))
# addop("fstenv", [bs8(0x9b), bs8(0xd9)] + rmmod(d6, rm_arg_m80)) # XXX
# TODO: m14?
addop("fnstenv", [bs8(0xd9)] + rmmod(d6, rm_arg_m80))  # XXX TODO: m14?
# addop("fstsw", [bs8(0x9b), bs8(0xdd)] + rmmod(d7, rm_arg_m16))
addop("fnstsw", [bs8(0xdd)] + rmmod(d7, rm_arg_m16))
# addop("fstsw", [bs8(0x9b), bs8(0xdf), bs8(0xe0), d_ax])
addop("fnstsw", [bs8(0xdf), bs8(0xe0), d_ax])

addop("fsub", [bs("11011"), sd, bs("00")] + rmmod(d4, rm_arg_sd))
addop("fsub", [bs8(0xd8), bs("11100"), d_st, fltreg])
addop("fsub", [bs8(0xdc), bs("11101"), fltreg, d_st])
addop("fsubp", [bs8(0xde), bs("11101"), fltreg, d_st])
addop("fisub", [bs("11011"), wd, bs("10")] + rmmod(d4, rm_arg_wd))

addop("fsubr", [bs("11011"), sd, bs("00")] + rmmod(d5, rm_arg_sd))
addop("fsubr", [bs8(0xd8), bs("11101"), d_st, fltreg])
addop("fsubr", [bs8(0xdc), bs("11100"), fltreg, d_st])
addop("fsubrp", [bs8(0xde), bs("11100"), fltreg, d_st])
addop("fisubr", [bs("11011"), wd, bs("10")] + rmmod(d5, rm_arg_wd))
addop("ftst", [bs8(0xd9), bs8(0xe4)])


addop("fucom", [bs8(0xdd), bs("11100"), fltreg])
addop("fucomp", [bs8(0xdd), bs("11101"), fltreg])
addop("fucompp", [bs8(0xda), bs8(0xe9)])

addop("fxam", [bs8(0xd9), bs8(0xe5)])
addop("fxch", [bs8(0xd9), bs("11001"), fltreg])
addop("fxrstor", [bs8(0x0f), bs8(0xae)]
      + rmmod(d1, rm_arg_m80))  # XXX TODO m512
addop("fxsave", [bs8(0x0f), bs8(0xae)]
      + rmmod(d0, rm_arg_m80))  # XXX TODO m512
addop("stmxcsr", [bs8(0x0f), bs8(0xae)] + rmmod(d3))
addop("ldmxcsr", [bs8(0x0f), bs8(0xae)] + rmmod(d2))

addop("fxtract", [bs8(0xd9), bs8(0xf4)])
addop("fyl2x", [bs8(0xd9), bs8(0xf1)])
addop("fyl2xp1", [bs8(0xd9), bs8(0xf9)])

addop("hlt", [bs8(0xf4)])
addop("icebp", [bs8(0xf1)])

addop("idiv", [bs('1111011'), w8] + rmmod(d7, rm_arg_w8))

addop("imul", [bs('1111011'), w8] + rmmod(d5, rm_arg_w8))
addop("imul", [bs8(0x0f), bs8(0xaf)] + rmmod(rmreg))

addop("imul", [bs("011010"), se, bs('1')] + rmmod(rmreg) + [d_imm])

addop("in", [bs("1110010"), w8, d_eax, u08])
addop("in", [bs("1110110"), w8, d_eax, d_edx])

addop("inc", [bs('1111111'), w8] + rmmod(d0, rm_arg_w8))
addop("inc", [bs('01000'), reg, bs_modeno64])

addop("insb", [bs8(0x6c)])
addop("insw", [bs8(0x6d), bs_opmode16])
addop("insd", [bs8(0x6d), bs_opmode32])
addop("insd", [bs8(0x6d), bs_opmode64])

addop("int", [bs8(0xcc), u08_3])
addop("int", [bs8(0xcd), u08])
addop("into", [bs8(0xce)])
addop("invd", [bs8(0x0f), bs8(0x08)])
addop("invlpg", [bs8(0x0f), bs8(0x01)] + rmmod(d7))

addop("iret", [bs8(0xcf), bs_opmode16])
addop("iretd", [bs8(0xcf), bs_opmode32])
addop("iretq", [bs8(0xcf), bs_opmode64])

addop("j", [bs('0111'), cond, rel_off08])

addop("jcxz", [bs8(0xe3), rel_off08, bs_admode16])
addop("jecxz", [bs8(0xe3), rel_off08, bs_admode32])
addop("jrcxz", [bs8(0xe3), rel_off08, bs_admode64])

addop("j", [bs8(0x0f), bs('1000'), cond, rel_off])
addop("jmp", [bs8(0xeb), rel_off08])
addop("jmp", [bs8(0xe9), rel_off])
# TODO XXX replace stk force64?
addop("jmp", [bs8(0xff), stk] + rmmod(d4))
addop("jmp", [bs8(0xea), bs_modeno64, moff, msegoff])

addop("jmp", [bs8(0xff)] + rmmod(d5, rm_arg_x=rm_mem_far, modrm=mod_mem))

addop("lahf", [bs8(0x9f)])
addop("lar", [bs8(0x0f), bs8(0x02)] + rmmod(rmreg))

addop("lea", [bs8(0x8d)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))
addop("les", [bs8(0xc4)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))
addop("lds", [bs8(0xc5)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))
addop("lss", [bs8(0x0f), bs8(0xb2)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))
addop("lfs", [bs8(0x0f), bs8(0xb4)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))
addop("lgs", [bs8(0x0f), bs8(0xb5)] + rmmod(rmreg, rm_arg_x=rm_mem, modrm=mod_mem))

addop("lgdt", [bs8(0x0f), bs8(0x01)] + rmmod(d2, modrm=mod_mem))
addop("lidt", [bs8(0x0f), bs8(0x01)] + rmmod(d3, modrm=mod_mem))

addop("lfence", [bs8(0x0f), bs8(0xae), bs8(0xe8), no_xmm_pref])
addop("mfence", [bs8(0x0f), bs8(0xae), bs8(0xf0)])
addop("sfence", [bs8(0x0f), bs8(0xae), bs8(0xf8)])

addop("leave", [bs8(0xc9), stk])

addop("lodsb", [bs8(0xac)])
addop("lodsw", [bs8(0xad), bs_opmode16])
addop("lodsd", [bs8(0xad), bs_opmode32])
addop("lodsq", [bs8(0xad), bs_opmode64])

addop("loop", [bs8(0xe2), rel_off08])
addop("loope", [bs8(0xe1), rel_off08])
addop("loopne", [bs8(0xe0), rel_off08])
addop("lsl", [bs8(0x0f), bs8(0x03)] + rmmod(rmreg))
addop("monitor", [bs8(0x0f), bs8(0x01), bs8(0xc8)])

addop("mov", [bs("100010"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("mov", [bs("100011"), swapargs, bs('0')] + rmmod(segm), [rm_arg, segm])
addop("mov", [bs("101000"), swapargs, w8, d_eax, movoff], [d_eax, movoff])
addop("mov", [bs("1011"), w8, reg, d_imm64])
addop("mov", [bs("1100011"), w8] + rmmod(d0, rm_arg_w8) + [d_imm])
addop("mov", [bs8(0x0f), bs("001000"), swapargs, bs('0')]
      + rmmod(crreg), [rm_arg, crreg])
addop("mov", [bs8(0x0f), bs("001000"), swapargs, bs('1')]
      + rmmod(drreg), [rm_arg, drreg])
addop("movsb", [bs8(0xa4)])
addop("movsw", [bs8(0xa5), bs_opmode16])
addop("movsd", [bs8(0xa5), bs_opmode32])
addop("movsq", [bs8(0xa5), bs_opmode64])

addop("movsx", [bs8(0x0f), bs("1011111"), w8, sx] + rmmod(rmreg, rm_arg_sx))
addop("movsxd", [bs8(0x63), sxd, bs_mode64] + rmmod(rmreg, rm_arg_sxd))

addop("movups", [bs8(0x0f), bs("0001000"), swapargs, no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])
addop("movsd", [bs8(0x0f), bs("0001000"), swapargs, pref_f2]
      + rmmod(xmm_reg, rm_arg_xmm_m64), [xmm_reg, rm_arg_xmm_m64])
addop("movss", [bs8(0x0f), bs("0001000"), swapargs, pref_f3] +
      rmmod(xmm_reg, rm_arg_xmm_m32), [xmm_reg, rm_arg_xmm_m32])
addop("movupd", [bs8(0x0f), bs8(0x10), pref_66] + rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])
addop("movupd", [bs8(0x0f), bs8(0x11), pref_66] + rmmod(xmm_reg, rm_arg_xmm), [rm_arg_xmm, xmm_reg])


addop("movd", [bs8(0x0f), bs('011'), swapargs, bs('1110'), no_xmm_pref] +
      rmmod(mm_reg, rm_arg), [mm_reg, rm_arg])
addop("movd", [bs8(0x0f), bs('011'), swapargs, bs('1110'), pref_66, bs_opmode32] +
      rmmod(xmm_reg, rm_arg), [xmm_reg, rm_arg])
addop("movq", [bs8(0x0f), bs('011'), swapargs, bs('1110'), pref_66, bs_opmode64] +
      rmmod(xmm_reg, rm_arg), [xmm_reg, rm_arg])

addop("movq", [bs8(0x0f), bs('011'), swapargs, bs('1111'), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64), [mm_reg, rm_arg_mm_m64])

addop("movq", [bs8(0x0f), bs8(0x7e), pref_f3] +
      rmmod(xmm_reg, rm_arg_xmm_m64), [xmm_reg, rm_arg_xmm_m64])
addop("movq", [bs8(0x0f), bs8(0xd6), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m64), [rm_arg_xmm_m64, xmm_reg])

addop("movmskps", [bs8(0x0f), bs8(0x50), no_xmm_pref] +
      rmmod(reg_modrm, rm_arg_xmm_reg))
addop("movmskpd", [bs8(0x0f), bs8(0x50), pref_66] +
      rmmod(reg_modrm, rm_arg_xmm_reg))

addop("movnti", [bs8(0x0f), bs8(0xc3)] + rmmod(rmreg), [rm_arg, rmreg])

addop("addss", [bs8(0x0f), bs8(0x58), pref_f3] + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("addsd", [bs8(0x0f), bs8(0x58), pref_f2] + rmmod(xmm_reg, rm_arg_xmm_m64))

addop("subss", [bs8(0x0f), bs8(0x5c), pref_f3] + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("subsd", [bs8(0x0f), bs8(0x5c), pref_f2] + rmmod(xmm_reg, rm_arg_xmm_m64))

addop("mulss", [bs8(0x0f), bs8(0x59), pref_f3] + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("mulsd", [bs8(0x0f), bs8(0x59), pref_f2] + rmmod(xmm_reg, rm_arg_xmm_m64))

addop("divss", [bs8(0x0f), bs8(0x5e), pref_f3] + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("divsd", [bs8(0x0f), bs8(0x5e), pref_f2] + rmmod(xmm_reg, rm_arg_xmm_m64))

addop("roundss", [bs8(0x0f), bs8(0x3a), bs8(0x0a), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m32) + [u08])
addop("roundsd", [bs8(0x0f), bs8(0x3a), bs8(0x0b), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m64) + [u08])

addop("pminsw", [bs8(0x0f), bs8(0xea), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("pminsw", [bs8(0x0f), bs8(0xea), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("ucomiss", [bs8(0x0f), bs8(0x2e), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("ucomisd", [bs8(0x0f), bs8(0x2e), pref_66] + rmmod(xmm_reg, rm_arg_xmm_m64))


addop("movzx", [bs8(0x0f), bs("1011011"), w8, sx] + rmmod(rmreg, rm_arg_sx))
addop("mul", [bs('1111011'), w8] + rmmod(d4, rm_arg_w8))

addop("neg", [bs('1111011'), w8] + rmmod(d3, rm_arg_w8))
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d0, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d1, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d2, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d3, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d4, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d5, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d6, rm_arg))  # XXX TODO m512
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d7, rm_arg))  # XXX TODO m512
addop("not", [bs('1111011'), w8] + rmmod(d2, rm_arg_w8))
addop("or", [bs("0000110"), w8, d_eax, d_imm])
addop("or", [bs("100000"), se, w8] + rmmod(d1, rm_arg_w8) + [d_imm])
addop("or", [bs("000010"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("out", [bs("1110011"), w8, u08, d_eax])
addop("out", [bs("1110111"), w8, d_edx, d_eax])

addop("outsb", [bs8(0x6e)])
addop("outsw", [bs8(0x6f), bs_opmode16])
addop("outsd", [bs8(0x6f), bs_opmode32])
addop("outsd", [bs8(0x6f), bs_opmode64])

addop("setalc", [bs8(0xD6)])

# addop("pause", [bs8(0xf3), bs8(0x90)])

addop("popw", [bs8(0x8f), stk, bs_opmode16] + rmmod(d0))
addop("popw", [bs("01011"), stk, reg, bs_opmode16])
addop("popw", [bs8(0x1f), stk, d_ds, bs_opmode16])
addop("popw", [bs8(0x07), stk, d_es, bs_opmode16])
addop("popw", [bs8(0x17), stk, d_ss, bs_opmode16])
addop("popw", [bs8(0x0f), stk, bs8(0xa1), d_fs, bs_opmode16])
addop("popw", [bs8(0x0f), stk, bs8(0xa9), d_gs, bs_opmode16])

addop("pop", [bs8(0x8f), stk, bs_opmode32] + rmmod(d0))
addop("pop", [bs("01011"), stk, reg, bs_opmode32])
addop("pop", [bs8(0x1f), stk, d_ds, bs_opmode32])
addop("pop", [bs8(0x07), stk, d_es, bs_opmode32])
addop("pop", [bs8(0x17), stk, d_ss, bs_opmode32])
addop("pop", [bs8(0x0f), stk, bs8(0xa1), d_fs, bs_opmode32])
addop("pop", [bs8(0x0f), stk, bs8(0xa9), d_gs, bs_opmode32])

addop("pop", [bs8(0x8f), stk, bs_opmode64] + rmmod(d0))
addop("pop", [bs("01011"), stk, reg, bs_opmode64])
addop("pop", [bs8(0x1f), stk, d_ds, bs_opmode64])
addop("pop", [bs8(0x07), stk, d_es, bs_opmode64])
addop("pop", [bs8(0x17), stk, d_ss, bs_opmode64])
addop("pop", [bs8(0x0f), stk, bs8(0xa1), d_fs, bs_opmode64])
addop("pop", [bs8(0x0f), stk, bs8(0xa9), d_gs, bs_opmode64])


addop("popa", [bs8(0x61), stk, bs_opmode16])
addop("popad", [bs8(0x61), stk, bs_opmode32])

addop("popfw", [bs8(0x9d), stk, bs_opmode16])
addop("popfd", [bs8(0x9d), stk, bs_opmode32])
addop("popfq", [bs8(0x9d), stk, bs_opmode64])

addop("prefetch0", [bs8(0x0f), bs8(0x18)] + rmmod(d1, rm_arg_m08))
addop("prefetch1", [bs8(0x0f), bs8(0x18)] + rmmod(d2, rm_arg_m08))
addop("prefetch2", [bs8(0x0f), bs8(0x18)] + rmmod(d3, rm_arg_m08))
addop("prefetchnta", [bs8(0x0f), bs8(0x18)] + rmmod(d0, rm_arg_m08))
addop("prefetchw", [bs8(0x0f), bs8(0x0d)] + rmmod(d1, rm_arg_m08))

addop("pushw", [bs8(0xff), stk, bs_opmode16] + rmmod(d6))
addop("pushw", [bs("01010"), stk, reg, bs_opmode16])
addop("pushw", [bs8(0x6a), s08, stk, bs_opmode16])
addop("pushw", [bs8(0x68), d_imm, stk, bs_opmode16])
addop("pushw", [bs8(0x0e), stk, d_cs, bs_opmode16])
addop("pushw", [bs8(0x16), stk, d_ss, bs_opmode16])
addop("pushw", [bs8(0x1e), stk, d_ds, bs_opmode16])
addop("pushw", [bs8(0x06), stk, d_es, bs_opmode16])
addop("pushw", [bs8(0x0f), stk, bs8(0xa0), d_fs, bs_opmode16])
addop("pushw", [bs8(0x0f), stk, bs8(0xa8), d_gs, bs_opmode16])

addop("push", [bs8(0xff), stk, bs_opmode32] + rmmod(d6))
addop("push", [bs("01010"), stk, reg, bs_opmode32])
addop("push", [bs8(0x6a), s08, stk, bs_opmode32])
addop("push", [bs8(0x68), d_imm, stk, bs_opmode32])
addop("push", [bs8(0x0e), stk, d_cs, bs_opmode32])
addop("push", [bs8(0x16), stk, d_ss, bs_opmode32])
addop("push", [bs8(0x1e), stk, d_ds, bs_opmode32])
addop("push", [bs8(0x06), stk, d_es, bs_opmode32])
addop("push", [bs8(0x0f), stk, bs8(0xa0), d_fs, bs_opmode32])
addop("push", [bs8(0x0f), stk, bs8(0xa8), d_gs, bs_opmode32])

addop("push", [bs8(0xff), stk, bs_opmode64] + rmmod(d6))
addop("push", [bs("01010"), stk, reg, bs_opmode64])
addop("push", [bs8(0x6a), s08, stk, bs_opmode64])
addop("push", [bs8(0x68), d_imm, stk, bs_opmode64])
addop("push", [bs8(0x0e), stk, d_cs, bs_opmode64])
addop("push", [bs8(0x16), stk, d_ss, bs_opmode64])
addop("push", [bs8(0x1e), stk, d_ds, bs_opmode64])
addop("push", [bs8(0x06), stk, d_es, bs_opmode64])
addop("push", [bs8(0x0f), stk, bs8(0xa0), d_fs, bs_opmode64])
addop("push", [bs8(0x0f), stk, bs8(0xa8), d_gs, bs_opmode64])

addop("pusha", [bs8(0x60), stk, bs_opmode16_no64])
addop("pushad", [bs8(0x60), stk, bs_opmode32_no64])


addop("pushfw", [bs8(0x9c), stk, bs_opmode16])
addop("pushfd", [bs8(0x9c), stk, bs_opmode32])
addop("pushfq", [bs8(0x9c), stk, bs_opmode64])

addop("rcl", [bs('110100'), d_cl1, w8] +
      rmmod(d2, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("rcl", [bs('1100000'), w8] + rmmod(d2, rm_arg_w8) + [u08])
addop("rcr", [bs('110100'), d_cl1, w8] +
      rmmod(d3, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("rcr", [bs('1100000'), w8] + rmmod(d3, rm_arg_w8) + [u08])
addop("rol", [bs('110100'), d_cl1, w8]
      + rmmod(d0, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("rol", [bs('1100000'), w8] + rmmod(d0, rm_arg_w8) + [u08])
addop("ror", [bs('110100'), d_cl1, w8]
      + rmmod(d1, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("ror", [bs('1100000'), w8] + rmmod(d1, rm_arg_w8) + [u08])

addop("rdmsr", [bs8(0x0f), bs8(0x32)])
addop("rdpmc", [bs8(0x0f), bs8(0x33)])
addop("rdtsc", [bs8(0x0f), bs8(0x31)])
addop("ret", [bs8(0xc3), stk])
addop("ret", [bs8(0xc2), stk, u16])
addop("retf", [bs8(0xcb), stk])
addop("retf", [bs8(0xca), stk, u16])

addop("rsm", [bs8(0x0f), bs8(0xaa)])
addop("sahf", [bs8(0x9e)])

# XXX tipo in doc: /4 instead of /6
addop("sal", [bs('110100'), d_cl1, w8] +
      rmmod(d6, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("sal", [bs('1100000'), w8] + rmmod(d6, rm_arg_w8) + [u08])
addop("sar", [bs('110100'), d_cl1, w8] +
      rmmod(d7, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("sar", [bs('1100000'), w8] + rmmod(d7, rm_arg_w8) + [u08])

addop("scasb", [bs8(0xae)])
addop("scasw", [bs8(0xaf), bs_opmode16])
addop("scasd", [bs8(0xaf), bs_opmode32])
addop("scasq", [bs8(0xaf), bs_opmode64])

addop("shl", [bs('110100'), d_cl1, w8]
      + rmmod(d4, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("shl", [bs('1100000'), w8] + rmmod(d4, rm_arg_w8) + [u08])
addop("shr", [bs('110100'), d_cl1, w8]
      + rmmod(d5, rm_arg_w8), [rm_arg_w8, d_cl1])
addop("shr", [bs('1100000'), w8] + rmmod(d5, rm_arg_w8) + [u08])

addop("sbb", [bs("0001110"), w8, d_eax, d_imm])
addop("sbb", [bs("100000"), se, w8] + rmmod(d3, rm_arg_w8) + [d_imm])
addop("sbb", [bs("000110"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("set", [bs8(0x0f), bs('1001'), cond] + rmmod(regnoarg, rm_arg_08))
addop("sgdt", [bs8(0x0f), bs8(0x01)] + rmmod(d0, modrm=mod_mem))
addop("shld", [bs8(0x0f), bs8(0xa4)] +
      rmmod(rmreg) + [u08], [rm_arg, rmreg, u08])
addop("shld", [bs8(0x0f), bs8(0xa5)] +
      rmmod(rmreg) + [d_cl], [rm_arg, rmreg, d_cl])
addop("shrd", [bs8(0x0f), bs8(0xac)] +
      rmmod(rmreg) + [u08], [rm_arg, rmreg, u08])
addop("shrd", [bs8(0x0f), bs8(0xad)] +
      rmmod(rmreg) + [d_cl], [rm_arg, rmreg, d_cl])
addop("sidt", [bs8(0x0f), bs8(0x01)] + rmmod(d1, modrm=mod_mem))
addop("sldt", [bs8(0x0f), bs8(0x00)] + rmmod(d0, rm_arg_x=rm_arg_reg_m16))
addop("smsw", [bs8(0x0f), bs8(0x01)] + rmmod(d4))
addop("stc", [bs8(0xf9)])
addop("std", [bs8(0xfd)])
addop("sti", [bs8(0xfb)])
addop("stosb", [bs8(0xaa)])
addop("stosw", [bs8(0xab), bs_opmode16])
addop("stosd", [bs8(0xab), bs_opmode32])
addop("stosq", [bs8(0xab), bs_opmode64])

addop("str", [bs8(0x0f), bs8(0x00)] + rmmod(d1))

addop("sub", [bs("0010110"), w8, d_eax, d_imm])
addop("sub", [bs("100000"), se, w8] + rmmod(d5, rm_arg_w8) + [d_imm])
addop("sub", [bs("001010"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("syscall", [bs8(0x0f), bs8(0x05)])
addop("sysenter", [bs8(0x0f), bs8(0x34)])
addop("sysexit", [bs8(0x0f), bs8(0x35)])
addop("sysret", [bs8(0x0f), bs8(0x07)])
addop("test", [bs("1010100"), w8, d_eax, d_imm])
addop("test", [bs("1111011"), w8] + rmmod(d0, rm_arg_w8) + [d_imm])
addop("test", [bs("1000010"), w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("ud2", [bs8(0x0f), bs8(0x0b)])
addop("verr", [bs8(0x0f), bs8(0x00)] + rmmod(d4))
addop("verw", [bs8(0x0f), bs8(0x00)] + rmmod(d5))
addop("wbinvd", [bs8(0x0f), bs8(0x09)])
addop("wrmsr", [bs8(0x0f), bs8(0x30)])
addop("xadd", [bs8(0x0f), bs("1100000"), w8]
      + rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("nop", [bs8(0x90), no_rex], alias=True)

addop("xchg", [bs('10010'), d_eax, reg])
addop("xchg", [bs('1000011'), w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("xlat", [bs8(0xd7)])


addop("xor", [bs("0011010"), w8, d_eax, d_imm])
addop("xor", [bs("100000"), se, w8] + rmmod(d6, rm_arg_w8) + [d_imm])
addop("xor", [bs("001100"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])


addop("xgetbv", [bs8(0x0f), bs8(0x01), bs8(0xd0)])



#### MMX/SSE/AVX operations
#### Categories are the same than here: https://software.intel.com/sites/landingpage/IntrinsicsGuide/
####

### Arithmetic (integers)
###

## Move
# SSE
addop("movapd", [bs8(0x0f), bs("0010100"), swapargs]
      + rmmod(xmm_reg, rm_arg_xmm) + [bs_opmode16], [xmm_reg, rm_arg_xmm])
addop("movaps", [bs8(0x0f), bs("0010100"), swapargs]
      + rmmod(xmm_reg, rm_arg_xmm_m128) + [bs_opmode32], [xmm_reg, rm_arg_xmm_m128])
addop("movaps", [bs8(0x0f), bs("0010100"), swapargs]
      + rmmod(xmm_reg, rm_arg_xmm_m128) + [bs_opmode64], [xmm_reg, rm_arg_xmm_m128])
addop("movdqu", [bs8(0x0f), bs("011"), swapargs, bs("1111"), pref_f3]
      + rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])
addop("movdqa", [bs8(0x0f), bs("011"), swapargs, bs("1111"), pref_66]
      + rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

addop("movhpd", [bs8(0x0f), bs("0001011"), swapargs, pref_66] +
      rmmod(xmm_reg, rm_arg_m64), [xmm_reg, rm_arg_m64])
addop("movhps", [bs8(0x0f), bs("0001011"), swapargs, no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_m64), [xmm_reg, rm_arg_m64])
addop("movlpd", [bs8(0x0f), bs("0001001"), swapargs, pref_66] +
      rmmod(xmm_reg, rm_arg_m64), [xmm_reg, rm_arg_m64])
addop("movlps", [bs8(0x0f), bs("0001001"), swapargs, no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_m64), [xmm_reg, rm_arg_m64])

addop("movhlps", [bs8(0x0f), bs8(0x12), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm_reg), [xmm_reg, rm_arg_xmm_reg])
addop("movlhps", [bs8(0x0f), bs8(0x16), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm_reg), [xmm_reg, rm_arg_xmm_reg])

addop("movdq2q", [bs8(0x0f), bs8(0xd6), pref_f2] +
      rmmod(mm_reg, rm_arg_xmm_reg), [mm_reg, rm_arg_xmm_reg])
addop("movq2dq", [bs8(0x0f), bs8(0xd6), pref_f3] +
      rmmod(xmm_reg, rm_arg_mm))

## Additions
# SSE
addop("paddb", [bs8(0x0f), bs8(0xfc), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("paddw", [bs8(0x0f), bs8(0xfd), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("paddd", [bs8(0x0f), bs8(0xfe), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("paddq", [bs8(0x0f), bs8(0xd4), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("paddb", [bs8(0x0f), bs8(0xfc), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("paddw", [bs8(0x0f), bs8(0xfd), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("paddd", [bs8(0x0f), bs8(0xfe), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("paddq", [bs8(0x0f), bs8(0xd4), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))

## Substractions
# SSE
addop("psubb", [bs8(0x0f), bs8(0xf8), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("psubw", [bs8(0x0f), bs8(0xf9), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("psubd", [bs8(0x0f), bs8(0xfa), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("psubq", [bs8(0x0f), bs8(0xfb), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("psubb", [bs8(0x0f), bs8(0xf8), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("psubw", [bs8(0x0f), bs8(0xf9), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("psubd", [bs8(0x0f), bs8(0xfa), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))
addop("psubq", [bs8(0x0f), bs8(0xfb), no_xmm_pref] + rmmod(mm_reg, rm_arg_mm))

### Arithmetic (floating-point)
###

## Additions
# SSE
addop("addps", [bs8(0x0f), bs8(0x58), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("addpd", [bs8(0x0f), bs8(0x58), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## Substractions
# SSE
addop("subps", [bs8(0x0f), bs8(0x5c), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("subpd", [bs8(0x0f), bs8(0x5c), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## Multiplications
# SSE
addop("mulps", [bs8(0x0f), bs8(0x59), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("mulpd", [bs8(0x0f), bs8(0x59), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## Divisions
# SSE
addop("divps", [bs8(0x0f), bs8(0x5e), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("divpd", [bs8(0x0f), bs8(0x5e), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

### Logical (floating-point)
###

## XOR
addop("xorps", [bs8(0x0f), bs8(0x57), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("xorpd", [bs8(0x0f), bs8(0x57), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## AND
addop("andps", [bs8(0x0f), bs8(0x54), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("andpd", [bs8(0x0f), bs8(0x54), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("andnps", [bs8(0x0f), bs8(0x55), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("andnpd", [bs8(0x0f), bs8(0x55), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## OR
addop("orps", [bs8(0x0f), bs8(0x56), no_xmm_pref] + rmmod(xmm_reg, rm_arg_xmm))
addop("orpd", [bs8(0x0f), bs8(0x56), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

## AND
# MMX
addop("pand", [bs8(0x0f), bs8(0xdb), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
# SSE
addop("pand", [bs8(0x0f), bs8(0xdb), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

## ANDN
# MMX
addop("pandn", [bs8(0x0f), bs8(0xdf), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
# SSE
addop("pandn", [bs8(0x0f), bs8(0xdf), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

## OR
# MMX
addop("por", [bs8(0x0f), bs8(0xeb), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
# SSE
addop("por", [bs8(0x0f), bs8(0xeb), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

## XOR
# MMX
addop("pxor", [bs8(0x0f), bs8(0xef), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
# MMX
addop("pxor", [bs8(0x0f), bs8(0xef), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

### Comparisons (floating-point)
###
addop("minps", [bs8(0x0f), bs8(0x5d), no_xmm_pref] + rmmod(xmm_reg,
                                                           rm_arg_xmm_m128))
addop("minss", [bs8(0x0f), bs8(0x5d), pref_f3] + rmmod(xmm_reg,
                                                       rm_arg_xmm_m32))
addop("minpd", [bs8(0x0f), bs8(0x5d), pref_66] + rmmod(xmm_reg,
                                                       rm_arg_xmm_m128))
addop("minsd", [bs8(0x0f), bs8(0x5d), pref_f2] + rmmod(xmm_reg,
                                                       rm_arg_xmm_m64))
addop("maxps", [bs8(0x0f), bs8(0x5f), no_xmm_pref] + rmmod(xmm_reg,
                                                           rm_arg_xmm_m128))
addop("maxpd", [bs8(0x0f), bs8(0x5f), pref_66] + rmmod(xmm_reg,
                                                       rm_arg_xmm_m128))
addop("maxsd", [bs8(0x0f), bs8(0x5f), pref_f2] + rmmod(xmm_reg, rm_arg_xmm_m64))
addop("maxss", [bs8(0x0f), bs8(0x5f), pref_f3] + rmmod(xmm_reg, rm_arg_xmm_m32))

for cond_name, value in [
        ("eq", 0x00),
        ("lt", 0x01),
        ("le", 0x02),
        ("unord", 0x03),
        ("neq", 0x04),
        ("nlt", 0x05),
        ("nle", 0x06),
        ("ord", 0x07),
]:
    addop("cmp%sps" % cond_name, [bs8(0x0f), bs8(0xc2), no_xmm_pref] +
          rmmod(xmm_reg, rm_arg_xmm_m64) + [bs8(value)])
    addop("cmp%spd" % cond_name, [bs8(0x0f), bs8(0xc2), pref_66] +
          rmmod(xmm_reg, rm_arg_xmm_m64) + [bs8(value)])
    addop("cmp%sss" % cond_name, [bs8(0x0f), bs8(0xc2), pref_f3] +
          rmmod(xmm_reg, rm_arg_xmm_m32) + [bs8(value)])
    addop("cmp%ssd" % cond_name, [bs8(0x0f), bs8(0xc2), pref_f2] +
          rmmod(xmm_reg, rm_arg_xmm_m32) + [bs8(value)])



addop("pshufb", [bs8(0x0f), bs8(0x38), bs8(0x00), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pshufb", [bs8(0x0f), bs8(0x38), bs8(0x00), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("pshufd", [bs8(0x0f), bs8(0x70), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128) + [u08])
addop("pshuflw", [bs8(0x0f), bs8(0x70), pref_f2] +
      rmmod(xmm_reg, rm_arg_xmm_m128) + [u08])
addop("pshufhw", [bs8(0x0f), bs8(0x70), pref_f3] +
      rmmod(xmm_reg, rm_arg_xmm_m128) + [u08])


### Convert
### SS = single precision
### SD = double precision
###

## SS -> SD
##

addop("cvtdq2pd", [bs8(0x0f), bs8(0xe6), pref_f3]
      + rmmod(xmm_reg, rm_arg_xmm_m64))
addop("cvtdq2ps", [bs8(0x0f), bs8(0x5b), no_xmm_pref]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvtpd2dq", [bs8(0x0f), bs8(0xe6), pref_f2]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvtpd2pi", [bs8(0x0f), bs8(0x2d), pref_66]
      + rmmod(mm_reg, rm_arg_xmm))
addop("cvtpd2ps", [bs8(0x0f), bs8(0x5a), pref_66]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvtpi2pd", [bs8(0x0f), bs8(0x2a), pref_66]
      + rmmod(xmm_reg, rm_arg_mm_m64))
addop("cvtpi2ps", [bs8(0x0f), bs8(0x2a), no_xmm_pref]
      + rmmod(xmm_reg, rm_arg_mm_m64))
addop("cvtps2dq", [bs8(0x0f), bs8(0x5b), pref_66]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvtps2pd", [bs8(0x0f), bs8(0x5a), no_xmm_pref]
      + rmmod(xmm_reg, rm_arg_xmm_m64))
addop("cvtps2pi", [bs8(0x0f), bs8(0x2d), no_xmm_pref]
      + rmmod(mm_reg, rm_arg_xmm_m64))
addop("cvtsd2si", [bs8(0x0f), bs8(0x2d), pref_f2]
      + rmmod(reg, rm_arg_xmm_m64))
addop("cvtsd2ss", [bs8(0x0f), bs8(0x5a), pref_f2]
      + rmmod(xmm_reg, rm_arg_xmm_m64))
addop("cvtsi2sd", [bs8(0x0f), bs8(0x2a), pref_f2]
      + rmmod(xmm_reg, rm_arg))
addop("cvtsi2ss", [bs8(0x0f), bs8(0x2a), xmmreg, pref_f3]
      + rmmod(xmm_reg, rm_arg))
addop("cvtss2sd", [bs8(0x0f), bs8(0x5a), pref_f3]
      + rmmod(xmm_reg, rm_arg_xmm_m32))
addop("cvtss2si", [bs8(0x0f), bs8(0x2d), pref_f3]
      + rmmod(rmreg, rm_arg_xmm_m32))
addop("cvttpd2pi",[bs8(0x0f), bs8(0x2c), pref_66]
      + rmmod(mm_reg, rm_arg_xmm))
addop("cvttpd2dq",[bs8(0x0f), bs8(0xe6), pref_66]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvttps2dq",[bs8(0x0f), bs8(0x5b), pref_f3]
      + rmmod(xmm_reg, rm_arg_xmm))
addop("cvttps2pi",[bs8(0x0f), bs8(0x2c), no_xmm_pref]
      + rmmod(mm_reg, rm_arg_xmm_m64))
addop("cvttsd2si",[bs8(0x0f), bs8(0x2c), pref_f2]
      + rmmod(reg, rm_arg_xmm_m64))
addop("cvttss2si",[bs8(0x0f), bs8(0x2c), pref_f3]
      + rmmod(reg, rm_arg_xmm_m32))

addop("palignr", [bs8(0x0f), bs8(0x73), bs8(0x0f), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64) + [u08], [mm_reg, rm_arg_mm_m64, u08])
addop("palignr", [bs8(0x0f), bs8(0x3a), bs8(0x0f), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128) + [u08], [xmm_reg, rm_arg_xmm_m128, u08])

addop("psrlq", [bs8(0x0f), bs8(0x73), no_xmm_pref] +
      rmmod(d2, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("psrlq", [bs8(0x0f), bs8(0x73), pref_66] +
      rmmod(d2, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psrlq", [bs8(0x0f), bs8(0xd3), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
addop("psrlq", [bs8(0x0f), bs8(0xd3), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])


addop("psrld", [bs8(0x0f), bs8(0x72), no_xmm_pref] +
      rmmod(d2, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("psrld", [bs8(0x0f), bs8(0x72), pref_66] +
      rmmod(d2, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psrld", [bs8(0x0f), bs8(0xd2), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
addop("psrld", [bs8(0x0f), bs8(0xd2), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

addop("psrldq", [bs8(0x0f), bs8(0x73), pref_66] +
      rmmod(d3, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psrlw", [bs8(0x0f), bs8(0x71), no_xmm_pref] +
      rmmod(d2, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("psrlw", [bs8(0x0f), bs8(0x71), pref_66] +
      rmmod(d2, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psrlw", [bs8(0x0f), bs8(0xd1), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64), [mm_reg, rm_arg_mm_m64])
addop("psrlw", [bs8(0x0f), bs8(0xd1), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128), [xmm_reg, rm_arg_xmm_m128])

addop("psraw", [bs8(0x0f), bs8(0xe1), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64), [mm_reg, rm_arg_mm_m64])
addop("psraw", [bs8(0x0f), bs8(0xe1), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128), [xmm_reg, rm_arg_xmm_m128])

addop("psraw", [bs8(0x0f), bs8(0x71), no_xmm_pref] +
      rmmod(d4, rm_arg_mm_m64) + [u08], [rm_arg_mm_m64, u08])
addop("psraw", [bs8(0x0f), bs8(0x71), pref_66] +
      rmmod(d4, rm_arg_xmm_m128) + [u08], [rm_arg_xmm_m128, u08])

addop("psrad", [bs8(0x0f), bs8(0xe2), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64), [mm_reg, rm_arg_mm_m64])
addop("psrad", [bs8(0x0f), bs8(0xe2), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128), [xmm_reg, rm_arg_xmm_m128])

addop("psrad", [bs8(0x0f), bs8(0x72), no_xmm_pref] +
      rmmod(d4, rm_arg_mm_m64) + [u08], [rm_arg_mm_m64, u08])
addop("psrad", [bs8(0x0f), bs8(0x72), pref_66] +
      rmmod(d4, rm_arg_xmm_m128) + [u08], [rm_arg_xmm_m128, u08])


addop("psllq", [bs8(0x0f), bs8(0x73), no_xmm_pref] +
      rmmod(d6, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("psllq", [bs8(0x0f), bs8(0x73), pref_66] +
      rmmod(d6, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psllq", [bs8(0x0f), bs8(0xf3), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
addop("psllq", [bs8(0x0f), bs8(0xf3), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])


addop("pslld", [bs8(0x0f), bs8(0x72), no_xmm_pref] +
      rmmod(d6, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("pslld", [bs8(0x0f), bs8(0x72), pref_66] +
      rmmod(d6, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("pslld", [bs8(0x0f), bs8(0xf2), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
addop("pslld", [bs8(0x0f), bs8(0xf2), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])


addop("psllw", [bs8(0x0f), bs8(0x71), no_xmm_pref] +
      rmmod(d6, rm_arg_mm) + [u08], [rm_arg_mm, u08])
addop("psllw", [bs8(0x0f), bs8(0x71), pref_66] +
      rmmod(d6, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])

addop("psllw", [bs8(0x0f), bs8(0xf1), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm), [mm_reg, rm_arg_mm])
addop("psllw", [bs8(0x0f), bs8(0xf1), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm), [xmm_reg, rm_arg_xmm])

addop("pslldq", [bs8(0x0f), bs8(0x73), pref_66] +
      rmmod(d7, rm_arg_xmm) + [u08], [rm_arg_xmm, u08])


addop("pmaxub", [bs8(0x0f), bs8(0xde), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pmaxub", [bs8(0x0f), bs8(0xde), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pmaxuw", [bs8(0x0f), bs8(0x38), bs8(0x3e), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pmaxud", [bs8(0x0f), bs8(0x38), bs8(0x3f), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pmaxsw", [bs8(0x0f), bs8(0xee), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmaxsw", [bs8(0x0f), bs8(0xee), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("pminub", [bs8(0x0f), bs8(0xda), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pminub", [bs8(0x0f), bs8(0xda), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pminuw", [bs8(0x0f), bs8(0x38), bs8(0x3a), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pminud", [bs8(0x0f), bs8(0x38), bs8(0x3b), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))


addop("pcmpeqb", [bs8(0x0f), bs8(0x74), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpeqb", [bs8(0x0f), bs8(0x74), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpeqw", [bs8(0x0f), bs8(0x75), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpeqw", [bs8(0x0f), bs8(0x75), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpeqd", [bs8(0x0f), bs8(0x76), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpeqd", [bs8(0x0f), bs8(0x76), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpgtb", [bs8(0x0f), bs8(0x64), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpgtb", [bs8(0x0f), bs8(0x64), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpgtw", [bs8(0x0f), bs8(0x65), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpgtw", [bs8(0x0f), bs8(0x65), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpgtd", [bs8(0x0f), bs8(0x66), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("pcmpgtd", [bs8(0x0f), bs8(0x66), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("pcmpeqq", [bs8(0x0f), bs8(0x38), bs8(0x29), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("pcmpgtq", [bs8(0x0f), bs8(0x38), bs8(0x37), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("punpckhbw", [bs8(0x0f), bs8(0x68), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpckhbw", [bs8(0x0f), bs8(0x68), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpckhwd", [bs8(0x0f), bs8(0x69), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpckhwd", [bs8(0x0f), bs8(0x69), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpckhdq", [bs8(0x0f), bs8(0x6a), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpckhdq", [bs8(0x0f), bs8(0x6a), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpckhqdq", [bs8(0x0f), bs8(0x6d), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))



addop("punpcklbw", [bs8(0x0f), bs8(0x60), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpcklbw", [bs8(0x0f), bs8(0x60), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpcklwd", [bs8(0x0f), bs8(0x61), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpcklwd", [bs8(0x0f), bs8(0x61), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpckldq", [bs8(0x0f), bs8(0x62), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm))
addop("punpckldq", [bs8(0x0f), bs8(0x62), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))

addop("punpcklqdq", [bs8(0x0f), bs8(0x6c), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))


addop("unpckhps", [bs8(0x0f), bs8(0x15), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm))
addop("unpckhpd", [bs8(0x0f), bs8(0x15), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))


addop("unpcklps", [bs8(0x0f), bs8(0x14), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm))
addop("unpcklpd", [bs8(0x0f), bs8(0x14), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))



addop("pinsrb", [bs8(0x0f), bs8(0x3a), bs8(0x20), pref_66] +
      rmmod(xmm_reg, rm_arg_reg_m08) + [u08])
addop("pinsrd", [bs8(0x0f), bs8(0x3a), bs8(0x22), pref_66, bs_opmode32] +
      rmmod(xmm_reg, rm_arg) + [u08])
addop("pinsrq", [bs8(0x0f), bs8(0x3a), bs8(0x22), pref_66] +
      rmmod(xmm_reg, rm_arg_m64) + [bs_opmode64] + [u08])

addop("pinsrw", [bs8(0x0f), bs8(0xc4), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_reg_m16) + [u08])
addop("pinsrw", [bs8(0x0f), bs8(0xc4), pref_66] +
      rmmod(xmm_reg, rm_arg_reg_m16) + [u08])


addop("pextrb", [bs8(0x0f), bs8(0x3a), bs8(0x14), pref_66] +
      rmmod(xmm_reg, rm_arg_reg_m08) + [u08], [rm_arg_reg_m08, xmm_reg, u08])
addop("pextrd", [bs8(0x0f), bs8(0x3a), bs8(0x16), pref_66, bs_opmode32] +
      rmmod(xmm_reg, rm_arg) + [u08], [rm_arg, xmm_reg, u08])
addop("pextrq", [bs8(0x0f), bs8(0x3a), bs8(0x16), pref_66] +
      rmmod(xmm_reg, rm_arg_m64) + [bs_opmode64] + [u08], [rm_arg_m64, xmm_reg, u08])


addop("pextrw", [bs8(0x0f), bs8(0x3a), bs8(0x15), pref_66] +
      rmmod(xmm_reg, rm_arg_reg_m16) + [u08], [rm_arg_reg_m16, xmm_reg, u08])
addop("pextrw", [bs8(0x0f), bs8(0xc5), no_xmm_pref] +
      rmmod(rmreg, rm_arg_mm) + [u08], [rmreg, rm_arg_mm, u08])
addop("pextrw", [bs8(0x0f), bs8(0xc5), pref_66] +
      rmmod(rmreg, rm_arg_xmm) + [u08], [rmreg, rm_arg_xmm, u08])


addop("sqrtpd", [bs8(0x0f), bs8(0x51), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm))
addop("sqrtps", [bs8(0x0f), bs8(0x51), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm))
addop("sqrtsd", [bs8(0x0f), bs8(0x51), pref_f2] +
      rmmod(xmm_reg, rm_arg_xmm_m64))
addop("sqrtss", [bs8(0x0f), bs8(0x51), pref_f3] +
      rmmod(xmm_reg, rm_arg_xmm_m32))

addop("pmovmskb", [bs8(0x0f), bs8(0xd7), no_xmm_pref] +
      rmmod(reg_modrm, rm_arg_mm_reg))
addop("pmovmskb", [bs8(0x0f), bs8(0xd7), pref_66] +
      rmmod(reg_modrm, rm_arg_xmm_reg))

addop("shufps", [bs8(0x0f), bs8(0xc6), no_xmm_pref] +
      rmmod(xmm_reg, rm_arg_xmm) + [u08])
addop("shufpd", [bs8(0x0f), bs8(0xc6), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm) + [u08])

addop("aesenc", [bs8(0x0f), bs8(0x38), bs8(0xdc), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("aesdec", [bs8(0x0f), bs8(0x38), bs8(0xde), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("aesenclast", [bs8(0x0f), bs8(0x38), bs8(0xdd), pref_66] + rmmod(xmm_reg, rm_arg_xmm))
addop("aesdeclast", [bs8(0x0f), bs8(0x38), bs8(0xdf), pref_66] + rmmod(xmm_reg, rm_arg_xmm))

addop("packsswb", [bs8(0x0f), bs8(0x63), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("packsswb", [bs8(0x0f), bs8(0x63), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("packssdw", [bs8(0x0f), bs8(0x6b), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("packssdw", [bs8(0x0f), bs8(0x6b), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("packuswb", [bs8(0x0f), bs8(0x67), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("packuswb", [bs8(0x0f), bs8(0x67), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("pmullw", [bs8(0x0f), bs8(0xd5), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmullw", [bs8(0x0f), bs8(0xd5), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("pmulhuw", [bs8(0x0f), bs8(0xe4), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmulhuw", [bs8(0x0f), bs8(0xe4), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("pmulhw", [bs8(0x0f), bs8(0xe5), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmulhw", [bs8(0x0f), bs8(0xe5), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("pmuludq", [bs8(0x0f), bs8(0xf4), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmuludq", [bs8(0x0f), bs8(0xf4), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))


addop("psubusb", [bs8(0x0f), bs8(0xd8), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("psubusb", [bs8(0x0f), bs8(0xd8), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("psubusw", [bs8(0x0f), bs8(0xd9), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("psubusw", [bs8(0x0f), bs8(0xd9), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("psubsb", [bs8(0x0f), bs8(0xe8), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("psubsb", [bs8(0x0f), bs8(0xe8), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("psubsw", [bs8(0x0f), bs8(0xe9), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("psubsw", [bs8(0x0f), bs8(0xe9), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))


addop("paddusb", [bs8(0x0f), bs8(0xdc), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("paddusb", [bs8(0x0f), bs8(0xdc), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("paddusw", [bs8(0x0f), bs8(0xdd), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("paddusw", [bs8(0x0f), bs8(0xdd), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("paddsb", [bs8(0x0f), bs8(0xec), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("paddsb", [bs8(0x0f), bs8(0xec), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("paddsw", [bs8(0x0f), bs8(0xed), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("paddsw", [bs8(0x0f), bs8(0xed), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("pmaddwd", [bs8(0x0f), bs8(0xf5), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pmaddwd", [bs8(0x0f), bs8(0xf5), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("psadbw", [bs8(0x0f), bs8(0xf6), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("psadbw", [bs8(0x0f), bs8(0xf6), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("pavgb", [bs8(0x0f), bs8(0xe0), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pavgb", [bs8(0x0f), bs8(0xe0), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))
addop("pavgw", [bs8(0x0f), bs8(0xe3), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_m64))
addop("pavgw", [bs8(0x0f), bs8(0xe3), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_m128))

addop("maskmovq", [bs8(0x0f), bs8(0xf7), no_xmm_pref] +
      rmmod(mm_reg, rm_arg_mm_reg))
addop("maskmovdqu", [bs8(0x0f), bs8(0xf7), pref_66] +
      rmmod(xmm_reg, rm_arg_xmm_reg))

addop("emms", [bs8(0x0f), bs8(0x77)])

addop("incssp", [pref_f3, bs8(0x0f), bs8(0xae)] + rmmod(d5))
addop("rdssp", [pref_f3, bs8(0x0f), bs8(0x1e)] + rmmod(d1, modrm=mod_reg))
addop("saveprevssp", [pref_f3, bs8(0x0f), bs8(0x01), bs8(0xea)])
addop("rstorssp", [pref_f3, bs8(0x0f), bs8(0x01)] + rmmod(d5, rm_arg_xmm, modrm=mod_mem))
addop("wrss", [bs8(0x0f), bs8(0x38), bs8(0xf6)] + rmmod(rmreg, rm_arg), [rm_arg, rmreg])
addop("wruss", [pref_66, bs8(0x0f), bs8(0x38), bs8(0xf5)] + rmmod(rmreg, rm_arg), [rm_arg, rmreg])
addop("setssbsy", [pref_f3, bs8(0x0f), bs8(0x01), bs8(0xe8)])
addop("clrssbsy", [pref_f3, bs8(0x0f), bs8(0xae)] + rmmod(d6, rm_arg_xmm))
addop("endbr64", [pref_f3, bs8(0x0f), bs8(0x1e), bs8(0xfa)])
addop("endbr32", [pref_f3, bs8(0x0f), bs8(0x1e), bs8(0xfb)])

mn_x86.bintree = factor_one_bit(mn_x86.bintree)
# mn_x86.bintree = factor_fields_all(mn_x86.bintree)
"""
mod reg r/m
 XX XXX XXX

"""


def print_size(e):
    print(e, e.size)
    return e
