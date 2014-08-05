#!/usr/bin/env python
#-*- coding:utf-8 -*-

import re
from miasm2.expression.expression import *
from pyparsing import *
from miasm2.core.cpu import *
from collections import defaultdict
import regs as regs_module
from regs import *
from miasm2.ir.ir import *

log = logging.getLogger("x86_arch")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)


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

}

replace_regs32 = {
    AL: EAX[:8],   CL: ECX[:8],   DL: EDX[:8],   BL: EBX[:8],
    AH: EAX[8:16], CH: ECX[8:16], DH: EDX[8:16], BH: EBX[8:16],

    AX: EAX[:16], CX: ECX[:16], DX: EDX[:16], BX: EBX[:16],
    SP: ESP[:16], BP: EBP[:16], SI: ESI[:16], DI: EDI[:16],

    IP: EIP[:16]
}

replace_regs16 = {
    AL: AX[:8],   CL: CX[:8],   DL: DX[:8],   BL: BX[:8],
    AH: AX[8:16], CH: CX[8:16], DH: DX[8:16], BH: BX[8:16],

    AX: AX[:16],  CX: CX[:16],  DX: DX[:16],  BX: BX[:16],
    SP: SP[:16],  BP: BP[:16],  SI: SI[:16],  DI: DI[:16],
}

replace_regs = {16: replace_regs16,
                32: replace_regs32,
                64: replace_regs64}


# parser helper ###########
PLUS = Suppress("+")
MULT = Suppress("*")

COLON = Suppress(":")


LBRACK = Suppress("[")
RBRACK = Suppress("]")

dbreg = Group(gpregs16.parser | gpregs32.parser | gpregs64.parser)
gpreg = (gpregs08.parser | gpregs08_64.parser | gpregs16.parser   |
         gpregs32.parser | gpregs64.parser    | gpregs_xmm.parser |
         gpregs_mm.parser)


def reg2exprid(r):
    if not r.name in all_regs_ids_byname:
        raise ValueError('unknown reg')
    return all_regs_ids_byname[r.name]


def parse_deref_reg(s, l, t):
    t = t[0][0]
    return t[0]


def parse_deref_int(s, l, t):
    t = t[0]
    return t[0]


def parse_deref_regint(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    i1 = ExprInt_from(r1, t[1].arg)
    return r1 + i1


def parse_deref_regreg(s, l, t):
    t = t[0]
    return t[0][0] + t[1][0]


def parse_deref_regregint(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    r2 = reg2exprid(t[1][0])
    i1 = ExprInt_from(r1, t[2].arg)
    return r1 + r2 + i1


def parse_deref_reg_intmreg(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    r2 = reg2exprid(t[1][0])
    i1 = ExprInt_from(r1, t[2].arg)
    return r1 + (r2 * i1)


def parse_deref_reg_intmreg_int(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    r2 = reg2exprid(t[1][0])
    i1 = ExprInt_from(r1, t[2].arg)
    i2 = ExprInt_from(r1, t[3].arg)
    return r1 + (r2 * i1) + i2


def parse_deref_intmreg(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    i1 = ExprInt_from(r1, t[1].arg)
    return r1 * i1


def parse_deref_intmregint(s, l, t):
    t = t[0]
    r1 = reg2exprid(t[0][0])
    i1 = ExprInt_from(r1, t[1].arg)
    i2 = ExprInt_from(r1, t[1].arg)
    return (r1 * i1) + i2


def getreg(s, l, t):
    t = t[0]
    return t[0]


def parse_deref_ptr(s, l, t):
    t = t[0]
    return ExprMem(ExprOp('segm', t[0], t[1]))

def parse_deref_segmoff(s, l, t):
    t = t[0]
    return ExprOp('segm', t[0], t[1])


variable, operand, base_expr = gen_base_expr()


def ast_id2expr(t):
    if not t in mn_x86.regs.all_regs_ids_byname:
        r = ExprId(t)
    else:
        r = mn_x86.regs.all_regs_ids_byname[t]
    return r


def ast_int2expr(a):
    return ExprInt64(a)


my_var_parser = parse_ast(ast_id2expr, ast_int2expr)
base_expr.setParseAction(my_var_parser)

int_or_expr = base_expr

deref_mem_ad = Group(LBRACK + dbreg + RBRACK).setParseAction(parse_deref_reg)
deref_mem_ad |= Group(
    LBRACK + int_or_expr + RBRACK).setParseAction(parse_deref_int)
deref_mem_ad |= Group(
    LBRACK + dbreg + PLUS +
    int_or_expr + RBRACK).setParseAction(parse_deref_regint)
deref_mem_ad |= Group(
    LBRACK + dbreg + PLUS +
    dbreg + RBRACK).setParseAction(parse_deref_regreg)
deref_mem_ad |= Group(
    LBRACK + dbreg + PLUS + dbreg + PLUS +
    int_or_expr + RBRACK).setParseAction(parse_deref_regregint)
deref_mem_ad |= Group(
    LBRACK + dbreg + PLUS + dbreg + MULT +
    int_or_expr + RBRACK).setParseAction(parse_deref_reg_intmreg)
deref_mem_ad |= Group(
    LBRACK + dbreg + PLUS + dbreg + MULT + int_or_expr +
    PLUS + int_or_expr + RBRACK).setParseAction(parse_deref_reg_intmreg_int)
deref_mem_ad |= Group(
    LBRACK + dbreg + MULT +
    int_or_expr + RBRACK).setParseAction(parse_deref_intmreg)
deref_mem_ad |= Group(
    LBRACK + dbreg + MULT + int_or_expr +
    PLUS + int_or_expr + RBRACK).setParseAction(parse_deref_intmregint)


deref_ptr = Group(int_or_expr + COLON +
                  int_or_expr).setParseAction(parse_deref_segmoff)


PTR = Suppress('PTR')


BYTE = Literal('BYTE')
WORD = Literal('WORD')
DWORD = Literal('DWORD')
QWORD = Literal('QWORD')
TBYTE = Literal('TBYTE')


def parse_deref_mem(s, l, t):
    sz = {'BYTE': 8, 'WORD': 16, 'DWORD': 32, 'QWORD': 64, 'TBYTE': 80}
    t = t[0]
    if len(t) == 2:
        s, ptr = t
        return ExprMem(ptr, sz[s[0]])
    elif len(t) == 3:
        s, segm, ptr = t
        return ExprMem(ExprOp('segm', segm[0], ptr), sz[s[0]])
    else:
        raise ValueError('len(t) > 3')

mem_size = Group(BYTE | DWORD | QWORD | WORD | TBYTE)
deref_mem = Group(mem_size + PTR + Optional(Group(int_or_expr + COLON))
                  + deref_mem_ad).setParseAction(parse_deref_mem)


rmarg = Group(gpregs08.parser |
              gpregs08_64.parser |
              gpregs16.parser |
              gpregs32.parser |
              gpregs64.parser |
              gpregs_mm.parser |
              gpregs_xmm.parser
              ).setParseAction(getreg)

rmarg |= deref_mem


cl_or_imm = Group(r08_ecx.parser).setParseAction(getreg)
cl_or_imm |= int_or_expr


class r_al(reg_noarg, m_arg):
    reg_info = r08_eax
    parser = reg_info.parser


class r_ax(reg_noarg, m_arg):
    reg_info = r16_eax
    parser = reg_info.parser


class r_dx(reg_noarg, m_arg):
    reg_info = r16_edx
    parser = reg_info.parser


class r_eax(reg_noarg, m_arg):
    reg_info = r32_eax
    parser = reg_info.parser


class r_rax(reg_noarg, m_arg):
    reg_info = r64_eax
    parser = reg_info.parser


class r_cl(reg_noarg, m_arg):
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
        if rex_w == 1:
            return 64
        elif stk:
            if opmode == 1:
                return 16
            else:
                return 64
        elif opmode == 1:
            return 16
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

segm2enc = {CS: 1, SS: 2, DS: 3, ES: 4, FS: 5, GS: 6}
enc2segm = dict([(x[1], x[0]) for x in segm2enc.items()])


class group:

    def __init__(self):
        self.value = None


class additional_info:

    def __init__(self):
        self.except_on_instr = False
        self.g1 = group()
        self.g2 = group()
        self.vopmode = None
        self.stk = False
        self.v_opmode = None
        self.v_admode = None
        self.prefixed = ''


class instruction_x86(instruction):
    delayslot = 0

    def __init__(self, *args, **kargs):
        super(instruction_x86, self).__init__(*args, **kargs)
        self.additional_info.stk = hasattr(self, 'stk')

    def v_opmode(self):
        return self.additional_info.v_opmode

    def v_admode(self):
        return self.additional_info.v_admode

    def dstflow(self):
        if self.name.startswith('J'):
            return True
        if self.name.startswith('LOOP'):
            return True
        # repxx yyy generate split flow
        # if self.g1.value & 6 and self.name in repeat_mn:
        #    return True
        return self.name in ['CALL']

    def dstflow2label(self, symbol_pool):
        if self.additional_info.g1.value & 6 and self.name in repeat_mn:
            return
        e = self.args[0]
        if isinstance(e, ExprId) and not e.name in all_regs_ids_byname:
            l = symbol_pool.getby_name_create(e.name)
            s = ExprId(l, e.size)
            self.args[0] = s
        elif isinstance(e, ExprInt):
            ad = e.arg + int(self.offset) + self.l
            l = symbol_pool.getby_offset_create(ad)
            s = ExprId(l, e.size)
            self.args[0] = s
        else:
            return

    def breakflow(self):
        if self.name.startswith('J'):
            return True
        if self.name.startswith('LOOP'):
            return True
        if self.name.startswith('RET'):
            return True
        if self.name.startswith('INT'):
            return True
        if self.name.startswith('SYS'):
            return True
        # repxx yyy generate split flow
        # if self.g1.value & 6 and self.name in repeat_mn:
        #    return True
        return self.name in ['CALL', 'HLT', 'IRET', 'ICEBP']

    def splitflow(self):
        if self.name.startswith('JMP'):
            return False
        if self.name.startswith('J'):
            return True
        if self.name.startswith('LOOP'):
            return True
        if self.name.startswith('INT'):
            return True
        if self.name.startswith('SYS'):
            return True
        # repxx yyy generate split flow
        # if self.g1.value & 6 and self.name in repeat_mn:
        #    return True
        return self.name in ['CALL']

    def setdstflow(self, a):
        return

    def is_subcall(self):
        return self.name in ['CALL']

    def getdstflow(self, symbol_pool):
        if self.additional_info.g1.value & 6 and self.name in repeat_mn:
            ad = int(self.offset)
            l = symbol_pool.getby_offset_create(ad)
            # XXX size ???
            s = ExprId(l, self.v_opmode())
            return [s]
        return [self.args[0]]

    def get_symbol_size(self, symbol, symbol_pool):
        return self.mode

    def fixDstOffset(self):
        e = self.args[0]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % l)
        if not isinstance(e, ExprInt):
            # raise ValueError('dst must be int or label')
            log.warning('dynamic dst %r' % e)
            return
        # return ExprInt32(e.arg - (self.offset + self.l))
        self.args[0] = ExprInt_fromsize(
            self.mode, e.arg - (self.offset + self.l))

    def get_info(self, c):
        self.additional_info.g1.value = c.g1.value
        self.additional_info.g2.value = c.g2.value
        self.additional_info.v_opmode = c.v_opmode()
        self.additional_info.v_admode = c.v_admode()
        self.additional_info.prefix = c.prefix
        self.additional_info.prefixed = getattr(c, "prefixed", "")

    def __str__(self):
        o = super(instruction_x86, self).__str__()
        if self.additional_info.g1.value & 1:
            o = "LOCK %s" % o
        if self.additional_info.g1.value & 2:
            if getattr(self.additional_info.prefixed, 'default', "") != "\xF2":
                o = "REPNE %s" % o
        if self.additional_info.g1.value & 4:
            if getattr(self.additional_info.prefixed, 'default', "") != "\xF3":
                o = "REPE %s" % o
        return o

    def get_args_expr(self):
        args = []
        for a in self.args:
            a = a.replace_expr(replace_regs[self.mode])
            args.append(a)
        return args

    @staticmethod
    def arg2str(e, pos = None):
        if isinstance(e, ExprId) or isinstance(e, ExprInt):
            o = str(e)
        elif isinstance(e, ExprMem):
            sz = {8: 'BYTE', 16: 'WORD', 32: 'DWORD',
                  64: 'QWORD', 80: 'TBYTE'}[e.size]
            segm = ""
            if e.is_op_segm():
                segm = "%s:" % e.arg.args[0]
                e = e.arg.args[1]
            else:
                e = e.arg
            if isinstance(e, ExprOp):
                # s = str(e.arg)[1:-1]
                s = str(e).replace('(', '').replace(')', '')
            else:
                s = str(e)
            o = sz + ' PTR %s[%s]' % (segm, s)
        elif isinstance(e, ExprOp) and e.op == 'segm':
            o = "%s:%s" % (e.args[0], e.args[1])
        else:
            raise ValueError('check this %r' % e)
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
        info.v_opmode = self.v_opmode()
        info.prefixed = ""
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
    def fromstring(cls, s, mode):
        pref = 0
        prefix, new_s = get_prefix(s)
        if prefix == "LOCK":
            pref |= 1
            s = new_s
        elif prefix == "REPNE":
            pref |= 2
            s = new_s
        elif prefix == "REPE":
            pref |= 4
            s = new_s
        c = super(mn_x86, cls).fromstring(s, mode)
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
                        'prefix': "",
                        'prefixed': "",
                        }
        while True:
            c = v.getbytes(offset)
            if c == '\x66':
                # pre_dis_info.opmode = 1
                pre_dis_info['opmode'] = 1
            elif c == '\x67':
                pre_dis_info['admode'] = 1
            elif c == '\xf0':
                pre_dis_info['g1'] = 1
            elif c == '\xf2':
                pre_dis_info['g1'] = 2
            elif c == '\xf3':
                pre_dis_info['g1'] = 4

            elif c == '\x2e':
                pre_dis_info['g2'] = 1
            elif c == '\x36':
                pre_dis_info['g2'] = 2
            elif c == '\x3e':
                pre_dis_info['g2'] = 3
            elif c == '\x26':
                pre_dis_info['g2'] = 4
            elif c == '\x64':
                pre_dis_info['g2'] = 5
            elif c == '\x65':
                pre_dis_info['g2'] = 6

            elif mode == 64 and c in '@ABCDEFGHIJKLMNO':
                x = ord(c)
                pre_dis_info['rex_p'] = 1
                pre_dis_info['rex_w'] = (x >> 3) & 1
                pre_dis_info['rex_r'] = (x >> 2) & 1
                pre_dis_info['rex_x'] = (x >> 1) & 1
                pre_dis_info['rex_b'] = (x >> 0) & 1
                offset += 1
                break
            else:
                c = ''
                break
            pre_dis_info['prefix'] += c
            offset += 1
        # pre_dis_info.b = v[:offset]
        return pre_dis_info, v, mode, offset, offset - offset_o

    @classmethod
    def get_cls_instance(cls, cc, mode, infos=None):
        for opmode in [0, 1]:
            for admode in [0, 1]:
                # c = cls.all_mn_inst[cc][0]
                c = cc()
                c.init_class()

                c.reset_class()
                c.add_pre_dis_info()
                c.dup_info(infos)

                c.mode = mode
                c.opmode = opmode
                c.admode = admode

                if hasattr(c, "fopmode") and c.fopmode.mode == 64:
                    c.rex_w.value = 1
                yield c

    def post_dis(self):
        if self.g2.value:
            for a in self.args:
                if not isinstance(a.expr, ExprMem):
                    continue
                m = a.expr
                a.expr = ExprMem(
                    ExprOp('segm', enc2segm[self.g2.value], m.arg), m.size)
        if self.name == 'LEA':
            if not isinstance(self.args[1].expr, ExprMem):
                return None
        return self

    def dup_info(self, infos):
        if infos is not None:
            self.g1.value = infos.g1.value
            self.g2.value = infos.g2.value

    def reset_class(self):
        super(mn_x86, self).reset_class()
        # self.rex_w.value, self.rex_b.value,
        # self.rex_x.value = None, None, None
        # self.opmode.value, self.admode.value = None, None
        if hasattr(self, "opmode"):
            del(self.opmode)
        if hasattr(self, "admode"):
            del(self.admode)
        # self.opmode = 0
        # self.admode = 0

    def add_pre_dis_info(self, pre_dis_info=None):
        # print 'add_pre_dis_info', pre_dis_info

        if pre_dis_info is None:
            return True
        if hasattr(self, "prefixed") and self.prefixed.default == "\x66":
            pre_dis_info['opmode'] = 0
            # if self.opmode != 0:
            #    return False

        # if pre_dis_info['opmode'] != self.opmode:
        #    return False
        # if pre_dis_info['admode'] != self.admode:
        #    return False
        self.opmode = pre_dis_info['opmode']
        self.admode = pre_dis_info['admode']

        if hasattr(self, 'no_xmm_pref') and\
                pre_dis_info['prefix'] and\
                pre_dis_info['prefix'][-1] in '\x66\xf2\xf3':
            return False
        if (hasattr(self, "prefixed") and
            not pre_dis_info['prefix'].endswith(self.prefixed.default)):
            return False
        # print self.rex_w.value, pre_dis_info['rex_w']
        # print 'rex', self.rex_w.value, self.rex_b.value, self.rex_x.value
        if (self.rex_w.value is not None and
            self.rex_w.value != pre_dis_info['rex_w']):
            return False
        else:
            self.rex_w.value = pre_dis_info['rex_w']
        self.rex_r.value = pre_dis_info['rex_r']
        self.rex_b.value = pre_dis_info['rex_b']
        self.rex_x.value = pre_dis_info['rex_x']
        self.rex_p.value = pre_dis_info['rex_p']
        self.g1.value = pre_dis_info['g1']
        self.g2.value = pre_dis_info['g2']
        self.prefix = pre_dis_info['prefix']
        # self.prefixed = pre_dis_info['prefixed']

        """
        if hasattr(self, "p_"):
            self.prefixed = self.p_.default
            if self.p_.default == "\x66":
                pre_dis_info['opmode'] = 0
                if self.opmode != 0:
                    return False
        #self.pre_dis_info = pre_dis_info
        """
        return True

    def post_asm(self, v):
        return v

    def encodefields(self, decoded):
        v = super(mn_x86, self).encodefields(decoded)

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
            v = chr(rex) + v

        if hasattr(self, 'prefixed'):
            v = self.prefixed.default + v

        if self.g1.value & 1:
            v = "\xf0" + v
        if self.g1.value & 2:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = "\xf2" + v
        if self.g1.value & 4:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = "\xf3" + v
        if self.g2.value:
            v = {1: '\x2e', 2: '\x36', 3: '\x3e', 4:
                 '\x26', 5: '\x64', 6: '\x65'}[self.g2.value] + v
        # mode prefix
        if hasattr(self, "admode") and self.admode:
            v = "\x67" + v

        if hasattr(self, "opmode") and self.opmode:
            if hasattr(self, 'no_xmm_pref'):
                return None
            v = "\x66" + v

        return v

    def getnextflow(self, symbol_pool):
        raise NotImplementedError('not fully functional')
        return self.offset + 4

    def ir_pre_instruction(self):
        return [ExprAff(mRIP[self.mode],
            ExprInt_from(mRIP[self.mode], self.offset + self.l))]

    @classmethod
    def filter_asm_candidates(cls, instr, candidates):

        cand_same_mode = []
        cand_diff_mode = []
        out = []
        for c, v in candidates:
            if (hasattr(c, 'no_xmm_pref') and
                (c.g1.value & 2 or c.g1.value & 4 or c.opmode)):
                continue
            if hasattr(c, "fopmode") and v_opmode(c) != c.fopmode.mode:
                # print 'DROP', c, v_opmode(c), c.fopmode.mode
                continue
            if hasattr(c, "fadmode") and v_admode(c) != c.fadmode.mode:
                # print 'DROP', c, v_opmode(c), c.fopmode.mode
                continue
            # relative dstflow must not have opmode set
            # (affect IP instead of EIP for instance)
            if (instr.dstflow() and
                instr.name not in ["JCXZ", "JECXZ", "JRCXZ"] and
                len(instr.args) == 1 and
                    isinstance(instr.args[0], ExprInt) and c.opmode):
                continue

            out.append((c, v))
        candidates = out
        # return [x[1][0] for x in candidates]
        for c, v in candidates:
            if v_opmode(c) == instr.mode:
                cand_same_mode += v
        for c, v in candidates:
            if v_opmode(c) != instr.mode:
                cand_diff_mode += v
        cand_same_mode.sort(key=lambda x: len(x))
        cand_diff_mode.sort(key=lambda x: len(x))
        return cand_same_mode + cand_diff_mode


class bs8(bs):
    prio = default_prio

    def __init__(self, v, cls=None, fname=None, **kargs):
        super(bs8, self).__init__(int2bin(v, 8), 8,
                                  cls=cls, fname=fname, **kargs)


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
            # no mode64 existance in name means no 64bit version of mnemo
            if mode == 64:
                if mode in self.args['name']:
                    nfields = fields[:]
                    f, i = getfieldindexby_name(nfields, 'rex_w')
                    # f = bs("1", l=0, fname = 'rex_w')
                    f = bs("1", l=0, cls=(bs_fbit,), fname="rex_w")
                    osize = v_opmode_info(size, opmode, 1, 0)
                    nfields[i] = f
                    nfields = nfields[:-1]
                    args = dict(self.args)
                    ndct = dict(dct)
                    if osize in self.args['name']:
                        ndct['name'] = self.args['name'][osize]
                        out.append((cls, ndct['name'], bases, ndct, nfields))

                    nfields = fields[:]
                    nfields = nfields[:-1]
                    f, i = getfieldindexby_name(nfields, 'rex_w')
                    # f = bs("0", l=0, fname = 'rex_w')
                    f = bs("0", l=0, cls=(bs_fbit,), fname="rex_w")
                    osize = v_opmode_info(size, opmode, 0, 0)
                    nfields[i] = f
                    args = dict(self.args)
                    ndct = dict(dct)
                    if osize in self.args['name']:
                        ndct['name'] = self.args['name'][osize]
                        out.append((cls, ndct['name'], bases, ndct, nfields))
            else:
                l = opmode_prefix((dct['mode'], dct['opmode'], dct['admode']))
                osize = v_opmode_info(size, opmode, None, 0)
                nfields = fields[:-1]
                args = dict(self.args)
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


class x86_imm_fix(imm_noarg):
    parser = base_expr

    def decodeval(self, v):
        return self.ival

    def encodeval(self, v):
        if v != self.ival:
            return False
        return self.ival


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
        e = sign_ext(v, self.intsize, admode)
        e = ExprInt_fromsize(admode, e)
        self.expr = e
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
        return ExprInt16(x)

    def int2expr(self, v):
        return self.myexpr(v)

    def expr2int(self, e):
        if not isinstance(e, ExprInt):
            return None
        v = int(e.arg)
        if v & ~((1 << self.l) - 1) != 0:
            return None
        return v

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if self.parent.v_opmode() == 64:
            self.expr = ExprInt64(sign_ext(v, self.in_size, 64))
        else:
            if (1 << (self.l - 1)) & v:
                v = sign_ext(v, self.l, self.out_size)
            self.expr = self.myexpr(v)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr.arg)
        opmode = self.parent.v_opmode()

        out_size = self.out_size
        if opmode != self.out_size:
            if opmode == 32 and self.out_size == 64:
                out_size = opmode
                if v == sign_ext(
                    int(v & ((1 << self.in_size) - 1)), self.in_size, out_size):
                    pass
                else:
                    # print 'cannot encode1', hex(v),
                    # print hex(sign_ext(int(v&((1<<self.in_size)-1)),
                    #     self.in_size, out_size))
                    # test with rex_w
                    self.parent.rex_w.value = 1
                    opmode = self.parent.v_opmode()
                    out_size = opmode
                    if (v != sign_ext(
                        int(v & ((1 << self.in_size) - 1)),
                        self.in_size, out_size)):
                        # print 'cannot encode2', hex(v),
                        # hex(sign_ext(int(v&((1<<self.in_size)-1)),
                        # self.in_size, out_size))
                        return False
                    else:
                        pass
            else:
                pass
        if v != sign_ext(
            int(v & ((1 << self.in_size) - 1)), self.in_size, out_size):
            # print 'cannot encode3', hex(v),
            # hex(sign_ext(int(v&((1<<self.in_size)-1)), self.in_size,
            # self.out_size))
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
        return ExprInt32(x)

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if self.parent.rex_w.value == 1:
            v = ExprInt64(sign_ext(v, self.in_size, 64))
        else:
            v = ExprInt32(sign_ext(v, self.in_size, 32))

        self.expr = v
        # print "INT1", self.parent.rex_w.value, self.expr, self.expr.size
        return True


class x86_s08to64(x86_s08to16):
    in_size = 8
    out_size = 64

    def myexpr(self, x):
        return ExprInt64(x)

    def decode(self, v):
        v = v & self.lmask
        v = self.decodeval(v)
        if self.parent.rex_w.value == 1:
            v = ExprInt64(sign_ext(v, self.in_size, 64))
        else:
            v = ExprInt32(sign_ext(v, self.in_size, 32))

        self.expr = v
        # print "INT1X", self.parent.prefix.rex_w, self.expr, self.expr.size
        return True


class x86_s32to64(x86_s08to32):
    in_size = 32
    out_size = 64

    def myexpr(self, x):
        return ExprInt64(x)


class bs_eax(m_arg):
    reg_info = r_eax_all
    rindex = 0
    parser = reg_info.parser

    def decode(self, v):
        p = self.parent
        e = None
        if hasattr(p, 'w8') and p.w8.value == 0:
            e = regs08_expr[self.rindex]
        else:
            e = size2gpregs[p.v_opmode()].expr[self.rindex]
        self.expr = e
        return True

    def encode(self):
        self.value = 0
        p = self.parent
        e = self.expr
        # print "EEEEE", e, p.w8.value
        # print 'XXX', p.mode, p.opmode
        osize = p.v_opmode()
        if hasattr(p, 'w8'):
            if p.w8.value is None:
                # XXX TODO: priority in w8 erase?
                if e.size == 8:
                    p.w8.value = 0
                else:
                    p.w8.value = 1
        if hasattr(p, 'w8') and p.w8.value == 0:
            return e == regs08_expr[self.rindex]
        elif p.mode in [16, 32]:
            return e == size2gpregs[osize].expr[self.rindex]
        elif p.mode == 64:
            if e == size2gpregs[64].expr[self.rindex]:
                p.rex_w.value = 1
                return True
            elif e == size2gpregs[osize].expr[self.rindex]:
                return True
            return False


class bs_seg(m_arg):
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


class x86_reg_st(reg_noarg, m_arg):
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
    for rex_x in xrange(2):
        o = []
        for rex_b in xrange(2):
            x = [{f_isad: True} for i in range(0x100)]
            o.append(x)
        sib_u64.append(o)

    sib_u64_ebp = []
    for rex_x in xrange(2):
        o = []
        for rex_b in xrange(2):
            x = [{f_isad: True} for i in range(0x100)]
            o.append(x)
        sib_u64_ebp.append(o)

    sib_64_s08_ebp = []
    for rex_x in xrange(2):
        o = []
        for rex_b in xrange(2):
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
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                            sib_rez[rex_x][rex_b][index][ebp + 8 * rex_b] = 1
                elif sib_rez == sib_u64:
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                elif sib_rez == sib_64_s08_ebp:
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
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
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
                            sib_rez[rex_x][rex_b][index][b + 8 * rex_b] = 1
                            sib_rez[rex_x][rex_b][index][f_imm] = f_u32
                elif sib_rez == sib_u64:
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
                            sib_rez[rex_x][rex_b][index][b + 8 * rex_b] = 1
                elif sib_rez == sib_64_s08_ebp:
                    for rex_b in xrange(2):
                        for rex_x in xrange(2):
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
                for rex_b in xrange(2):
                    for rex_x in xrange(2):
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
    for size, db_afs in byte2modrm.items():
        for i, modrm in enumerate(db_afs):
            if not isinstance(modrm, list):
                modrm = modrm.items()
                modrm.sort()
                modrm = tuple(modrm)
                modrm2byte[size][modrm].append(i)
                continue
            for j, modrm_f in enumerate(modrm):
                modrm_f = modrm_f.items()
                modrm_f.sort()
                modrm_f = tuple(modrm_f)
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
                if out and r1:
                    raise ValueError('multiple displacement!')
                out = r
            return out
        elif e.op == "*":
            mul = int(e.args[1].arg)
            a = e.args[0]
            i = size2gpregs[a.size].expr.index(a)
            o[i] = mul
        else:
            raise ValueError('bad op')
    return None


def expr2modrm(e, p, w8, sx=0, xmm=0, mm=0):
    o = {}
    if e.size == 64 and not e in gpregs_mm.expr:
        if hasattr(p, 'sd'):
            p.sd.value = 1
        # print 'set64pref', str(e)
        elif hasattr(p, 'wd'):
            pass
        elif hasattr(p, 'stk'):
            pass
        else:
            p.rex_w.value = 1
    opmode = p.v_opmode()
    if sx == 1:
        opmode = 16
    if sx == 2:
        opmode = 32
    if e.size == 8 and w8 != 0:
        return None, None, False

    if w8 == 0 and e.size != 8:
        return None, None, False

    if not isinstance(e, ExprMem):
        o[f_isad] = False
        if xmm:
            if e in gpregs_xmm.expr:
                i = gpregs_xmm.expr.index(e)
                o[i] = 1
                return [o], None, True
            else:
                return None, None, False
        if mm:
            if e in gpregs_mm.expr:
                i = gpregs_mm.expr.index(e)
                o[i] = 1
                return [o], None, True
            else:
                return None, None, False
        if w8 == 0:
            # if (p.v_opmode() == 64 or p.rex_p.value == 1) and e in
            # gpregs08_64.expr:
            if p.mode == 64 and e in gpregs08_64.expr:
                r = gpregs08_64
                p.rex_p.value = 1
            else:
                p.rex_p.value = 0
                p.rex_x.value = 0
                r = size2gpregs[8]
            if not e in r.expr:
                return None, None, False
            i = r.expr.index(e)
            o[i] = 1
            return [o], None, True
        # print "ttt", opmode, e.size
        if opmode != e.size:
            # print "FFFF"
            return None, None, False
        if not e in size2gpregs[opmode].expr:
            return None, None, False
        i = size2gpregs[opmode].expr.index(e)
        # print 'aaa', p.mode, i
        if i > 7:
            if p.mode == 64:
                # p.rex_b.value = 1
                # i -=7
                # print "SET REXB"
                pass
            else:
                return None, None, False
        o[i] = 1
        return [o], None, True
    if e.is_op_segm() and isinstance(e.arg.args[0], ExprInt):
        return None, None, False

    if e.is_op_segm():
        segm = e.arg.args[0]
        ptr = e.arg.args[1]
    else:
        segm = None
        ptr = e.arg

    o[f_isad] = True
    ad_size = ptr.size
    admode = p.v_admode()
    if ad_size != admode:
        return None, None, False
    """
    if e.size == 64:
        if hasattr(p, 'sd'):
            p.sd.value = 1
        else:
            p.rex_w.value = 1
    """

    if w8 == 1 and e.size != opmode:  # p.v_opmode():
        if not (hasattr(p, 'sd') or hasattr(p, 'wd')):
            return None, None, False
    # print 'tttt'

    if hasattr(p, 'wd'):
        s = e.size
        if s == 16:
            p.wd.value = 1
        elif s == 32:
            pass
        else:
            return None, None, False

    if p.mode == 64 and ptr.size == 32:
        if p.admode != 1:
            return None, None, False

    o = {f_isad: True}
    disp = exprfindmod(ptr, o)
    out = []
    if disp is None:
        # add 0 disp
        disp = ExprInt32(0)
    if disp is not None:
        for s, x in [(f_s08, ExprInt8), (f_s16, ExprInt16), (f_s32, ExprInt32),
                     (f_u08, ExprInt8), (f_u16, ExprInt16), (f_u32, ExprInt32)]:
            # print "1", disp
            v = x(int(disp.arg))
            # print "2", v, hex(sign_ext(int(v.arg), v.size, disp.size))
            if int(disp.arg) != sign_ext(int(v.arg), v.size, disp.size):
                # print 'nok'
                continue
            # print 'ok', s, v
            x1 = dict(o)
            x1[f_imm] = (s, v)
            out.append(x1)
    else:
        out = [o]
    return out, segm, True


def modrm2expr(m, p, w8, sx=0, xmm=0, mm=0):
    o = []
    if not m[f_isad]:
        k = [x[0] for x in m.items() if x[1] == 1]
        if len(k) != 1:
            raise ValueError('strange reg encoding %r' % m)
        k = k[0]
        if w8 == 0:
            opmode = 8
        elif sx == 1:
            opmode = 16
        elif sx == 2:
            opmode = 32
        else:
            opmode = p.v_opmode()
        """
        if k > 7:
            # XXX HACK TODO
            e = size2gpregs[64].expr[k]
        else:
            e = size2gpregs[opmode].expr[k]
        """
        # print 'yyy', opmode, k
        if xmm:
            e = gpregs_xmm.expr[k]
        elif mm:
            e = gpregs_mm.expr[k]
        elif opmode == 8 and (p.v_opmode() == 64 or p.rex_p.value == 1):
            e = gpregs08_64.expr[k]
        else:
            e = size2gpregs[opmode].expr[k]
        return e
    # print "enc", m, p.v_admode(), p.prefix.opmode, p.prefix.admode
    admode = p.v_admode()
    opmode = p.v_opmode()
    for k, v in m.items():
        if type(k) in [int, long]:
            e = size2gpregs[admode].expr[k]
            if v != 1:
                e = ExprInt_fromsize(admode, v) * e
            o.append(e)
    # print [str(x) for x in o]
    if f_imm in m:
        if p.disp.value is None:
            return None
        o.append(ExprInt_fromsize(admode, p.disp.expr.arg))
    e = ExprOp('+', *o)
    if w8 == 0:
        opmode = 8
    elif sx == 1:
        opmode = 16
    elif sx == 2:
        opmode = 32
    e = ExprMem(e, size=opmode)
    # print "mem size", opmode, e
    return e


class x86_rm_arg(m_arg):
    parser = rmarg

    def fromstring(self, s, parser_result=None):
        start, stop = super(x86_rm_arg, self).fromstring(s, parser_result)
        e = self.expr
        p = self.parent
        if start is None:
            return None, None
        s = e.size
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
            # print 'SIB', hex(v)
            # v |= p.rex_b.value << 8
            # v |= p.rex_x.value << 9
            # if v >= 0x100:
            #    pass
            xx = xx[v]
        return xx

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        mm = hasattr(self.parent, "mm")
        xmm = hasattr(self.parent, "xmm")
        e = modrm2expr(xx, p, 1, xmm=xmm, mm=mm)
        if e is None:
            return False
        self.expr = e
        return True

    def gen_cand(self, v_cand, admode):
        # print "GEN CAND"
        if not admode in modrm2byte:
            # XXX TODO: 64bit
            raise StopIteration
        if not v_cand:
            raise StopIteration

        p = self.parent
        o_rex_x = p.rex_x.value
        o_rex_b = p.rex_b.value
        # add candidate without 0 imm
        new_v_cand = []
        moddd = False
        for v in v_cand:
            new_v_cand.append(v)
            # print 'CANDI', v, admode
            if f_imm in v and int(v[f_imm][1].arg) == 0:
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
                disp = int(disp.arg)
                # disp = swap_uint(f_imm2size[size], int(disp))

                v[f_imm] = size
            vo = v
            # print 'vv', v, disp
            v = v.items()
            v.sort()
            v = tuple(v)
            # print "II", e, admode
            # print 'III', v
            # if (8, 1) in v:
            #    pass
            if not v in modrm2byte[admode]:
                # print 'cannot find'
                continue
            # print "FOUND1", v
            xx = modrm2byte[admode][v]
            # if opmode == 64 and admode == 64:
            #    pdb.set_trace()

            # print "FOUND2", xx
            # default case
            for x in xx:
                if type(x) == tuple:
                    modrm, sib = x
                else:
                    modrm = x
                    sib = None
                # print 'mod sib', hex(modrm), sib
                # print p.sib_scale
                # print p.sib_base
                # print p.sib_index

                # 16 bit cannot have sib
                if (not sib is None) and admode == 16:
                    continue
                # if ((p.sib_scale and sib is None) or
                #     (p.sib_scale is None and sib)):
                # log.debug('dif sib %r %r'%(p.sib_scale, sib))
                #    continue
                # print hex(modrm), sib
                # p.mod.value, dum, p.rm.value = getmodrm(modrm)
                rex = modrm >> 8  # 0# XXX HACK REM temporary REX modrm>>8
                if rex and admode != 64:
                    continue
                # print 'prefix', hex(rex)
                # p.rex_x.value = o_rex_x
                # p.rex_b.value = o_rex_b

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
                # p.mod.value.append(mod)
                # p.rm.value.append(rm)

                if sib:
                    # print 'REX', p.rex_x.value, p.rex_b.value
                    # print hex(modrm), hex(sib)
                    # if (modrm & 0xFF == 4 and sib & 0xFF == 0x5
                    #    and p.rex_b.value ==1 and p.rex_x.value == 0):
                    #    pass
                    s_scale, s_index, s_base = getmodrm(sib)
                    # p.sib_scale.value, p.sib_index.value,
                    # p.sib_base.value = getmodrm(sib)
                    # p.sib_scale.decode(mod)
                    # p.sib_index.decode(re)
                    # p.sib_base.decode(rm)
                    # p.sib_scale.value.append(mod)
                    # p.sib_index.value.append(re)
                    # p.sib_base.value.append(rm)
                else:
                    # p.sib_scale.value.append(None)
                    # p.sib_index.value.append(None)
                    # p.sib_base.value.append(None)
                    s_scale, s_index, s_base = None, None, None

                # print 'IIII', repr(p.disp), f_imm in v
                # if p.disp and not f_imm in vo:
                #    continue
                # if not p.disp and f_imm in vo:
                #    continue
                # if p.disp:
                #    if p.disp.l != f_imm2size[vo[f_imm]]:
                #        continue
                # print "DISP", repr(p.disp), p.disp.l
                # p.disp.value = int(disp.arg)
                # print 'append'
                # print mod, rm, s_scale, s_index, s_base, disp
                # print p.mod, p.rm
                # out_c.append((mod, rm, s_scale, s_index, s_base, disp))
                p.mod.value = mod
                p.rm.value = rm
                p.sib_scale.value = s_scale
                p.sib_index.value = s_index
                p.sib_base.value = s_base
                p.disp.value = disp
                if disp is not None:
                    p.disp.l = f_imm2size[vo[f_imm]]

                yield True

        raise StopIteration

    def encode(self):
        e = self.expr
        # print "eee", e
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        admode = p.v_admode()
        mode = e.size
        mm = hasattr(self.parent, 'mm')
        xmm = hasattr(self.parent, 'xmm')
        v_cand, segm, ok = expr2modrm(e, p, 1, xmm=xmm, mm=mm)
        if segm:
            p.g2.value = segm2enc[segm]
        # print "REZ1", v_cand, ok
        for x in self.gen_cand(v_cand, admode):
            yield x


class x86_rm_w8(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, p.w8.value)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        if p.w8.value is None:
            if e.size == 8:
                p.w8.value = 0
            else:
                p.w8.value = 1

        # print 'TTTTT', e
        v_cand, segm, ok = expr2modrm(e, p, p.w8.value)
        if segm:
            p.g2.value = segm2enc[segm]
        # print "REZ2", v_cand, ok
        for x in self.gen_cand(v_cand, p.v_admode()):
            # print 'REZ', p.rex_x.value
            yield x


class x86_rm_sx(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, p.w8.value, 1)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        if p.w8.value is None:
            if e.size == 8:
                p.w8.value = 0
            else:
                p.w8.value = 1
        v_cand, segm, ok = expr2modrm(e, p, p.w8.value, 1)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_sxd(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, 1, 2)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        v_cand, segm, ok = expr2modrm(e, p, 1, 2)
        if segm:
            p.g2.value = segm2enc[segm]
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_sd(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, 1)
        if not isinstance(e, ExprMem):
            return False
        if p.sd.value == 0:
            e = ExprMem(e.arg, 32)
        else:
            e = ExprMem(e.arg, 64)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        if not e.size in [32, 64]:
            raise StopIteration
        p.sd.value = 0
        v_cand, segm, ok = expr2modrm(e, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_wd(x86_rm_arg):

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, 1)
        if not isinstance(e, ExprMem):
            return False
        if p.wd.value == 0:
            e = ExprMem(e.arg, 32)
        else:
            e = ExprMem(e.arg, 16)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        p = self.parent
        p.wd.value = 0
        v_cand, segm, ok = expr2modrm(e, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m80(x86_rm_arg):
    msize = 80

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        # print "aaa", xx
        e = modrm2expr(xx, p, 1)
        if not isinstance(e, ExprMem):
            return False
        e = ExprMem(e.arg, self.msize)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if isinstance(e, ExprInt):
            raise StopIteration
        if not isinstance(e, ExprMem) or e.size != self.msize:
            raise StopIteration
        p = self.parent
        mode = p.mode
        if mode == 64:
            mode = 32
        e = ExprMem(e.arg, mode)
        v_cand, segm, ok = expr2modrm(e, p, 1)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m08(x86_rm_arg):
    msize = 8

    def decode(self, v):
        p = self.parent
        xx = self.get_modrm()
        e = modrm2expr(xx, p, 0)
        self.expr = e
        return e is not None

    def encode(self):
        e = self.expr
        if e.size != 8:
            raise StopIteration
        """
        if not isinstance(e, ExprMem) or e.size != self.msize:
            raise StopIteration
        """
        p = self.parent
        mode = p.mode
        # if mode == 64:
        #    mode = 32
        # e = ExprMem(e.arg, mode)
        v_cand, segm, ok = expr2modrm(e, p, 0)
        for x in self.gen_cand(v_cand, p.v_admode()):
            yield x


class x86_rm_m16(x86_rm_m80):
    msize = 16


class x86_rm_m64(x86_rm_m80):
    msize = 64


class x86_rm_reg_noarg(object):
    prio = default_prio + 1

    parser = gpreg

    def fromstring(self, s, parser_result=None):
        # print 'parsing reg', s, opmode
        if not hasattr(self.parent, 'sx') and hasattr(self.parent, "w8"):
            self.parent.w8.value = 1
        if parser_result:
            e, start, stop = parser_result[self.parser]
            # print 'reg result', e, start, stop
            if e is None:
                return None, None
            self.expr = e
            if self.expr.size == 8:
                if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                    return None, None
                self.parent.w8.value = 0
            return start, stop
        try:
            v, start, stop = self.parser.scanString(s).next()
        except StopIteration:
            return None, None
        self.expr = v[0]
        if self.expr.size == 0:
            if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                return None, None
            self.parent.w8.value = 0

        # print 'parsed', s, self.expr
        return start, stop

    def getrexsize(self):
        return self.parent.rex_r.value

    def setrexsize(self, v):
        self.parent.rex_r.value = v

    def decode(self, v):
        v = v & self.lmask
        p = self.parent
        opmode = p.v_opmode()
        # if hasattr(p, 'sx'):
        #    opmode = 16
        if not hasattr(p, 'sx') and (hasattr(p, 'w8') and p.w8.value == 0):
            opmode = 8
        r = size2gpregs[opmode]
        if p.mode == 64 and self.getrexsize():
            v |= 0x8
        # print "XXX", p.v_opmode(), p.rex_p.value
        if p.v_opmode() == 64 or p.rex_p.value == 1:
            if not hasattr(p, 'sx') and (hasattr(p, 'w8') and p.w8.value == 0):
            # if (hasattr(p, 'w8') and p.w8.value == 0):
                r = gpregs08_64
        """
        if v < 8:
            self.expr = r.expr[v]
        else:
            self.expr = size2gpregs[64].expr[v]
        """
        if hasattr(p, "xmm") or hasattr(p, "xmmreg"):
            e = gpregs_xmm.expr[v]
        elif hasattr(p, "mm") or hasattr(p, "mmreg"):
            e = gpregs_mm.expr[v]
        else:
            e = r.expr[v]
        self.expr = e
        return True

    def encode(self):
        if not isinstance(self.expr, ExprId):
            return False
        if self.expr in gpregs64.expr and not hasattr(self.parent, 'stk'):
            self.parent.rex_w.value = 1
        # print self.parent.opmode
        # fd
        opmode = self.parent.v_opmode()
        # if hasattr(self.parent, 'sx'):
        #    opmode = 16
        # print 'reg encode', self.expr, opmode
        if not hasattr(self.parent, 'sx') and hasattr(self.parent, 'w8'):
            self.parent.w8.value = 1
        if self.expr.size == 8:
            if hasattr(self.parent, 'sx') or not hasattr(self.parent, 'w8'):
                return False
            self.parent.w8.value = 0
            opmode = 8
        r = size2gpregs[opmode]
        # print "YYY", opmode, self.expr
        if ((hasattr(self.parent, 'xmm') or hasattr(self.parent, 'xmmreg'))
            and self.expr in gpregs_xmm.expr):
            i = gpregs_xmm.expr.index(self.expr)
        elif ((hasattr(self.parent, 'mm') or hasattr(self.parent, 'mmreg'))
            and self.expr in gpregs_mm.expr):
            i = gpregs_mm.expr.index(self.expr)
        elif self.expr in r.expr:
            i = r.expr.index(self.expr)
        elif (opmode == 8 and self.parent.mode == 64 and
            self.expr in gpregs08_64.expr):
            i = gpregs08_64.expr.index(self.expr)
            self.parent.rex_p.value = 1
        else:
            log.debug("cannot encode reg %r" % self.expr)
            return False
        # print "zzz", opmode, self.expr, i, self.parent.mode
        if self.parent.v_opmode() == 64:
            if i > 7:
                self.setrexsize(1)
                i -= 8
        elif self.parent.mode == 64 and i > 7:
            i -= 8
            # print 'rrr', self.getrexsize()
            # self.parent.rex_b.value = 1
            self.setrexsize(1)
        if hasattr(self.parent, 'xmm') or hasattr(self.parent, 'mm'):
            if i > 7:
                i -= 8
        self.value = i
        if self.value > self.lmask:
            log.debug("cannot encode field value %x %x" %
                      (self.value, self.lmask))
            return False
        # print 'RR ok'
        return True


class x86_rm_reg(x86_rm_reg_noarg, m_arg):
    pass


class x86_reg(x86_rm_reg):

    def getrexsize(self):
        return self.parent.rex_b.value

    def setrexsize(self, v):
        self.parent.rex_b.value = v


class x86_reg_noarg(x86_rm_reg_noarg):

    def getrexsize(self):
        return self.parent.rex_b.value

    def setrexsize(self, v):
        self.parent.rex_b.value = v


class x86_rm_segm(reg_noarg, m_arg):
    prio = default_prio + 1
    reg_info = segmreg
    parser = reg_info.parser


class x86_rm_cr(reg_noarg, m_arg):
    prio = default_prio + 1
    reg_info = crregs
    parser = reg_info.parser


class x86_rm_dr(reg_noarg, m_arg):
    prio = default_prio + 1
    reg_info = drregs
    parser = reg_info.parser


class x86_rm_flt(reg_noarg, m_arg):
    prio = default_prio + 1
    reg_info = fltregs
    parser = reg_info.parser


class bs_fbit(bsi):

    def decode(self, v):
        # value already decoded in pre_dis_info
        # print "jj", self.value
        return True


class bs_cl1(bsi, m_arg):
    parser = cl_or_imm

    def decode(self, v):
        if v == 1:
            self.expr = regs08_expr[1]
        else:
            self.expr = ExprInt8(1)
        return True

    def encode(self):
        if self.expr == regs08_expr[1]:
            self.value = 1
        elif isinstance(self.expr, ExprInt) and int(self.expr.arg) == 1:
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
        return super(bs_cond, self).encode()

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
        # print 'disp cond', mode,
        # print v, v_admode_info(mode, v['opmode'], v['admode'])
        # if v_admode_info(mode, v['opmode'], v['admode']) ==16:
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
        v = ExprInt_fromsize(admode, v)
        self.expr = v
        return True


class bs_cond_imm(bs_cond_scale, m_arg):
    parser = int_or_expr
    max_size = 32

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
        else:
            try:
                e, start, stop = self.parser.scanString(s).next()
            except StopIteration:
                e = None
        self.expr = e

        if len(self.parent.args) > 1:
            l = self.parent.args[0].expr.size
        else:
            l = self.parent.v_opmode()
        # l = min(l, self.max_size)
        # l = offsize(self.parent)
        if isinstance(self.expr, ExprInt):
            v = int(self.expr.arg)
            mask = ((1 << l) - 1)
            v = v & mask
            e = ExprInt_fromsize(l, v)
            self.expr = e

        if self.expr is None:
            log.debug('cannot fromstring int %r' % s)
            return None, None
        return start, stop

    @classmethod
    def flen(cls, mode, v):
        if 'w8' not in v or v['w8'] == 1:
            if 'se' in v and v['se'] == 1:
                return 8
            else:
                # osize = v_opmode_info(mode, v['opmode'], v['admode'])
                # osize = opmode_prefix((mode, v['opmode'], v['admode']))
                osize = v_opmode_info(mode, v['opmode'], v['rex_w'], 0)
                osize = min(osize, cls.max_size)
                return osize
        return 8

    def getmaxlen(self):
        return 32

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            raise StopIteration
        arg0_expr = self.parent.args[0].expr
        self.parent.rex_w.value = 0
        # special case for push
        if len(self.parent.args) == 1:
            v = int(self.expr.arg)
            l = self.parent.v_opmode()
            l = min(l, self.max_size)

            self.l = l
            mask = ((1 << self.l) - 1)
            # print 'ext', self.l, l, hex(v), hex(sign_ext(v & ((1<<self.l)-1),
            # self.l, l))
            if v != sign_ext(v & mask, self.l, l):
                raise StopIteration
            self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
            # print hex(self.value)
            yield True
            raise StopIteration

        # assume 2 args; use first arg to guess op size
        if arg0_expr.size == 64:
            self.parent.rex_w.value = 1

        l = self.parent.v_opmode()  # self.parent.args[0].expr.size
        # print 'imm enc', l, self.parent.rex_w.value
        v = int(self.expr.arg)
        # print "imms size", l, hex(v), arg0_expr.size
        if arg0_expr.size == 8:
            if not hasattr(self.parent, 'w8'):
                raise StopIteration
            self.parent.w8.value = 0
            l = 8
            if hasattr(self.parent, 'se'):
                self.parent.se.value = 0
        elif hasattr(self.parent, 'se'):
            if hasattr(self.parent, 'w8'):
                self.parent.w8.value = 1
            # print 'test', 8, hex(v),
            # print hex(sign_ext(v & 0xFF, 8, arg0_expr.size))
            # try to generate signed extended version
            if v == sign_ext(v & 0xFF, 8, arg0_expr.size):
                # print 'setse'
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
        # l = min(l, self.max_size)

        mask = ((1 << self.l) - 1)
        # print 'ext', self.l, l, hex(v), hex(sign_ext(v & ((1<<self.l)-1),
        # self.l, l))
        if v != sign_ext(v & mask, self.l, l):
            raise StopIteration
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        # print hex(self.value)
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        v = swap_uint(self.l, v)
        self.value = v
        l_out = opmode
        if hasattr(self.parent, 'w8') and self.parent.w8.value == 0:
            l_out = 8
        v = sign_ext(v, self.l, l_out)
        v = ExprInt_fromsize(l_out, v)
        self.expr = v
        # print self.expr, repr(self.expr)
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


class bs_rel_off(bs_cond_imm):  # m_arg):
    parser = int_or_expr

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
        else:
            try:
                e, start, stop = self.parser.scanString(s).next()
            except StopIteration:
                e = None
        self.expr = e
        l = self.parent.mode
        if isinstance(self.expr, ExprInt):
            v = int(self.expr.arg)
            mask = ((1 << l) - 1)
            v = v & mask
            e = ExprInt_fromsize(l, v)
            self.expr = e
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
            raise StopIteration
        arg0_expr = self.parent.args[0].expr
        if self.l != 0:
            l = self.l
        else:
            l = self.parent.v_opmode()  # self.parent.args[0].expr.size
            self.l = l
            # if l == 16:
            #    self.l = 16
            # else:
            #    self.l = 32
        l = offsize(self.parent)

        # l = self.parent.v_opmode()#self.parent.args[0].expr.size
        # print 'imm enc', l, self.parent.rex_w.value
        v = int(self.expr.arg)
        mask = ((1 << self.l) - 1)
        # print 'ext', self.l, l, hex(v), hex(sign_ext(v & ((1<<self.l)-1),
        # self.l, l))
        if self.l > l:
            raise StopIteration
        if v != sign_ext(v & mask, self.l, l):
            raise StopIteration
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        # print hex(self.value)
        yield True

    def decode(self, v):
        v = swap_uint(self.l, v)
        size = offsize(self.parent)
        v = sign_ext(v, self.l, size)
        v = ExprInt_fromsize(size, v)
        self.expr = v
        # print self.expr, repr(self.expr)
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
            raise StopIteration
        m = self.parent.mseg.expr
        if not (isinstance(m, ExprOp) and m.op == 'segm'):
            raise StopIteration
        if not isinstance(m.args[1], ExprInt):
            raise StopIteration
        l = self.parent.v_opmode()  # self.parent.args[0].expr.size
        if l == 16:
            self.l = 16
        else:
            self.l = 32
        # print 'imm enc', l, self.parent.rex_w.value
        v = int(m.args[1].arg)
        mask = ((1 << self.l) - 1)
        # print 'ext', self.l, l, hex(v), hex(sign_ext(v & ((1<<self.l)-1),
        # self.l, l))
        if v != sign_ext(v & mask, self.l, l):
            raise StopIteration
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        # print hex(self.value)
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        if opmode == 64:
            return False
        v = swap_uint(self.l, v)
        self.value = v
        v = sign_ext(v, self.l, opmode)
        v = ExprInt_fromsize(opmode, v)
        self.expr = v
        # print self.expr, repr(self.expr)
        return True


class bs_movoff(m_arg):
    parser = deref_mem

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            if e is None:
                return None, None
            # print 'fromstring', hex(e), self.int2expr
            if not isinstance(e, ExprMem):
                return None, None
            self.expr = e
            if self.expr is None:
                return None, None
            return start, stop
        try:
            v, start, stop = self.parser.scanString(s).next()
        except StopIteration:
            return None, None
        if not isinstance(e, ExprMem):
            return None, None
        e = v[0]
        if e is None:
            log.debug('cannot fromstring int %r' % s)
            return None, None
        self.expr = e
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
        e = self.expr
        p = self.parent
        if not isinstance(e, ExprMem) or not isinstance(e.arg, ExprInt):
            raise StopIteration
        self.l = p.v_admode()
        # print 'imm enc', l, self.parent.rex_w.value
        v = int(e.arg.arg)
        mask = ((1 << self.l) - 1)
        if v != mask & v:
            raise StopIteration
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
        v = ExprInt_fromsize(l, v)
        size = self.parent.v_opmode()
        if self.parent.w8.value == 0:
            size = 8
        self.expr = ExprMem(v, size)
        # print self.expr, repr(self.expr)
        return True


class bs_msegoff(m_arg):
    parser = deref_ptr

    def fromstring(self, s, parser_result=None):
        if parser_result:
            e, start, stop = parser_result[self.parser]
            if e is None:
                return None, None
            self.expr = e
            if self.expr is None:
                return None, None
            return start, stop
        try:
            v, start, stop = self.parser.scanString(s).next()
        except StopIteration:
            return None, None
        e = v[0]
        print "XXX", e
        if e is None:
            log.debug('cannot fromstring int %r' % s)
            return None, None
        self.expr = e
        return start, stop

    def encode(self):
        if not (isinstance(self.expr, ExprOp) and self.expr.op == 'segm'):
            raise StopIteration
        if not isinstance(self.expr.args[0], ExprInt):
            raise StopIteration
        if not isinstance(self.expr.args[1], ExprInt):
            raise StopIteration
        l = self.parent.v_opmode()  # self.parent.args[0].expr.size
        # print 'imm enc', l, self.parent.rex_w.value
        v = int(self.expr.args[0].arg)
        mask = ((1 << self.l) - 1)
        # print 'ext', self.l, l, hex(v), hex(sign_ext(v & ((1<<self.l)-1),
        # self.l, l))
        if v != sign_ext(v & mask, self.l, l):
            raise StopIteration
        self.value = swap_uint(self.l, v & ((1 << self.l) - 1))
        yield True

    def decode(self, v):
        opmode = self.parent.v_opmode()
        v = swap_uint(self.l, v)
        self.value = v
        #v = sign_ext(v, self.l, opmode)
        v = ExprInt16(v)
        e = ExprOp('segm', v, self.parent.off.expr)
        self.expr = e
        # print self.expr, repr(self.expr)
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


xmm = bs(l=0, fname="xmm")
mm = bs(l=0, fname="mm")
xmmreg = bs(l=0, fname="xmmreg")
mmreg = bs(l=0, fname="mmreg")

pref_f2 = bs(l=0, fname="prefixed", default="\xf2")
pref_f3 = bs(l=0, fname="prefixed", default="\xf3")
pref_66 = bs(l=0, fname="prefixed", default="\x66")
no_xmm_pref = bs(l=0, fname="no_xmm_pref")

sib_scale = bs(l=2, cls=(bs_cond_scale,), fname = "sib_scale")
sib_index = bs(l=3, cls=(bs_cond_index,), fname = "sib_index")
sib_base = bs(l=3, cls=(bs_cond_index,), fname = "sib_base")

disp = bs(l=0, cls=(bs_cond_disp,), fname = "disp")


u08 = bs(l=8, cls=(x86_08, m_arg))
u07 = bs(l=7, cls=(x86_08, m_arg))
u16 = bs(l=16, cls=(x86_16, m_arg))
u32 = bs(l=32, cls=(x86_32, m_arg))
s3264 = bs(l=32, cls=(x86_s32to64, m_arg))

u08_3 = bs(l=0, cls=(x86_imm_fix, m_arg), ival = 3)

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


class field_size:
    prio = default_prio

    def __init__(self, d=None):
        if d is None:
            d = {}
        self.d = d

    def get(self, opm, adm=None):
        return self.d[opm]

d_imm64 = bs(l=0, fname="imm64")

# d_eax = bs_eax(l=0)
d_eax = bs(l=0, cls=(bs_eax, ), fname='eax')
d_edx = bs(l=0, cls=(bs_edx, ), fname='edx')
d_st = bs(l=0, cls=(x86_reg_st, ), fname='st')
# d_imm = bs(l=0, cls=(bs_cond_imm,), fname="imm")
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

rel_off = bs(l=0, cls=(bs_rel_off,), fname="off")
rel_off08 = bs(l=8, cls=(bs_rel_off08,), fname="off")
moff = bs(l=0, cls=(bs_moff,), fname="off")
msegoff = bs(l=16, cls=(bs_msegoff,), fname="mseg")
movoff = bs(l=0, cls=(bs_movoff,), fname="off")
mod = bs(l=2, fname="mod")

rmreg = bs(l=3, cls=(x86_rm_reg, ), order =1, fname = "reg")
reg = bs(l=3, cls=(x86_reg, ), order =1, fname = "reg")
regnoarg = bs(l=3, default_val="000", order=1, fname="reg")
segm = bs(l=3, cls=(x86_rm_segm, ), order =1, fname = "reg")
crreg = bs(l=3, cls=(x86_rm_cr, ), order =1, fname = "reg")
drreg = bs(l=3, cls=(x86_rm_dr, ), order =1, fname = "reg")

fltreg = bs(l=3, cls=(x86_rm_flt, ), order =1, fname = "reg")

rm = bs(l=3, fname="rm")

rm_arg = bs(l=0, cls=(x86_rm_arg,), fname='rmarg')
rm_arg_w8 = bs(l=0, cls=(x86_rm_w8,), fname='rmarg')
rm_arg_sx = bs(l=0, cls=(x86_rm_sx,), fname='rmarg')
rm_arg_sxd = bs(l=0, cls=(x86_rm_sxd,), fname='rmarg')
rm_arg_sd = bs(l=0, cls=(x86_rm_sd,), fname='rmarg')
rm_arg_wd = bs(l=0, cls=(x86_rm_wd,), fname='rmarg')
rm_arg_m80 = bs(l=0, cls=(x86_rm_m80,), fname='rmarg')
rm_arg_m64 = bs(l=0, cls=(x86_rm_m64,), fname='rmarg')
rm_arg_m08 = bs(l=0, cls=(x86_rm_m08,), fname='rmarg')
rm_arg_m16 = bs(l=0, cls=(x86_rm_m16,), fname='rmarg')

swapargs = bs_swapargs(l=1, fname="swap", mn_mod=range(1 << 1))


cond_list = ["O", "NO", "B", "AE",
             "Z", "NZ", "BE", "A",
             "S", "NS", "PE", "NP",
             #"L", "NL", "NG", "G"]
             "L", "GE", "LE", "G"]
cond = bs_mod_name(l=4, fname='cond', mn_mod=cond_list)


def rmmod(r, rm_arg_x=rm_arg):
    return [mod, r, rm, sib_scale, sib_index, sib_base, disp, rm_arg_x]

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
addop("call", [bs8(0x9a), moff, msegoff])


class bs_op_mode(bsi):

    def decode(self, v):
        opmode = self.parent.v_opmode()
        # print "MODE", opmode, self.mode
        return opmode == self.mode


class bs_ad_mode(bsi):

    def decode(self, v):
        admode = self.parent.v_admode()
        # print "MODE", opmode, self.mode
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
        # print "MODE", opmode, self.mode
        return opmode == self.mode


bs_opmode16 = bs(l=0, cls=(bs_op_mode,), mode = 16, fname="fopmode")
bs_opmode32 = bs(l=0, cls=(bs_op_mode,), mode = 32, fname="fopmode")
bs_opmode64 = bs(l=0, cls=(bs_op_mode,), mode = 64, fname="fopmode")


bs_admode16 = bs(l=0, cls=(bs_ad_mode,), mode = 16, fname="fadmode")
bs_admode32 = bs(l=0, cls=(bs_ad_mode,), mode = 32, fname="fadmode")
bs_admode64 = bs(l=0, cls=(bs_ad_mode,), mode = 64, fname="fadmode")

bs_opmode16_no64 = bs(l=0, cls=(bs_op_mode_no64,), mode = 16, fname="fopmode")
bs_opmode32_no64 = bs(l=0, cls=(bs_op_mode_no64,), mode = 32, fname="fopmode")

# class ia32_call(mn_x86):
#    fields = [bs8(0xff)] + rmmod(d3)
# conv_name = {16:'CBW', 32:'CWDE', 64:'CDQE'}
# bs_conv_name = bs_modname_size(l=0, name=conv_name)
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
# cmps_name = {16:'CMPSW', 32:'CMPSD', 64:'CMPSQ'}
# bs_cmps_name = bs_modname_size(l=0, name=cmps_name)
# addop("cmps", [bs8(0xa7), bs_cmps_name])
addop("cmpsw", [bs8(0xa7), bs_opmode16])
addop("cmpsd", [bs8(0xa7), bs_opmode32])
addop("cmpsq", [bs8(0xa7), bs_opmode64])

addop("cmpxchg", [bs8(0x0f), bs('1011000'), w8]
      + rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
# XXX TODO CMPXCHG8/16
addop("cpuid", [bs8(0x0f), bs8(0xa2)])

# convbis_name = {16:'CWD', 32:'CDQ', 64:'CQO'}
# bs_convbis_name = bs_modname_size(l=0, name=convbis_name)
# addop("convbis", [bs8(0x99), bs_convbis_name])
addop("cwd", [bs8(0x99), bs_opmode16])
addop("cdq", [bs8(0x99), bs_opmode32])
addop("cqo", [bs8(0x99), bs_opmode64])


addop("daa", [bs8(0x27)])
addop("das", [bs8(0x2f)])
addop("dec", [bs('1111111'), w8] + rmmod(d1, rm_arg_w8))
addop("dec", [bs('01001'), reg])
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
addop("inc", [bs('01000'), reg])

addop("insb", [bs8(0x6c)])
# ins_name = {16:'INSW', 32:'INSD', 64:'INSD'}
# bs_ins_name = bs_modname_size(l=0, name=ins_name)
# addop("ins", [bs8(0x6d), bs_ins_name])
addop("insw", [bs8(0x6d), bs_opmode16])
addop("insd", [bs8(0x6d), bs_opmode32])
addop("insd", [bs8(0x6d), bs_opmode64])

addop("int", [bs8(0xcc), u08_3])
addop("int", [bs8(0xcd), u08])
addop("into", [bs8(0xce)])
addop("invd", [bs8(0x0f), bs8(0x08)])
addop("invlpg", [bs8(0x0f), bs8(0x01)] + rmmod(d7))

# iret_name = {16:'IRET', 32:'IRETD', 64:'IRETQ'}
# bs_iret_name = bs_modname_size(l=0, name=iret_name)
# addop("iret", [bs8(0xcf), stk, bs_iret_name])
addop("iret", [bs8(0xcf), stk, bs_opmode16])
addop("iretd", [bs8(0xcf), stk, bs_opmode32])
addop("iretq", [bs8(0xcf), stk, bs_opmode64])

addop("j", [bs('0111'), cond, rel_off08])
# bs_jecxz_name = bs_modname_jecx(l=0)
# addop("jecxz", [bs8(0xe3), rel_off08, bs_jecxz_name])

addop("jcxz", [bs8(0xe3), rel_off08, bs_admode16])
addop("jecxz", [bs8(0xe3), rel_off08, bs_admode32])
addop("jrcxz", [bs8(0xe3), rel_off08, bs_admode64])

addop("j", [bs8(0x0f), bs('1000'), cond, rel_off])
addop("jmp", [bs8(0xeb), rel_off08])
addop("jmp", [bs8(0xe9), rel_off])
# TODO XXX replace stk force64?
addop("jmp", [bs8(0xff), stk] + rmmod(d4))
addop("jmpf", [bs8(0xea), moff, msegoff])

addop("jmpf", [bs8(0xff), stk] + rmmod(d5))

addop("lahf", [bs8(0x9f)])
addop("lar", [bs8(0x0f), bs8(0x02)] + rmmod(rmreg))

# XXX TODO LDS LES ...
addop("lea", [bs8(0x8d)] + rmmod(rmreg))
addop("leave", [bs8(0xc9)])

addop("lodsb", [bs8(0xac)])
# lods_name = {16:'LODSW', 32:'LODSD', 64:'LODSQ'}
# bs_lods_name = bs_modname_size(l=0, name=lods_name)
# addop("lods", [bs8(0xad), bs_lods_name])
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
# movs_name = {16:'MOVSW', 32:'MOVSD', 64:'MOVSQ'}
# bs_movs_name = bs_modname_size(l=0, name=movs_name)
# addop("movs", [bs8(0xa5), bs_movs_name])
addop("movsw", [bs8(0xa5), bs_opmode16])
addop("movsd", [bs8(0xa5), bs_opmode32])
addop("movsq", [bs8(0xa5), bs_opmode64])

addop("movsx", [bs8(0x0f), bs("1011111"), w8, sx] + rmmod(rmreg, rm_arg_sx))
# addop("movsxd", [bs8(0x63), sxd] + rmmod(rmreg, rm_arg_sxd))
type("movsxd", (mn_x86,), {
     "fields": [bs8(0x63), sxd] + rmmod(rmreg, rm_arg_sxd),
     "modes": [64], 'alias': False})

addop("movups",
      [bs8(0x0f), bs8(0x10), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("movsd", [bs8(0x0f), bs("0001000"), swapargs, xmm, pref_f2]
      + rmmod(rmreg, rm_arg), [xmm, rm_arg])
addop("movss", [bs8(0x0f), bs("0001000"), swapargs, xmm, pref_f3] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])
addop("movupd", [bs8(0x0f), bs8(0x10), xmm, pref_66] + rmmod(rmreg, rm_arg))


addop("movd", [bs8(0x0f), bs('011'), swapargs, bs('1110'), mm, no_xmm_pref] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])
addop("movd", [bs8(0x0f), bs('011'), swapargs, bs('1110'), xmm, pref_66] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])

addop("movq", [bs8(0x0f), bs('011'), swapargs, bs('1111'), mm, no_xmm_pref] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])

addop("movq", [bs8(0x0f), bs8(0x7e), xmm, pref_f3] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])
addop("movq", [bs8(0x0f), bs8(0xd6), xmm, pref_66] +
      rmmod(rmreg, rm_arg), [rm_arg, rmreg])



addop("addss", [bs8(0x0f), bs8(0x58), xmm, pref_f3] + rmmod(rmreg, rm_arg))
addop("addsd", [bs8(0x0f), bs8(0x58), xmm, pref_f2] + rmmod(rmreg, rm_arg))

addop("subss", [bs8(0x0f), bs8(0x5c), xmm, pref_f3] + rmmod(rmreg, rm_arg))
addop("subsd", [bs8(0x0f), bs8(0x5c), xmm, pref_f2] + rmmod(rmreg, rm_arg))

addop("mulss", [bs8(0x0f), bs8(0x59), xmm, pref_f3] + rmmod(rmreg, rm_arg))
addop("mulsd", [bs8(0x0f), bs8(0x59), xmm, pref_f2] + rmmod(rmreg, rm_arg))

addop("divss", [bs8(0x0f), bs8(0x5e), xmm, pref_f3] + rmmod(rmreg, rm_arg))
addop("divsd", [bs8(0x0f), bs8(0x5e), xmm, pref_f2] + rmmod(rmreg, rm_arg))


addop("pminsw", [bs8(0x0f), bs8(0xea), mm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("pminsw", [bs8(0x0f), bs8(0xea), xmm, pref_66] + rmmod(rmreg, rm_arg))


addop("pxor", [bs8(0x0f), bs8(0xef), xmm] + rmmod(rmreg, rm_arg))

addop("ucomiss",
      [bs8(0x0f), bs8(0x2e), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("ucomisd", [bs8(0x0f), bs8(0x2e), xmm, pref_66] + rmmod(rmreg, rm_arg))

addop("andps", [bs8(0x0f), bs8(0x54), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("andpd", [bs8(0x0f), bs8(0x54), xmm, pref_66] + rmmod(rmreg, rm_arg))


addop("maxsd", [bs8(0x0f), bs8(0x5f), xmm, pref_f2] + rmmod(rmreg, rm_arg))

addop("cvtsi2sd",
      [bs8(0x0f), bs8(0x2a), xmmreg, pref_f2] + rmmod(rmreg, rm_arg))
addop("cvtsi2ss",
      [bs8(0x0f), bs8(0x2a), xmmreg, pref_f3] + rmmod(rmreg, rm_arg))


addop("cvttsd2ss",
      [bs8(0x0f), bs8(0x2c), xmmreg, pref_f2] + rmmod(rmreg, rm_arg))
addop("cvttss2si",
      [bs8(0x0f), bs8(0x2c), xmmreg, pref_f3] + rmmod(rmreg, rm_arg))


# type("movupd", (mn_x86,), {"fields":[bs8(0x0f), bs8(0x10), xmm, pref_f2]
# + rmmod(rmreg, rm_arg_sxd), 'prefixed':'\xf2'})

addop("movzx", [bs8(0x0f), bs("1011011"), w8, sx] + rmmod(rmreg, rm_arg_sx))
addop("mul", [bs('1111011'), w8] + rmmod(d4, rm_arg_w8))

addop("neg", [bs('1111011'), w8] + rmmod(d3, rm_arg_w8))
addop("nop", [bs8(0x0f), bs8(0x1f)] + rmmod(d0, rm_arg))  # XXX TODO m512
addop("not", [bs('1111011'), w8] + rmmod(d2, rm_arg_w8))
addop("or", [bs("0000110"), w8, d_eax, d_imm])
addop("or", [bs("100000"), se, w8] + rmmod(d1, rm_arg_w8) + [d_imm])
addop("or", [bs("000010"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("out", [bs("1110011"), w8, u08, d_eax])
addop("out", [bs("1110111"), w8, d_edx, d_eax])

addop("outsb", [bs8(0x6e)])
# outs_name = {16:'OUTSW', 32:'OUTSD', 64:'OUTSD'}
# bs_outs_name = bs_modname_size(l=0, name=outs_name)
# addop("outs", [bs8(0x6f), bs_outs_name])
addop("outsw", [bs8(0x6f), bs_opmode16])
addop("outsd", [bs8(0x6f), bs_opmode32])
addop("outsd", [bs8(0x6f), bs_opmode64])


# addop("pause", [bs8(0xf3), bs8(0x90)])

addop("pop", [bs8(0x8f), stk] + rmmod(d0))
addop("pop", [bs("01011"), stk, reg])
addop("pop", [bs8(0x1f), d_ds])
addop("pop", [bs8(0x07), d_es])
addop("pop", [bs8(0x17), d_ss])
addop("pop", [bs8(0x0f), bs8(0xa1), d_fs])
addop("pop", [bs8(0x0f), bs8(0xa9), d_gs])

# popa_name = {16:'POPA', 32:'POPAD'}
# bs_popa_name = bs_modname_size(l=0, name=popa_name)
# addop("popa", [bs8(0x61), bs_popa_name])
addop("popa", [bs8(0x61), bs_opmode16])
addop("popad", [bs8(0x61), bs_opmode32])

# popf_name = {16:'POPF', 32:'POPFD', 64:'POPFQ'}
# bs_popf_name = bs_modname_size(l=0, name=popf_name)
# addop("popf", [bs8(0x9d), bs_popf_name])
addop("popf", [bs8(0x9d), bs_opmode16])
addop("popfd", [bs8(0x9d), bs_opmode32])
addop("popfq", [bs8(0x9d), bs_opmode64])

addop("prefetch0", [bs8(0x0f), bs8(0x18)] + rmmod(d1, rm_arg_m08))
addop("prefetch1", [bs8(0x0f), bs8(0x18)] + rmmod(d2, rm_arg_m08))
addop("prefetch2", [bs8(0x0f), bs8(0x18)] + rmmod(d3, rm_arg_m08))
addop("prefetchnta", [bs8(0x0f), bs8(0x18)] + rmmod(d0, rm_arg_m08))

addop("push", [bs8(0xff), stk] + rmmod(d6))
addop("push", [bs("01010"), stk, reg])
addop("push", [bs8(0x6a), rel_off08, stk])
addop("push", [bs8(0x68), d_imm, stk])
addop("push", [bs8(0x0e), d_cs])
addop("push", [bs8(0x16), d_ss])
addop("push", [bs8(0x1e), d_ds])
addop("push", [bs8(0x06), d_es])
addop("push", [bs8(0x0f), bs8(0xa0), d_fs])
addop("push", [bs8(0x0f), bs8(0xa8), d_gs])

# pusha_name = {16:'PUSHA', 32:'PUSHAD'}
# bs_pusha_name = bs_modname_size(l=0, name=pusha_name)
# addop("pusha", [bs8(0x60), bs_pusha_name])
addop("pusha", [bs8(0x60), bs_opmode16_no64])
addop("pushad", [bs8(0x60), bs_opmode32_no64])


# pushf_name = {16:'PUSHF', 32:'PUSHFD', 64:'PUSHFQ'}
# bs_pushf_name = bs_modname_size(l=0, name=pushf_name)
# addop("pushf", [bs8(0x9c), bs_pushf_name])
addop("pushf", [bs8(0x9c), bs_opmode16])
addop("pushfd", [bs8(0x9c), bs_opmode32])
addop("pushfq", [bs8(0x9c), bs_opmode64])

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
# scas_name = {16:'SCASW', 32:'SCASD', 64:'SCASQ'}
# bs_scas_name = bs_modname_size(l=0, name=scas_name)
# addop("scas", [bs8(0xaf), bs_scas_name])
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

addop("set", [bs8(0x0f), bs('1001'), cond] + rmmod(regnoarg, rm_arg_m08))
addop("sgdt", [bs8(0x0f), bs8(0x01)] + rmmod(d0))
addop("shld", [bs8(0x0f), bs8(0xa4)] +
      rmmod(rmreg) + [u08], [rm_arg, rmreg, u08])
addop("shld", [bs8(0x0f), bs8(0xa5)] +
      rmmod(rmreg) + [d_cl], [rm_arg, rmreg, d_cl])
addop("shrd", [bs8(0x0f), bs8(0xac)] +
      rmmod(rmreg) + [u08], [rm_arg, rmreg, u08])
addop("shrd", [bs8(0x0f), bs8(0xad)] +
      rmmod(rmreg) + [d_cl], [rm_arg, rmreg, d_cl])
addop("sidt", [bs8(0x0f), bs8(0x01)] + rmmod(d1))
addop("sldt", [bs8(0x0f), bs8(0x00)] + rmmod(d0))
addop("smsw", [bs8(0x0f), bs8(0x01)] + rmmod(d4))
addop("stc", [bs8(0xf9)])
addop("std", [bs8(0xfd)])
addop("sti", [bs8(0xfb)])
addop("stosb", [bs8(0xaa)])
# stos_name = {16:'STOSW', 32:'STOSD', 64:'STOSQ'}
# bs_stos_name = bs_modname_size(l=0, name=stos_name)
# addop("stos", [bs8(0xab), bs_stos_name])
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
addop("wbind", [bs8(0x0f), bs8(0x09)])
addop("wrmsr", [bs8(0x0f), bs8(0x30)])
addop("xadd", [bs8(0x0f), bs("1100000"), w8]
      + rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])

addop("nop", [bs8(0x90)], alias=True)

addop("xchg", [bs('10010'), d_eax, reg])
addop("xchg", [bs('1000011'), w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])
addop("xlat", [bs8(0xd7)])


addop("xor", [bs("0011010"), w8, d_eax, d_imm])
addop("xor", [bs("100000"), se, w8] + rmmod(d6, rm_arg_w8) + [d_imm])
addop("xor", [bs("001100"), swapargs, w8] +
      rmmod(rmreg, rm_arg_w8), [rm_arg_w8, rmreg])


addop("xgetbv", [bs8(0x0f), bs8(0x01), bs8(0xd0)])


#addop("pand", [bs8(0x0f), bs8(0xdb), xmm, pref_66])# + rmmod(rmreg, rm_arg))

#### MMX/SSE/AVX operations
#### Categories are the same than here: https://software.intel.com/sites/landingpage/IntrinsicsGuide/
####

### Arithmetic (integers)
###

## Move
# SSE
# movaps_name = {16:'MOVAPD', 32:'MOVAPS', 64:'MOVAPS'}
# bs_movaps_name = bs_modname_size(l=0, name=movaps_name)
# addop("movaps", [bs8(0x0f), bs("0010100"), swapargs, xmm] + rmmod(rmreg,
# rm_arg) + [ bs_movaps_name], [rmreg, rm_arg])
addop("movapd", [bs8(0x0f), bs("0010100"), swapargs, xmm]
      + rmmod(rmreg, rm_arg) + [bs_opmode16], [rmreg, rm_arg])
addop("movaps", [bs8(0x0f), bs("0010100"), swapargs, xmm]
      + rmmod(rmreg, rm_arg) + [bs_opmode32], [rmreg, rm_arg])
addop("movaps", [bs8(0x0f), bs("0010100"), swapargs, xmm]
      + rmmod(rmreg, rm_arg) + [bs_opmode64], [rmreg, rm_arg])
addop("movdqu", [bs8(0x0f), bs("011"), swapargs, bs("1111"), xmm, pref_f3]
      + rmmod(rmreg, rm_arg), [rmreg, rm_arg])
addop("movdqa", [bs8(0x0f), bs("011"), swapargs, bs("1111"), xmm, pref_66]
      + rmmod(rmreg, rm_arg), [rmreg, rm_arg])



## Additions
# SSE
addop("paddb", [bs8(0x0f), bs8(0xfc), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("paddw", [bs8(0x0f), bs8(0xfd), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("paddd", [bs8(0x0f), bs8(0xfe), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("paddq", [bs8(0x0f), bs8(0xd4), xmm, pref_66] + rmmod(rmreg, rm_arg))

## Substractions
# SSE
addop("psubb", [bs8(0x0f), bs8(0xf8), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("psubw", [bs8(0x0f), bs8(0xf9), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("psubd", [bs8(0x0f), bs8(0xfa), xmm, pref_66] + rmmod(rmreg, rm_arg))
addop("psubq", [bs8(0x0f), bs8(0xfb), xmm, pref_66] + rmmod(rmreg, rm_arg))

### Arithmetic (floating-point)
###

## Additions
# SSE
addop("addps", [bs8(0x0f), bs8(0x58), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("addpd", [bs8(0x0f), bs8(0x58), xmm, pref_66] + rmmod(rmreg, rm_arg))

## Substractions
# SSE
addop("subps", [bs8(0x0f), bs8(0x5c), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("subpd", [bs8(0x0f), bs8(0x5c), xmm, pref_66] + rmmod(rmreg, rm_arg))

## Multiplications
# SSE
addop("mulps", [bs8(0x0f), bs8(0x59), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("mulpd", [bs8(0x0f), bs8(0x59), xmm, pref_66] + rmmod(rmreg, rm_arg))

## Divisions
# SSE
addop("divps", [bs8(0x0f), bs8(0x5e), xmm, no_xmm_pref] + rmmod(rmreg, rm_arg))
addop("divpd", [bs8(0x0f), bs8(0x5e), xmm, pref_66] + rmmod(rmreg, rm_arg))

### Logical (floating-point)
###

## XOR
# SSE
# xorps_name = {16:'XORPD', 32:'XORPS', 64:'XORPS'}
# bs_xorps_name = bs_modname_size(l=0, name=xorps_name)
# addop("xorps", [bs8(0x0f), bs8(0x57), xmm] + rmmod(rmreg) + [
# bs_xorps_name] )
addop("xorpd", [bs8(0x0f), bs8(0x57), xmm] + rmmod(rmreg) + [bs_opmode16])
addop("xorps", [bs8(0x0f), bs8(0x57), xmm] + rmmod(rmreg) + [bs_opmode32])
addop("xorps", [bs8(0x0f), bs8(0x57), xmm] + rmmod(rmreg) + [bs_opmode64])

## AND
# MMX
addop("pand", [bs8(0x0f), bs8(0xdb), mm, no_xmm_pref] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])
# SSE
addop("pand", [bs8(0x0f), bs8(0xdb), xmm, pref_66] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])

## OR
# MMX
addop("por", [bs8(0x0f), bs8(0xeb), mm, no_xmm_pref] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])
# SSE
addop("por", [bs8(0x0f), bs8(0xeb), xmm, pref_66] +
      rmmod(rmreg, rm_arg), [rmreg, rm_arg])

### Convert
### SS = single precision
### SD = double precision
###

## SS -> SD
##

# SSE
addop("cvtss2sd", [bs8(0x0f), bs8(0x5a), xmm, pref_f3]
      + rmmod(rmreg, rm_arg))

## SD -> SS
##

# SSE
addop("cvtsd2ss", [bs8(0x0f), bs8(0x5a), xmm, pref_f2]
      + rmmod(rmreg, rm_arg))


mn_x86.bintree = factor_one_bit(mn_x86.bintree)
# mn_x86.bintree = factor_fields_all(mn_x86.bintree)
"""
mod reg r/m
 XX XXX XXX

"""


def print_size(e):
    print e, e.size
    return e
