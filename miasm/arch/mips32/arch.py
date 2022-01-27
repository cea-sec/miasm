#-*- coding:utf-8 -*-

import logging
from collections import defaultdict

from pyparsing import Literal, Optional

from miasm.expression.expression import ExprMem, ExprInt, ExprId, ExprOp, ExprLoc
from miasm.core.bin_stream import bin_stream
import miasm.arch.mips32.regs as regs
import miasm.core.cpu as cpu
from miasm.ir.ir import color_expr_html

from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp

log = logging.getLogger("mips32dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)


gpregs = cpu.reg_info(regs.regs32_str, regs.regs32_expr)


LPARENTHESIS = Literal("(")
RPARENTHESIS = Literal(")")

def cb_deref(tokens):
    if len(tokens) != 4:
        raise NotImplementedError("TODO")
    return AstMem(tokens[2] + tokens[0], 32)

def cb_deref_nooff(tokens):
    if len(tokens) != 3:
        raise NotImplementedError("TODO")
    return AstMem(tokens[1], 32)

base_expr = cpu.base_expr

deref_off = (Optional(base_expr) + LPARENTHESIS + gpregs.parser + RPARENTHESIS).setParseAction(cb_deref)
deref_nooff = (LPARENTHESIS + gpregs.parser + RPARENTHESIS).setParseAction(cb_deref_nooff)
deref = deref_off | deref_nooff


class additional_info(object):
    def __init__(self):
        self.except_on_instr = False

br_0 = ['B', 'J', 'JR', 'BAL', 'JAL', 'JALR']
br_1 = ['BGEZ', 'BLTZ', 'BGTZ', 'BGTZL', 'BLEZ', 'BLEZL', 'BC1T', 'BC1TL', 'BC1F', 'BC1FL']
br_2 = ['BEQ', 'BEQL', 'BNE', 'BNEL']


class instruction_mips32(cpu.instruction):
    __slots__ = []

    def __init__(self, *args, **kargs):
        super(instruction_mips32, self).__init__(*args, **kargs)
        self.delayslot = 1


    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int():
            return str(expr)
        elif expr.is_loc():
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)
        assert(isinstance(expr, ExprMem))
        arg = expr.ptr
        if isinstance(arg, ExprId):
            return "(%s)"%arg
        assert(len(arg.args) == 2 and arg.op == '+')
        return "%s(%s)"%(arg.args[1], arg.args[0])

    @staticmethod
    def arg2html(expr, index=None, loc_db=None):
        if expr.is_id() or expr.is_int() or expr.is_loc():
            return color_expr_html(expr, loc_db)
        assert(isinstance(expr, ExprMem))
        arg = expr.ptr
        if isinstance(arg, ExprId):
            return "(%s)"%color_expr_html(arg, loc_db)
        assert(len(arg.args) == 2 and arg.op == '+')
        return "%s(%s)"%(
            color_expr_html(arg.args[1], loc_db),
            color_expr_html(arg.args[0], loc_db)
        )

    def dstflow(self):
        if self.name == 'BREAK':
            return False
        if self.name in br_0 + br_1 + br_2:
            return True
        return False

    def get_dst_num(self):
        if self.name in br_0:
            i = 0
        elif self.name in br_1:
            i = 1
        elif self.name in br_2:
            i = 2
        else:
            raise NotImplementedError("TODO %s"%self)
        return i

    def dstflow2label(self, loc_db):
        if self.name in ["J", 'JAL']:
            expr = self.args[0]
            offset = int(expr)
            addr = ((self.offset & (0xFFFFFFFF ^ ((1<< 28)-1))) + offset) & int(expr.mask)
            loc_key = loc_db.get_or_create_offset_location(addr)
            self.args[0] = ExprLoc(loc_key, expr.size)
            return

        ndx = self.get_dst_num()
        expr = self.args[ndx]

        if not isinstance(expr, ExprInt):
            return
        addr = (int(expr) + self.offset) & int(expr.mask)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[ndx] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        if self.name == 'BREAK':
            return False
        if self.name in br_0 + br_1 + br_2:
            return True
        return False

    def is_subcall(self):
        if self.name in ['JAL', 'JALR', 'BAL']:
            return True
        return False

    def getdstflow(self, loc_db):
        if self.name in br_0:
            return [self.args[0]]
        elif self.name in br_1:
            return [self.args[1]]
        elif self.name in br_2:
            return [self.args[2]]
        elif self.name in ['JAL', 'JALR', 'JR', 'J']:
            return [self.args[0]]
        else:
            raise NotImplementedError("fix mnemo %s"%self.name)

    def splitflow(self):
        if self.name in ["B", 'JR', 'J']:
            return False
        if self.name in br_0:
            return True
        if self.name in br_1:
            return True
        if self.name in br_2:
            return True
        if self.name in ['JAL', 'JALR']:
            return True
        return False

    def get_symbol_size(self, symbol, loc_db):
        return 32

    def fixDstOffset(self):
        ndx = self.get_dst_num()
        e = self.args[ndx]
        if self.offset is None:
            raise ValueError('symbol not resolved %s' % self.l)
        if not isinstance(e, ExprInt):
            return
        off = (int(e) - self.offset) & int(e.mask)
        if int(off % 4):
            raise ValueError('strange offset! %r' % off)
        self.args[ndx] = ExprInt(off, 32)

    def get_args_expr(self):
        args = [a for a in self.args]
        return args


class mn_mips32(cpu.cls_mn):
    delayslot = 1
    name = "mips32"
    regs = regs
    bintree = {}
    num = 0
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    pc = {'l':regs.PC, 'b':regs.PC}
    sp = {'l':regs.SP, 'b':regs.SP}
    instruction = instruction_mips32
    max_instruction_len = 4

    @classmethod
    def getpc(cls, attrib = None):
        return regs.PC

    @classmethod
    def getsp(cls, attrib = None):
        return regs.SP

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getbits(cls, bitstream, attrib, start, n):
        if not n:
            return 0
        o = 0
        while n:
            offset = start // 8
            n_offset = cls.endian_offset(attrib, offset)
            c = cls.getbytes(bitstream, n_offset, 1)
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
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def value(self, mode):
        v = super(mn_mips32, self).value(mode)
        if mode == 'l':
            return [x[::-1] for x in v]
        elif mode == 'b':
            return [x for x in v]
        else:
            raise NotImplementedError('bad attrib')



def mips32op(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_mips32,), dct)
    #type(name, (mn_mips32b,), dct)

class mips32_arg(cpu.m_arg):
    def asm_ast_to_expr(self, arg, loc_db):
        if isinstance(arg, AstId):
            if isinstance(arg.name, ExprId):
                return arg.name
            if arg.name in gpregs.str:
                return None
            loc_key = loc_db.get_or_create_name_location(arg.name)
            return ExprLoc(loc_key, 32)
        if isinstance(arg, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
            if None in args:
                return None
            return ExprOp(arg.op, *args)
        if isinstance(arg, AstInt):
            return ExprInt(arg.value, 32)
        if isinstance(arg, AstMem):
            ptr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, arg.size)
        return None


class mips32_reg(cpu.reg_noarg, mips32_arg):
    pass

class mips32_gpreg(mips32_reg):
    reg_info = gpregs
    parser = reg_info.parser

class mips32_fltpreg(mips32_reg):
    reg_info = regs.fltregs
    parser = reg_info.parser


class mips32_fccreg(mips32_reg):
    reg_info = regs.fccregs
    parser = reg_info.parser

class mips32_imm(cpu.imm_noarg):
    parser = base_expr


class mips32_s16imm_noarg(mips32_imm):
    def decode(self, v):
        v = v & self.lmask
        v = cpu.sign_ext(v, 16, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 0x80000000:
            nv = v & ((1 << 16) - 1)
            assert( v == cpu.sign_ext(nv, 16, 32))
            v = nv
        self.value = v
        return True


class mips32_s09imm_noarg(mips32_imm):
    def decode(self, v):
        v = v & self.lmask
        v = cpu.sign_ext(v, 9, 32)
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 0x80000000:
            nv = v & ((1 << 9) - 1)
            assert( v == cpu.sign_ext(nv, 9, 32))
            v = nv
        self.value = v
        return True


class mips32_soff_noarg(mips32_imm):
    def decode(self, v):
        v = v & self.lmask
        v <<= 2
        v = cpu.sign_ext(v, 16+2, 32)
        # Add pipeline offset
        self.expr = ExprInt(v + 4, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        # Remove pipeline offset
        v = (int(self.expr) - 4) & 0xFFFFFFFF
        if v & 0x80000000:
            nv = v & ((1 << 16+2) - 1)
            assert( v == cpu.sign_ext(nv, 16+2, 32))
            v = nv
        self.value = v>>2
        return True


class mips32_s16imm(mips32_s16imm_noarg, mips32_arg):
    pass

class mips32_s09imm(mips32_s09imm_noarg, mips32_arg):
    pass

class mips32_soff(mips32_soff_noarg, mips32_arg):
    pass


class mips32_instr_index(mips32_imm, mips32_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt(v<<2, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        if v & 3:
            return False
        v>>=2
        if v > (1<<self.l):
            return False
        self.value = v
        return True


class mips32_u16imm(mips32_imm, mips32_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt(v, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        assert(v < (1<<16))
        self.value = v
        return True

class mips32_dreg_imm(mips32_arg):
    parser = deref
    def decode(self, v):
        imm = self.parent.imm.expr
        r = gpregs.expr[v]
        self.expr = ExprMem(r+imm, 32)
        return True

    def encode(self):
        e = self.expr
        if not isinstance(e, ExprMem):
            return False
        ptr = e.ptr
        if isinstance(ptr, ExprId):
            self.parent.imm.expr = ExprInt(0, 32)
            r = ptr
        elif len(ptr.args) == 2 and ptr.op == "+":
            self.parent.imm.expr = ptr.args[1]
            r = ptr.args[0]
        else:
            return False
        self.value = gpregs.expr.index(r)
        return True

    @staticmethod
    def arg2str(expr, index=None):
        assert(isinstance(expr, ExprMem))
        ptr = expr.ptr
        if isinstance(ptr, ExprId):
            return "(%s)"%ptr
        assert(len(ptr.args) == 2 and ptr.op == '+')
        return "%s(%s)"%(ptr.args[1], ptr.args[0])

class mips32_esize(mips32_imm, mips32_arg):
    def decode(self, v):
        v = v & self.lmask
        self.expr = ExprInt(v+1, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr) -1
        assert(v < (1<<16))
        self.value = v
        return True

class mips32_eposh(mips32_imm, mips32_arg):
    def decode(self, v):
        self.expr = ExprInt(v-int(self.parent.epos.expr)+1, 32)
        return True

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr) + int(self.parent.epos.expr) -1
        self.value = v
        return True




class mips32_cpr(mips32_arg):
    parser = regs.regs_cpr0_info.parser
    def decode(self, v):
        index = int(self.parent.cpr0.expr) << 3
        index += v
        self.expr = regs.regs_cpr0_expr[index]
        return True
    def encode(self):
        e = self.expr
        if not e in regs.regs_cpr0_expr:
            return False
        index = regs.regs_cpr0_expr.index(e)
        self.value = index & 7
        index >>=2
        self.parent.cpr0.value = index
        return True

rs = cpu.bs(l=5, cls=(mips32_gpreg,))
rt = cpu.bs(l=5, cls=(mips32_gpreg,))
rd = cpu.bs(l=5, cls=(mips32_gpreg,))
ft = cpu.bs(l=5, cls=(mips32_fltpreg,))
fs = cpu.bs(l=5, cls=(mips32_fltpreg,))
fd = cpu.bs(l=5, cls=(mips32_fltpreg,))

s16imm = cpu.bs(l=16, cls=(mips32_s16imm,))
u16imm = cpu.bs(l=16, cls=(mips32_u16imm,))
s09imm = cpu.bs(l=9, cls=(mips32_s09imm,))
sa = cpu.bs(l=5, cls=(mips32_u16imm,))
base = cpu.bs(l=5, cls=(mips32_dreg_imm,))
soff = cpu.bs(l=16, cls=(mips32_soff,))
oper = cpu.bs(l=5, cls=(mips32_u16imm,))

cpr0 = cpu.bs(l=5, cls=(mips32_imm,), fname="cpr0")
cpr =  cpu.bs(l=3, cls=(mips32_cpr,))

stype = cpu.bs(l=5, cls=(mips32_u16imm,))
hint_pref = cpu.bs(l=5, cls=(mips32_u16imm,))

s16imm_noarg = cpu.bs(l=16, cls=(mips32_s16imm_noarg,), fname="imm",
                  order=-1)
s09imm_noarg = cpu.bs(l=9, cls=(mips32_s09imm_noarg,), fname="imm",
                  order=-1)

hint = cpu.bs(l=5, default_val="00000")
fcc = cpu.bs(l=3, cls=(mips32_fccreg,))

sel = cpu.bs(l=3, cls=(mips32_u16imm,))

code = cpu.bs(l=20, cls=(mips32_u16imm,))

esize = cpu.bs(l=5, cls=(mips32_esize,))
epos = cpu.bs(l=5, cls=(mips32_u16imm,), fname="epos",
          order=-1)

eposh = cpu.bs(l=5, cls=(mips32_eposh,))

instr_index = cpu.bs(l=26, cls=(mips32_instr_index,))
bs_fmt = cpu.bs_mod_name(l=5, fname='fmt', mn_mod={0x10: '.S', 0x11: '.D',
                                                   0x14: '.W', 0x15: '.L',
                                                   0x16: '.PS'})
class bs_cond(cpu.bs_mod_name):
    mn_mod = ['.F', '.UN', '.EQ', '.UEQ',
              '.OLT', '.ULT', '.OLE', '.ULE',
              '.SF', '.NGLE', '.SEQ', '.NGL',
              '.LT', '.NGE', '.LE', '.NGT'
              ]

    def modname(self, name, f_i):
        raise NotImplementedError("Not implemented")


class bs_cond_name(cpu.bs_divert):
    prio = 2
    mn_mod = [['.F', '.UN', '.EQ', '.UEQ',
               '.OLT', '.ULT', '.OLE', '.ULE'],
              ['.SF', '.NGLE', '.SEQ', '.NGL',
               '.LT', '.NGE', '.LE', '.NGT']
              ]

    def divert(self, index, candidates):
        out = []
        for candidate in candidates:
            cls, name, bases, dct, fields = candidate
            cond1 = [f for f in fields if f.fname == "cond1"]
            assert(len(cond1) == 1)
            cond1 = cond1.pop()
            mm = self.mn_mod[cond1.value]
            for value, new_name in enumerate(mm):
                nfields = fields[:]
                s = cpu.int2bin(value, self.args['l'])
                args = dict(self.args)
                args.update({'strbits': s})
                f = cpu.bs(**args)
                nfields[index] = f
                ndct = dict(dct)
                ndct['name'] = name + new_name
                out.append((cls, new_name, bases, ndct, nfields))
        return out



class bs_cond_mod(cpu.bs_mod_name):
    prio = 1

bs_cond = bs_cond_mod(l=4,
                      mn_mod = ['.F', '.UN', '.EQ', '.UEQ',
                                '.OLT', '.ULT', '.OLE', '.ULE',
                                '.SF', '.NGLE', '.SEQ', '.NGL',
                                '.LT', '.NGE', '.LE', '.NGT'])



bs_arith = cpu.bs_name(l=6, name={'ADDU':0b100001,
                                  'SUBU':0b100011,
                                  'OR':0b100101,
                                  'AND':0b100100,
                                  'SLTU':0b101011,
                                  'XOR':0b100110,
                                  'SLT':0b101010,
                                  'SUBU':0b100011,
                                  'NOR':0b100111,
                                  'MOVN':0b001011,
                                  'MOVZ':0b001010,
                                  })

bs_shift = cpu.bs_name(l=6, name={'SLL':0b000000,
                                  'SRL':0b000010,
                                  'SRA':0b000011,
                                  })

bs_shift1 = cpu.bs_name(l=6, name={'SLLV':0b000100,
                                   'SRLV':0b000110,
                                   'SRAV':0b000111,
                                   })


bs_arithfmt = cpu.bs_name(l=6, name={'ADD':0b000000,
                                     'SUB':0b000001,
                                     'MUL':0b000010,
                                     'DIV':0b000011,
                                     })

bs_s_l = cpu.bs_name(l=6, name = {"SW":    0b101011,
                                  "SH":    0b101001,
                                  "SB":    0b101000,
                                  "LW":    0b100011,
                                  "LH":    0b100001,
                                  "LB":    0b100000,
                                  "LHU":   0b100101,
                                  "LBU":   0b100100,
                                  "LWL":   0b100010,
                                  "LWR":   0b100110,

                                  "SWL":   0b101010,
                                  "SWR":   0b101110,
                                  })


bs_oax = cpu.bs_name(l=6, name = {"ORI":    0b001101,
                                  "ANDI":   0b001100,
                                  "XORI":   0b001110,
                                  })

bs_bcc = cpu.bs_name(l=5, name = {"BGEZ":    0b00001,
                                  "BGEZL":   0b00011,
                                  "BGEZAL":  0b10001,
                                  "BGEZALL": 0b10011,
                                  "BLTZ":    0b00000,
                                  "BLTZL":   0b00010,
                                  "BLTZAL":  0b10000,
                                  "BLTZALL": 0b10010,
                                  })


bs_code = cpu.bs(l=10)


mips32op("addi",    [cpu.bs('001000'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("addiu",   [cpu.bs('001001'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("nop",     [cpu.bs('0'*32)], alias = True)
mips32op("lui",     [cpu.bs('001111'), cpu.bs('00000'), rt, u16imm])
mips32op("oax",     [bs_oax, rs, rt, u16imm], [rt, rs, u16imm])

mips32op("arith",   [cpu.bs('000000'), rs, rt, rd, cpu.bs('00000'), bs_arith],
         [rd, rs, rt])
mips32op("shift1",  [cpu.bs('000000'), rs, rt, rd, cpu.bs('00000'), bs_shift1],
         [rd, rt, rs])

mips32op("shift",   [cpu.bs('000000'), cpu.bs('00000'), rt, rd, sa, bs_shift],
         [rd, rt, sa])

mips32op("rotr",    [cpu.bs('000000'), cpu.bs('00001'), rt, rd, sa,
                     cpu.bs('000010')], [rd, rt, sa])

mips32op("mul",     [cpu.bs('011100'), rs, rt, rd, cpu.bs('00000'),
                     cpu.bs('000010')], [rd, rs, rt])
mips32op("div",     [cpu.bs('000000'), rs, rt, cpu.bs('0000000000'),
                     cpu.bs('011010')])

mips32op("s_l",     [bs_s_l, base, rt, s16imm_noarg], [rt, base])

#mips32op("mfc0",    [bs('010000'), bs('00000'), rt, rd, bs('00000000'), sel])
mips32op("mfc0",    [cpu.bs('010000'), cpu.bs('00000'), rt, cpr0,
                     cpu.bs('00000000'), cpr])
mips32op("mfc1",    [cpu.bs('010001'), cpu.bs('00000'), rt, fs,
                     cpu.bs('00000000000')])

mips32op("ldc1",    [cpu.bs('110101'), base, ft, s16imm_noarg], [ft, base])

mips32op("mov",     [cpu.bs('010001'), bs_fmt, cpu.bs('00000'), fs, fd,
                     cpu.bs('000110')], [fd, fs])

mips32op("add",     [cpu.bs('010001'), bs_fmt, ft, fs, fd, bs_arithfmt],
         [fd, fs, ft])

mips32op("divu",    [cpu.bs('000000'), rs, rt, cpu.bs('0000000000'),
                     cpu.bs('011011')])
mips32op("mult",    [cpu.bs('000000'), rs, rt, cpu.bs('0000000000'),
                     cpu.bs('011000')])
mips32op("multu",   [cpu.bs('000000'), rs, rt, cpu.bs('0000000000'),
                     cpu.bs('011001')])
mips32op("mflo",    [cpu.bs('000000'), cpu.bs('0000000000'), rd,
                     cpu.bs('00000'), cpu.bs('010010')])
mips32op("mfhi",    [cpu.bs('000000'), cpu.bs('0000000000'), rd,
                     cpu.bs('00000'), cpu.bs('010000')])


mips32op("b",       [cpu.bs('000100'), cpu.bs('00000'), cpu.bs('00000'), soff],
         alias = True)
mips32op("bne",     [cpu.bs('000101'), rs, rt, soff])
mips32op("bnel",    [cpu.bs('010101'), rs, rt, soff])

mips32op("beq",     [cpu.bs('000100'), rs, rt, soff])
mips32op("beql",    [cpu.bs('010100'), rs, rt, soff])

mips32op("blez",    [cpu.bs('000110'), rs, cpu.bs('00000'), soff])
mips32op("blezl",   [cpu.bs('010110'), rs, cpu.bs('00000'), soff])

mips32op("bcc",     [cpu.bs('000001'), rs, bs_bcc, soff])

mips32op("bgtz",    [cpu.bs('000111'), rs, cpu.bs('00000'), soff])
mips32op("bgtzl",   [cpu.bs('010111'), rs, cpu.bs('00000'), soff])
mips32op("bal",     [cpu.bs('000001'), cpu.bs('00000'), cpu.bs('10001'), soff],
         alias = True)


mips32op("slti",    [cpu.bs('001010'), rs, rt, s16imm], [rt, rs, s16imm])
mips32op("sltiu",   [cpu.bs('001011'), rs, rt, s16imm], [rt, rs, s16imm])


mips32op("j",       [cpu.bs('000010'), instr_index])
mips32op("jal",     [cpu.bs('000011'), instr_index])
mips32op("jalr",    [cpu.bs('000000'), rs, cpu.bs('00000'), rd, hint,
                     cpu.bs('001001')])
mips32op("jr",      [cpu.bs('000000'), rs, cpu.bs('0000000000'), hint,
                     cpu.bs('001000')])

mips32op("lwc1",    [cpu.bs('110001'), base, ft, s16imm_noarg], [ft, base])

#mips32op("mtc0",    [bs('010000'), bs('00100'), rt, rd, bs('00000000'), sel])
mips32op("mtc0",    [cpu.bs('010000'), cpu.bs('00100'), rt, cpr0,
                     cpu.bs('00000000'), cpr])
mips32op("mtc1",    [cpu.bs('010001'), cpu.bs('00100'), rt, fs,
                     cpu.bs('00000000000')])
# XXXX TODO CFC1
mips32op("cfc1",    [cpu.bs('010001'), cpu.bs('00010'), rt, fs,
                     cpu.bs('00000000000')])
# XXXX TODO CTC1
mips32op("ctc1",    [cpu.bs('010001'), cpu.bs('00110'), rt, fs,
                     cpu.bs('00000000000')])

mips32op("break",   [cpu.bs('000000'), code, cpu.bs('001101')])
mips32op("syscall", [cpu.bs('000000'), code, cpu.bs('001100')])


mips32op("c",       [cpu.bs('010001'), bs_fmt, ft, fs, fcc, cpu.bs('0'),
                     cpu.bs('0'), cpu.bs('11'), bs_cond], [fcc, fs, ft])


mips32op("bc1t",    [cpu.bs('010001'), cpu.bs('01000'), fcc, cpu.bs('0'),
                     cpu.bs('1'), soff])
mips32op("bc1tl",    [cpu.bs('010001'), cpu.bs('01000'), fcc, cpu.bs('1'),
                     cpu.bs('1'), soff])
mips32op("bc1f",    [cpu.bs('010001'), cpu.bs('01000'), fcc, cpu.bs('0'),
                     cpu.bs('0'), soff])
mips32op("bc1fl",    [cpu.bs('010001'), cpu.bs('01000'), fcc, cpu.bs('1'),
                     cpu.bs('0'), soff])

mips32op("swc1",    [cpu.bs('111001'), base, ft, s16imm_noarg], [ft, base])

mips32op("cvt.d",   [cpu.bs('010001'), bs_fmt, cpu.bs('00000'), fs, fd,
                     cpu.bs('100001')], [fd, fs])
mips32op("cvt.w",   [cpu.bs('010001'), bs_fmt, cpu.bs('00000'), fs, fd,
                     cpu.bs('100100')], [fd, fs])
mips32op("cvt.s",   [cpu.bs('010001'), bs_fmt, cpu.bs('00000'), fs, fd,
                     cpu.bs('100000')], [fd, fs])

mips32op("ext",     [cpu.bs('011111'), rs, rt, esize, epos, cpu.bs('000000')],
         [rt, rs, epos, esize])
mips32op("ins",     [cpu.bs('011111'), rs, rt, eposh, epos, cpu.bs('000100')],
         [rt, rs, epos, eposh])

mips32op("seb",     [cpu.bs('011111'), cpu.bs('00000'), rt, rd, cpu.bs('10000'),
                     cpu.bs('100000')], [rd, rt])
mips32op("seh",     [cpu.bs('011111'), cpu.bs('00000'), rt, rd, cpu.bs('11000'),
                     cpu.bs('100000')], [rd, rt])
mips32op("wsbh",    [cpu.bs('011111'), cpu.bs('00000'), rt, rd, cpu.bs('00010'),
                     cpu.bs('100000')], [rd, rt])

mips32op("di",      [cpu.bs('010000'), cpu.bs('01011'), rt, cpu.bs('01100'),
                     cpu.bs('00000'), cpu.bs('0'), cpu.bs('00'), cpu.bs('000')])
mips32op("ei",      [cpu.bs('010000'), cpu.bs('01011'), rt, cpu.bs('01100'),
                     cpu.bs('00000'), cpu.bs('1'), cpu.bs('00'), cpu.bs('000')])


mips32op("tlbp",    [cpu.bs('010000'), cpu.bs('1'), cpu.bs('0'*19),
                     cpu.bs('001000')])
mips32op("tlbwi",   [cpu.bs('010000'), cpu.bs('1'), cpu.bs('0'*19),
                     cpu.bs('000010')])


mips32op("teq",     [cpu.bs('000000'), rs, rt, bs_code, cpu.bs('110100')],
         [rs, rt])
mips32op("tne",     [cpu.bs('000000'), rs, rt, bs_code, cpu.bs('110110')],         
         [rs, rt])

mips32op("clz",     [cpu.bs('011100'), rs, rt, rd, cpu.bs('00000'), cpu.bs('100000')],
        [rd, rs])
mips32op("clz",     [cpu.bs('000000'), rs, cpu.bs('00000'), rd, cpu.bs('00001010000')],
        [rd, rs])

mips32op("ll",      [cpu.bs('110000'), base, rt, s16imm_noarg], [rt, base])
mips32op("ll",      [cpu.bs('011111'), base, rt, s09imm_noarg, cpu.bs('0110110')], [rt, base])

mips32op("sc",      [cpu.bs('111000'), base, rt, s16imm_noarg], [rt, base])
mips32op("sc",      [cpu.bs('011111'), base, rt, s09imm_noarg, cpu.bs('0'), cpu.bs('100110')], [rt, base])

mips32op("sync",    [cpu.bs('000000000000000000000'), stype, cpu.bs('001111')], [stype])

mips32op("pref",    [cpu.bs('110011'), base, hint_pref, s16imm_noarg], [hint_pref, base])
mips32op("pref",    [cpu.bs('011111'), base, hint_pref, s09imm_noarg, cpu.bs('0110101')], [hint_pref, base])

mips32op("tlbwr",   [cpu.bs('01000010000000000000000000000110')], [])
mips32op("tlbr",    [cpu.bs('01000010000000000000000000000001')], [])

mips32op("cache",   [cpu.bs('101111'), base, oper, s16imm_noarg], [oper, base])
mips32op("cache",   [cpu.bs('011111'), base, oper, s09imm_noarg, cpu.bs('0100101')], [oper, base])

mips32op("eret",    [cpu.bs('01000010000000000000000000011000')], [])

mips32op("mtlo",    [cpu.bs('000000'), rs, cpu.bs('000000000000000'), cpu.bs('010011')], [rs])
mips32op("mthi",    [cpu.bs('000000'), rs, cpu.bs('000000000000000'), cpu.bs('010001')], [rs])

