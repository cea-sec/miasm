#!/usr/bin/env python
#-*- coding:utf-8 -*-

from pyparsing import *
from miasm2.core.cpu import *
import miasm2.arch.ebc.regs as regs_module
from miasm2.arch.ebc.regs import *
import struct

def swap(l, v):
    if   l <=  8: return v
    elif l == 16: return struct.unpack('<H', struct.pack('>H', v))[0]
    elif l == 32: return struct.unpack('<I', struct.pack('>I', v))[0]
    elif l == 64: return struct.unpack('<Q', struct.pack('>Q', v))[0]

def decode_immvalue(s, v):
    return sign_ext(swap_sint(s, v), s, 64)

def encode_immvalue(s, v):
    return swap_uint(s, v & ((1 << s) - 1))

def decode_index(field, mode):
    value = swap(field.l, field.value)
    sign = (value >> (field.l - 1)) & 0b1
    w    = (value >> (field.l - 4)) & 0b111
    ln   = w * (field.l / 8)
    n    = value & ((1 << ln) - 1)
    c    = (value >> ln) & ((1 << (field.l - 4 - ln)) - 1)
    return (1 - 2 * sign) * (c + n * mode / 8)

def encode_index(value, mode, size):
    if  value  & (1 << 63):
        value -= (1 << 64)
    sign   = (value < 0) and 1 or 0
    value  = abs(value)
    if  0 <= value < (1 << (size - 1 - 3)):
        n, c   = 0, value
        ln, lc = 0, len(bin(c)[2:])
    else:
        n, c   = divmod(value, mode / 8)
        ln, lc = len(bin(n)[2:]), len(bin(c)[2:])
    ln = ln + (ln % 2)
    w  = ln / 2
    return swap(size, int(str(sign) + bin(w)[2:].zfill(3) + bin(c)[2:].zfill(size - 4 - ln) + bin(n)[2:][:ln].zfill(ln), 2))

class additional_info:
    def __init__(self):
        self.except_on_instr = False

class instruction_ebc(instruction):
    delayslot = 0
    @staticmethod
    def arg2str(e, pos=None):
        return str(e).replace('@64', '').replace('(', '').replace(')', '')
    def dstflow2label(self, symbol_pool):
        e = self.args[0]
        if   isinstance(e, ExprOp) and isinstance(e.args[0], ExprId) and e.args[0].name == 'R0':
             e = e.args[1]
        if   not isinstance(e, ExprInt):
             return
        v = e.arg.arg
        if   self.name.startswith('JMP8'):
             ad = ExprInt64(int(self.offset) + self.l + v * 2).arg
        elif self.name.startswith('JMP32'):
             ad = ExprInt64(int(self.offset) + self.l + v).arg
        elif self.name.startswith('CALL'):
             if   self.name in ['CALL32', 'CALL32EX']:    # relative / might be a little more complicated: see uefi documentation
                  ad = ExprInt64(int(self.offset) + self.l + v).arg
             elif self.name in ['CALL32A', 'CALL32EXA']:  # absolute
                  raise ValueError('not implemented %r' % [hex(self.offset), self.name, e])
        else:
             raise ValueError('not implemented %r' % [hex(self.offset), self.name, e])
        #print '\033[31mDEBUG\033[m', hex(self.offset), self.l, e.size, hex(e.arg.arg), hex(v), '->', hex(ad)
        l = symbol_pool.getby_offset_create(ad)
        s = ExprId(l, e.size)
        self.args[0] = s
    def getdstflow(self, symbol_pool):
        return [self.args[0]]
    def is_subcall(self):
        return self.name.startswith('CALL')
    def dstflow(self):
        return self.name.startswith('CALL') or self.name.startswith('JMP')
    def breakflow(self):
        return self.name.startswith('CALL') or self.name.startswith('JMP') or self.name == 'RET'
    def splitflow(self):
        return self.name.startswith('CALL') or self.name in ['JMP8CC', 'JMP8CS', 'JMP32CC', 'JMP32CS']

class mn_ebc(cls_mn):
    name = 'ebc'
    num = 0
    bintree = {}
    all_mn = []
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    instruction = instruction_ebc
    delayslot = 0
    regs = regs_module
    pc = {32: IP}
    sp = {32: R0}
    @classmethod
    def getpc(cls, attrib):
        return IP
    @classmethod
    def getsp(cls, attrib):
        return R0
    @classmethod
    def getmn(cls, name):
        return name.upper()
    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = 32
        return [(subcls, name, bases, dct, fields)]
    def additional_info(self):
        return additional_info()

class customobj:
    pass

_, _, base_expr64 = gen_base_expr()
base_parser = parse_ast(lambda exprid: regs16_expr[int(exprid[1])], lambda exprint: ExprInt64(exprint))
base_expr64.setParseAction(base_parser)
base_expr64 |= Group(Suppress('[') + base_expr64 + Suppress(']')).setParseAction(lambda s, l, t: ExprMem(t[0][0], 64))

def addop(name, fields, args=None):
    dct = {'fields': fields}
    if  args is not None:
        dct['args'] = args
    type(name, (mn_ebc,), dct)

class ebc_reg(reg_noarg):
    parser = base_expr64
    reg_info = gpregs

class ebc_imm(imm_noarg):
    parser = base_expr64
    def decodeval(self, v):
        return swap(self.l, v)
    def encodeval(self, v):
        return swap(self.l, v)
    def decode(self, v):
        self.expr = ExprInt64(decode_immvalue(self.intsize, v))
        return True
    def encode(self):
        self.value = encode_immvalue(self.l, self.expr.arg.arg)
        return True

class ebc_int8(ebc_imm):
    intsize = 8
    intmask = (1 << intsize) - 1

class ebc_int16(ebc_imm):
    intsize = 16
    intmask = (1 << intsize) - 1

class ebc_int32(ebc_imm):
    intsize = 32
    intmask = (1 << intsize) - 1

class ebc_int64(ebc_imm):
    intsize = 64
    intmask = (1 << intsize) - 1

class ebc_cond_int16_op1(bsi):
    @classmethod
    def flen(cls, mode, v):
        return v['op1_hasimm'] == 1 and 16 or 0

class ebc_cond_int16_op2(bsi):
    @classmethod
    def flen(cls, mode, v):
        return v['op2_hasimm'] == 1 and 16 or 0

class ebc_cond_int32_op1(bsi):
    @classmethod
    def flen(cls, mode, v):
        return v['op1_hasimm'] == 1 and 32 or 0

class ebc_cond_int32_op2(bsi):
    @classmethod
    def flen(cls, mode, v):
        return v['op2_hasimm'] == 1 and 32 or 0

class op_arg(m_arg):
    parser = base_expr64
    def decode(self, v):
        fields = customobj()
        for fname in ['reg', 'isdir', 'hasimm', 'imm']:
            setattr(fields, 'op' + '_' + fname, getattr(self.parent, self.fname + '_' + fname, None))
        self.expr = fields.op_reg.expr
        if  fields.op_hasimm is not None and fields.op_hasimm.value:
            if  fields.op_isdir.value or self.parent.name in ['MOVQW','MOVQD']:
                value = decode_index(fields.op_imm, self.parent.mode)
            else:
                value = decode_immvalue(fields.op_imm.l, fields.op_imm.value)
            self.expr += ExprInt64(value)
        if  fields.op_isdir.value:
            self.expr = ExprMem(self.expr, 64)
        return True
    def encode(self):
        fields = customobj()
        for fname in ['reg', 'isdir', 'hasimm', 'imm']:
            setattr(fields, 'op' + '_' + fname, getattr(self.parent, self.fname + '_' + fname, None))
        e = self.expr
        if   isinstance(e, ExprMem):
             fields.op_isdir.value = 1
             e = e.arg
        else:
             fields.op_isdir.value = 0
        if   isinstance(e, ExprOp):
             if  fields.op_hasimm is not None:
                 fields.op_hasimm.value = 1
             if  fields.op_imm    is not None:
                 if  self.parent.name in ['MOVND','MOVQD','JMP32','CALL32']:
                     opsize = 32
                 else:
                     opsize = 16
                 if  fields.op_isdir.value or self.parent.name in ['MOVQW','MOVQD']:
                     fields.op_imm.value = encode_index(e.args[1].arg.arg, self.parent.mode, opsize)
                 else:
                     fields.op_imm.value = encode_immvalue(opsize, e.args[1].arg.arg)
             e = e.args[0]
        else:
             if  fields.op_hasimm is not None:
                 fields.op_hasimm.value = 0
             if  fields.op_imm    is not None:
                 fields.op_imm = None
        if   isinstance(e, ExprId):
             fields.op_reg.expr = e
        return True

op1_reg    = bs(l=3,  cls=(ebc_reg,),            fname='op1_reg')
op1_isdir  = bs(l=1,                             fname='op1_isdir')
op1_hasimm = bs(l=1,                             fname='op1_hasimm')
op1_imm16  = bs(l=16, cls=(ebc_cond_int16_op1,), fname='op1_imm')
op1_imm32  = bs(l=32, cls=(ebc_cond_int32_op1,), fname='op1_imm')
op1_op     = bs(l=0,  cls=(op_arg,),             fname='op1')
op2_reg    = bs(l=3,  cls=(ebc_reg,),            fname='op2_reg')
op2_isdir  = bs(l=1,                             fname='op2_isdir')
op2_hasimm = bs(l=1,                             fname='op2_hasimm')
op2_imm16  = bs(l=16, cls=(ebc_cond_int16_op2,), fname='op2_imm')
op2_imm32  = bs(l=32, cls=(ebc_cond_int32_op2,), fname='op2_imm')
op2_op     = bs(l=0,  cls=(op_arg,),             fname='op2')
op_mreg    = bs(l=3,  cls=(ebc_reg,   m_arg,))
op_int8    = bs(l=8,  cls=(ebc_int8,  m_arg,))
op_int16   = bs(l=16, cls=(ebc_int16, m_arg,))
op_int32   = bs(l=32, cls=(ebc_int32, m_arg,))
op_int64   = bs(l=64, cls=(ebc_int64, m_arg,))

addop('add32',      [ op2_hasimm, bs('0'),    bs('001100'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('add64',      [ op2_hasimm, bs('1'),    bs('001100'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('ashr32',     [ op2_hasimm, bs('0'),    bs('011001'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('break',      [                       bs('00000000'), op_int8 ],                                                                        [ op_int8 ])
addop('call32',     [ op1_hasimm, bs('0'),    bs('000011'), bs('00'), bs('0'), bs('1'), op1_isdir, op1_reg, op1_imm32, op1_op ],              [ op1_op ])
addop('call32a',    [ op1_hasimm, bs('0'),    bs('000011'), bs('00'), bs('0'), bs('0'), op1_isdir, op1_reg, op1_imm32, op1_op ],              [ op1_op ])
addop('call32exa',  [ op1_hasimm, bs('0'),    bs('000011'), bs('00'), bs('1'), bs('0'), op1_isdir, op1_reg, op1_imm32, op1_op ],              [ op1_op ])
addop('cmp32eq',    [ op2_hasimm, bs('0'),    bs('000101'), op2_isdir, op2_reg, bs('0'), op_mreg, op2_imm16, op2_op ],                        [ op_mreg, op2_op ])
addop('cmp64eq',    [ op2_hasimm, bs('1'),    bs('000101'), op2_isdir, op2_reg, bs('0'), op_mreg, op2_imm16, op2_op ],                        [ op_mreg, op2_op ])
addop('cmp64ugte',  [ op2_hasimm, bs('1'),    bs('001001'), op2_isdir, op2_reg, bs('0'), op_mreg, op2_imm16, op2_op ],                        [ op_mreg, op2_op ])
addop('cmp64ulte',  [ op2_hasimm, bs('1'),    bs('001000'), op2_isdir, op2_reg, bs('0'), op_mreg, op2_imm16, op2_op ],                        [ op_mreg, op2_op ])
addop('cmpi32weq',  [ bs('0'), bs('0'),       bs('101101'), bs('000'), op1_hasimm, op1_isdir, op1_reg, op1_imm16, op_int16, op1_op ],         [ op1_op, op_int16 ])
addop('cmpi32wgte', [ bs('0'), bs('0'),       bs('101111'), bs('000'), op1_hasimm, op1_isdir, op1_reg, op1_imm16, op_int16, op1_op ],         [ op1_op, op_int16 ])
addop('cmpi32wlte', [ bs('0'), bs('0'),       bs('101110'), bs('000'), op1_hasimm, op1_isdir, op1_reg, op1_imm16, op_int16, op1_op ],         [ op1_op, op_int16 ])
addop('extndd64',   [ op2_hasimm, bs('1'),    bs('011100'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('jmp8',       [ bs('0'), bs('0'),       bs('000010'), op_int8 ],                                                                        [ op_int8 ])
addop('jmp8cc',     [ bs('1'), bs('0'),       bs('000010'), op_int8 ],                                                                        [ op_int8 ])
addop('jmp8cs',     [ bs('1'), bs('1'),       bs('000010'), op_int8 ],                                                                        [ op_int8 ])
addop('jmp32',      [ op1_hasimm, bs('0'),    bs('000001'), bs('0'), bs('0'), bs('0'), bs('1'), op1_isdir, op1_reg, op1_imm32, op1_op ],      [ op1_op ])
addop('jmp32cc',    [ op1_hasimm, bs('0'),    bs('000001'), bs('1'), bs('0'), bs('0'), bs('1'), op1_isdir, op1_reg, op1_imm32, op1_op ],      [ op1_op ])
addop('jmp32cs',    [ op1_hasimm, bs('0'),    bs('000001'), bs('1'), bs('1'), bs('0'), bs('1'), op1_isdir, op1_reg, op1_imm32, op1_op ],      [ op1_op ])
addop('mod32',      [ op2_hasimm, bs('0'),    bs('010010'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('movbd',      [ op1_hasimm, op2_hasimm, bs('100001'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm32, op2_imm32, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movbw',      [ op1_hasimm, op2_hasimm, bs('011101'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movdd',      [ op1_hasimm, op2_hasimm, bs('100011'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm32, op2_imm32, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movdw',      [ op1_hasimm, op2_hasimm, bs('011111'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movqd',      [ op1_hasimm, op2_hasimm, bs('100100'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm32, op2_imm32, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movqw',      [ op1_hasimm, op2_hasimm, bs('100000'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movwd',      [ op1_hasimm, op2_hasimm, bs('100010'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm32, op2_imm32, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movww',      [ op1_hasimm, op2_hasimm, bs('011110'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movnd',      [ op1_hasimm, op2_hasimm, bs('110011'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm32, op2_imm32, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movnw',      [ op1_hasimm, op2_hasimm, bs('110010'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movsnw',     [ op1_hasimm, op2_hasimm, bs('100101'), op2_isdir, op2_reg, op1_isdir, op1_reg, op1_imm16, op2_imm16, op1_op, op2_op ],   [ op1_op, op2_op ])
addop('movidw',     [ bs('01'),               bs('110111'), bs('0'), op1_hasimm, bs('10'), op1_isdir, op1_reg, op1_imm16, op_int16, op1_op ], [ op1_op, op_int16 ])
addop('moviqd',     [ bs('10'),               bs('110111'), bs('0'), op1_hasimm, bs('11'), op1_isdir, op1_reg, op1_imm16, op_int32, op1_op ], [ op1_op, op_int32 ])
addop('moviqq',     [ bs('11'),               bs('110111'), bs('0'), op1_hasimm, bs('11'), op1_isdir, op1_reg, op1_imm16, op_int64, op1_op ], [ op1_op, op_int64 ])
addop('moviqw',     [ bs('01'),               bs('110111'), bs('0'), op1_hasimm, bs('11'), op1_isdir, op1_reg, op1_imm16, op_int16, op1_op ], [ op1_op, op_int16 ])
addop('movreld',    [ bs('10'),               bs('111001'), bs('0'), op1_hasimm, bs('00'), op1_isdir, op1_reg, op1_imm16, op_int32, op1_op ], [ op1_op, op_int32 ])
addop('movreld',    [ bs('10'),               bs('111001'), bs('0'), op1_hasimm, bs('11'), op1_isdir, op1_reg, op1_imm16, op_int32, op1_op ], [ op1_op, op_int32 ])
addop('mul64',      [ op2_hasimm, bs('1'),    bs('001110'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('neg32',      [ op2_hasimm, bs('0'),    bs('001011'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('neg64',      [ op2_hasimm, bs('1'),    bs('001011'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('not32',      [ op2_hasimm, bs('0'),    bs('001010'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('or32',       [ op2_hasimm, bs('0'),    bs('010101'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('shl32',      [ op2_hasimm, bs('0'),    bs('010111'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('shl64',      [ op2_hasimm, bs('1'),    bs('010111'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('xor32',      [ op2_hasimm, bs('0'),    bs('010110'), op2_isdir, op2_reg, op1_isdir, op1_reg, op2_imm16, op1_op, op2_op ],              [ op1_op, op2_op ])
addop('ret',        [ bs('0000010000000000') ], [])

