#-*- coding:utf-8 -*-

from builtins import range

import logging
from pyparsing import *
from collections import defaultdict
from builtins import range
import struct
from math import ceil

from miasm.expression.expression import *
from miasm.core.cpu import *
from miasm.core.bin_stream import bin_stream
import miasm.arch.wasm.regs as regs_module
from miasm.arch.wasm.regs import *
from miasm.core.asm_ast import AstInt, AstId, AstMem, AstOp
from miasm.loader.wasm_utils import encode_LEB128

log = logging.getLogger("wasmdis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

SPACE = Suppress(' ')
LPAR = Suppress('(')
RPAR = Suppress(')')
RESULT = Suppress('result')
EQUAL = Suppress('=')
OFFSET = Suppress('offset')
ALIGN = Suppress('align')

# (non-empty) block type parser
valtypes_str = ['f64', 'f32', 'i64', 'i32']
valtypes_expr = [ExprId(i, 8) for i in valtypes_str]
def valtype_str2expr(tokens):
    assert len(tokens) == 1 and len(tokens[0]) == 1 # In Wasm v1, a block can return at most one value
    i = valtypes_str.index(tokens[0][0])
    return AstId(valtypes_expr[i])

blocktype_val = Group(LPAR + RESULT + literal_list(valtypes_str) + RPAR).setParseAction(valtype_str2expr)

# Memargs
basic_deref = lambda x: x[0][0]
offset_parser = Optional(Group(OFFSET + EQUAL + base_expr), default=0).setParseAction(basic_deref)

def align_parser(default_value):
    return Optional(Group(ALIGN + EQUAL + base_expr), default=default_value).setParseAction(basic_deref)

# Floats
frac = Word(nums).setParseAction()

#float_parser = Or()

class additional_info(object):

    def __init__(self):
        self.except_on_instr = False


class instruction_wasm(instruction):
    __slots__ = []
    delayslot = 0

    @property
    def has_memarg(self):
        try:
            opcode = struct.unpack('B', self.b[0])[0]
            return (0x27 < opcode) and (opcode < 0x3F)
        except TypeError:
            return self.name in [
                'i32.load',
                'i64.load',
                'f32.load',
                'f64.load',
                'i32.load8_s',
                'i32.load8_u',
                'i32.load16_s',
                'i32.load16_u',
                'i64.load8_s',
                'i64.load8_u',
                'i64.load16_s',
                'i64.load16_u',
                'i64.load32_s',
                'i64.load32_u',
                'i32.store',
                'i64.store',
                'f32.store',
                'f64.store',
                'i32.store8',
                'i32.store16',
                'i64.store8',
                'i64.store16',
                'i64.store32',
            ]

    def to_string(self, loc_db=None):
        o = "%-10s " % self.name
        args = []
        for i, arg in enumerate(self.args):
            if isinstance(arg, int):
                return o
            if not isinstance(arg, m2_expr.Expr):
                raise ValueError('zarb arg type')
            x = self.arg2str(arg, i, loc_db)
            args.append(x)
        if self.has_memarg:
            o += self.gen_memarg(args)
        else:
            o += self.gen_args(args)
        return o

    def gen_args(self, args):
        return ' '.join([str(x) for x in args])

    def gen_memarg(self, args):
        assert len(args) == 2
        return 'offset={} align={}'.format(str(args[0]), str(args[1]))

    @staticmethod
    def arg2str(expr, index=None, loc_db=None):
        if isinstance(expr, ExprInt): # Only valid for standard integers
            o = str(expr)
        elif isinstance(expr, ExprId):
            # valtype in structure's return
            if expr.name in ['i32', 'i64', 'f32', 'f64']:
                o = "(result {})".format(expr.name)
            elif expr.name.startswith('$'): # structure label
                o = expr.name
            else:
                fds
        elif isinstance(expr, ExprLoc):
            o, = loc_db.get_location_names(expr.loc_key)
        else:
            fds
        return o

    @property
    def is_structure(self):
        return self.name in ['loop', 'block', 'end', 'if', 'else']

    def dstflow(self):
        return self.name in ['br', 'br_if', 'br_table', 'return']

    def dstflow2label(self, loc_db):
        fds
        expr = self.args[1]
        if not isinstance(expr, ExprInt):
            return

        addr = int(expr)
        loc_key = loc_db.get_or_create_offset_location(addr)
        self.args[1] = ExprLoc(loc_key, expr.size)

    def breakflow(self):
        return self.name in ['br', 'br_if', 'br_table', 'if', 'else', 'call', 'return'] # call_indirect ?

    def splitflow(self):
        return self.name in ['br_if', 'if', 'call'] # call_indirect ?

    def setdstflow(self, a):
        fds

    def is_subcall(self):
        return self.name in ['call'] # call_indirect ?

    def getdstflow(self, loc_db):
        if self.name in ['br', 'br_if']:
            return self.args[0] # br idx
        if self.name in ['br_table']:
            return self.args # all br indexes
        if self.name in ['call']: # call_indirect ?
            return self.args[0] # func idx
        fds

    def get_symbol_size(self, symbol, loc_db):
        fds

    def fixDstOffset(self):
        e = self.args[1]
        if not isinstance(e, ExprInt):
            log.debug('dyn dst %r', e)
            return
        off = int(e)
        if off % 2:
            raise ValueError('strange offset! %r' % off)
        self.args[1] = ExprInt(off, 16)

    def get_info(self, c):
        pass

    def __str__(self):
        o = super(instruction_wasm, self).__str__()
        return o

    def get_args_expr(self):
        args = []
        for a in self.args:
            args.append(a)
        return args

class mn_wasm(cls_mn):
    name = "wasm"
    regs = regs_module
    all_mn = []
    bintree = {}
    num = 0
    delayslot = 0
    pc = {None: PC}
    sp = {None: SP}
    all_mn_mode = defaultdict(list)
    all_mn_name = defaultdict(list)
    all_mn_inst = defaultdict(list)
    instruction = instruction_wasm
    # max_instruction_len = Nothing (instructions may be very long...)


    @classmethod
    def getpc(cls, attrib):
        return PC

    @classmethod
    def getsp(cls, attrib):
        return SP

    @classmethod
    def check_mnemo(cls, fields):
        pass

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        dct['mode'] = None
        return [(subcls, name, bases, dct, fields)]

    def additional_info(self):
        info = additional_info()
        return info

    @classmethod
    def getmn(cls, name):
        return name

    def reset_class(self):
        super(mn_wasm, self).reset_class()

    def getnextflow(self, loc_db):
        raise NotImplementedError('not fully functional')


def addop(name, fields, args=None, alias=False):
    dct = {"fields": fields}
    dct["alias"] = alias
    if args is not None:
        dct['args'] = args
    type(name, (mn_wasm,), dct)


class wasm_arg(m_arg):
    def asm_ast_to_expr(self, arg, loc_db):
        if isinstance(arg, AstInt):
            if hasattr(self, '_int_size'): # arg is LEB_128-encoded
                return ExprInt(arg.value, self._int_size)
            fds
        if isinstance(arg, AstId):
            if isinstance(arg.name, ExprId):
                return arg.name
            fds
        fds
        if isinstance(arg, AstMem):
            if isinstance(arg.ptr, AstId) and isinstance(arg.ptr.name, str):
                return None
            ptr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if ptr is None:
                return None
            return ExprMem(ptr, arg.size)
        fds
        if isinstance(arg, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
            if None in args:
                return None
            return ExprOp(arg.op, *args)
        return None

mask_all = lambda x: (1 << x) - 1
mask_msb = lambda x: 1 << (x - 1)

def sxt(i, cur_l, dst_l):
    '''
    Sign extends the integer @i (encoded on @cur_l bits)
    to an int of @dst_l bits
    '''
    if cur_l < dst_l and i & mask_msb(cur_l) != 0:
        i |= mask_all(dst_l) ^ mask_all(cur_l)
    return i

def sct(i, cur_l):
    '''
    "Sign contracts" the @cur_l-bits integer @i as much as possible:
    - removes the MSBs while they are all the same
    - sign extends to the lowest 7-bit multiple greater than the result
    - returns a list of 7-bits inegers to encode
    '''
    n = cur_l
    msb_zero = True if i & mask_msb(n) == 0 else False
    res = i & mask_all(7)
    while n > 7:
        n -= 1
        if msb_zero ^ (i & mask_msb(n) == 0):
            n += 2
            res = i & mask_all(n)
            break
    res_array = []
    while n > 0:
        res_array.append(res & mask_all(7))
        res >>= 7
        n -= 7
    return res_array

def vtobl(v, n_bytes):
    '''
    "v to byte_list": convert the v arg of decode method
    to a list of bytes
    '''
    res = []
    for i in range(n_bytes):
        res[0:0] = [v & 0xff]
        v >>= 8
    return res

def decode_LEB128(bl):
    '''
    bl is the result returned by vtobl
    '''
    res = 0
    i = 0
    n = len(bl)
    while True:
        if i == n:
            raise Exception("Malformed integer")
        byt = bl[i]
        # get value of the 7-bit sub-integer
        # and add it correctly to the result
        res += (byt & 0x7f) << (7*i)
        i += 1

        # test if it was the last one
        if byt & 0x80 == 0:
            break
    return res, i

def get_LEB128_len(bs, max_len):
    '''
    gets the number of bytes a LEB128 is encoded on
    does not rewind the bs pointer
    '''
    i = 0
    while i < max_len:
        i += 1
        byte = ord(bs.readbs())
        if byte & 0x80 == 0:
            return i*8
    return None

class imm_arg_LEB128(imm_noarg, wasm_arg):
    '''
    This argument is a LEB128-encoded integer
    Make classes inerit from this one and add
    a '_int_size' attribute with the size of the
    integer (in bits)
    '''
    parser = base_expr

    @classmethod
    def flen(cls, mode, v, bs, offset_b):
        ofs = bs.offset
        # do not parse some bytes, start at the right spot
        assert(offset_b % 8 == 0)
        bs.setoffset(offset_b // 8)
        max_l = ceil(cls._int_size / 7.)
        res = get_LEB128_len(bs, max_l)
        bs.setoffset(ofs)
        return res

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False

        # Value to encode in LEB_128
        LEB128_bytes = sct(int(self.expr), self._int_size)

        self.value  = 0
        for b in LEB128_bytes[:-1]:
            self.value += 0x80
            self.value += b
            self.value <<= 8
        self.value += LEB128_bytes[-1]
        self.l = len(LEB128_bytes)*8
        return True

    def decode(self, v):
        n_bytes = self.l // 8
        bl = vtobl(v, n_bytes)
        val, n = decode_LEB128(bl)
        assert(n == n_bytes)
        val = sxt(val, n*7, self._int_size) & mask_all(self._int_size)
        self.expr = ExprInt(val, self._int_size)
        return True

class imm_arg_i32(imm_arg_LEB128):
    _int_size = 32

class imm_arg_i64(imm_arg_LEB128):
    _int_size = 64

class imm_arg_offset(imm_arg_i32):
    parser = offset_parser

class imm_arg_align_1(imm_arg_i32):
    parser = align_parser(1)

class imm_arg_align_2(imm_arg_i32):
    parser = align_parser(2)

class imm_arg_align_4(imm_arg_i32):
    parser = align_parser(4)

class imm_arg_align_8(imm_arg_i32):
    parser = align_parser(8)

class arg_br_table(wasm_arg):

    @classmethod
    def flen(cls, mode, v, bs, offset_b):
        ofs = bs.offset

        assert(offset_b % 8 == 0)
        bs.setoffset(offset_b // 8)

        # Find the length of the head integer and decode it
        i = 0
        max_l = 5
        len_head = None
        n_dest = 0
        while i < max_l:
            byte = ord(bs.readbs())
            n_dest += (byte & 0x7f) << (7 * i)
            i += 1
            if byte & 0x80 == 0:
                len_head = i*8
                break

        if len_head == None:
            return None

        total_length = len_head
        for i in range(n_dest +1):
            total_length += get_LEB128_len(bs, 5)

        bs.setoffset(ofs)
        return total_length

    def decode(self, v):
        n_bytes = self.l // 8
        bl = vtobl(v, n_bytes)
        args = []
        n_parsed = 0
        while n_parsed < n_bytes:
            val, n = decode_LEB128(bl[n_parsed:])
            val = sxt(val, n*7, 32) & mask_all(32)
            arg = imm_arg_i32()
            arg.expr = ExprInt(val, 32)
            args.append(arg)
            n_parsed += n
        # remove vec length
        self.parent.args = args[1:]
        return True

    def encode(self):
        self.value = 0
        self.l = 0

        # Encode number of args (minus default) + args
        for i in [len(self.parent.args)-1] + [int(arg.expr) for arg in self.parent.args]:
            # make room for the upcoming arg
            self.value <<= 8
            LEB128_bytes = sct(i, 32)
            for b in LEB128_bytes[:-1]:
                self.value += 0x80
                self.value += b
                self.value <<= 8
            self.value += LEB128_bytes[-1]
            self.l += len(LEB128_bytes) * 8
        return True


VALTYPES = [
    (0x7F,'i32'),
    (0x7E,'i64'),
    (0x7D,'f32'),
    (0x7C,'f64'),
]

class imm_f32(wasm_arg):
    parser = base_expr

    def decode(self, v):
        pass

    def encode(self, v):
        pass

class block_result_no_empty(imm_noarg):
    parser = blocktype_val

    def decode(self, v):
        for val, name in VALTYPES:
            if val == v:
                self.expr = ExprId(name, 8)
                return True
        return False

    def encode(self):
        if not self.expr.is_id():
            return False
        for i, v in VALTYPES:
            if v == self.expr.name:
                self.value = i
                return True
        fds
        return False



single_byte_name = bs_name(l=8, name={
    'unreachable'         : 0x00,
    'nop'                 : 0x01,
    'else'                : 0x05,
    'end'                 : 0x0B,
    'return'              : 0x0F,
    'drop'                : 0x1A,
    'select'              : 0x1B,
    'i32.eqz'             : 0x45,
    'i32.eq'              : 0x46,
    'i32.ne'              : 0x47,
    'i32.lt_s'            : 0x48,
    'i32.lt_u'            : 0x49,
    'i32.gt_s'            : 0x4A,
    'i32.gt_u'            : 0x4B,
    'i32.le_s'            : 0x4C,
    'i32.le_u'            : 0x4D,
    'i32.ge_s'            : 0x4E,
    'i32.ge_u'            : 0x4F,
    'i64.eqz'             : 0x50,
    'i64.eq'              : 0x51,
    'i64.ne'              : 0x52,
    'i64.lt_s'            : 0x53,
    'i64.lt_u'            : 0x54,
    'i64.gt_s'            : 0x55,
    'i64.gt_u'            : 0x56,
    'i64.le_s'            : 0x57,
    'i64.le_u'            : 0x58,
    'i64.ge_s'            : 0x59,
    'i64.ge_u'            : 0x5A,
    'f32.eq'              : 0x5B,
    'f32.ne'              : 0x5C,
    'f32.lt'              : 0x5D,
    'f32.gt'              : 0x5E,
    'f32.le'              : 0x5F,
    'f32.ge'              : 0x60,
    'f64.eq'              : 0x61,
    'f64.ne'              : 0x62,
    'f64.lt'              : 0x63,
    'f64.gt'              : 0x64,
    'f64.le'              : 0x65,
    'f64.ge'              : 0x66,
    'i32.clz'             : 0x67,
    'i32.ctz'             : 0x68,
    'i32.popcnt'          : 0x69,
    'i32.add'             : 0x6A,
    'i32.sub'             : 0x6B,
    'i32.mul'             : 0x6C,
    'i32.div_s'           : 0x6D,
    'i32.div_u'           : 0x6E,
    'i32.rem_s'           : 0x6F,
    'i32.rem_u'           : 0x70,
    'i32.and'             : 0x71,
    'i32.or'              : 0x72,
    'i32.xor'             : 0x73,
    'i32.shl'             : 0x74,
    'i32.shr_s'           : 0x75,
    'i32.shr_u'           : 0x76,
    'i32.rotl'            : 0x77,
    'i32.rotr'            : 0x78,
    'i64.clz'             : 0x79,
    'i64.ctz'             : 0x7A,
    'i64.popcnt'          : 0x7B,
    'i64.add'             : 0x7C,
    'i64.sub'             : 0x7D,
    'i64.mul'             : 0x7E,
    'i64.div_s'           : 0x7F,
    'i64.div_u'           : 0x80,
    'i64.rem_s'           : 0x81,
    'i64.rem_u'           : 0x82,
    'i64.and'             : 0x83,
    'i64.or'              : 0x84,
    'i64.xor'             : 0x85,
    'i64.shl'             : 0x86,
    'i64.shr_s'           : 0x87,
    'i64.shr_u'           : 0x88,
    'i64.rotl'            : 0x89,
    'i64.rotr'            : 0x8A,
    'f32.abs'             : 0x8B,
    'f32.neg'             : 0x8C,
    'f32.ceil'            : 0x8D,
    'f32.floor'           : 0x8E,
    'f32.trunc'           : 0x8F,
    'f32.nearest'         : 0x90,
    'f32.sqrt'            : 0x91,
    'f32.add'             : 0x92,
    'f32.sub'             : 0x93,
    'f32.mul'             : 0x94,
    'f32.div'             : 0x95,
    'f32.min'             : 0x96,
    'f32.max'             : 0x97,
    'f32.copysign'        : 0x98,
    'f64.abs'             : 0x99,
    'f64.neg'             : 0x9A,
    'f64.ceil'            : 0x9B,
    'f64.floor'           : 0x9C,
    'f64.trunc'           : 0x9D,
    'f64.nearest'         : 0x9E,
    'f64.sqrt'            : 0x9F,
    'f64.add'             : 0xA0,
    'f64.sub'             : 0xA1,
    'f64.mul'             : 0xA2,
    'f64.div'             : 0xA3,
    'f64.min'             : 0xA4,
    'f64.max'             : 0xA5,
    'f64.copysign'        : 0xA6,
    'i32.wrap_i64'        : 0xA7,
    'i32.trunc_f32_s'     : 0xA8,
    'i32.trunc_f32_u'     : 0xA9,
    'i32.trunc_f64_s'     : 0xAA,
    'i32.trunc_f64_u'     : 0xAB,
    'i64.extend_i32_s'    : 0xAC,
    'i64.extend_i32_u'    : 0xAD,
    'i64.trunc_f32_s'     : 0xAE,
    'i64.trunc_f32_u'     : 0xAF,
    'i64.trunc_f64_s'     : 0xB0,
    'i64.trunc_f64_u'     : 0xB1,
    'f32.convert_i32_s'   : 0xB2,
    'f32.convert_i32_u'   : 0xB3,
    'f32.convert_i64_s'   : 0xB4,
    'f32.convert_i64_u'   : 0xB5,
    'f32.demote_f64'      : 0xB6,
    'f64.convert_i32_s'   : 0xB7,
    'f64.convert_i32_u'   : 0xB8,
    'f64.convert_i64_s'   : 0xB9,
    'f64.convert_i64_u'   : 0xBA,
    'f64.promote_f32'     : 0xBB,
    'i32.reinterpret_f32' : 0xBC,
    'i64.reinterpret_f64' : 0xBD,
    'f32.reinterpret_i32' : 0xBE,
    'f64.reinterpret_i64' : 0xBF,
})

addop('single_byte', [single_byte_name])

memarg_1 = [bs(l=8888, cls=(imm_arg_offset,)), bs(l=8888, cls=(imm_arg_align_1,))]
memarg_2 = [bs(l=8888, cls=(imm_arg_offset,)), bs(l=8888, cls=(imm_arg_align_2,))]
memarg_4 = [bs(l=8888, cls=(imm_arg_offset,)), bs(l=8888, cls=(imm_arg_align_4,))]
memarg_8 = [bs(l=8888, cls=(imm_arg_offset,)), bs(l=8888, cls=(imm_arg_align_8,))]

i32_bs = [bs(l=1, cls=(imm_arg_i32,))]
addop('i32.const', [bs('01000001')] + i32_bs)


i64_bs = [bs(l=1, cls=(imm_arg_i64,))]
addop('i64.const',[bs('01000010')] + i64_bs)

# Floating numbers
#TODO#
#addop('f32.const', [])

block_ret = bs(l=8, cls=(block_result_no_empty, wasm_arg))

# Structured instructions
#no return
addop('block', [bs('00000010'), bs('01000000')])
addop('loop',  [bs('00000011'), bs('01000000')])
addop('if',    [bs('00000100'), bs('01000000')])
#return
addop('block', [bs('00000010'), block_ret])
addop('loop',  [bs('00000011'), block_ret])
addop('if',    [bs('00000100'), block_ret])

# Branches
addop('br',       [bs('00001100')] + i32_bs)
addop('br_if',    [bs('00001101')] + i32_bs)
addop('br_table', [bs('00001110'), bs(l=1, cls=(arg_br_table,))])

# Calls
addop('call',          [bs('00010000')] + i32_bs)
addop('call_indirect', [bs('00010001')] + i32_bs + [bs('00000000')])

# Variable instructions
var_instr_names = bs_name(l=8, name={
    'local.get' : 0x20,
    'local.set' : 0x21,
    'local.tee' : 0x22,
    'global.get': 0x23,
    'global.set': 0x24,
})
addop('var_instr', [var_instr_names] + i32_bs)

# Memory instructions
#The 'align' field in most memory instructions has a default value
#This value depends on the instruction
mem_instr_default_1 = bs_name(l=8, name={
    'i32.load8_s': 0x2C,
    'i32.load8_u': 0x2D,
    'i64.load8_s': 0x30,
    'i64.load8_u': 0x31,
    'i32.store8' : 0x3A,
    'i64.store8' : 0x3C,
})
addop('mem_instr_default_1', [mem_instr_default_1] + memarg_1)

mem_instr_default_2 = bs_name(l=8, name={
    'i32.load16_s': 0x2E,
    'i32.load16_u': 0x2F,
    'i64.load16_s': 0x32,
    'i64.load16_u': 0x33,
    'i32.store16' : 0x3B,
    'i64.store16' : 0x3D,
})
addop('mem_instr_default_2', [mem_instr_default_2] + memarg_2)

mem_instr_default_4 = bs_name(l=8, name={
    'i32.load'    : 0x28,
    'f32.load'    : 0x2A,
    'i64.load32_s': 0x34,
    'i64.load32_u': 0x35,
    'i32.store'   : 0x36,
    'f32.store'   : 0x38,
    'i64.store32' : 0x3E,
})
addop('mem_instr_default_4', [mem_instr_default_4] + memarg_4)

mem_instr_default_8 = bs_name(l=8, name={
    'i64.load' : 0x29,
    'f64.load' : 0x2B,
    'i64.store': 0x37,
    'f64.store': 0x39,
})
addop('mem_instr_default_8', [mem_instr_default_8] + memarg_4)

addop('memory.size', [bs('0011111100000000')])
addop('memory.grow', [bs('0100000000000000')])
