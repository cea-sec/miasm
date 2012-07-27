#
# Copyright (C) 2011 Pierre LALET <pierre.lalet@cea.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import struct
import logging
from shlex import shlex

log = logging.getLogger("javaarch")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

SEXES = {
    0: '>', # big-endian
    1: '<', # little-endian
    }

mnemo_db = {}
mnemo_db_name = {}

ARG_CONST = 0     # Constant
ARG_CPI = 1       # Constant Pool Index
ARG_LOCALVAR = 2  # Local var #
ARG_OFFSET = 3    # Memory offset (e.g. goto, if*, etc.)
ARG_ARRAYTYPE = 4 # specific for newarray

ARG_ARRAYTYPE_TYPES = {
    4: "boolean",
    5: "char",
    6: "float",
    7: "double",
    8: "byte",
    9: "short",
    10:"int",
    11:"long"
}

AFS_symb = "symb__intern__"
AFS_imm = "imm"

class mnemonic:
    def __init__(self, name, code, size, desc, fmt=None,
                 breakflow=False, splitflow=False, dstflow=False):
        self.code = code
        self.size = size
        self.name = name
        self.desc = desc
        if fmt is None:
            self.argfmt = argfmt()
        elif type(fmt) is str:
            self.argfmt = argfmt(fmt=fmt)
        else:
            self.argfmt = fmt
        self.breakflow = breakflow
        self.splitflow = splitflow
        self.dstflow = dstflow
        mnemo_db[code] = self
        mnemo_db_name[name] = self
    def __repr__(self):
        r =  "mnemonic(%s, %s, %s, %s" % (repr(self.name), repr(self.code),
                                          repr(self.size), repr(self.desc))
        if repr(self.argfmt) !=  "argfmt()":
            r += ", fmt=%s" % repr(self.argfmt)
        if self.breakflow: r += ", breakflow=True"
        if self.splitflow: r += ", splitflow=True"
        if self.dstflow: r += ", dstflow=True"
        return r + ")"

class argfmt:
    def __init__(self, fmt='', types=None, align=None):
        self.fmt = fmt
        self.types = types
        self.align = align
    def __repr__(self):
        r = "argfmt("
        if self.fmt != '':
            r += 'fmt=%s' % repr(self.fmt)
        if self.types is not None:
            if r != "argfmt(": r += ', '
            r += 'types=%s' % repr(self.types)
        if self.align is not None:
            if r != "argfmt(": r += ', '
            r += 'align=%s' % repr(self.align)
        return r+')'
    def get(self, bin, sex=0, address=None):
        sex = SEXES[sex]
        if self.align is not None:
            if address is not None:
                x = bin.readbs((self.align - ((address+1) % self.align)) % self.align)
                if x != len(x) * '\x00':
                    log.warning('Reading %s as padding (address == %s, align == %d)' % (repr(x), hex(address), self.align))
            else:
                log.warning('Address not specified while needed to align properly')
        fmt = self.fmt.split('#')
        arg = struct.unpack(sex+fmt[0], bin.readbs(struct.calcsize(fmt[0])))
        for f in fmt[1:]:
            # special format #x:y:z means eval(x) times an 'y' format
            # elt, then z (regular format) ; see {table,lookup}switch.
            f = f.split(':', 2)
            # in case we are disassembling invalid instructions
            ff = f[1] * eval(f[0])
            if len(ff) > 0x1000:
                raise ValueError("Probably disassembling invalid code: too many arguments.")
            for h in ff, f[2]:
                arg += struct.unpack(sex+h, bin.readbs(struct.calcsize(h)))
        return list(arg)
    def set(self, arg, sex=0, address=None):
        toparse = map(int, arg)
        sex = SEXES[sex]
        out = ''
        if self.align is not None:
            if address is not None:
                out += ((self.align - ((address+1) % self.align)) % self.align) * '\x00'
            else:
                log.warning('Address not specified while needed to align properly')
        fmt = self.fmt.split('#')
        # WARNING: using len() to get the number of parameters makes
        # it impossible to use things like "4b" in format
        # specifications.
        out += struct.pack(sex+fmt[0], *toparse[:len(fmt[0])])
        arg = toparse[:len(fmt[0])]
        toparse = toparse[len(fmt[0]):]
        for f in fmt[1:]:
            # see comment in .get() method
            f = f.split(':', 2)
            ff = f[1] * eval(f[0])
            if len(ff) > 0x1000:
                raise ValueError("Probably disassembling invalid code: too many arguments.")
            for h in ff, f[2]:
                # WARNING: same here.
                out += struct.pack(sex+h, *toparse[:len(h)])
                arg += toparse[:len(h)]
                toparse = toparse[len(h):]
        return out
    def calcsize(self):
        if self.fmt == '' or '#' in self.fmt: return 0
        return struct.calcsize(self.fmt)
    def resolve(self, args, cpsymbols={}, localsymbols={}):
        rargs = []
        for i, a in enumerate(args):
            if i < len(self.types[0]):
                t = self.types[0][i]
            else:
                t = self.types[1][(i - len(self.types[0])) % len(self.types[1])]
            if t == ARG_CPI:
                rargs.append(cpsymbols.get(int(args[i]), args[i]))
            elif t == ARG_LOCALVAR:
                try:
                    rargs.append('var_%d' % int(args[i]))
                except:
                    rargs.append(args[i])
            elif t == ARG_ARRAYTYPE:
                rargs.append(ARG_ARRAYTYPE_TYPES.get(int(args[i]), args[i]))
            # for now, OFFSET is not handled here -- see
            # java_mn.{set,get}dstflow methods
            else:
                rargs.append(args[i])
        return rargs

## Following code (mnemonic() objects creation) has been generated
## automatically using the Victor Stinner and Julien Muchembled's
## hachoir project, and particularly Thomas de Grenier de Latour's
## Java classes parser.
##
## The code used for the auto-generation is included in miasm
## documentation.
##
mnemonic('nop', 0, 1, 'performs no operation. Stack: [No change]')
mnemonic('aconst_null', 1, 1, "pushes a 'null' reference onto the stack. Stack: -> null")
mnemonic('iconst_m1', 2, 1, 'loads the int value -1 onto the stack. Stack: -> -1')
mnemonic('iconst_0', 3, 1, 'loads the int value 0 onto the stack. Stack: -> 0')
mnemonic('iconst_1', 4, 1, 'loads the int value 1 onto the stack. Stack: -> 1')
mnemonic('iconst_2', 5, 1, 'loads the int value 2 onto the stack. Stack: -> 2')
mnemonic('iconst_3', 6, 1, 'loads the int value 3 onto the stack. Stack: -> 3')
mnemonic('iconst_4', 7, 1, 'loads the int value 4 onto the stack. Stack: -> 4')
mnemonic('iconst_5', 8, 1, 'loads the int value 5 onto the stack. Stack: -> 5')
mnemonic('lconst_0', 9, 1, 'pushes the long 0 onto the stack. Stack: -> 0L')
mnemonic('lconst_1', 10, 1, 'pushes the long 1 onto the stack. Stack: -> 1L')
mnemonic('fconst_0', 11, 1, "pushes '0.0f' onto the stack. Stack: -> 0.0f")
mnemonic('fconst_1', 12, 1, "pushes '1.0f' onto the stack. Stack: -> 1.0f")
mnemonic('fconst_2', 13, 1, "pushes '2.0f' onto the stack. Stack: -> 2.0f")
mnemonic('dconst_0', 14, 1, "pushes the constant '0.0' onto the stack. Stack: -> 0.0")
mnemonic('dconst_1', 15, 1, "pushes the constant '1.0' onto the stack. Stack: -> 1.0")
mnemonic('bipush', 16, 2, 'pushes the signed 8-bit integer argument onto the stack. Stack: -> value', fmt=argfmt(fmt='b', types=[[0]]))
mnemonic('sipush', 17, 3, 'pushes the signed 16-bit integer argument onto the stack. Stack: -> value', fmt=argfmt(fmt='h', types=[[0]]))
mnemonic('ldc', 18, 2, 'pushes a constant from a constant pool (String, int, float or class type) onto the stack. Stack: -> value', fmt=argfmt(fmt='B', types=[[1]]))
mnemonic('ldc_w', 19, 3, 'pushes a constant from a constant pool (String, int, float or class type) onto the stack. Stack: -> value', fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('ldc2_w', 20, 3, 'pushes a constant from a constant pool (double or long) onto the stack. Stack: -> value', fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('iload', 21, 2, "loads an int 'value' from a local variable '#index'. Stack: -> value", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('lload', 22, 2, "loads a long value from a local variable '#index'. Stack: -> value", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('fload', 23, 2, "loads a float 'value' from a local variable '#index'. Stack: -> value", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('dload', 24, 2, "loads a double 'value' from a local variable '#index'. Stack: -> value", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('aload', 25, 2, "loads a reference onto the stack from a local variable '#index'. Stack: -> objectref", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('iload_0', 26, 1, "loads an int 'value' from variable 0. Stack: -> value")
mnemonic('iload_1', 27, 1, "loads an int 'value' from variable 1. Stack: -> value")
mnemonic('iload_2', 28, 1, "loads an int 'value' from variable 2. Stack: -> value")
mnemonic('iload_3', 29, 1, "loads an int 'value' from variable 3. Stack: -> value")
mnemonic('lload_0', 30, 1, 'load a long value from a local variable 0. Stack: -> value')
mnemonic('lload_1', 31, 1, 'load a long value from a local variable 1. Stack: -> value')
mnemonic('lload_2', 32, 1, 'load a long value from a local variable 2. Stack: -> value')
mnemonic('lload_3', 33, 1, 'load a long value from a local variable 3. Stack: -> value')
mnemonic('fload_0', 34, 1, "loads a float 'value' from local variable 0. Stack: -> value")
mnemonic('fload_1', 35, 1, "loads a float 'value' from local variable 1. Stack: -> value")
mnemonic('fload_2', 36, 1, "loads a float 'value' from local variable 2. Stack: -> value")
mnemonic('fload_3', 37, 1, "loads a float 'value' from local variable 3. Stack: -> value")
mnemonic('dload_0', 38, 1, 'loads a double from local variable 0. Stack: -> value')
mnemonic('dload_1', 39, 1, 'loads a double from local variable 1. Stack: -> value')
mnemonic('dload_2', 40, 1, 'loads a double from local variable 2. Stack: -> value')
mnemonic('dload_3', 41, 1, 'loads a double from local variable 3. Stack: -> value')
mnemonic('aload_0', 42, 1, 'loads a reference onto the stack from local variable 0. Stack: -> objectref')
mnemonic('aload_1', 43, 1, 'loads a reference onto the stack from local variable 1. Stack: -> objectref')
mnemonic('aload_2', 44, 1, 'loads a reference onto the stack from local variable 2. Stack: -> objectref')
mnemonic('aload_3', 45, 1, 'loads a reference onto the stack from local variable 3. Stack: -> objectref')
mnemonic('iaload', 46, 1, 'loads an int from an array. Stack: arrayref, index -> value')
mnemonic('laload', 47, 1, 'load a long from an array. Stack: arrayref, index -> value')
mnemonic('faload', 48, 1, 'loads a float from an array. Stack: arrayref, index -> value')
mnemonic('daload', 49, 1, 'loads a double from an array. Stack: arrayref, index -> value')
mnemonic('aaload', 50, 1, 'loads onto the stack a reference from an array. Stack: arrayref, index -> value')
mnemonic('baload', 51, 1, 'loads a byte or Boolean value from an array. Stack: arrayref, index -> value')
mnemonic('caload', 52, 1, 'loads a char from an array. Stack: arrayref, index -> value')
mnemonic('saload', 53, 1, 'load short from array. Stack: arrayref, index -> value')
mnemonic('istore', 54, 2, "store int 'value' into variable '#index'. Stack: value ->", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('lstore', 55, 2, "store a long 'value' in a local variable '#index'. Stack: value ->", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('fstore', 56, 2, "stores a float 'value' into a local variable '#index'. Stack: value ->", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('dstore', 57, 2, "stores a double 'value' into a local variable '#index'. Stack: value ->", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('astore', 58, 2, "stores a reference into a local variable '#index'. Stack: objectref ->", fmt=argfmt(fmt='B', types=[[2]]))
mnemonic('istore_0', 59, 1, "store int 'value' into variable 0. Stack: value ->")
mnemonic('istore_1', 60, 1, "store int 'value' into variable 1. Stack: value ->")
mnemonic('istore_2', 61, 1, "store int 'value' into variable 2. Stack: value ->")
mnemonic('istore_3', 62, 1, "store int 'value' into variable 3. Stack: value ->")
mnemonic('lstore_0', 63, 1, "store a long 'value' in a local variable 0. Stack: value ->")
mnemonic('lstore_1', 64, 1, "store a long 'value' in a local variable 1. Stack: value ->")
mnemonic('lstore_2', 65, 1, "store a long 'value' in a local variable 2. Stack: value ->")
mnemonic('lstore_3', 66, 1, "store a long 'value' in a local variable 3. Stack: value ->")
mnemonic('fstore_0', 67, 1, "stores a float 'value' into local variable 0. Stack: value ->")
mnemonic('fstore_1', 68, 1, "stores a float 'value' into local variable 1. Stack: value ->")
mnemonic('fstore_2', 69, 1, "stores a float 'value' into local variable 2. Stack: value ->")
mnemonic('fstore_3', 70, 1, "stores a float 'value' into local variable 3. Stack: value ->")
mnemonic('dstore_0', 71, 1, 'stores a double into local variable 0. Stack: value ->')
mnemonic('dstore_1', 72, 1, 'stores a double into local variable 1. Stack: value ->')
mnemonic('dstore_2', 73, 1, 'stores a double into local variable 2. Stack: value ->')
mnemonic('dstore_3', 74, 1, 'stores a double into local variable 3. Stack: value ->')
mnemonic('astore_0', 75, 1, 'stores a reference into local variable 0. Stack: objectref ->')
mnemonic('astore_1', 76, 1, 'stores a reference into local variable 1. Stack: objectref ->')
mnemonic('astore_2', 77, 1, 'stores a reference into local variable 2. Stack: objectref ->')
mnemonic('astore_3', 78, 1, 'stores a reference into local variable 3. Stack: objectref ->')
mnemonic('iastore', 79, 1, 'stores an int into an array. Stack: arrayref, index, value ->')
mnemonic('lastore', 80, 1, 'store a long to an array. Stack: arrayref, index, value ->')
mnemonic('fastore', 81, 1, 'stores a float in an array. Stack: arreyref, index, value ->')
mnemonic('dastore', 82, 1, 'stores a double into an array. Stack: arrayref, index, value ->')
mnemonic('aastore', 83, 1, 'stores into a reference to an array. Stack: arrayref, index, value ->')
mnemonic('bastore', 84, 1, 'stores a byte or Boolean value into an array. Stack: arrayref, index, value ->')
mnemonic('castore', 85, 1, 'stores a char into an array. Stack: arrayref, index, value ->')
mnemonic('sastore', 86, 1, 'store short to array. Stack: arrayref, index, value ->')
mnemonic('pop', 87, 1, 'discards the top value on the stack. Stack: value ->')
mnemonic('pop2', 88, 1, 'discards the top two values on the stack (or one value, if it is a double or long). Stack: {value2, value1} ->')
mnemonic('dup', 89, 1, 'duplicates the value on top of the stack. Stack: value -> value, value')
mnemonic('dup_x1', 90, 1, 'inserts a copy of the top value into the stack two values from the top. Stack: value2, value1 -> value1, value2, value1')
mnemonic('dup_x2', 91, 1, 'inserts a copy of the top value into the stack two (if value2 is double or long it takes up the entry of value3, too) or three values (if value2 is neither double nor long) from the top. Stack: value3, value2, value1 -> value1, value3, value2, value1')
mnemonic('dup2', 92, 1, 'duplicate top two stack words (two values, if value1 is not double nor long; a single value, if value1 is double or long). Stack: {value2, value1} -> {value2, value1}, {value2, value1}')
mnemonic('dup2_x1', 93, 1, 'duplicate two words and insert beneath third word. Stack: value3, {value2, value1} -> {value2, value1}, value3, {value2, value1}')
mnemonic('dup2_x2', 94, 1, 'duplicate two words and insert beneath fourth word. Stack: {value4, value3}, {value2, value1} -> {value2, value1}, {value4, value3}, {value2, value1}')
mnemonic('swap', 95, 1, 'swaps two top words on the stack (note that value1 and value2 must not be double or long). Stack: value2, value1 -> value1, value2')
mnemonic('iadd', 96, 1, 'adds two ints together. Stack: value1, value2 -> result')
mnemonic('ladd', 97, 1, 'add two longs. Stack: value1, value2 -> result')
mnemonic('fadd', 98, 1, 'adds two floats. Stack: value1, value2 -> result')
mnemonic('dadd', 99, 1, 'adds two doubles. Stack: value1, value2 -> result')
mnemonic('isub', 100, 1, 'int subtract. Stack: value1, value2 -> result')
mnemonic('lsub', 101, 1, 'subtract two longs. Stack: value1, value2 -> result')
mnemonic('fsub', 102, 1, 'subtracts two floats. Stack: value1, value2 -> result')
mnemonic('dsub', 103, 1, 'subtracts a double from another. Stack: value1, value2 -> result')
mnemonic('imul', 104, 1, 'multiply two integers. Stack: value1, value2 -> result')
mnemonic('lmul', 105, 1, 'multiplies two longs. Stack: value1, value2 -> result')
mnemonic('fmul', 106, 1, 'multiplies two floats. Stack: value1, value2 -> result')
mnemonic('dmul', 107, 1, 'multiplies two doubles. Stack: value1, value2 -> result')
mnemonic('idiv', 108, 1, 'divides two integers. Stack: value1, value2 -> result')
mnemonic('ldiv', 109, 1, 'divide two longs. Stack: value1, value2 -> result')
mnemonic('fdiv', 110, 1, 'divides two floats. Stack: value1, value2 -> result')
mnemonic('ddiv', 111, 1, 'divides two doubles. Stack: value1, value2 -> result')
mnemonic('irem', 112, 1, 'logical int remainder. Stack: value1, value2 -> result')
mnemonic('lrem', 113, 1, 'remainder of division of two longs. Stack: value1, value2 -> result')
mnemonic('frem', 114, 1, 'gets the remainder from a division between two floats. Stack: value1, value2 -> result')
mnemonic('drem', 115, 1, 'gets the remainder from a division between two doubles. Stack: value1, value2 -> result')
mnemonic('ineg', 116, 1, 'negate int. Stack: value -> result')
mnemonic('lneg', 117, 1, 'negates a long. Stack: value -> result')
mnemonic('fneg', 118, 1, 'negates a float. Stack: value -> result')
mnemonic('dneg', 119, 1, 'negates a double. Stack: value -> result')
mnemonic('ishl', 120, 1, 'int shift left. Stack: value1, value2 -> result')
mnemonic('lshl', 121, 1, "bitwise shift left of a long 'value1' by 'value2' positions. Stack: value1, value2 -> result")
mnemonic('ishr', 122, 1, 'int shift right. Stack: value1, value2 -> result')
mnemonic('lshr', 123, 1, "bitwise shift right of a long 'value1' by 'value2' positions. Stack: value1, value2 -> result")
mnemonic('iushr', 124, 1, 'int shift right. Stack: value1, value2 -> result')
mnemonic('lushr', 125, 1, "bitwise shift right of a long 'value1' by 'value2' positions, unsigned. Stack: value1, value2 -> result")
mnemonic('iand', 126, 1, 'performs a logical and on two integers. Stack: value1, value2 -> result')
mnemonic('land', 127, 1, 'bitwise and of two longs. Stack: value1, value2 -> result')
mnemonic('ior', 128, 1, 'logical int or. Stack: value1, value2 -> result')
mnemonic('lor', 129, 1, 'bitwise or of two longs. Stack: value1, value2 -> result')
mnemonic('ixor', 130, 1, 'int xor. Stack: value1, value2 -> result')
mnemonic('lxor', 131, 1, 'bitwise exclusive or of two longs. Stack: value1, value2 -> result')
mnemonic('iinc', 132, 3, "increment local variable '#index' by signed byte 'const'. Stack: [No change]", fmt=argfmt(fmt='Bb', types=[[2, 0]]))
mnemonic('i2l', 133, 1, 'converts an int into a long. Stack: value -> result')
mnemonic('i2f', 134, 1, 'converts an int into a float. Stack: value -> result')
mnemonic('i2d', 135, 1, 'converts an int into a double. Stack: value -> result')
mnemonic('l2i', 136, 1, 'converts a long to an int. Stack: value -> result')
mnemonic('l2f', 137, 1, 'converts a long to a float. Stack: value -> result')
mnemonic('l2d', 138, 1, 'converts a long to a double. Stack: value -> result')
mnemonic('f2i', 139, 1, 'converts a float to an int. Stack: value -> result')
mnemonic('f2l', 140, 1, 'converts a float to a long. Stack: value -> result')
mnemonic('f2d', 141, 1, 'converts a float to a double. Stack: value -> result')
mnemonic('d2i', 142, 1, 'converts a double to an int. Stack: value -> result')
mnemonic('d2l', 143, 1, 'converts a double to a long. Stack: value -> result')
mnemonic('d2f', 144, 1, 'converts a double to a float. Stack: value -> result')
mnemonic('i2b', 145, 1, 'converts an int into a byte. Stack: value -> result')
mnemonic('i2c', 146, 1, 'converts an int into a character. Stack: value -> result')
mnemonic('i2s', 147, 1, 'converts an int into a short. Stack: value -> result')
mnemonic('lcmp', 148, 1, 'compares two longs values. Stack: value1, value2 -> result')
mnemonic('fcmpl', 149, 1, 'compares two floats. Stack: value1, value2 -> result')
mnemonic('fcmpg', 150, 1, 'compares two floats. Stack: value1, value2 -> result')
mnemonic('dcmpl', 151, 1, 'compares two doubles. Stack: value1, value2 -> result')
mnemonic('dcmpg', 152, 1, 'compares two doubles. Stack: value1, value2 -> result')
mnemonic('ifeq', 153, 3, "if 'value' is 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ifne', 154, 3, "if 'value' is not 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ifge', 156, 3, "if 'value' is greater than or equal to 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ifgt', 157, 3, "if 'value' is greater than 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ifle', 158, 3, "if 'value' is less than or equal to 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmpeq', 159, 3, 'if ints are equal, branch to the 16-bit instruction offset argument. Stack: value1, value2 ->', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmpne', 160, 3, 'if ints are not equal, branch to the 16-bit instruction offset argument. Stack: value1, value2 ->', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmplt', 161, 3, "if 'value1' is less than 'value2', branch to the 16-bit instruction offset argument. Stack: value1, value2 ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmpge', 162, 3, "if 'value1' is greater than or equal to 'value2', branch to the 16-bit instruction offset argument. Stack: value1, value2 ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmpgt', 163, 3, "if 'value1' is greater than 'value2', branch to the 16-bit instruction offset argument. Stack: value1, value2 ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_icmple', 164, 3, "if 'value1' is less than or equal to 'value2', branch to the 16-bit instruction offset argument. Stack: value1, value2 ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_acmpeq', 165, 3, 'if references are equal, branch to the 16-bit instruction offset argument. Stack: value1, value2 ->', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('if_acmpne', 166, 3, 'if references are not equal, branch to the 16-bit instruction offset argument. Stack: value1, value2 ->', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('goto', 167, 3, 'goes to the 16-bit instruction offset argument. Stack: [no change]', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, dstflow=True)
mnemonic('jsr', 168, 3, 'jump to subroutine at the 16-bit instruction offset argument and place the return address on the stack. Stack: -> address', fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ret', 169, 2, "continue execution from address taken from a local variable '#index'. Stack: [No change]", fmt=argfmt(fmt='B', types=[[2]]), breakflow=True)
mnemonic('tableswitch', 170, 0, "continue execution from an address in the table at offset 'index'. Stack: index ->", fmt=argfmt(fmt='iii#arg[2]-arg[1]+1:i:', types=[[3, 0, 0], [3]], align=4), breakflow=True, dstflow=True)
mnemonic('lookupswitch', 171, 0, 'a target address is looked up from a table using a key and execution continues from the instruction at that address. Stack: key ->', fmt=argfmt(fmt='ii#arg[1]*2:i:', types=[[3, 0], [0, 3]], align=4), breakflow=True, dstflow=True)
mnemonic('ireturn', 172, 1, 'returns an integer from a method. Stack: value -> [empty]', breakflow=True)
mnemonic('lreturn', 173, 1, 'returns a long value. Stack: value -> [empty]', breakflow=True)
mnemonic('freturn', 174, 1, 'returns a float. Stack: value -> [empty]', breakflow=True)
mnemonic('dreturn', 175, 1, 'returns a double from a method. Stack: value -> [empty]', breakflow=True)
mnemonic('areturn', 176, 1, 'returns a reference from a method. Stack: objectref -> [empty]', breakflow=True)
mnemonic('return', 177, 1, 'return void from method. Stack: -> [empty]', breakflow=True)
mnemonic('getstatic', 178, 3, "gets a static field 'value' of a class, where the field is identified by field reference in the constant pool. Stack: -> value", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('putstatic', 179, 3, "set static field to 'value' in a class, where the field is identified by a field reference in constant pool. Stack: value ->", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('getfield', 180, 3, "gets a field 'value' of an object 'objectref', where the field is identified by field reference <argument> in the constant pool. Stack: objectref -> value", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('putfield', 181, 3, "set field to 'value' in an object 'objectref', where the field is identified by a field reference <argument> in constant pool. Stack: objectref, value ->", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('invokevirtual', 182, 3, "invoke virtual method on object 'objectref', where the method is identified by method reference <argument> in constant pool. Stack: objectref, [arg1, arg2, ...] ->", fmt=argfmt(fmt='H', types=[[1]]), breakflow=True, splitflow=True)
mnemonic('invokespecial', 183, 3, "invoke instance method on object 'objectref', where the method is identified by method reference <argument> in constant pool. Stack: objectref, [arg1, arg2, ...] ->", fmt=argfmt(fmt='H', types=[[1]]), breakflow=True, splitflow=True)
mnemonic('invokestatic', 184, 3, 'invoke a static method, where the method is identified by method reference <argument> in the constant pool. Stack: [arg1, arg2, ...] ->', fmt=argfmt(fmt='H', types=[[1]]), breakflow=True, splitflow=True)
mnemonic('invokeinterface', 185, 5, "invokes an interface method on object 'objectref', where the interface method is identified by method reference <argument> in constant pool. Stack: objectref, [arg1, arg2, ...] ->", fmt=argfmt(fmt='HBB', types=[[1, 0, 0]]), breakflow=True, splitflow=True)
mnemonic('xxxunusedxxx', 186, 1, 'this opcode is reserved for historical reasons. Stack: ')
mnemonic('new', 187, 3, 'creates new object of type identified by class reference <argument> in constant pool. Stack: -> objectref', fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('newarray', 188, 2, "creates new array with 'count' elements of primitive type given in the argument. Stack: count -> arrayref", fmt=argfmt(fmt='B', types=[[4]]))
mnemonic('anewarray', 189, 3, "creates a new array of references of length 'count' and component type identified by the class reference <argument> in the constant pool. Stack: count -> arrayref", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('arraylength', 190, 1, 'gets the length of an array. Stack: arrayref -> length')
mnemonic('athrow', 191, 1, 'throws an error or exception (notice that the rest of the stack is cleared, leaving only a reference to the Throwable). Stack: objectref -> [empty], objectref', breakflow=True)
mnemonic('checkcast', 192, 3, "checks whether an 'objectref' is of a certain type, the class reference of which is in the constant pool. Stack: objectref -> objectref", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('instanceof', 193, 3, "determines if an object 'objectref' is of a given type, identified by class reference <argument> in constant pool. Stack: objectref -> result", fmt=argfmt(fmt='H', types=[[1]]))
mnemonic('monitorenter', 194, 1, 'enter monitor for object ("grab the lock" - start of synchronized() section). Stack: objectref -> ')
mnemonic('monitorexit', 195, 1, 'exit monitor for object ("release the lock" - end of synchronized() section). Stack: objectref -> ')
mnemonic('wide', 196, 0, "execute 'opcode', where 'opcode' is either iload, fload, aload, lload, dload, istore, fstore, astore, lstore, dstore, or ret, but assume the 'index' is 16 bit; or execute iinc, where the 'index' is 16 bits and the constant to increment by is a signed 16 bit short. Stack: [same as for corresponding instructions]")
mnemonic('multianewarray', 197, 4, "create a new array of 'dimensions' dimensions with elements of type identified by class reference in constant pool; the sizes of each dimension is identified by 'count1', ['count2', etc]. Stack: count1, [count2,...] -> arrayref", fmt=argfmt(fmt='HB', types=[[1, 0]]))
mnemonic('ifnull', 198, 3, "if 'value' is null, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('ifnonnull', 199, 3, "if 'value' is not null, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('goto_w', 200, 5, 'goes to another instruction at the 32-bit branch offset argument. Stack: [no change]', fmt=argfmt(fmt='i', types=[[3]]), breakflow=True, dstflow=True)
mnemonic('jsr_w', 201, 5, 'jump to subroutine at the 32-bit branch offset argument and place the return address on the stack. Stack: -> address', fmt=argfmt(fmt='i', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)
mnemonic('breakpoint', 202, 1, 'reserved for breakpoints in Java debuggers; should not appear in any class file.')
mnemonic('impdep1', 254, 1, 'reserved for implementation-dependent operations within debuggers; should not appear in any class file.')
mnemonic('impdep2', 255, 1, 'reserved for implementation-dependent operations within debuggers; should not appear in any class file.')

# This was missing in hachoir
mnemonic('iflt', 155, 3, "if 'value' is less than 0, branch to the 16-bit instruction offset argument. Stack: value ->", fmt=argfmt(fmt='h', types=[[3]]), breakflow=True, splitflow=True, dstflow=True)


class java_mnemo_metaclass(type):
    rebuilt_inst = False
    
    def dis(cls, op, attrib = {} ):
        i = cls.__new__(cls)
        i.__init__(0)
        u = i._dis(op)
        if not u: return None
        return i
    
    def asm(cls, l, symbol_reloc_off={}, sex=0, address=0):
        i = cls.__new__(cls)
        i.__init__(sex)
        return i._asm(l, symbol_reloc_off, address=address)
    
    def asm_instr(cls, l, sex=0):
        i = cls.__new__(cls)
        i.__init__(sex)
        i._asm_instr(l)
        return i
    
    def fix_symbol(cls, a, symbol_pool = None):
        if not AFS_symb in a: return a
        cp = a.copy()
        if not symbol_pool:
            del cp[AFS_symb]
            if not AFS_imm in cp:
                cp[AFS_imm] = 0
            return cp
        raise Exception('.fix_symbol() cannot handle that for now (and should not have too do so).')
    
    def is_mem(cls, a): return False
    
    def get_label(cls, a):
        if not AFS_symb in a:
            return None
        n = a[AFS_symb]
        if len(n) != 1:
            return None
        k = n.keys()[0]
        if n[k] != 1:
            return None
        return k
    
    def has_symb(cls, a):
        return AFS_symb in a
    
    def get_symbols(cls, a):
        if AFS_symb in a:
            return a[AFS_symb].items()
        return None
    
    def names2symbols(cls, a, s_dict):
        all_s = a[AFS_symb]
        for name, s in s_dict.items():
            count = all_s[name]
            del(all_s[name])
            all_s[s] = count
    
    def parse_address(cls, a):
        if a.isdigit(): return {AFS_imm: int(a)}
        return {AFS_symb: {a: 1}}


class java_mn:
    __metaclass__ = java_mnemo_metaclass
    def __init__(self, sex=0):
        self.sex = 0
    def get_attrib(self):
        return {}

    def breakflow(self):
        return self.m.breakflow
    def splitflow(self):
        return self.m.splitflow
    def dstflow(self):
        return self.m.dstflow
    
    def getnextflow(self):
        return self.offset + self.m.size
    
    def getdstflow(self):
        if len(self.arg) == 1:
            dsts = [ self.arg[0] ]
        elif self.m.name == 'tableswitch':
            dsts = self.arg[:1]+self.arg[3:]
        elif self.m.name == 'lookupswitch':
            dsts = self.arg[:1]+[ self.arg[2*i+3] for i in range(len(self.arg[2:])/2) ]
        out = []
        for d in dsts:
            if type(d) is int:
                out.append(self.offset + d)
            elif not AFS_symb in d:
                out.append(self.offset + a[AFS_imm])
            else:
                out.append(d)
        return out
    
    def setdstflow(self, dst):
        if len(self.arg) == 1:
            self.arg = [{AFS_symb:{dst[0]:1}}]
        elif self.m.name == 'tableswitch':
            self.arg = [dst[0], self.arg[1], self.arg[2]] + dst[1:]
        elif self.m.name == 'lookupswitch':
            self.arg = [dst[0], self.arg[1]] + reduce(lambda x, y: x+y, [ [self.arg[2*i+2], dst[i+1]] for i in range(len(dst)-1) ])
    
    def fixdst(self, lbls, my_offset, is_mem):
        dsts = [0]
        if self.m.name == 'tableswitch':
            dsts += range(3, len(args))
        elif self.m.name == 'lookupswitch':
            dsts += range(3, len(args), 2)
        newarg = []
        for i, a in enumerate(self.arg):
            if not i in dsts:
                newarg.append(a)
                continue
            offset = lbls[a[AFS_symb].keys()[0].name]
            if self.m.size == 0:
                self.fixsize()
            newarg.append({AFS_imm:offset-(my_offset)+self.m.size})
        self.arg = newarg
    
    def fixsize(self):
        if self.m.name.endswith('switch'):
            self.size = 4 * len(self.arg) + 1 # opcode + args
            self.size +=  ((4 - ((self.offset+1) % 4)) % 4) # align
        else:
            raise ValueError(".fixsize() should not be called for %s." % self.m.name)
    
    def set_args_symbols(self, cpsymbols={}):
        self.arg = self.m.argfmt.resolve(self.arg, cpsymbols=cpsymbols)
    
    def is_subcall(self):
        return self.m.name.startswith('jsr') or self.m.name.startswith('invoke')
    
    def __str__(self):
        arg = []
        for a in self.arg:
            if type(a) is not dict:
                arg.append(a)
                continue
            if len(a) == 1:
                if AFS_imm in a:
                    arg.append(a[AFS_imm])
                    continue
                elif AFS_symb in a and len(a[AFS_symb]) == 1:
                    arg.append(a[AFS_symb].keys()[0])
                    continue
            log.warning('Weird argument spotted while assembling %s %r' % (self.m.name, self.arg))
            arg.append(0)
        if self.m.name == 'tableswitch':
            out = "tableswitch    %d %d\n" % (arg[1], arg[2])
            out += "    %s: %s\n" % ('default', arg[0])
            out += "\n".join(["    %-8s %s" % (str(i)+':', arg[3+i-int(arg[1])]) for i in range(int(arg[1]), int(arg[2])+1)])
            return out
        if self.m.name == 'lookupswitch':
            out = "lookupswitch   %s\n" % arg[1]
            out += "    %s:\t%s\n" % ('default', arg[0])
            out += "\n".join(["    %-8s %s" % (str(arg[2*i+2])+':', arg[2*i+3]) for i in range(len(arg)/2-1) ])
            return out
        return "%-15s" % self.m.name + " ".join(map(str, arg))
    
    def _dis(self, bin):
        if type(bin) is str:
            from miasm.core.bin_stream import bin_stream
            bin = bin_stream(bin)
        self.offset = bin.offset
        try:
            self.m = mnemo_db[ord(bin.readbs(1))]
            self.arg = self.m.argfmt.get(bin, sex=self.sex, address=self.offset)
            self.l = bin.offset  - self.offset
        except Exception as e:
            log.warning(e.message)
            return False
        return True
    
    @classmethod
    def parse_mnemo(cls, txt):
        if ';' in txt: txt = txt[:txt.index(';')]
        txt = txt.strip()
        txt = filter(lambda x: x != ',', list(shlex(txt)))
        t = []
        r = ''
        for l in txt:
            if l == '-':
                r = l
            else:
                t.append(r+l)
                r = ''
        return None, t[0], t[1:]
    
    def _asm_instr(self, txt, address=0):
        p, mn, t = self.parse_mnemo(txt)
        self.m = mnemo_db_name[mn]
        self.arg = t
        self.offset = address
    
    def _asm(self, txt, symbol_reloc_off={}, address=0):
        p, mn, t = self.parse_mnemo(txt)
        mnemo = mnemo_db_name[mn]
        if mnemo.name == 'tableswitch':
            table = {}
            dflt = None
            if len(t) % 3 == 2:
                # 'tableswitch' has the second (optional) argument
                arg = t[0:2]
                rest = t[2:]
            elif len(t) % 3 == 1:
                # 'tableswitch' does not have the second argument ; we
                # will have to set it
                arg = t[:1]
                rest = t[1:]
            else:
                # 'tableswitch' have the second argument plus the "to"
                # keyword, just before.
                if t[1] != "to":
                    log.warning("Wrong argument format for tableswitch instruction: expecting 'to', but got '%s'" % t[1])
                arg = [ t[0], t[2] ]
                rest = t[3:]
            for i in range(len(rest)/3):
                k = rest[3*i]
                v = rest[3*i+2]
                if rest[3*i+1] != ':':
                    log.warning("Invalid tableswitch format: expecting ':', but got '%s'." % rest[3*i+1])
                if k == 'default': dflt = v
                else:
                    if k in table:
                        log.warning("tableswitch instruction contains multiple offsets for value %s" % v)
                    else:
                        table[k] = v
            if dflt is None:
                raise ValueError("tableswitch instruction must contain a default label.")
            keys = map(int, table.keys())
            keys.sort()
            if keys != range(min(keys), len(keys)):
                raise ValueError("tableswitch instruction does not contain all values between %d and %d." % (min(keys), len(keys)-1))
            if len(arg) == 2:
                if arg[1] != str(len(keys)-1):
                    raise ValueError("tableswitch maximum label is incorrect: excpected %d and got %s." % (len(keys)-1, arg[2]))
            else:
                arg.append(str(len(keys)-1))
            arg = [ dflt ] + arg
            for k in range(min(keys), len(keys)):
                arg.append(table[str(k)])
        elif mnemo.name == 'lookupswitch':
            nbr = int(t[0])
            table = {}
            dflt = None
            for i in range(len(t[1:])/3):
                k = t[3*i+1]
                v = t[3*i+3]
                if t[3*i+2] != ':':
                    log.warning("Invalid lookupswitch format: expecting ':', but got '%s'." %  t[3*i+2])
                if k == 'default': dflt = v
                else:
                    if k in table:
                        log.warning("lookupswitch instruction contains multiple offsets for value %s" % v)
                    else:
                        table[k] = v
            if dflt is None:
                raise ValueError("lookupswitch instruction must contain a default label.")
            arg = [ dflt, str(nbr) ]
            for k in table:
                arg += [ k, table[k] ]
        else:
            arg = t
        try:
            return [ chr(mnemo.code) + mnemo.argfmt.set(arg, address=address) ]
        except: pass
        return [ chr(mnemo.code) + mnemo.argfmt.set([0]*len(arg), address=address) ]
