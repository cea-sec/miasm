import struct
import collections
from future.utils import PY2

def byte_to_int(b):
    if type(b) == int:
        return b
    return struct.unpack('B', b)[0]

def int_to_byte(i):
    return struct.pack('B', i)

def encode_LEB128(uint):
    '''
    Encode a LEB128 unsigned integer from the (positive) integer uint
    Returns bytes
    @uint: integer to encode
    '''
    if uint == 0:
        return b'\x00'
    bts = []
    while uint != 0:
        byte = uint &0x7f
        uint >>= 7
        if uint != 0:
            byte |= 0x80
        bts.append(struct.pack('B', byte))
    return b''.join(bts)

def decode_LEB128(bs):
    '''
    Decode a LEB128-encoded unsigned integer at the beginning of the byte string bs
    Returns a tuple (res, n_bytes)
    @bs: byte string
    -res: the decoded integer
    -n_bytes: the number of bytes it was encoded on
    '''
    res = 0
    n = 0
    for b in bs:
        if PY2:
            b = struct.unpack('B', b)[0]
        res |= (b&0x7f) << n*7
        n += 1
        if b&0x80 == 0:
            break
    bs = bs[n:]
    return res, n

def list_eq(l, m):
    '''
    Test if @l and @m contain the same elements
    Elements have to be hashable
    '''
    return collections.Counter(l) == collections.Counter(m)


