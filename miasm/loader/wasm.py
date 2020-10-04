from miasm.loader.wasm_utils import *

class TwoWayTable(object):
    __slots__ = ['_b_dict','_s_dict']
    '''
    Table that makes different byte <-> string equivalences
    Note that in Python2, 'bytes' and 'str' are the same type
    To prevent collisions, 'bytes' are converted to 'int' in the object
    '''
    def __init__(self, byte_str_pair_list):
        self._s_dict = {}
        self._b_dict = {}
        for b, s in byte_str_pair_list:
            if type(b) != int:
                b = byte_to_int(b)
            if b in self._b_dict or s in self._s_dict:
                raise Exception("Cannot build TwoWayTable: duplicate")
            self._s_dict[s] = b
            self._b_dict[b] = s[:]

    def str_version(self, val):
        '''
        Returns the 'str' version of @val in the table
        Raises an Exception if not possible
        '''
        if type(val) == str and val in self._s_dict:
            return val
        if type(val) == bytes and len(val) == 1:
            val = byte_to_int(val)
        if type(val) == int and val in self._b_dict:
            return self._b_dict[val]
        raise Exception("Not found")

    def int_version(self, val):
        '''
        Returns the 'int' version of @val in the table
        Raises an Exception if not possible
        '''
        if type(val) == str and val in self._s_dict:
            return self._s_dict[val]
        if type(val) == bytes and len(val) == 1:
            val = byte_to_int(val)
        if type(val) == int and val in self._b_dict:
            return val
        raise Exception("Not found")

    def byte_version(self, val):
        '''
        Returns the 'bytes' version of @val in the table
        Raises an Exception if not possible
        '''
        return int_to_byte(self.int_version(val))


CONSTINSTRS = TwoWayTable([(0x41,'i32.const'),
                          (0x42,'i64.const'),
                          (0x43,'f32.const'),
                          (0x44,'f64.const'),
                          (0x23,'global.get'),
                          (0x0b,'end')])

VALTYPES = TwoWayTable([(0x7f,'i32'),
                       (0x7e,'i64'),
                       (0x7d,'f32'),
                       (0x7c,'f64')])

ELEMTYPES = TwoWayTable([(0x70,'funcref')])

MUTTYPES = TwoWayTable([(0x00,'const'),
                        (0x01,'var')])

NAMETYPES = TwoWayTable([(0x00,'mname'),
                         (0x01,'fnames'),
                         (0x02,'lnames')])

IMPORTTYPES = TwoWayTable([(0x00,'func'),
                           (0x01,'table'),
                           (0x02,'mem'),
                           (0x03,'global')])

EXPORTTYPES = IMPORTTYPES

SHT_CUSTOM =	0
SHT_TYPE =	1
SHT_IMPORT =	2
SHT_FUNCTION =	3
SHT_TABLE =	4
SHT_MEMORY =	5
SHT_GLOBAL =	6
SHT_EXPORT =	7
SHT_START =	8
SHT_ELEMENT =	9
SHT_CODE =	10
SHT_DATA =	11
