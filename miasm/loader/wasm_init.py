#! /usr/bin/env python

import logging
import struct
import collections

from future.utils import PY2, PY3

from miasm.loader.wasm import *
from miasm.loader.wasm_utils import *
from miasm.loader.strpatchwork import StrPatchwork
from miasm.analysis.binary import (ContainerSignatureException,
                                   ContainerParsingException)

log = logging.getLogger('wasmparse')
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)



class serializer(object):
    '''
    Collection of functions (class methods) used to serialize different values.
    The parameters' types depend on the data you want to serialize
    However, all the functions return the same type : a byte string containing the serialized data
    '''
    @classmethod
    def u32(cls, n):
        '''Does not check that n fits on 32 bits, and might use extra bytes if n is too big'''
        return encode_LEB128(n)


class parser(object):
    '''
    Collection of functions (class methods) used to parse different values.
    Each one takes a byte string @bs, an offset @ofs, and possibly other inputs.
    It returns a tuple (res, n_bytes) containing:
      - res: result
      - n: number of bytes read.
    The result type is different depending on the value type parsed
    '''

    @classmethod
    def u32(cls, bs, ofs):
        '''In the specification, u32 is a LEB128-encoded unsigned int with a value in [0, 2**32]
        res type: int'''
        return decode_LEB128(bs[ofs : ofs + 5])

    @classmethod
    def skip_iN(cls, bs, ofs, N):
        '''
        Partially decodes a iN LEB128-encoded integer:
        does not return its value, but returns the number of bytes it was encoded on
        '''
        n = 0
        for b in bs[ofs : ofs + N//7 +1]:
            if PY2:
                b = struct.unpack('B', b)[0]
            n += 1
            if b&0x80 == 0:
                break
        return None, n

    @classmethod
    def skip_i32(cls, bs, ofs):
        return parser.skip_iN(bs, ofs, 32)

    @classmethod
    def skip_i64(cls, bs, ofs):
        return parser.skip_iN(bs, ofs, 64)

    @classmethod
    def const_instr(cls, bs, ofs):
        '''Parses a constant instruction, returns True if the instruction is 'end', False otherwise (along with the number of bytes read)'''
        instr = CONSTINSTRS.str_version(bs[ofs])
        if instr == 'end':
            return True, 1
        elif instr == 'i32.const':
            _, n = parser.skip_i32(bs, ofs+1)
        elif instr == 'i64.const':
            _, n = parser.skip_i64(bs, ofs+1)
        elif instr == 'f32.const':
            n = 4
        elif instr == 'f64.const':
            n = 8
        else:
            log.error("Non constant or unknown instruction found in constant expression")
            raise ContainerParsingException("Unknown/non constant instruction found in constant expression")
        return False, n+1

    @classmethod
    def const_expr(cls, bs, ofs):
        n = 0
        tst = False
        while not tst:
            tst, m = parser.const_instr(bs, ofs+n)
            n += m
        return bs[ofs:ofs+n], n


def homogenize(lst, cls):
    '''Generator that tries to convert all elements of lst to cls'''
    for i in lst:
        if isinstance(i, cls):
            yield i
        else:
            try:
                yield cls(i)
            except Exception as e:
                e.args = ("Cannot convert {} to {}".format(type(i), cls),)
                raise

class HomogeneousList(list):
    '''
    Python list that enforces the type of its elements
    May raise Exceptions if you try tu put elements that are
    not convertible into the list's elements' type
    '''
    __slots__ = ['_item_type']

    def __init__(self, value, item_type):
        self._item_type = item_type
        super(HomogeneousList, self).__init__(homogenize(value, item_type))

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            value = homogenize(value, self._item_type)
        elif not isinstance(value, self._item_type) :
            value = self._item_type(value)
        return list.__setitem__(self, key, value)

    def append(self, value):
        if not isinstance(value, self._item_type):
            value = self._item_type(value)
        return list.append(self, value)

    def insert(self, value):
        if not isinstance(value, self._item_type):
            value = self._item_type(value)
        return list.insert(self, value)

    def extend(self, value):
        value = homogenize(value, self._item_type)
        return list.extend(self, value)

    def __add__(self, other):
        other = homogenize(other, self._item_type)
        return self.__class__(list.__add__(self, other), self._item_type)

    def __radd__(self, other):
        other = homogenize(other, self._item_type)
        return self.__class__(list.__radd__(self, other), self._item_type)

    def __iadd__(self, other):
        other = homogenize(other, self._item_type)
        return self.__class__(list.__iadd__(self, other), self._item_type)

    @property
    def item_type(self):
        return self._item_type


class WasmItem(object):
    '''Python representation of a wasm-formatted item'''
    __slots__ = []

    def __init__(self):
        object.__init__(self)

    @staticmethod
    def parse(bs, ofs=0):
        '''
        Parses the byte string @bs from the offset @ofs
        Returns a pair (obj, n) containing:
          - obj: the instantiated object
          - n: number of bytes read in @bs
        Has to be implemented by sub-classes
        '''
        raise NotImplementedError()

    def build(self):
        '''
        Needed to re-convert the object to its representation in bytes
        Has to be implemented by sub-classes
        '''
        raise NotImplementedError()


    @classmethod
    def from_bytes(cls, bs, *args, **kwargs):
        return cls.parse(bs, 0, *args, **kwargs)[0]


class WasmItemVec(WasmItem, HomogeneousList):
    '''
    HomogeneousList of a particular WasmItem
    Is itself a WasmItem
    '''
    __slots__ = []

    def __init__(self, lst, item_type):
        if not issubclass(item_type, WasmItem):
            raise TypeError("{} is not sub-class of WasmItem"
                            .format(item_type))
        WasmItem.__init__(self)
        HomogeneousList.__init__(self, lst, item_type)

    @classmethod
    def parse(cls, bs, ofs, item_type, *args, **kwargs):
        elems = []
        n_elems, ofs_vec = parser.u32(bs, ofs)
        for _ in range(n_elems):
            elt, n = item_type.parse(bs, ofs+ofs_vec, *args, **kwargs)
            elems.append(elt)
            ofs_vec += n
        return cls(elems, item_type), ofs_vec

    def build(self):
        return serializer.u32(len(self)) + b''.join([i.build() for i in self])

class WasmItemOptionVec(WasmItemVec):
    __slots__ = []

    def build(self):
        if len(self) == 0:
            return b''
        return WasmItemVec.build(self)

def simple_twt_item(table):
    '''Decorator that creates a basic WasmItem corresponding to a TwoWayTable'''
    def wrapper(cls):
        cls.__slots__ = ['_value']

        def init(self, value):
            if isinstance(value, cls):
                self._value = value._value
            else:
                self._value = table.int_version(value)
            super(cls, self).__init__()
        cls.__init__ = init

        @classmethod
        def parser(c, bs, ofs):
            return c(bs[ofs]), 1
        cls.parse = parser

        cls.build = lambda self: table.byte_version(self._value)

        cls.__repr__  = lambda self: table.str_version(self._value)

        def eq(self, other):
            if not isinstance(other, cls):
                other = cls(other)
            return self._value == other._value
        cls.__eq__ = eq
        return cls
    return wrapper

@simple_twt_item(VALTYPES)
class ValType(WasmItem):
    pass

@simple_twt_item(IMPORTTYPES)
class ImportType(WasmItem):
    pass

@simple_twt_item(ELEMTYPES)
class ElemType(WasmItem):
    pass

@simple_twt_item(MUTTYPES)
class MutType(WasmItem):
    pass

@simple_twt_item(NAMETYPES)
class NameType(WasmItem):
    pass

def prop(name, prop_type, optional=False):
    def wrapper(cls):
        if '_' + name not in cls.__slots__:
            raise Exception("Please add '{}' in {}.__slots__"
                            .format('_' + name, cls.__name__))
        g = lambda self: getattr(self, '_' + name)
        def s(self, value):
            if optional and value is None:
                setattr(self, '_' + name, None)
            elif isinstance(value, prop_type):
                setattr(self, '_' + name, value)
            else:
                try:
                    setattr(self, '_' + name, prop_type(value))
                except:
                    raise Exception("Cannot convert {} to {}"
                                    .format(value, prop_type))
        setattr(cls, name, property(g, s))
        return cls
    return wrapper

def prop_list(name, elem_type, optional=False):
    def wrapper(cls):
        if '_' + name not in cls.__slots__:
            raise Exception("Please add '{}' in {}.__slots__"
                            .format('_' + name, cls.__name__))
        g = lambda self: getattr(self, '_' + name)
        def s(self, value):
            if optional and value is None:
                setattr(self, '_' + name, None)
            elif (isinstance(value, WasmItemVec) and
                  issubclass(value._item_type, elem_type)):
                setattr(self, '_' + name, value)
            else:
                try:
                    setattr(self, '_' + name, WasmItemVec(value, elem_type))
                except Exception as e:
                    raise Exception("Cannot convert {} to a list of {}"
                                    .format(value, elem_type))
        setattr(cls, name, property(g, s))
        return cls
    return wrapper

def can_be_exported(cls):
    cls = prop('export_name', Name, optional = True)(cls)
        
    def is_exported(self):
        return hasattr(self, 'export_name') and self.export_name != None

    setattr(cls, 'is_exported', property(is_exported))
    return cls

def can_be_imported(cls):
    def is_imported(self):
        return hasattr(self, 'import_info') and self.import_info != None
        
    setattr(cls, 'is_imported', property(is_imported))
    return cls

class Name(str, WasmItem):
    __slots__=[]

    def __init__(self, string):
        WasmItem.__init__(self)
        super(Name, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        size, n = parser.u32(bs, ofs)
        res = bs[ofs+n:ofs+n+size].decode('UTF-8', 'strict')
        if PY2:
            res = bs[ofs+n:ofs+n+size]
        return Name(res), size+n

    def build(self):
        s = str(self)
        if PY3:
            s = bytes(s, 'utf-8')
        return serializer.u32(len(s)) + s



@prop('name', Name)
@prop('mod', Name)
class ImportInfo(WasmItem):
    __slots__ = ['_name', '_mod']

    def __init__(self, mod, name):
        self.mod = mod
        self.name = name
        super(ImportInfo, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        mod, n = Name.parse(bs, ofs)
        name, m = Name.parse(bs, ofs+n)
        return ImportInfo(mod, name), n+m

    def build(self):
        return self.mod.build() + self.name.build()

    def __repr__(self):
        return "<'{}' in module '{}'>".format(self.name, self.mod)


class ImportDesc(WasmItem):
    '''Not used by end users'''
    __slots__ = ['_importtype', '_content']
    
    def __init__(self, importtype, content):
        self._importtype = importtype
        self._content = content

    @staticmethod
    def parse(bs, ofs):
        t = ImportType(bs[ofs])
        if t == 'func':
            content, n = parser.u32(bs, ofs+1)
        elif t == 'table':
            content, n = TableType.parse(bs, ofs+1)
        elif t == 'mem':
            content, n = Limits.parse(bs, ofs+1)
        elif t == 'global':
            content, n = GlobalType.parse(bs, ofs+1)
        else:
            raise ContainerParsingException("Error parsing import description")
        return ImportDesc(t, content), n+1

    def build(self):
        if self._importtype == 'func':
            return self._importtype.build() + serializer.u32(self._content)
        return self._importtype.build() + self._content.build()

@prop('info', ImportInfo)
@prop('desc', ImportDesc)
class Import(WasmItem):
    __slots__ = ['_info', '_desc']

    def __init__(self, info, desc):
        self.info = info
        self.desc = desc
        super(Import, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        info, n = ImportInfo.parse(bs, ofs)
        desc, m = ImportDesc.parse(bs, ofs+n)
        return Import(info, desc), n+m

    def build(self):
        return self.info.build() + self.desc.build()


class ExportDesc(WasmItem):
    __slots__ = ['_exporttype', '_idx']

    def __init__(self, et, idx):
        self._exporttype = et
        self._idx = idx
        super(ExportDesc, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        t = ImportType(bs[ofs])
        idx, n = parser.u32(bs, ofs+1)
        return ExportDesc(t, idx), n+1

    def build(self):
        return self._exporttype.build() + serializer.u32(self._idx)

@prop('name', Name)
@prop('desc', ExportDesc)
class Export(WasmItem):
    __slots__ = ['_name', '_desc']
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc
        super(Export, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        name, n = Name.parse(bs, ofs)
        desc, m = ExportDesc.parse(bs, ofs+n)
        return Export(name, desc), n+m

    def build(self):
        return self.name.build() + self.desc.build()


@prop('valtype', ValType)
class Locals(WasmItem):
    __slots__ = ['n', '_valtype']

    def __init__(self, n, valtype):
        self.n = n
        self.valtype = valtype
        super(Locals, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        nmb, n = parser.u32(bs, ofs)
        valtype, m = ValType.parse(bs, ofs + n)
        return Locals(nmb, valtype), n+m

    def build(self):
        return serializer.u32(self.n) + self.valtype.build()


@prop('name', Name, optional=True)
class Local(ValType):
    __slots__ = ['_name']

    def __init__(self, valtype, name=None):
        self.name = name
        super(Local, self).__init__(valtype)

    def __repr__(self):
        res = super(Local, self).__repr__()
        if isinstance(self.name, Name):
            res += ' {}'.format(self.name)
        return res

@prop_list('locs', Local)
class FunctionCode(WasmItem):
    __slots__ = ['body', '_locs', '_loc_names']

    def __init__(self, locs=[], body=b"", loc_names=None):
        self.body = body
        self.locs = []
        for l in locs:
            if isinstance(l, Local):
                self.locs.append(l)
            elif isinstance(l, Locals):
                for i in range(l.n):
                    self.locs.append(Local(l.valtype))
            else:
                raise Exception("{} is not valid candidate for function local(s)"
                                .format(l))
        super(FunctionCode, self).__init__()

    @staticmethod
    def parse(bs, ofs=0):
        size, n = parser.u32(bs, ofs)
        locs, m = WasmItemVec.parse(bs, ofs+n, Locals)
        body = bs[ofs+n+m : ofs+n+size]
        return FunctionCode(locs, body), n+size

    def build(self):
        locs_todo = WasmItemVec([], Locals)
        i = 0
        lim = len(self.locs)
        while i < lim:
            if not isinstance(self.locs[i], Local):
                raise Exception("{} is not a valid local"
                                .format(self.locs[i]))
            n = 1
            t = self.locs[i]
            i += 1
            while i < lim and self.locs[i] == t:
                n += 1
                i += 1
            locs_todo.append(Locals(n = n, valtype = t))

        res = locs_todo.build() + self.body
        return serializer.u32(len(res)) + res


@prop_list('params', Local) # Parameters are locals
@prop_list('results', ValType)
class Signature(WasmItem):
    __slots__ = ['_params', '_results']

    def __init__(self, params=[], results=[]):
        self.params = params
        self.results = results
        super(Signature, self).__init__()

    @staticmethod
    def parse(bs, ofs=0):
        val = byte_to_int(bs[ofs])
        if val != 0x60:
            log.error("Function type malformed")
            raise Exception("Function type malformed")
        params, n = WasmItemVec.parse(bs, ofs+1, ValType)
        results, m = WasmItemVec.parse(bs, ofs+n+1, ValType)
        return Signature(params, results), 1+n+m

    def build(self):
        return b'\x60' + self.params.build() + self.results.build()

    def __repr__(self):
        return "({0}) -> ({1})".format(', '.join([repr(i) for i in self._params]),
                                     ', '.join([repr(i) for i in self._results]))

    def __eq__(self, other):
        return (isinstance(other, Signature) and
                self.build() == other.build())

    def __deepcopy__(self):
        return Signature([i.build() for i in self._params],
                         [i.build() for i in self._results])


class LocalIndexer(object):
    __slots__ = ['_parent']

    @property
    def params(self):
        return self._parent.signature.params

    @property
    def locs(self):
        if isinstance(self._parent, LocalFunction):
            return self._parent.code.locs
        return None

    def __init__(self, parent_function):
        self._parent = parent_function
        super(LocalIndexer, self).__init__()
        
    def __getitem__(self, key):
        l = len(self.params)
        if key < l:
            return self.params[key]
        if self.locs is not None:
            return self.locs[key-l]
        return None

    def __setitem__(self, key, val): #TODO# remove ? can be ambiguous
        l = len(self.params)
        if key < l:
            return self.params.__setitem__(key, val)
        if self.locs is not None:
            return self.locs.__setitem__(key-l, val)
        return None

    def __repr__(self):
        if self.locs is None:
            return repr(self.params)
        return repr(list(self.params) + list(self.locs))

    def __len__(self):
        if self.locs is None:
            return len(self.params)
        return len(self.params) + len(self.locs)

@can_be_exported
@can_be_imported
@prop('signature', Signature)
@prop('name', Name, optional = True)
class Function(object):
    __slots__ = ['_signature', '_export_name', '_name', '_locals']

    @property
    def locals(self):
        return self._locals

    def __init__(self, signature, name = None):
        self.signature = signature
        self.name = name
        self._locals = LocalIndexer(self)
        super(Function, self).__init__()

    def __repr__(self):
        res = "fn "
        if self.name is None:
            res += "_?_"
        else:
            res += self.name
        res += repr(self.signature)
        if self.is_exported:
            res += "\n\tExported as '{}'".format(self.export_name)
        return res


@prop('import_info', ImportInfo)
class ImportedFunction(Function):
    __slots__ = ['_import_info']

    def __init__(self, import_info, *args, **kwargs):
        self.import_info = import_info
        super(ImportedFunction, self).__init__(*args, **kwargs)

    def __repr__(self):
        res = super(ImportedFunction, self).__repr__() + '\n'
        res += '\tImported from:' + repr(self.import_info)
        return res

@prop('code', FunctionCode)
class LocalFunction(Function):
    __slots__ = ['_code']

    def __init__(self, code, *args, **kwargs):
        self.code = code
        super(LocalFunction, self).__init__(*args, **kwargs)

    def __repr__(self):
        res = super(LocalFunction, self).__repr__() + '\n'
        return res #TODO#

class Limits(WasmItem):
    __slots__ = ['min', 'max']
    def __init__(self, mini, maxi=None):
        self.min = mini
        self.max = maxi
        super(Limits, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        mini, n = parser.u32(bs, ofs+1)
        if byte_to_int(bs[ofs]) == 1:
            maxi, m = parser.u32(bs, ofs+1+n)
            return Limits(mini, maxi), 1+n+m
        return Limits(mini), 1+n

    def build(self):
        if self.max is None:
            return b'\x00' + serializer.u32(self.min)
        return b'\x01' + serializer.u32(self.min) + serializer.u32(self.max)

@prop('elemtype', ElemType)
@prop('limits', Limits)
class TableType(WasmItem):
    __slots__ = ['_elemtype', '_limits']
    def __init__(self, elemtype, limits):
        self.elemtype = elemtype
        self.limits = limits
        super(TableType, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        elemtype, n = ElemType.parse(bs, ofs)
        limits, m = Limits.parse(bs, ofs+n)
        return TableType(elemtype, limits), n+m

    def build(self):
        return self.elemtype.build() + self.limits.build()

@can_be_imported
@can_be_exported
@prop('tabletype', TableType)
class Table(WasmItem):
    __slots__ = ['_tabletype', '_export_name']

    def __init__(self, tabletype):
        self.tabletype = tabletype
        super(Table, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        tt, n = TableType.parse(bs, ofs)
        return Table(tt), n

    def build(self):
        return self.tabletype.build()


@prop('import_info', ImportInfo)
class ImportedTable(object):
    __slots__ = ['_import_info']

    def __init__(self, import_info, *args, **kwargs):
        self.import_info = import_info
        super(ImportedTable, self).__init(*args, **kwargs)

@can_be_imported
@can_be_exported
@prop('limits', Limits)
class Memory(WasmItem):
    __slots__ = ['_limits', '_export_name']

    def __init__(self, limits):
        self.limits = limits
        super(Memory, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        lims, n = Limits.parse(bs, ofs)
        return Memory(lims), n

    def build(self):
        return self.limits.build()

@prop('import_info', ImportInfo)
class ImportedMemory(Memory):
    __slots__ = ['_import_info']

    def __init__(self, import_info, *args, **kwargs):
        self.import_info = import_info
        super(ImportedMemory, self).__init(*args, **kwargs)

class Element(WasmItem):
    __slots__ = ['table', 'offset', 'init']
    
    def __init__(self, table, offset, init):
        self.table = table
        self.offset = offset
        self.init = init
        super(Element, self).__init__()
        
    @staticmethod
    def parse(bs, ofs):
        tidx, n = parser.u32(bs, ofs)
        offset, m = parser.const_expr(bs, ofs+n)
        length, p = parser.u32(bs, ofs+n+m)
        N = n+m+p
        init = []
        for i in range(length):
            fidx, n = parser.u32(bs, ofs+N)
            N += n
            init.append(fidx)
        return Element(tidx, offset, init), N

    def build(self):
        res = serializer.u32(self.table) + self.offset
        res += serializer.u32(len(self.init))
        for i in self.init:
            res += serializer.u32(i)
        return res

class Data(WasmItem):
    __slots__ = ['mem', 'offset', 'init']

    def __init__(self, mem, offset, init):
        self.mem = mem
        self.offset = offset
        self.init = init
        super(Data, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        midx, N = parser.u32(bs, ofs)
        offset, n = parser.const_expr(bs, ofs+N)
        N += n
        l, n = parser.u32(bs, ofs+N)
        N += n
        init = bs[ofs+N : ofs+N+l]
        return Data(midx, offset, init), N+l

    def build(self):
        return (serializer.u32(self.mem) + self.offset +
                serializer.u32(len(self.init)) + self.init)

@prop('valtype', ValType)
@prop('mutable', MutType)
class GlobalType(WasmItem):
    __slots__ = ['_valtype', '_mutable']

    def __init__(self, valtype, mutable):
        self.valtype = valtype
        self.mutable = mutable
        super(GlobalType, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        typ, n = ValType.parse(bs, ofs)
        mut, m = MutType.parse(bs, ofs+n)
        return GlobalType(typ, mut), n+m

    def build(self):
        return self.valtype.build() +  self.mutable.build()

@can_be_imported
@can_be_exported
@prop('globaltype', GlobalType)
class Global(WasmItem):
    __slots__ = ['_globaltype', '_export_name']

    def __init__(self, globtype):
        self.globaltype = globtype
        super(Global, self).__init__()


@prop('import_info', ImportInfo)
class ImportedGlobal(Global):
    __slots__ = ['_import_info']

    def __init__(self, import_info, *args, **kwargs):
        self.import_info = import_info
        super(ImportedGlobal, self).__init(*args, **kwargs)

class LocalGlobal(Global):
    __slots__ = ['init']
    
    def __init__(self, global_type, init):
        self.init = init
        super(LocalGlobal, self).__init__(global_type)

    @staticmethod
    def parse(bs, ofs):
        gt, n = GlobalType.parse(bs, ofs)
        init, m = parser.const_expr(bs, ofs+n)
        return LocalGlobal(gt, init), n+m

    def build(self):
        return self.globaltype.build() + self.init


@prop('name', Name)
class NameAssoc(WasmItem):
    __slots__ = ['idx', '_name']

    def __init__(self, idx, name):
        self.idx = idx
        self.name = name
        super(NameAssoc, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        idx, n = parser.u32(bs, ofs)
        name, m = Name.parse(bs, ofs+n)
        return NameAssoc(idx, name), n+m

    def build(self):
        return serializer.u32(self.idx) + self.name.build()

@prop_list('assocs', NameAssoc)
class NameMap(WasmItem):
    __slots__ = ['_assocs']
    
    def __init__(self, assocs):
        self.assocs = assocs
        super(NameMap, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        asc, n = WasmItemVec.parse(bs, ofs, NameAssoc)
        return NameMap(asc), n

    def build(self):
        return self.assocs.build()

@prop('nmap', NameMap)
class IndirectNameAssoc(WasmItem):
    __slots__ = ['idx', '_nmap']
    
    def __init__(self, idx, nmap):
        self.idx = idx
        self.nmap = nmap
        super(IndirectNameAssoc, self).__init__()

    @staticmethod
    def parse(bs, ofs): 
        idx, n = parser.u32(bs, ofs)
        nmap, m = NameMap.parse(bs, ofs+n)
        return IndirectNameAssoc(idx, nmap), n+m       

    def build(self):
        return serializer.u32(self.idx) + self.nmap.build()

@prop_list('iassocs', IndirectNameAssoc)
class IndirectNameMap(WasmItem):
    __slots__ = ['_iassocs']

    def __init__(self, iassocs):
        self.iassocs = iassocs
        super(IndirectNameMap, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        asc, n = WasmItemVec.parse(bs, ofs, IndirectNameAssoc)
        return IndirectNameMap(asc), n

    def build(self):
        return self.iassocs.build()    

@prop('typ', NameType)
class NameSubSec(WasmItem):
    __slots__ = ['_typ', 'content']
    
    def __init__(self, typ, content):
        self.typ = typ
        self.content = content
        super(NameSubSec, self).__init__()

    @staticmethod
    def parse(bs, ofs):
        t, n = NameType.parse(bs, ofs)
        sz, nn = parser.u32(bs, ofs+n)
        n += nn
        if t == 0:
            cnt, m = Name.parse(bs, ofs+n)
        elif t == 1:
            cnt, m = NameMap.parse(bs, ofs+n)
        elif t == 2:
            cnt, m = IndirectNameMap.parse(bs, ofs+n)
        else:
            log.warn("Name section is broken")
        if sz != m:
            log.warn("Name section inconsistent")
        return NameSubSec(t, cnt), n+m

    def build(self):
        cnt = self.content.build()
        return self.typ.build + serializer.u32(len(cnt)) + cnt


class Section(object):

    @staticmethod
    def new(wasmstr, offset):
        '''Parses the header of the section starting at @wasmstr[@offset:] and returns an instance of the correct section type'''
        # Get section type
        t = byte_to_int(wasmstr[offset])

        # Instentiate the correct Section object
        if t >= len(SECTIONS) or t < 0:
            return UnknownSection(wasmstr, offset)
        return SECTIONS[t](wasmstr, offset)


    def __init__(self, wasmstr, offset):
        # Get data and its size
        self.payload_size, n = parser.u32(wasmstr, offset+1)
        self.size = 1 + n + self.payload_size
        self.wasmstr = wasmstr
        self.offset = offset+n+1
        self.current = self.offset
        
        # Parse data
        self.parse_content()

        # Verify the quantity of data parsed
        if self.payload_size + self.offset != self.current:
            log.warn("Section of type {0} is inconsistent: header announces {1} bytes of data but {2} bytes were parsed"
                     .format(self.stype, self.payload_size, self.current - self.offset))


    def parse_content(self):
        '''To be implemented by each section type'''
        pass


    def get_bytes(self, n):
        '''Returns @n next bytes of content, but does not move the cursor'''
        return self.wasmstr[self.current : self.current + n]


    def pop_bytes(self, n):
        '''Returns @n next bytes of content, and moves the cursor @n bytes forward'''
        self.current += n
        return self.wasmstr[self.current - n : self.current]


    def pop_parse(self, parse_func, *args, **kwargs):
        '''Parses content using parse_func, returns the result, and moves the cursor accordingly'''
        res, n = parse_func(self.wasmstr, self.current, *args, **kwargs)
        self.pop_bytes(n)
        return res


class UnknownSection(Section):
    stype = -1


class CustomSection(Section):
    stype = SHT_CUSTOM

    def parse_content(self):
        # Parse section's name
        self.name = self.pop_parse(Name.parse)
        self.unknown = False

        # Search for symbols if Name section
        if self.name == "name":
            l = 0
            self.content = []
            lim = self.payload_size + self.offset
            while self.current < lim:
                self.content.append(self.pop_parse(NameSubSec.parse))

        else:
            log.warn("Unknown custom section '{}' has been ignored".format(self.name))
            self.unknown = True
            self.content = self.wasmstr[self.offset:self.offset+self.payload_size]
            self.current = self.offset + self.payload_size


class TypeSection(Section):
    stype = SHT_TYPE

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Signature)


class ImportSection(Section):
    stype = SHT_IMPORT

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Import)


class FunctionSection(Section):
    stype = SHT_FUNCTION

    def parse_content(self):
        self.content = []
        n = self.pop_parse(parser.u32)
        for i in range(n):
            self.content.append(self.pop_parse(parser.u32))


class TableSection(Section):
    stype = SHT_TABLE

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Table)


class MemorySection(Section):
    stype = SHT_MEMORY

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Memory)

class GlobalSection(Section):
    stype = SHT_GLOBAL

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, LocalGlobal)


class ExportSection(Section):
    stype = SHT_EXPORT

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Export)


class StartSection(Section):
    stype = SHT_START

    def parse_content(self):
        self.content = self.pop_parse(parser.u32)


class ElementSection(Section):
    stype = SHT_ELEMENT

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Element)

class CodeSection(Section):
    stype = SHT_CODE

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, FunctionCode)

class DataSection(Section):
    stype = SHT_DATA

    def parse_content(self):
        self.content = self.pop_parse(WasmItemVec.parse, Data)

SECTIONS = [
    CustomSection,
    TypeSection,
    ImportSection,
    FunctionSection,
    TableSection,
    MemorySection,
    GlobalSection,
    ExportSection,
    StartSection,
    ElementSection,
    CodeSection,
    DataSection,
]

def add_section_header(section_type):
    def builder_decorator(func):
        def func_wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            l = len(res)
            if l == 0:
                return res
            return int_to_byte(section_type) + serializer.u32(l) + res
        return func_wrapper
    return builder_decorator

def find_section_offset(wasmstr, first_section_offset, s_desc, end=False):
    '''Returns the offset in @wasmstr at which the section described by @s_desc starts (or ends if @end==True)'''
    c = first_section_offset
    l = len(wasmstr)
    while True:
        t = byte_to_int(wasmstr[c])
        size, n = parser.u32(wasmstr, c+1)
        if t == s_desc['type'] and (s_desc['name'] == None or s_desc['name'] == Name.parse(wasmstr, c+1+n)[0]):
            if end:
                return c+1+n+size
            return c
        c += 1+n+size
        if c >= l:
            break
    return None

def _sec_desc(s, name=None):
    '''A short description of a section: its type (+ its name if custom)'''
    if isinstance(s, Section):
        if s.stype == SHT_CUSTOM:
            return {'type': s.stype, 'name': s.name}
        return {'type': s.stype, 'name': None}
    return {'type': s, 'name': name}
        
def filter_local(lst):
    '''Returns the elements of lst that are not imported'''
    res = []
    flag = False
    for i in lst:
        if i.is_imported:
            if flag:
                raise Exception("Imported and non-imported are mixed up in {}"
                                .format(lst))
            continue
        flag = True
        res.append(i)
    return res

def find_imports(lst):
    '''Finds the imported elements in lst and returns a list of Import objects'''
    if len(lst) == 0:
        return []

    if isinstance(lst[0], Function):
        t = ImportType('func')
        cb = lambda i, lst: i
    elif isinstance(lst[0], Table):
        t = ImportType('table')
        cb = lambda i, lst: lst[i].tabletype
    elif isinstance(lst[0], Memory):
        t = ImportType('mem')
        cb = lambda i, lst: lst[i].limits
    elif isinstance(lst[0], Global):
        t = ImportType('global')
        cb = lambda i, lst: lst[i].globtype
    else:
        raise Exception("Error finding import type")

    res = []
    flag = False
    for i in range(len(lst)):
        if  not lst[i].is_imported:
            flag = True
            continue
        if flag:
            raise Exception("Imported and non-imported {} are mixed up..."
                            .format(repr(t)))
        res.append(Import(lst[i].import_info, ImportDesc(t, cb(i, lst))))
    return res

def find_exports(lst):
    '''Finds the exported elements in lst and returns a list of Export objects'''
    if len(lst) == 0:
        return []
        
    if isinstance(lst[0], Function):
        t = ImportType('func')
    elif isinstance(lst[0], Table):
        t = ImportType('table')
    elif isinstance(lst[0], Memory):
        t = ImportType('mem')
    elif isinstance(lst[0], Global):
        t = ImportType('global')
    else:
        raise Exception("Error finding export type")

    res = []
    for i in range(len(lst)):
        if lst[i].is_exported:
            res.append(Export(lst[i].export_name, ExportDesc(t, i)))
    return res

def find_section_offset(wasmstr, first_section_offset, s_desc, end=False):
    '''Returns the offset in @wasmstr at which the section described by @s_desc starts (or ends if @end==True)'''
    c = first_section_offset
    l = len(wasmstr)
    while True:
        t = byte_to_int(wasmstr[c])
        size, n = parser.u32(wasmstr, c+1)
        if t == s_desc['type'] and (s_desc['name'] == None or s_desc['name'] == Name.parse(wasmstr, c+1+n)[0]):
            if end:
                return c+1+n+size
            return c
        c += 1+n+size
        if c >= l:
            break
    return None

@prop('name', Name, optional=True)
class Wasm(object):
    __slots__ = ['_slist', '_builders', '_tmp_signatures',
                 'functions', 'mems', 'tables', 'globs',
                 '_name', 'entry', 'elements', 'data', 'header']

    @classmethod
    def from_path(cls, path):
        return cls(open(path, 'rb').read())

    def __init__(self, wasmstr=None):
        super(Wasm, self).__init__()
        if wasmstr == None:
            wasmstr = b"\x00\x61\x73\x6d\x01\x00\x00\x00" # Empty wasm file version 01
        self.header = wasmstr[:8]
        magic = struct.unpack('<I', self.header[:4])[0]
        if magic != 0x6d736100:
            log.error("{} is not the WASM magic number, aborting...".format(hex(magic)))
            raise ContainerSignatureException("Wrong Magic Number in wasm module")
        version = struct.unpack('<I', self.header[4:8])[0]
        if version != 1:
            log.error("Version '{}' of wasm isn't supported, aborting...".format(version))
            raise ContainerParsingException("Unsupported wasm version")

        #self.content = WasmModule(wasmstr)
        self._init_content(wasmstr)

    def _init_content(self, wasmstr):
        self._slist = []
        i = 8
        size = len(wasmstr)
        while i != size:
            self._slist.append(Section.new(wasmstr, i))
            i += self._slist[-1].size

        self._validate_sections()
        
        self._init_attrs()

        self._init_imports()
        self._init_local_functions()
        self._init_local_tables()
        self._init_local_mems()
        self._init_local_globals()
        self._init_exports()
        self._init_start()
        self._init_elements()
        self._init_data()
        self._init_name()

        self._builders = [
            Wasm._build_type,
            Wasm._build_import,
            Wasm._build_function,
            Wasm._build_table,
            Wasm._build_memory,
            Wasm._build_global,
            Wasm._build_export,
            Wasm._build_start,
            Wasm._build_element,
            Wasm._build_code,
            Wasm._build_data,
            Wasm._build_name,
        ]

    def resize(self, old, new):
        # Not needed
        pass

    def __eq__(self, other):
        return self.header == other.header and self.content == other.content

    def build(self):
        tmp = self.build_content()
        tmp[0:0] = self.header
        return bytes(tmp)

    def __repr__(self): 
        return """\
        Wasm v1 module containing:
        \t-{} functions
        \t-{} tables
        \t-{} memories
        \t-{} globals\
        """.format(
            len(self.functions),
            len(self.tables),
            len(self.mems),
            len(self.globs),)

    def _get_sections_by_name(self, name):
        '''Returns a list of 'custom' sections that have the name 'name\''''
        return [s for s in self._slist if s.stype == SHT_CUSTOM and s.name == name]

    def _get_section_by_id(self, sid):
        '''Returns the first section that has the specified id'''
        for s in self._slist:
            if s.stype == sid:
                return s
        return None

    def _init_attrs(self):
        self.functions = []
        self.tables = []
        self.mems = []
        self.globs = []

    def _init_imports(self):
        
        try:
            signatures = self._get_section_by_id(SHT_TYPE).content
        except:
            signatures = []

        try:
            imports = self._get_section_by_id(SHT_IMPORT).content
        except:
            return

        for imp in imports:
            t = imp.desc._importtype
            if t == 'func':
                self.functions.append(
                    ImportedFunction(
                        imp.info,
                        signatures[imp.desc._content].__deepcopy__()))
            elif t == 'table':
                self.tables.append(
                    ImportedTable(imp.info, imp.desc._content))
            elif t == 'mem':
                self.mems.append(
                    ImportedMemory(imp.info, imp.desc._content))
            elif t == 'global':
                self.globs.append(
                    ImportedGlobal(imp.info, imp.desc._content))
            else:
                raise ContainerParsingException("Error")

    def _init_local_functions(self):
        '''
        Parses content of sections for information about local functions
        Does not search if the function is exported nor its name,
        these must be specified later manually
        '''
        try:
            signatures = self._get_section_by_id(SHT_TYPE).content
            codes = self._get_section_by_id(SHT_CODE).content
            funcs = self._get_section_by_id(SHT_FUNCTION).content
        except:
            return

        for i in range(len(funcs)):
            self.functions.append(
                LocalFunction(
                    code = codes[i],
                    signature = signatures[funcs[i]].__deepcopy__()))

    def _init_local_tables(self):
        try:
            self.tables.extend(self._get_section_by_id(SHT_TABLE).content)
        except:
            return

    def _init_local_mems(self):
        try:
            self.mems.extend(self._get_section_by_id(SHT_MEMORY).content)
        except:
            return

    def _init_local_globals(self):
        try:
            self.globs.extend(self._get_section_by_id(SHT_GLOBAL).content)
        except:
            return

    def _init_exports(self):
        try:
            exports = self._get_section_by_id(SHT_EXPORT).content
        except:
            return

        for exp in exports:
            if exp.desc._exporttype == 'func':
                dst = self.functions
            elif exp.desc._exporttype == 'table':
                dst = self.tables
            elif exp.desc._exporttype == 'mem':
                dst = self.mems
            elif exp.desc._exporttype == 'global':
              dst = self.globs
            else:
                raise ContainerParsingException("Error")
            dst[exp.desc._idx].export_name = exp.name

    def _init_start(self):
        start = self._get_section_by_id(SHT_START)
        self.entry = None
        if start is not None:
            self.entry = start.content

    def _init_elements(self):
        try:
            self.elements = self._get_section_by_id(SHT_ELEMENT).content
        except:
            self.elements = WasmItemOptionVec([], Element)

    def _init_data(self):
        try:
            self.data = self._get_section_by_id(SHT_DATA).content
        except:
            self.data = WasmItemOptionVec([], Data)

    def _init_name(self):
        '''Try to parse 'name' custom section for symbols'''
        self.name = None
        tmp = self._get_sections_by_name('name')
        fnames = None
        lnames = None
        if len(tmp) != 0:
            for ss in tmp[0].content:
                if ss.typ == 0:
                    self.name = ss.content
                elif ss.typ == 1:
                    fnames = ss.content.assocs
                elif ss.typ == 2:
                    lnames = ss.content.iassocs

        if fnames is not None:
            for f in fnames:
                self.functions[f.idx].name = f.name

        if lnames is not None:
            for f in lnames:
                for l in f.nmap.assocs:
                    self.functions[f.idx].locals[l.idx].name = l.name        

    def _validate_sections(self):
        '''Checks the validity (presence, uniqueness...) of present sections'''
        last_section = 0
        for s in self._slist:

            # Check that official sections appear only once and in order
            if s.stype != 0:
                if last_section >= s.stype:
                    log.error("Invalid wasm file: section {} is either duplicate or misplaced".format(s.stype))
                    raise ContainerParsingException("Duplicate or misplaced section")
                else:
                    last_section = s.stype
            else:
                # Check that 'name' section follows 'Data' section
                # (other custom sections are allowed between 'Data' and 'name'
                if s.name == "name" and last_section != SHT_DATA:
                    log.warn("Section 'name' misplacement: should follow Data Section.")

        log.info("Sections placement validated")

    
    def build_content(self):
        '''
        Re-builds wasm sections (without the wasm header) and returns them in a StrPatchwork
        '''
        res = StrPatchwork()
        for builder in self._builders:
            res += builder(self)
        self._inject_unknown_custom(res)
        return res

    @add_section_header(SHT_TYPE)
    def _build_type(self):
        signs = WasmItemOptionVec([], Signature)
        for f in self.functions:
            if f.signature not in signs:
                signs.append(f.signature)
        self._tmp_signatures = signs
        return signs.build()

    @add_section_header(SHT_IMPORT)
    def _build_import(self):
        imprts = WasmItemOptionVec([], Import)
        for i in [self.functions, self.tables, self.mems, self.globs]:
            imprts.extend(find_imports(i))
        return imprts.build()

    @add_section_header(SHT_FUNCTION)
    def _build_function(self):
        idxs = []
        for f in filter_local(self.functions):
            for i in range(len(self._tmp_signatures)):
                if self._tmp_signatures[i] == f.signature:
                    idxs.append(i)
                    break
        return serializer.u32(len(idxs)) + b''.join([serializer.u32(i) for i in idxs])

    @add_section_header(SHT_TABLE)
    def _build_table(self):
        return WasmItemOptionVec([t.tabletype for t in filter_local(self.tables)],
                                 TableType).build()

    @add_section_header(SHT_MEMORY)
    def _build_memory(self):
        return WasmItemOptionVec([m.limits for m in filter_local(self.mems)],
                                 Limits).build()

    @add_section_header(SHT_GLOBAL)
    def _build_global(self):
        return WasmItemOptionVec(filter_local(self.globs),
                                 Global).build()

    @add_section_header(SHT_EXPORT)
    def _build_export(self):
        exprts = WasmItemOptionVec([], Export)
        for i in [self.functions, self.tables, self.mems, self.globs]:
            exprts.extend(find_exports(i))
        return exprts.build()

    @add_section_header(SHT_START)
    def _build_start(self):
        if self.entry is not None:
            return serializer.u32(self.entry)
        return b''

    @add_section_header(SHT_ELEMENT)
    def _build_element(self):
        return self.elements.build()

    @add_section_header(SHT_CODE)
    def _build_code(self):
        return WasmItemOptionVec([f.code for f in filter_local(self.functions)],
                                 FunctionCode).build()

    @add_section_header(SHT_DATA)
    def _build_data(self):
        return self.data.build()

    @add_section_header(SHT_CUSTOM)
    def _build_name(self):
        res = b''
        # Add module name, if any
        if self.name is not None:
            res += b'\x00' + serializer.u32(len(self.name)) + self.name

        # Look for function or local names
        fnames = WasmItemVec([], NameAssoc)
        lnames = WasmItemVec([], IndirectNameAssoc)
        for i in range(len(self.functions)):
            f = self.functions[i]
            if hasattr(f, 'name') and f.name is not None:
                fnames.append(NameAssoc(i, f.name))
            assocs = []
            for j in range(len(f.locals)):
                loc = f.locals[j]
                if hasattr(loc, 'name') and loc.name is not None:
                    assocs.append(NameAssoc(j, loc.name))
            if len(assocs) > 0:
                lnames.append(IndirectNameAssoc(i, NameMap(assocs)))

        if len(fnames) > 0:
            tmp = fnames.build()
            res += b'\x01' + serializer.u32(len(tmp)) + tmp
        if len(lnames) > 0:
            tmp = lnames.build()
            res += b'\x02' + serializer.u32(len(tmp)) + tmp
        if len(res) != 0:
            res = Name('name').build() + res
        return res


    @add_section_header(SHT_CUSTOM)
    def _build_unknown_custom(self, s):
        return s.content


    def _inject_unknown_custom(self, out):
        '''
        Try to re-inject custom sections that were not parsed.
        To do so, the type (and name if custom) of the sections directly before and after a block of unknown sections\
        when the file was parsed must be the same as in the output build.
        If this is not possible, the block of custom sections are placed at the end of the output
        '''
        todo = []
        i = 0
        l = len(self._slist)
        while i != l:
            s = self._slist[i]
            if s.stype == SHT_CUSTOM and s.unknown:
                block = {'content': b'', 'prev': None, 'next': None}
                if i > 0:
                    block['prev'] = _sec_desc(self._slist[i-1])
                while i!=l:
                    s = self._slist[i]
                    if not (s.stype == SHT_CUSTOM and s.unknown):
                        break
                    block['content'] += self._build_unknown_custom(s)
                    i += 1
                if i!=l:
                    block['next'] = _sec_desc(self._slist[i])
                todo.append(block)
            i += 1
        for t in todo:
            if t['prev'] is not None:
                ofs = find_section_offset(out, 0, t['prev'], end=True)
                if t['next'] is not None:
                    ofs2 = find_section_offset(out, 0, t['next'], end=False)
                    if ofs != ofs2:
                        ofs = None
            elif t['next'] is not None:
                ofs = find_section_offset(out, 0, t['next'], end=False)
            else:
                ofs = 0
            if ofs is not None:
                out[ofs:ofs] = t['content']
            else:
                log.warn("Some unknown custom sections were added at the end of the build because I couldn't gess where to put them...")
                out += t['content']
