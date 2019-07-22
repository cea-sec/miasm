from miasm.core.objc import CLeafTypes, ObjCDecl, PADDING_TYPE_NAME
from miasm.core.ctypesmngr import CTypeId, CTypePtr


class CTypeAMD64_unk(CLeafTypes):
    """Define C types sizes/alignment for x86_64 architecture"""

    obj_pad = ObjCDecl(PADDING_TYPE_NAME, 1, 1) # __padding__ is size 1/align 1

    obj_char = ObjCDecl("char", 1, 1)
    obj_short = ObjCDecl("short", 2, 2)
    obj_int = ObjCDecl("int", 4, 4)
    obj_long = ObjCDecl("long", 8, 8)

    obj_uchar = ObjCDecl("uchar", 1, 1)
    obj_ushort = ObjCDecl("ushort", 2, 2)
    obj_uint = ObjCDecl("uint", 4, 4)
    obj_ulong = ObjCDecl("ulong", 8, 8)

    obj_void = ObjCDecl("void", 1, 1)

    obj_enum = ObjCDecl("enum", 4, 4)

    obj_float = ObjCDecl("float", 4, 4)
    obj_double = ObjCDecl("double", 8, 8)
    obj_ldouble = ObjCDecl("ldouble", 16, 16)

    def __init__(self):
        self.types = {
            CTypeId(PADDING_TYPE_NAME): self.obj_pad,

            CTypeId('char'): self.obj_char,
            CTypeId('short'): self.obj_short,
            CTypeId('int'): self.obj_int,
            CTypeId('void'): self.obj_void,
            CTypeId('long',): self.obj_long,
            CTypeId('float'): self.obj_float,
            CTypeId('double'): self.obj_double,

            CTypeId('signed', 'char'): self.obj_char,
            CTypeId('unsigned', 'char'): self.obj_uchar,

            CTypeId('short', 'int'): self.obj_short,
            CTypeId('signed', 'short'): self.obj_short,
            CTypeId('signed', 'short', 'int'): self.obj_short,
            CTypeId('unsigned', 'short'): self.obj_ushort,
            CTypeId('unsigned', 'short', 'int'): self.obj_ushort,

            CTypeId('unsigned', ): self.obj_uint,
            CTypeId('unsigned', 'int'): self.obj_uint,
            CTypeId('signed', 'int'): self.obj_int,

            CTypeId('long', 'int'): self.obj_long,
            CTypeId('long', 'long'): self.obj_long,
            CTypeId('long', 'long', 'int'): self.obj_long,
            CTypeId('signed', 'long', 'long'): self.obj_long,
            CTypeId('unsigned', 'long', 'long'): self.obj_ulong,
            CTypeId('signed', 'long', 'long', 'int'): self.obj_long,
            CTypeId('unsigned', 'long', 'long', 'int'): self.obj_ulong,

            CTypeId('signed', 'long'): self.obj_long,
            CTypeId('unsigned', 'long'): self.obj_ulong,
            CTypeId('signed', 'long', 'int'): self.obj_long,
            CTypeId('unsigned', 'long', 'int'): self.obj_ulong,

            CTypeId('long', 'double'): self.obj_ldouble,
            CTypePtr(CTypeId('void')): self.obj_ulong,
        }





class CTypeX86_unk(CLeafTypes):
    """Define C types sizes/alignment for x86_32 architecture"""

    obj_pad = ObjCDecl(PADDING_TYPE_NAME, 1, 1) # __padding__ is size 1/align 1

    obj_char = ObjCDecl("char", 1, 1)
    obj_short = ObjCDecl("short", 2, 2)
    obj_int = ObjCDecl("int", 4, 4)
    obj_long = ObjCDecl("long", 4, 4)

    obj_uchar = ObjCDecl("uchar", 1, 1)
    obj_ushort = ObjCDecl("ushort", 2, 2)
    obj_uint = ObjCDecl("uint", 4, 4)
    obj_ulong = ObjCDecl("ulong", 4, 4)

    obj_void = ObjCDecl("void", 1, 1)

    obj_enum = ObjCDecl("enum", 4, 4)

    obj_float = ObjCDecl("float", 4, 4)
    obj_double = ObjCDecl("double", 8, 8)
    obj_ldouble = ObjCDecl("ldouble", 16, 16)

    def __init__(self):
        self.types = {
            CTypeId(PADDING_TYPE_NAME): self.obj_pad,

            CTypeId('char'): self.obj_char,
            CTypeId('short'): self.obj_short,
            CTypeId('int'): self.obj_int,
            CTypeId('void'): self.obj_void,
            CTypeId('long',): self.obj_long,
            CTypeId('float'): self.obj_float,
            CTypeId('double'): self.obj_double,

            CTypeId('signed', 'char'): self.obj_char,
            CTypeId('unsigned', 'char'): self.obj_uchar,

            CTypeId('short', 'int'): self.obj_short,
            CTypeId('signed', 'short'): self.obj_short,
            CTypeId('signed', 'short', 'int'): self.obj_short,
            CTypeId('unsigned', 'short'): self.obj_ushort,
            CTypeId('unsigned', 'short', 'int'): self.obj_ushort,

            CTypeId('unsigned', ): self.obj_uint,
            CTypeId('unsigned', 'int'): self.obj_uint,
            CTypeId('signed', 'int'): self.obj_int,

            CTypeId('long', 'int'): self.obj_long,
            CTypeId('long', 'long'): self.obj_long,
            CTypeId('long', 'long', 'int'): self.obj_long,
            CTypeId('signed', 'long', 'long'): self.obj_long,
            CTypeId('unsigned', 'long', 'long'): self.obj_ulong,
            CTypeId('signed', 'long', 'long', 'int'): self.obj_long,
            CTypeId('unsigned', 'long', 'long', 'int'): self.obj_ulong,

            CTypeId('signed', 'long'): self.obj_long,
            CTypeId('unsigned', 'long'): self.obj_ulong,
            CTypeId('signed', 'long', 'int'): self.obj_long,
            CTypeId('unsigned', 'long', 'int'): self.obj_ulong,

            CTypeId('long', 'double'): self.obj_ldouble,
            CTypePtr(CTypeId('void')): self.obj_uint,
        }
