from miasm2.core.objc import CTypeTemplate, ObjCDecl


class CTypeAMD64_unk(CTypeTemplate):
    """Define C types sizes/alignement for x86_64 architecture"""

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


    def __init__(self):
        self.types = {
            ('char',): self.obj_char,
            ('short',): self.obj_short,
            ('int',): self.obj_int,
            ('void',): self.obj_void,
            ('enum',): self.obj_enum,

            ('signed', 'char'): self.obj_char,
            ('unsigned', 'char'): self.obj_uchar,
            ('signed', 'short', 'int'): self.obj_short,
            ('short', 'int'): self.obj_short,
            ('unsigned', 'short'): self.obj_ushort,
            ('unsigned', 'short', 'int'): self.obj_ushort,
            ('signed', 'int'): self.obj_int,
            ('unsigned', 'int'): self.obj_uint,
            ('long', 'int'): self.obj_long,
            ('unsigned', 'long'): self.obj_ulong,
            ('signed', 'long', 'int'): self.obj_long,
            ('unsigned', 'long', 'int'): self.obj_ulong,
            ('long',): self.obj_long,
            ('unsigned', ): self.obj_uint,

            ('signed', 'long', 'long', 'int'): self.obj_long,
            ('long', 'unsigned', 'int'): self.obj_ulong,
            ('unsigned', 'long', 'long'): self.obj_ulong,
            ('long', 'long', 'int'): self.obj_long,
            ('unsigned', 'long', 'long', 'int'): self.obj_ulong,
            ('void*',): self.obj_ulong,
        }
