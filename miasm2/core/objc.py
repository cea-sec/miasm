"""
C helper for Miasm:
* raw C to Miasm expression
* Miasm expression to raw C
* Miasm expression to C type
"""


from pycparser import c_parser, c_ast

from miasm2.expression.expression_reduce import ExprReducer
from miasm2.expression.expression import ExprInt, ExprId, ExprOp, ExprMem

from miasm2.core.ctypesmngr import CTypeUnion, CTypeStruct, CTypeId, CTypePtr,\
    CTypeArray, CTypeOp, CTypeSizeof, CTypeEnum, CTypeFunc, CTypeEllipsis


PADDING_TYPE_NAME = "___padding___"

class ObjC(object):
    """Generic ObjC"""

    def set_align_size(self, align, size):
        """Set C object alignment and size"""

        self.align = align
        self.size = size

    def eq_base(self, other):
        return (self.__class__ == other.__class__ and
                self.align == other.align and
                self.size == other.size)


class ObjCDecl(ObjC):
    """C Declaration identified"""

    def __init__(self, name, align, size):
        super(ObjCDecl, self).__init__()
        self.name, self.align, self.size = name, align, size

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.name)

    def __str__(self):
        return '%s' % (self.name)

    def __eq__(self, other):
        if not self.eq_base(other):
            return False
        return self.name == other.name


class ObjCInt(ObjC):
    """C integer"""

    def __init__(self):
        super(ObjCInt, self).__init__()
        self.size = None
        self.align = None

    def __str__(self):
        return 'int'

    def __eq__(self, other):
        return self.eq_base(other)


class ObjCPtr(ObjC):
    """C Pointer"""

    def __init__(self, objtype, void_p_align, void_p_size):
        """Init ObjCPtr

        @objtype: pointer target ObjC
        @void_p_align: pointer alignment (in bytes)
        @void_p_size: pointer size (in bytes)
        """

        super(ObjCPtr, self).__init__()
        self.objtype = objtype
        self.align = void_p_align
        self.size = void_p_size

    def __repr__(self):
        return '<%s %r>' % (self.__class__.__name__,
                            self.objtype.__class__)

    def __str__(self):
        target = self.objtype
        if isinstance(target, ObjCDecl):
            return "%s *" % target.name
        elif isinstance(target, ObjCPtr):
            return "%s *" % target
        elif isinstance(target, ObjCStruct):
            return "struct %s *" % target.name
        elif isinstance(target, ObjCUnion):
            return "union %s *" % target.name
        elif isinstance(target, ObjCArray):
            return "%s (*)[%s]" % (target.objtype, target.elems)
        elif isinstance(target, ObjCFunc):
            args = ", ".join([str(arg) for arg in target.args])
            return "%s (*%s)(%s)" % (target.type_ret, target.name, args)
        else:
            return '*%s' % (target)

    def __eq__(self, other):
        if not self.eq_base(other):
            return False
        return self.objtype == other.objtype


class ObjCArray(ObjC):
    """C array (test[XX])"""

    def __init__(self, objtype, elems):
        """Init ObjCArray

        @objtype: pointer target ObjC
        @elems: number of elements in the array
        """

        super(ObjCArray, self).__init__()
        self.elems = elems
        self.objtype = objtype
        self.align = objtype.align
        self.size = elems * objtype.size

    def __repr__(self):
        return '<%r[%d]>' % (self.objtype, self.elems)

    def __str__(self):
        return '%s[%d]' % (self.objtype, self.elems)

    def __eq__(self, other):
        if not self.eq_base(other):
            return False
        return (self.elems == other.elems and
                self.objtype == other.objtype)


class ObjCStruct(ObjC):
    """C object for structures"""

    def __init__(self, name):
        super(ObjCStruct, self).__init__()
        self.name = name
        self.fields = []

    def add_field(self, name, objtype, offset, size):
        """Add a field into the structure
        @name: field name
        @objtype: field type
        @offset: field offset in the structure
        @size: field size
        """

        self.fields.append((name, objtype, offset, size))

    def __repr__(self):
        out = []
        out.append("Struct %s: (align: %d)" % (self.name, self.align))
        out.append("  off sz  name")
        for name, objtype, offset, size in self.fields:
            out.append("  0x%-3x %-3d %-10s %r" %
                       (offset, size, name, objtype.__class__.__name__))
        return '\n'.join(out)

    def __str__(self):
        return 'struct %s' % (self.name)

    def __eq__(self, other):
        if not (self.eq_base(other) and self.name == other.name):
            return False
        if len(self.fields) != len(other.fields):
            return False
        for field_a, field_b in zip(self.fields, other.fields):
            if field_a != field_b:
                return False
        return True


class ObjCUnion(ObjC):
    """C object for unions"""

    def __init__(self, name):
        super(ObjCUnion, self).__init__()
        self.name = name
        self.fields = []

    def add_field(self, name, objtype, offset, size):
        """Add a field into the structure
        @name: field name
        @objtype: field type
        @offset: field offset in the structure
        @size: field size
        """

        self.fields.append((name, objtype, offset, size))

    def __repr__(self):
        out = []
        out.append("Union %s: (align: %d)" % (self.name, self.align))
        out.append("  off sz  name")
        for name, objtype, offset, size in self.fields:
            out.append("  0x%-3x %-3d %-10s %r" %
                       (offset, size, name, objtype))
        return '\n'.join(out)

    def __str__(self):
        return 'union %s' % (self.name)

    def __eq__(self, other):
        if not (self.eq_base(other) and self.name == other.name):
            return False
        if len(self.fields) != len(other.fields):
            return False
        for field_a, field_b in zip(self.fields, other.fields):
            if field_a != field_b:
                return False
        return True


class ObjCEllipsis(ObjC):
    """C integer"""

    def __init__(self):
        super(ObjCEllipsis, self).__init__()
        self.size = None
        self.align = None

    def __eq__(self, other):
        return self.eq_base(other)


class ObjCFunc(ObjC):
    """C object for Functions"""

    def __init__(self, name, abi, type_ret, args, void_p_align, void_p_size):
        super(ObjCFunc, self).__init__()
        self.name = name
        self.abi = abi
        self.type_ret = type_ret
        self.args = args
        self.align = void_p_align
        self.size = void_p_size

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,
                            self.name)

    def __str__(self):
        out = []
        out.append("Function (%s)  %s: (align: %d)" % (self.abi, self.name, self.align))
        out.append("  ret: %s" % (str(self.type_ret)))
        out.append("  Args:")
        for arg in self.args:
            out.append("  %s" % arg)
        return '\n'.join(out)

    def __eq__(self, other):
        if not (self.eq_base(other) and self.name == other.name and
                self.type_ret == other.type_ret):
            return False
        if len(self.args) != len(other.args):
            return False
        for arg_a, arg_b in zip(self.args, other.args):
            if arg_a != arg_b:
                return False
        return True


def access_simplifier(expr):
    """Expression visitor to simplify a C access represented in Miasm

    @expr: Miasm expression representing the C access

    Example:

    IN: (In c: ['*(&((&((*(ptr_Test)).a))[0]))'])
    [ExprOp('deref', ExprOp('addr', ExprOp('[]', ExprOp('addr',
    ExprOp('field', ExprOp('deref', ExprId('ptr_Test', 64)),
    ExprId('a', 64))), ExprInt(0x0, 64))))]

    OUT: (In c: ['(ptr_Test)->a'])
    [ExprOp('->', ExprId('ptr_Test', 64), ExprId('a', 64))]
    """

    if (expr.is_op("addr") and
            expr.args[0].is_op("[]") and
            expr.args[0].args[1] == ExprInt(0, 64)):
        return expr.args[0].args[0]
    elif (expr.is_op("[]") and
          expr.args[0].is_op("addr") and
          expr.args[1] == ExprInt(0, 64)):
        return expr.args[0].args[0]
    elif (expr.is_op("addr") and
          expr.args[0].is_op("deref")):
        return expr.args[0].args[0]
    elif (expr.is_op("deref") and
          expr.args[0].is_op("addr")):
        return expr.args[0].args[0]
    elif (expr.is_op("field") and
          expr.args[0].is_op("deref")):
        return ExprOp("->", expr.args[0].args[0], expr.args[1])
    return expr


def access_str(expr):
    """Return the C string of a C access represented in Miasm

    @expr: Miasm expression representing the C access

    In:
    ExprOp('->', ExprId('ptr_Test', 64), ExprId('a', 64))
    OUT:
    '(ptr_Test)->a'
    """

    if isinstance(expr, ExprId):
        out = str(expr)
    elif isinstance(expr, ExprInt):
        out = str(int(expr))
    elif expr.is_op("addr"):
        out = "&(%s)" % access_str(expr.args[0])
    elif expr.is_op("deref"):
        out = "*(%s)" % access_str(expr.args[0])
    elif expr.is_op("field"):
        out = "(%s).%s" % (access_str(expr.args[0]), access_str(expr.args[1]))
    elif expr.is_op("->"):
        out = "(%s)->%s" % (access_str(expr.args[0]), access_str(expr.args[1]))
    elif expr.is_op("[]"):
        out = "(%s)[%s]" % (access_str(expr.args[0]), access_str(expr.args[1]))
    else:
        raise RuntimeError("unknown op")

    return out


class CGen(object):
    """Generic object to represent a C expression"""

    default_size = 64

    def to_c(self):
        """Generate corresponding C"""

        raise NotImplementedError("Virtual")

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        raise NotImplementedError("Virtual")


class CGenInt(CGen):
    """Int C object"""

    def __init__(self, integer):
        assert isinstance(integer, (int, long))
        self.integer = integer
        self.ctype = ObjCInt()

    def to_c(self):
        """Generate corresponding C"""

        return "0x%X" % self.integer

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,
                            self.integer)

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        return ExprInt(self.integer, self.default_size)


class CGenId(CGen):
    """ID of a C object"""

    def __init__(self, ctype, name):
        self.ctype = ctype
        self.name = name
        assert isinstance(name, str)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,
                            self.name)

    def to_c(self):
        """Generate corresponding C"""

        return "%s" % (self.name)

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        return ExprId(self.name, self.default_size)


class CGenField(CGen):
    """
    Field of a C struct/union

    IN:
    - struct (not ptr struct)
    - field name
    OUT:
    - input type of the field => output type
    - X[] => X[]
    - X => X*
    """

    def __init__(self, struct, field, fieldtype, void_p_align, void_p_size):
        self.struct = struct
        self.field = field
        assert isinstance(field, str)
        if isinstance(fieldtype, ObjCArray):
            ctype = fieldtype
        else:
            ctype = ObjCPtr(fieldtype, void_p_align, void_p_size)
        self.ctype = ctype

    def to_c(self):
        """Generate corresponding C"""

        if isinstance(self.ctype, ObjCArray):
            return "(%s).%s" % (self.struct.to_c(), self.field)
        elif isinstance(self.ctype, ObjCPtr):
            return "&((%s).%s)" % (self.struct.to_c(), self.field)
        else:
            raise RuntimeError("Strange case")

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__,
                               self.struct,
                               self.field)

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        if isinstance(self.ctype, ObjCArray):
            return ExprOp("field",
                          self.struct.to_expr(),
                          ExprId(self.field, self.default_size))
        elif isinstance(self.ctype, ObjCPtr):
            return ExprOp("addr",
                          ExprOp("field",
                                 self.struct.to_expr(),
                                 ExprId(self.field, self.default_size)))
        else:
            raise RuntimeError("Strange case")


class CGenArray(CGen):
    """
    C Array

    This object does *not* deref the source, it only do object casting.

    IN:
    - obj
    OUT:
    - X* => X*
    - ..[][] => ..[]
    - X[] => X*
    """

    def __init__(self, name, element, void_p_align, void_p_size):
        ctype = name.ctype
        if isinstance(ctype, ObjCPtr):
            pass
        elif isinstance(ctype, ObjCArray) and isinstance(ctype.objtype, ObjCArray):
            ctype = ctype.objtype
        elif isinstance(ctype, ObjCArray):
            ctype = ObjCPtr(ctype.objtype, void_p_align, void_p_size)
        else:
            raise TypeError("Strange case")
        self.ctype = ctype
        self.name = name
        self.element = element

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,
                            self.name)

    def to_c(self):
        """Generate corresponding C"""

        if isinstance(self.ctype, ObjCPtr):
            out_str = "&((%s)[%d])" % (self.name.to_c(), self.element)
        elif isinstance(self.ctype, ObjCArray):
            out_str = "(%s)[%d]" % (self.name.to_c(), self.element)
        else:
            raise RuntimeError("Strange case")
        return out_str

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        if isinstance(self.ctype, ObjCPtr):
            return ExprOp("addr",
                          ExprOp("[]",
                                 self.name.to_expr(),
                                 ExprInt(self.element, self.default_size)))
        elif isinstance(self.ctype, ObjCArray):
            return ExprOp("[]",
                          self.name.to_expr(),
                          ExprInt(self.element, self.default_size))
        else:
            raise RuntimeError("Strange case")


class CGenDeref(CGen):
    """
    C dereference

    IN:
    - ptr
    OUT:
    - X* => X
    """

    def __init__(self, mem):
        assert isinstance(mem.ctype, ObjCPtr)
        self.ctype = mem.ctype.objtype
        self.mem = mem

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__,
                            self.mem)

    def to_c(self):
        """Generate corresponding C"""

        if not isinstance(self.mem.ctype, ObjCPtr):
            raise RuntimeError()
        return "*(%s)" % (self.mem.to_c())

    def to_expr(self):
        """Generate Miasm expression representing the C access"""

        if not isinstance(self.mem.ctype, ObjCPtr):
            raise RuntimeError()
        return ExprOp("deref", self.mem.to_expr())


def ast_get_c_access_expr(ast, expr_types, lvl=0):
    """Transform C ast object into a C Miasm expression

    @ast: parsed pycparser.c_ast object
    @expr_types: a dictionnary linking ID names to their types
    @lvl: actual recursion level

    Example:

    IN:
    StructRef: ->
      ID: ptr_Test
      ID: a

    OUT:
    ExprOp('->', ExprId('ptr_Test', 64), ExprId('a', 64))
    """

    if isinstance(ast, c_ast.Constant):
        obj = ExprInt(int(ast.value), 64)
    elif isinstance(ast, c_ast.StructRef):
        name, field = ast.name, ast.field.name
        name = ast_get_c_access_expr(name, expr_types)
        if ast.type == "->":
            s_name = name
            s_field = ExprId(field, 64)
            obj = ExprOp('->', s_name, s_field)
        elif ast.type == ".":
            s_name = name
            s_field = ExprId(field, 64)
            obj = ExprOp("field", s_name, s_field)
        else:
            raise RuntimeError("Unknown struct access")
    elif isinstance(ast, c_ast.UnaryOp) and ast.op == "&":
        tmp = ast_get_c_access_expr(ast.expr, expr_types, lvl + 1)
        obj = ExprOp("addr", tmp)
    elif isinstance(ast, c_ast.ArrayRef):
        tmp = ast_get_c_access_expr(ast.name, expr_types, lvl + 1)
        index = ast_get_c_access_expr(ast.subscript, expr_types, lvl + 1)
        obj = ExprOp("[]", tmp, index)
    elif isinstance(ast, c_ast.ID):
        assert ast.name in expr_types
        obj = ExprId(ast.name, 64)
    elif isinstance(ast, c_ast.UnaryOp) and ast.op == "*":
        tmp = ast_get_c_access_expr(ast.expr, expr_types, lvl + 1)
        obj = ExprOp("deref", tmp)
    else:
        raise NotImplementedError("Unknown type")
    return obj


def parse_access(c_access):
    """Parse C access

    @c_access: C access string
    """

    main = '''
    int main() {
    %s;
    }
    ''' % c_access

    parser = c_parser.CParser()
    node = parser.parse(main, filename='<stdin>')
    access = node.ext[-1].body.block_items[0]
    return access


class CTypeAnalyzer(ExprReducer):
    """
    Return the C type(s) of a native Miasm expression
    """

    def __init__(self, expr_types, types_mngr, enforce_strict_access=True):
        """Init TypeAnalyzer
        @expr_types: a dictionnary linking ID names to their types
        @types_mngr: types manager
        @enforce_strict_access: If false, get type even on expression
        pointing to a middle of an object. If true, raise exception if such a
        pointer is encountered
        """

        self.expr_types = expr_types
        self.types_mngr = types_mngr
        self.enforce_strict_access = enforce_strict_access

    def updt_expr_types(self, expr_types):
        """Update expr_types
        @expr_types: Dictionnary associating name to type
        """

        self.expr_types = expr_types

    CST = ObjCInt()

    def get_typeof(self, base_type, offset, deref, lvl=0):
        """Return a list of pointers (or None) on the element at @offset of an
        object of type @base_type

        In case of no @deref, stops recursion as soon as we reached the base of
        an object.
        In other cases, we need to go down to the final dereferenced object

        @base_type: type of main object
        @offset: offset (in bytes) of the target sub object
        @deref: get type for a pointer or a deref
        @lvl: actual recursion level
        """
        void_type = self.types_mngr.void_ptr

        if isinstance(base_type, ObjCStruct):
            if offset == 0 and not deref:
                # In this case, return the struct*
                obj = ObjCPtr(base_type, void_type.align, void_type.size)
                new_type = [obj]
                return new_type
            for _, subtype, f_offset, size in base_type.fields:
                if not f_offset <= offset < f_offset + size:
                    continue
                new_type = self.get_typeof(
                    subtype, offset - f_offset, deref, lvl + 1)
                break
            else:
                raise RuntimeError('cannot find struct field')
        elif isinstance(base_type, ObjCArray):
            sub_offset = offset % (base_type.objtype.size)
            element_num = offset / (base_type.objtype.size)
            if element_num >= base_type.elems:
                return None
            if offset == 0 and not deref:
                # In this case, return the array
                return [base_type]
            obj = self.get_typeof(
                base_type.objtype, sub_offset, deref, lvl + 1)
            new_type = obj

        elif isinstance(base_type, ObjCDecl):
            if self.enforce_strict_access and offset != 0:
                return []
            obj = ObjCPtr(base_type, void_type.align, void_type.size)
            new_type = [obj]

        elif isinstance(base_type, ObjCUnion):
            out = []
            if offset == 0 and not deref:
                # In this case, return the struct*
                obj = ObjCPtr(base_type, void_type.align, void_type.size)
                new_type = [obj]
                return new_type
            for _, objtype, f_offset, size in base_type.fields:
                if not f_offset <= offset < f_offset + size:
                    continue
                new_type = self.get_typeof(
                    objtype, offset - f_offset, deref, lvl + 1)
                out += new_type
            new_type = out
        elif isinstance(base_type, ObjCPtr):
            if self.enforce_strict_access:
                assert offset % base_type.size == 0
            obj = ObjCPtr(base_type, void_type.align, void_type.size)
            new_type = [obj]
        else:
            raise NotImplementedError("deref type %r" % base_type)
        return new_type

    def reduce_id(self, node, _):
        """Get type of ExprId"""
        if not(isinstance(node.expr, ExprId) and node.expr.name in self.expr_types):
            return None
        return [self.expr_types[node.expr.name]]

    def reduce_int(self, node, _):
        """Get type of ExprInt"""

        if not isinstance(node.expr, ExprInt):
            return None
        return [self.CST]

    def get_solo_type(self, node):
        """Return the type of the @node if it has only one possible type,
        different from not None. In othe cases, return None.
        """
        if node.info is None or len(node.info) != 1:
            return None
        return type(node.info[0])

    def reduce_ptr_plus_cst(self, node, lvl):
        """Get type of ptr + CST"""

        if not node.expr.is_op("+") or len(node.args) != 2:
            return None
        args_types = set([self.get_solo_type(node.args[0]),
                          self.get_solo_type(node.args[1])])
        if args_types != set([ObjCInt, ObjCPtr]):
            return None
        arg0, arg1 = node.args
        out = []
        ptr_offset = int(arg1.expr)
        for info in arg0.info:
            ptr_basetype = info.objtype
            # Array-like: int* ptr; ptr[1] = X
            out += self.get_typeof(ptr_basetype,
                                   ptr_offset % ptr_basetype.size,
                                   False,
                                   lvl)

        return out

    def reduce_cst_op_cst(self, node, _):
        """Get type of CST + CST"""

        if not node.expr.is_op("+") or len(node.args) != 2:
            return None
        if node.args[0] is None or node.args[1] is None:
            return None
        args_types = set([self.get_solo_type(node.args[0]),
                          self.get_solo_type(node.args[1])])
        if args_types != set([ObjCInt]):
            return None
        return [self.CST]

    def reduce_deref(self, node, lvl):
        """Get type of a dereferenced expression:
        * @NN[ptr<elem>] -> elem  (type)
        * @64[ptr<ptr<elem>>] -> ptr<elem>
        * @32[ptr<struct>] -> struct.00
        """

        if not isinstance(node.expr, ExprMem):
            return None
        if node.arg.info is None:
            return None
        found = []
        for subtype in node.arg.info:
            # subtype : ptr<elem>
            if not isinstance(subtype, (ObjCPtr, ObjCArray)):
                return None
            target = subtype.objtype
            # target : type(elem)
            for ptr_target in self.get_typeof(target, 0, True, lvl):
                r_target = ptr_target.objtype
                # ptr_target: ptr<elem>
                # r_target: elem
                if (not(self.enforce_strict_access) or
                    r_target.size != node.expr.size / 8):
                    continue
                found.append(r_target)
        if not found:
            return None
        return found

    reduction_rules = [reduce_id, reduce_int,
                       reduce_ptr_plus_cst, reduce_cst_op_cst,
                       reduce_deref,
                      ]

    def get_type(self, expr):
        """Return the C type(s) of the native Miasm expression @expr
        @expr: Miasm expression"""

        return self.reduce(expr)


class ExprToAccessC(ExprReducer):
    """
    Generate the C access object(s) for a given native Miasm expression
    Example:
    IN:
    @32[ptr_Test]
    OUT:
    [<CGenDeref <CGenArray <CGenField <CGenDeref <CGenId ptr_Test>> a>>>]

    An expression may be represented by multiple accessor (due to unions).
    """

    def __init__(self, expr_types, types_mngr, enforce_strict_access=True):
        """Init GenCAccess

        @expr_types: a dictionnary linking ID names to their types
        @types_mngr: types manager
        @enforce_strict_access: If false, generate access even on expression
        pointing to a middle of an object. If true, raise exception if such a
        pointer is encountered
        """

        self.expr_types = expr_types
        self.types_mngr = types_mngr
        self.enforce_strict_access = enforce_strict_access

    def updt_expr_types(self, expr_types):
        """Update expr_types
        @expr_types: Dictionnary associating name to type
        """

        self.expr_types = expr_types

    def cgen_access(self, cgenobj, base_type, offset, deref, lvl=0):
        """Return the access(es) which lead to the element at @offset of an
        object of type @base_type

        In case of no @deref, stops recursion as soon as we reached the base of
        an object.
        In other cases, we need to go down to the final dereferenced object

        @cgenobj: current object access
        @base_type: type of main object
        @offset: offset (in bytes) of the target sub object
        @deref: get type for a pointer or a deref
        @lvl: actual recursion level


        IN:
        - base_type: struct Toto{
            int a
            int b
          }
        - base_name: var
        - 4
        OUT:
        - CGenField(var, b)



        IN:
        - base_type: int a
        - 0
        OUT:
        - CGenAddr(a)

        IN:
        - base_type: X = int* a
        - 0
        OUT:
        - CGenAddr(X)

        IN:
        - X = int* a
        - 8
        OUT:
        - ASSERT


        IN:
        - struct toto{
            int a
            int b[10]
          }
        - 8
        OUT:
        - CGenArray(CGenField(toto, b), 1)
        """

        void_type = self.types_mngr.void_ptr
        if isinstance(base_type, ObjCStruct):
            assert 0 <= offset < base_type.size
            if offset == 0 and not deref:
                # In this case, return the struct*
                return [cgenobj]

            out = []
            for fieldname, subtype, f_offset, size in base_type.fields:
                if not f_offset <= offset < f_offset + size:
                    continue
                fieldptr = CGenField(CGenDeref(cgenobj), fieldname, subtype,
                                     void_type.align, void_type.size)
                ret = self.cgen_access(
                    fieldptr, subtype, offset - f_offset, deref, lvl + 1)
                for sname in ret:
                    finalobj = sname
                    out.append(finalobj)
                new_type = out
                break
            else:
                raise RuntimeError('Cannot find struct field')
        elif isinstance(base_type, ObjCArray):
            element_num = offset / (base_type.objtype.size)
            assert element_num < base_type.elems
            f_offset = offset % base_type.objtype.size
            cur_objtype = base_type
            curobj = cgenobj
            subtype = cur_objtype.objtype
            if subtype == ObjCArray:
                raise NotImplementedError("TODO")
            else:
                if f_offset != 0:
                    curobj = CGenArray(curobj, element_num,
                                       void_type.align, void_type.size)
                    ret = self.cgen_access(
                        curobj, curobj.ctype.objtype, f_offset, deref, lvl + 1)
                else:
                    curobj = CGenArray(curobj, element_num,
                                       void_type.align, void_type.size)
                    ret = [curobj]
                new_type = ret
        elif isinstance(base_type, ObjCDecl):
            if self.enforce_strict_access:
                if offset % base_type.size != 0:
                    return []
            elem_num = offset / base_type.size

            nobj = CGenArray(cgenobj, elem_num,
                             void_type.align, void_type.size)
            new_type = [(nobj)]

        elif isinstance(base_type, ObjCUnion):
            out = []
            if offset == 0 and not deref:
                # In this case, return the struct*
                return [cgenobj]

            for fieldname, objtype, f_offset, size in base_type.fields:
                if not f_offset <= offset < f_offset + size:
                    continue
                field = CGenField(CGenDeref(cgenobj), fieldname, objtype,
                                  void_type.align, void_type.size)
                new_type = self.cgen_access(
                    field, objtype, offset - f_offset, deref, lvl + 1)
                if new_type is None:
                    continue
                for sname in new_type:
                    finalobj = sname
                    out.append(finalobj)
            new_type = out

        elif isinstance(base_type, ObjCPtr):
            elem_num = offset / base_type.size
            if self.enforce_strict_access:
                assert offset % base_type.size == 0

            nobj = CGenArray(cgenobj, elem_num,
                             void_type.align, void_type.size)
            new_type = [(nobj)]

        else:
            raise NotImplementedError("deref type %r" % base_type)
        return new_type

    def reduce_id(self, node, _):
        """Generate access for ExprId"""

        if not (isinstance(node.expr, ExprId) and
                node.expr.name in self.expr_types):
            return None

        objc = self.expr_types[node.expr.name]
        out = CGenId(objc, node.expr.name)
        return [out]

    def reduce_int(self, node, _):
        """Generate access for ExprInt"""

        if not isinstance(node.expr, ExprInt):
            return None
        return [CGenInt(int(node.expr))]

    def get_solo_type(self, node):
        """Return the type of the @node if it has only one possible type,
        different from not None. In othe cases, return None.
        """
        if node.info is None or len(node.info) != 1:
            return None
        return type(node.info[0].ctype)

    def reduce_op(self, node, lvl):
        """Generate access for ExprOp"""

        if not node.expr.is_op("+") or len(node.args) != 2:
            return None
        args_types = set([self.get_solo_type(node.args[0]),
                          self.get_solo_type(node.args[1])])
        if args_types != set([ObjCInt, ObjCPtr]):
            return None

        arg0, arg1 = node.args
        out = []
        ptr_offset = int(arg1.expr)
        for name in arg0.info:
            assert isinstance(name.ctype, ObjCPtr)
            ptr_basetype = name.ctype.objtype
            # Array-like: int* ptr; ptr[1] = X
            ret = self.cgen_access(name,
                                   ptr_basetype,
                                   ptr_offset, False, lvl)
            for subcgenobj in ret:
                out.append(subcgenobj)
        return out

    def reduce_mem(self, node, lvl):
        """Generate access for ExprMem:
        * @NN[ptr<elem>] -> elem  (type)
        * @64[ptr<ptr<elem>>] -> ptr<elem>
        * @32[ptr<struct>] -> struct.00
        """

        if not isinstance(node.expr, ExprMem):
            return None
        if node.arg.info is None:
            return None
        assert isinstance(node.arg.info, list)
        found = []
        for subcgenobj in node.arg.info:
            if not isinstance(subcgenobj.ctype, ObjCPtr):
                return None
            target = subcgenobj.ctype.objtype
            # target : type(elem)
            if isinstance(target, (ObjCStruct, ObjCUnion)):
                for finalcgenobj in self.cgen_access(subcgenobj, target, 0, True, lvl):
                    target = finalcgenobj.ctype.objtype
                    if not(self.enforce_strict_access) or target.size == node.expr.size / 8:
                        nobj = CGenDeref(finalcgenobj)
                        found.append(nobj)
            elif isinstance(target, ObjCArray):
                final = target.objtype
                if not(self.enforce_strict_access) or final.size == node.expr.size / 8:
                    nobj = CGenDeref(subcgenobj)
                    found.append(nobj)

            else:
                if not(self.enforce_strict_access) or target.size == node.expr.size / 8:
                    nobj = CGenDeref(subcgenobj)
                    found.append(nobj)
        assert found
        return found

    reduction_rules = [reduce_id,
                       reduce_int,
                       reduce_op,
                       reduce_mem,
                      ]

    def get_access(self, expr):
        """Generate C access(es) for the native Miasm expression @expr
        @expr: native Miasm expression
        """

        return self.reduce(expr)


class ExprCToExpr(ExprReducer):
    """Translate a Miasm expression (representing a C access) into a native
    Miasm expression and its C type:

    Example:

    IN: ((ptr_struct -> f_mini) field x)
    OUT: @32[ptr_struct + 0x80], int


    Tricky cases:
    Struct S0 {
        int x;
        int y[0x10];
    }

    Struct S1 {
        int a;
        S0 toto;
    }

    S1* ptr;

    Case 1:
    ptr->toto => ptr + 0x4
    &(ptr->toto) => ptr + 0x4

    Case 2:
    (ptr->toto).x => @32[ptr + 0x4]
    &((ptr->toto).x) => ptr + 0x4

    Case 3:
    (ptr->toto).y => ptr + 0x8
    &((ptr->toto).y) => ptr + 0x8

    Case 4:
    (ptr->toto).y[1] => @32[ptr + 0x8 + 0x4]
    &((ptr->toto).y[1]) => ptr + 0x8 + 0x4

    """

    def __init__(self, expr_types, types_mngr):
        """Init ExprCAccess

        @expr_types: a dictionnary linking ID names to their types
        @types_mngr: types manager
        """

        self.expr_types = expr_types
        self.types_mngr = types_mngr

    def updt_expr_types(self, expr_types):
        """Update expr_types
        @expr_types: Dictionnary associating name to type
        """

        self.expr_types = expr_types

    CST = "CST"

    def reduce_id(self, node, _):
        """Reduce ExprId"""
        if not isinstance(node.expr, ExprId):
            return None
        if node.expr.name in self.expr_types:
            objc = self.expr_types[node.expr.name]
            out = (node.expr, objc)
        else:
            out = (node.expr, None)
        return out

    def reduce_int(self, node, _):
        """Reduce ExprInt"""

        if not isinstance(node.expr, ExprInt):
            return None
        return self.CST

    def reduce_op_memberof(self, node, _):
        """Reduce -> operator"""

        if not node.expr.is_op('->'):
            return None
        assert len(node.args) == 2
        out = []
        assert isinstance(node.args[1].expr, ExprId)
        field = node.args[1].expr.name
        src, src_type = node.args[0].info
        assert isinstance(src_type, (ObjCPtr, ObjCArray))
        struct_dst = src_type.objtype
        assert isinstance(struct_dst, ObjCStruct)

        found = False
        for name, objtype, offset, _ in struct_dst.fields:
            if name != field:
                continue
            expr = src + ExprInt(offset, src.size)
            if isinstance(objtype, (ObjCArray, ObjCStruct, ObjCUnion)):
                pass
            else:
                expr = ExprMem(expr, objtype.size * 8)
            assert not found
            found = True
            out = (expr, objtype)
        assert found
        return out

    def reduce_op_field(self, node, _):
        """Reduce field operator (Struct or Union)"""

        if not node.expr.is_op('field'):
            return None
        assert len(node.args) == 2
        out = []
        assert isinstance(node.args[1].expr, ExprId)
        field = node.args[1].expr.name
        src, src_type = node.args[0].info
        struct_dst = src_type

        if isinstance(struct_dst, ObjCStruct):
            found = False
            for name, objtype, offset, _ in struct_dst.fields:
                if name != field:
                    continue
                expr = src + ExprInt(offset, src.size)
                if isinstance(objtype, ObjCArray):
                    # Case 4
                    pass
                elif isinstance(objtype, (ObjCStruct, ObjCUnion)):
                    # Case 1
                    pass
                else:
                    # Case 2
                    expr = ExprMem(expr, objtype.size * 8)
                assert not found
                found = True
                out = (expr, objtype)
        elif isinstance(struct_dst, ObjCUnion):
            found = False
            for name, objtype, offset, _ in struct_dst.fields:
                if name != field:
                    continue
                expr = src + ExprInt(offset, src.size)
                if isinstance(objtype, ObjCArray):
                    # Case 4
                    pass
                elif isinstance(objtype, (ObjCStruct, ObjCUnion)):
                    # Case 1
                    pass
                else:
                    # Case 2
                    expr = ExprMem(expr, objtype.size * 8)
                assert not found
                found = True
                out = (expr, objtype)
        else:
            raise NotImplementedError("unknown ObjC")
        assert found
        return out

    def reduce_op_array(self, node, _):
        """Reduce array operator"""

        if not node.expr.is_op('[]'):
            return None
        assert len(node.args) == 2
        out = []
        assert isinstance(node.args[1].expr, ExprInt)
        cst = node.args[1].expr
        src, src_type = node.args[0].info
        objtype = src_type.objtype
        expr = src + cst * ExprInt(objtype.size, cst.size)
        if isinstance(src_type, ObjCPtr):
            if isinstance(objtype, ObjCArray):
                final = objtype.objtype
                expr = src + cst * ExprInt(final.size, cst.size)
                objtype = final
                expr = ExprMem(expr, final.size * 8)
                found = True
            else:
                expr = ExprMem(expr, objtype.size * 8)
                found = True
        elif isinstance(src_type, ObjCArray):
            if isinstance(objtype, ObjCArray):
                final = objtype
                found = True
            elif isinstance(objtype, ObjCStruct):
                found = True
            else:
                expr = ExprMem(expr, objtype.size * 8)
                found = True
        else:
            raise NotImplementedError("Unknown access" % node.expr)
        assert found
        out = (expr, objtype)
        return out

    def reduce_op_addr(self, node, _):
        """Reduce addr operator"""

        if not node.expr.is_op('addr'):
            return None
        assert len(node.args) == 1
        out = []
        src, src_type = node.args[0].info

        void_type = self.types_mngr.void_ptr

        if isinstance(src_type, ObjCArray):
            out = (src.arg, ObjCPtr(src_type.objtype,
                                    void_type.align, void_type.size))
        elif isinstance(src, ExprMem):
            out = (src.arg, ObjCPtr(src_type,
                                    void_type.align, void_type.size))
        elif isinstance(src_type, ObjCStruct):
            out = (src, ObjCPtr(src_type,
                                void_type.align, void_type.size))
        elif isinstance(src_type, ObjCUnion):
            out = (src, ObjCPtr(src_type,
                                void_type.align, void_type.size))
        else:
            raise NotImplementedError("unk type")
        return out

    def reduce_op_deref(self, node, _):
        """Reduce deref operator"""

        if not node.expr.is_op('deref'):
            return None
        out = []
        src, src_type = node.args[0].info
        assert isinstance(src_type, (ObjCPtr, ObjCArray))
        size = src_type.objtype.size * 8
        out = (ExprMem(src, size), (src_type.objtype))
        return out

    reduction_rules = [reduce_id,
                       reduce_int,
                       reduce_op_memberof,
                       reduce_op_field,
                       reduce_op_array,
                       reduce_op_addr,
                       reduce_op_deref,
                      ]

    def get_expr(self, expr):
        """Translate a Miasm expression @expr (representing a C access) into a
        native Miasm expression and its C type

        @expr: Miasm expression (representing a C access)
        """

        return self.reduce(expr)


class CTypesManager(object):
    """Represent a C object, without any layout information"""

    def __init__(self, types_ast, leaf_types):
        self.types_ast = types_ast
        self.leaf_types = leaf_types

    @property
    def void_ptr(self):
        """Retrieve a void* objc"""
        return self.leaf_types.types.get(CTypePtr(CTypeId('void')))

    @property
    def padding(self):
        """Retrieve a padding ctype"""
        return CTypeId(PADDING_TYPE_NAME)

    def _get_objc(self, type_id, resolved=None, to_fix=None, lvl=0):
        if resolved is None:
            resolved = {}
        if to_fix is None:
            to_fix = []
        if type_id in resolved:
            return resolved[type_id]
        type_id = self.types_ast.get_type(type_id)
        fixed = True
        if isinstance(type_id, CTypeId):
            out = self.leaf_types.types.get(type_id, None)
            assert out is not None
        elif isinstance(type_id, CTypeUnion):
            out = ObjCUnion(type_id.name)
            align_max, size_max = 0, 0
            for name, field in type_id.fields:
                objc = self._get_objc(field, resolved, to_fix, lvl + 1)
                resolved[field] = objc
                align_max = max(align_max, objc.align)
                size_max = max(size_max, objc.size)
                out.add_field(name, objc, 0, objc.size)

            align, size = self.union_compute_align_size(align_max, size_max)
            out.set_align_size(align, size)

        elif isinstance(type_id, CTypeStruct):
            out = ObjCStruct(type_id.name)
            align_max, size_max = 0, 0

            offset, align_max = 0, 1
            pad_index = 0
            for name, field in type_id.fields:
                objc = self._get_objc(field, resolved, to_fix, lvl + 1)
                resolved[field] = objc
                align_max = max(align_max, objc.align)
                new_offset = self.struct_compute_field_offset(objc, offset)
                if new_offset - offset:
                    pad_name = "__PAD__%d__" % pad_index
                    pad_index += 1
                    size = new_offset - offset
                    pad_objc = self._get_objc(CTypeArray(self.padding, size), resolved, to_fix, lvl + 1)
                    out.add_field(pad_name, pad_objc, offset, pad_objc.size)
                offset = new_offset
                out.add_field(name, objc, offset, objc.size)
                offset += objc.size

            align, size = self.struct_compute_align_size(align_max, offset)
            out.set_align_size(align, size)

        elif isinstance(type_id, CTypePtr):
            target = type_id.target
            out = ObjCPtr(None, self.void_ptr.align, self.void_ptr.size)
            fixed = False

        elif isinstance(type_id, CTypeArray):
            target = type_id.target
            objc = self._get_objc(target, resolved, to_fix, lvl + 1)
            resolved[target] = objc
            if type_id.size is None:
                # case: toto[]
                # return ObjCPtr
                out = ObjCPtr(objc, self.void_ptr.align, self.void_ptr.size)
            else:
                size = self.size_to_int(type_id.size)
                if size is None:
                    raise RuntimeError('Enable to compute objc size')
                else:
                    out = ObjCArray(objc, size)
            assert out.size is not None and out.align is not None
        elif isinstance(type_id, CTypeEnum):
            # Enum are integer
            return self.leaf_types.types.get(CTypeId('int'))
        elif isinstance(type_id, CTypeFunc):
            type_ret = self._get_objc(
                type_id.type_ret, resolved, to_fix, lvl + 1)
            resolved[type_id.type_ret] = type_ret
            args = []
            for arg in type_id.args:
                objc = self._get_objc(arg, resolved, to_fix, lvl + 1)
                resolved[arg] = objc
                args.append(objc)
            out = ObjCFunc(type_id.name, type_id.abi, type_ret, args,
                           self.void_ptr.align, self.void_ptr.size)
        elif isinstance(type_id, CTypeEllipsis):
            out = ObjCEllipsis()
        else:
            raise TypeError("Unknown type %r" % type_id.__class__)
        if not isinstance(out, ObjCEllipsis):
            assert out.align is not None and out.size is not None

        if fixed:
            resolved[type_id] = out
        else:
            to_fix.append((type_id, out))
        return out

    def get_objc(self, type_id):
        """Get the ObjC corresponding to the CType @type_id
        @type_id: CTypeBase instance"""
        resolved = {}
        to_fix = []
        out = self._get_objc(type_id, resolved, to_fix)
        # Fix sub objects
        while to_fix:
            type_id, objc_to_fix = to_fix.pop()
            objc = self._get_objc(type_id.target, resolved, to_fix)
            objc_to_fix.objtype = objc
        self.check_objc(out)
        return out

    def check_objc(self, objc, done=None):
        """Ensure each sub ObjC is resolved
        @objc: ObjC instance"""
        if done is None:
            done = set()
        if objc in done:
            return True
        done.add(objc)
        if isinstance(objc, (ObjCDecl, ObjCInt, ObjCEllipsis)):
            return True
        elif isinstance(objc, (ObjCPtr, ObjCArray)):
            assert self.check_objc(objc.objtype, done)
            return True
        elif isinstance(objc, (ObjCStruct, ObjCUnion)):
            for _, field, _, _ in objc.fields:
                assert self.check_objc(field, done)
            return True
        elif isinstance(objc, ObjCFunc):
            assert self.check_objc(objc.type_ret, done)
            for arg in objc.args:
                assert self.check_objc(arg, done)
            return True
        else:
            assert False

    def size_to_int(self, size):
        """Resolve an array size
        @size: CTypeOp or integer"""
        if isinstance(size, CTypeOp):
            assert len(size.args) == 2
            arg0, arg1 = [self.size_to_int(arg) for arg in size.args]
            if size.operator == "+":
                return arg0 + arg1
            elif size.operator == "-":
                return arg0 - arg1
            elif size.operator == "*":
                return arg0 * arg1
            elif size.operator == "/":
                return arg0 / arg1
            elif size.operator == "<<":
                return arg0 << arg1
            elif size.operator == ">>":
                return arg0 >> arg1
            else:
                raise ValueError("Unknown operator %s" % size.operator)
        elif isinstance(size, (int, long)):
            return size
        elif isinstance(size, CTypeSizeof):
            obj = self._get_objc(size.target)
            return obj.size
        else:
            raise TypeError("Unknown size type")

    def struct_compute_field_offset(self, obj, offset):
        """Compute the offset of the field @obj in the current structure"""
        raise NotImplementedError("Abstract method")

    def struct_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current structure"""
        raise NotImplementedError("Abstract method")

    def union_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current union"""
        raise NotImplementedError("Abstract method")


class CTypesManagerNotPacked(CTypesManager):
    """Store defined C types (not packed)"""

    def struct_compute_field_offset(self, obj, offset):
        """Compute the offset of the field @obj in the current structure
        (not packed)"""

        if obj.align > 1:
            offset = (offset + obj.align - 1) & ~(obj.align - 1)
        return offset

    def struct_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current structure
        (not packed)"""
        if align_max > 1:
            size = (size + align_max - 1) & ~(align_max - 1)
        return align_max, size

    def union_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current union
        (not packed)"""
        return align_max, size


class CTypesManagerPacked(CTypesManager):
    """Store defined C types (packed form)"""

    def struct_compute_field_offset(self, _, offset):
        """Compute the offset of the field @obj in the current structure
        (packed form)"""
        return offset

    def struct_compute_align_size(self, _, size):
        """Compute the alignment and size of the current structure
        (packed form)"""
        return 1, size

    def union_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current union
        (packed form)"""
        return 1, size


class CHandler(object):
    """
    C manipulator for Miasm
    Miasm expr <-> C
    """

    exprCToExpr_cls = ExprCToExpr
    cTypeAnalyzer_cls = CTypeAnalyzer
    exprToAccessC_cls = ExprToAccessC

    def __init__(self, types_mngr, expr_types,
                 simplify_c=access_simplifier,
                 enforce_strict_access=True):
        self.exprc2expr = self.exprCToExpr_cls(expr_types, types_mngr)
        self.type_analyzer = self.cTypeAnalyzer_cls(expr_types, types_mngr,
                                                   enforce_strict_access)
        self.access_c_gen = self.exprToAccessC_cls(expr_types,
                                                   types_mngr,
                                                   enforce_strict_access)
        self.simplify_c = simplify_c
        self.expr_types = expr_types

    def updt_expr_types(self, expr_types):
        """Update expr_types
        @expr_types: Dictionnary associating name to type
        """

        self.expr_types = expr_types
        self.exprc2expr.updt_expr_types(expr_types)
        self.type_analyzer.updt_expr_types(expr_types)
        self.access_c_gen.updt_expr_types(expr_types)

    def expr_to_c(self, expr):
        """Convert a Miasm @expr into it's C equivatlent string
        @expr: Miasm expression"""

        expr_access = self.access_c_gen.get_access(expr)
        accesses = [access for access in expr_access.info]
        accesses_simp = [access_str(access.to_expr().visit(self.simplify_c))
                         for access in accesses]
        return accesses_simp

    def expr_to_types(self, expr):
        """Get the possible types of the Miasm @expr
        @expr: Miasm expression"""

        return self.type_analyzer.get_type(expr).info

    def c_to_expr(self, c_str):
        """Convert a C string expression to a Miasm expression
        @c_str: C string"""

        ast = parse_access(c_str)
        access_c = ast_get_c_access_expr(ast, self.expr_types)
        return self.exprc2expr.get_expr(access_c).info[0]

    def c_to_type(self, c_str):
        """Get the type of a C string expression
        @expr: Miasm expression"""

        ast = parse_access(c_str)
        access_c = ast_get_c_access_expr(ast, self.expr_types)
        ret_type = self.exprc2expr.get_expr(access_c).info[1]
        return ret_type


class CLeafTypes(object):
    """Define C types sizes/alignement for a given architecture"""
    pass
