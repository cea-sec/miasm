"""
C helper for Miasm:
* raw C to Miasm expression
* Miasm expression to raw C
* Miasm expression to C type
"""

import re

from pycparser import c_parser, c_ast

from miasm2.expression.expression_reduce import ExprReducer
from miasm2.expression.expression import ExprInt, ExprId, ExprOp, ExprMem

RE_HASH_CMT = re.compile(r'^#\s*\d+.*$', flags=re.MULTILINE)


class ObjC(object):
    """Generic ObjC"""

    def set_align_size(self, align, size):
        """Set C object alignment and size"""

        self.align = align
        self.size = size


class ObjCDecl(ObjC):
    """C Declaration identified"""

    def __init__(self, name, align, size):
        super(ObjCDecl, self).__init__()
        self.name, self.align, self.size = name, align, size

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.name)


class ObjCInt(ObjC):
    """C integer"""

    def __init__(self):
        super(ObjCInt, self).__init__()
        self.size = None
        self.align = None


class ObjCPtr(ObjC):
    """C Pointer"""

    def __init__(self, name, objtype, void_p_align, void_p_size):
        """Init ObjCPtr

        @name: object name
        @objtype: pointer target ObjC
        @void_p_align: pointer alignment (in bytes)
        @void_p_size: pointer size (in bytes)
        """

        super(ObjCPtr, self).__init__()
        self.name, self.objtype = name, objtype
        self.align = void_p_align
        self.size = void_p_size

    def __repr__(self):
        return '<PTR %r>' % (self.objtype)

    def __str__(self):
        return '<PTR %r>' % (self.objtype)


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


class _ObjCRecurse(ObjC):
    """Special C object array, used in recursive declarations. Used in parser
    *only*: this object is not intend to be in final objects
    """

    def __init__(self, name):
        super(_ObjCRecurse, self).__init__()
        self.name = name

    def __repr__(self):
        return '<%r>' % (self.name)


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
        return '<%s %s>' % (self.__class__.__name__, self.name)

    def __str__(self):
        out = []
        out.append("Struct %s: (align: %d)" % (self.name, self.align))
        out.append("  off sz  name")
        for name, objtype, offset, size in self.fields:
            out.append("  %-3d %-3d %-10s %r" % (offset, size, name, objtype))
        return '\n'.join(out)


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
        return '<%s %s>' % (self.__class__.__name__, self.name)

    def __str__(self):
        out = []
        out.append("Union %s: (align: %d)" % (self.name, self.align))
        out.append("  off sz  name")
        for name, objtype, offset, size in self.fields:
            out.append("  %-3d %-3d %-10s %r" % (offset, size, name, objtype))
        return '\n'.join(out)


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
            ctype = ObjCPtr(field, fieldtype, void_p_align, void_p_size)
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
            return ExprOp("field", self.struct.to_expr(), ExprId(self.field, self.default_size))
        elif isinstance(self.ctype, ObjCPtr):
            return ExprOp("addr", ExprOp("field", self.struct.to_expr(), ExprId(self.field, self.default_size)))
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
            ctype = ObjCPtr('noname', ctype.objtype, void_p_align, void_p_size)
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
            return ExprOp("addr", ExprOp("[]", self.name.to_expr(), ExprInt(self.element, self.default_size)))
        elif isinstance(self.ctype, ObjCArray):
            return ExprOp("[]", self.name.to_expr(), ExprInt(self.element, self.default_size))
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


def c_to_ast(c_str):
    """Transform a @c_str into a C ast
    Note: will ignore lines containing code refs ie:
    # 23 "miasm.h"
    """

    new_str = re.sub(RE_HASH_CMT, "", c_str)
    parser = c_parser.CParser()
    return parser.parse(new_str, filename='<stdin>')



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

    def __init__(self, expr_types, types_mngr):
        """Init TypeAnalyzer
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
                obj = ObjCPtr('noname', base_type,
                              void_type.align, void_type.size)
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
            if offset != 0:
                return []
            obj = ObjCPtr('noname', base_type, void_type.align, void_type.size)

            new_type = [obj]
        elif isinstance(base_type, ObjCUnion):
            out = []
            if offset == 0 and not deref:
                # In this case, return the struct*
                obj = ObjCPtr('noname', base_type,
                              void_type.align, void_type.size)
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
            obj = ObjCPtr('noname', base_type, void_type.align, void_type.size)
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

    def reduce_ptr_plus_cst(self, node, lvl):
        """Get type of ptr + CST"""

        if not (isinstance(node.expr, ExprOp) and
                node.expr.op == "+" and
                len(node.args) == 2 and
                set(type(x) for x in node.args[0].info + node.args[1].info) == set([ObjCInt, ObjCPtr])):
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

        if not (isinstance(node.expr, ExprOp) and
                node.expr.op == "+" and
                set(type(x) for x in node.args[0].info + node.args[1].info) == set([ObjCInt])):
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
                if r_target.size != node.expr.size / 8:
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

            if elem_num == 0:
                if self.enforce_strict_access:
                    assert offset % base_type.size == 0
                nobj = CGenArray(cgenobj, elem_num,
                                 void_type.align, void_type.size)
                new_type = [(nobj)]
            else:
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

        out = CGenId(self.expr_types[node.expr.name], node.expr.name)
        return [out]

    def reduce_int(self, node, _):
        """Generate access for ExprInt"""

        if not isinstance(node.expr, ExprInt):
            return None
        return [CGenInt(int(node.expr))]

    def reduce_op(self, node, lvl):
        """Generate access for ExprOp"""

        if not (isinstance(node.expr, ExprOp) and
                node.expr.op == "+" and
                len(node.args) == 2 and
                set(type(x.ctype) for x in node.args[0].info + node.args[1].info) == set([ObjCInt, ObjCPtr])):
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

        assert isinstance(node.arg.info, list)
        found = []
        for subcgenobj in node.arg.info:
            assert isinstance(subcgenobj.ctype, ObjCPtr)
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
            out = (node.expr, self.expr_types[node.expr.name])
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
            out = (src.arg, ObjCPtr('noname', src_type.objtype,
                                    void_type.align, void_type.size))
        elif isinstance(src, ExprMem):
            out = (src.arg, ObjCPtr('noname', src_type,
                                    void_type.align, void_type.size))
        elif isinstance(src_type, ObjCStruct):
            out = (src, ObjCPtr('noname', src_type,
                                void_type.align, void_type.size))
        elif isinstance(src_type, ObjCUnion):
            out = (src, ObjCPtr('noname', src_type,
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
        self.type_analyzer = self.cTypeAnalyzer_cls(expr_types, types_mngr)
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


class CTypeTemplate(object):
    """Define C types sizes/alignement for a given architecture"""
    pass
