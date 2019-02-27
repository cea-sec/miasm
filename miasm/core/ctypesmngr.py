import re

from pycparser import c_parser, c_ast

RE_HASH_CMT = re.compile(r'^#\s*\d+.*$', flags=re.MULTILINE)

# Ref: ISO/IEC 9899:TC2
# http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1124.pdf


def c_to_ast(parser, c_str):
    """Transform a @c_str into a C ast
    Note: will ignore lines containing code refs ie:
    # 23 "miasm.h"

    @parser: pycparser instance
    @c_str: c string
    """

    new_str = re.sub(RE_HASH_CMT, "", c_str)
    return parser.parse(new_str, filename='<stdin>')


class CTypeBase(object):
    """Object to represent the 3 forms of C type:
    * object types
    * function types
    * incomplete types
    """

    def __init__(self):
        self.__repr = str(self)
        self.__hash = hash(self.__repr)

    @property
    def _typerepr(self):
        return self.__repr

    def __eq__(self, other):
        raise NotImplementedError("Abstract method")

    def __ne__(self, other):
        return not self.__eq__(other)

    def eq_base(self, other):
        """Trivial common equality test"""
        return self.__class__ == other.__class__

    def __hash__(self):
        return self.__hash

    def __repr__(self):
        return self._typerepr


class CTypeId(CTypeBase):
    """C type id:
    int
    unsigned int
    """

    def __init__(self, *names):
        # Type specifier order does not matter
        # so the canonical form is ordered
        self.names = tuple(sorted(names))
        super(CTypeId, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.names))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.names == other.names)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Id:%s>" % ', '.join(self.names)


class CTypeArray(CTypeBase):
    """C type for array:
    typedef int XXX[4];
    """

    def __init__(self, target, size):
        assert isinstance(target, CTypeBase)
        self.target = target
        self.size = size
        super(CTypeArray, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.target, self.size))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.target == other.target and
                self.size == other.size)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Array[%s]:%s>" % (self.size, str(self.target))


class CTypePtr(CTypeBase):
    """C type for pointer:
    typedef int* XXX;
    """

    def __init__(self, target):
        assert isinstance(target, CTypeBase)
        self.target = target
        super(CTypePtr, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.target))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.target == other.target)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Ptr:%s>" % str(self.target)


class CTypeStruct(CTypeBase):
    """C type for structure"""

    def __init__(self, name, fields=None):
        assert name is not None
        self.name = name
        if fields is None:
            fields = ()
        for field_name, field in fields:
            assert field_name is not None
            assert isinstance(field, CTypeBase)
        self.fields = tuple(fields)
        super(CTypeStruct, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.name, self.fields))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.name == other.name and
                self.fields == other.fields)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        out = []
        out.append("<Struct:%s>" % self.name)
        for name, field in self.fields:
            out.append("\t%-10s %s" % (name, field))
        return '\n'.join(out)


class CTypeUnion(CTypeBase):
    """C type for union"""

    def __init__(self, name, fields=None):
        assert name is not None
        self.name = name
        if fields is None:
            fields = []
        for field_name, field in fields:
            assert field_name is not None
            assert isinstance(field, CTypeBase)
        self.fields = tuple(fields)
        super(CTypeUnion, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.name, self.fields))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.name == other.name and
                self.fields == other.fields)

    def __str__(self):
        out = []
        out.append("<Union:%s>" % self.name)
        for name, field in self.fields:
            out.append("\t%-10s %s" % (name, field))
        return '\n'.join(out)


class CTypeEnum(CTypeBase):
    """C type for enums"""

    def __init__(self, name):
        self.name = name
        super(CTypeEnum, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.name))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.name == other.name)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Enum:%s>" % self.name


class CTypeFunc(CTypeBase):
    """C type for enums"""

    def __init__(self, name, abi=None, type_ret=None, args=None):
        if type_ret:
            assert isinstance(type_ret, CTypeBase)
        if args:
            for arg_name, arg in args:
                assert isinstance(arg, CTypeBase)
            args = tuple(args)
        else:
            args = tuple()
        self.name = name
        self.abi = abi
        self.type_ret = type_ret
        self.args = args
        super(CTypeFunc, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.name, self.abi,
                     self.type_ret, self.args))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.name == other.name and
                self.abi == other.abi and
                self.type_ret == other.type_ret and
                self.args == other.args)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Func:%s (%s) %s(%s)>" % (self.type_ret,
                                          self.abi,
                                          self.name,
                                          ", ".join(["%s %s" % (name, arg) for (name, arg) in self.args]))


class CTypeEllipsis(CTypeBase):
    """C type for ellipsis argument (...)"""

    def __hash__(self):
        return hash((self.__class__))

    def __eq__(self, other):
        return self.eq_base(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Ellipsis>"


class CTypeSizeof(CTypeBase):
    """C type for sizeof"""

    def __init__(self, target):
        self.target = target
        super(CTypeSizeof, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.target))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.target == other.target)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "<Sizeof(%s)>" % self.target


class CTypeOp(CTypeBase):
    """C type for operator (+ * ...)"""

    def __init__(self, operator, *args):
        self.operator = operator
        self.args = tuple(args)
        super(CTypeOp, self).__init__()

    def __hash__(self):
        return hash((self.__class__, self.operator, self.args))

    def __eq__(self, other):
        return (self.eq_base(other) and
                self.operator == other.operator and
                self.args == other.args)

    def __str__(self):
        return "<CTypeOp(%s, %s)>" % (self.operator,
                                      ', '.join([str(arg) for arg in self.args]))


class FuncNameIdentifier(c_ast.NodeVisitor):
    """Visit an c_ast to find IdentifierType"""

    def __init__(self):
        super(FuncNameIdentifier, self).__init__()
        self.node_name = None

    def visit_TypeDecl(self, node):
        """Retrieve the name in a function declaration:
        Only one IdentifierType is present"""
        self.node_name = node


class CAstTypes(object):
    """Store all defined C types and typedefs"""
    INTERNAL_PREFIX = "__GENTYPE__"
    ANONYMOUS_PREFIX = "__ANONYMOUS__"

    def __init__(self, knowntypes=None, knowntypedefs=None):
        if knowntypes is None:
            knowntypes = {}
        if knowntypedefs is None:
            knowntypedefs = {}

        self._types = dict(knowntypes)
        self._typedefs = dict(knowntypedefs)
        self.cpt = 0
        self.loc_to_decl_info = {}
        self.parser = c_parser.CParser()
        self._cpt_decl = 0


        self.ast_to_typeid_rules = {
            c_ast.Struct: self.ast_to_typeid_struct,
            c_ast.Union: self.ast_to_typeid_union,
            c_ast.IdentifierType: self.ast_to_typeid_identifiertype,
            c_ast.TypeDecl: self.ast_to_typeid_typedecl,
            c_ast.Decl: self.ast_to_typeid_decl,
            c_ast.Typename: self.ast_to_typeid_typename,
            c_ast.FuncDecl: self.ast_to_typeid_funcdecl,
            c_ast.Enum: self.ast_to_typeid_enum,
            c_ast.PtrDecl: self.ast_to_typeid_ptrdecl,
            c_ast.EllipsisParam: self.ast_to_typeid_ellipsisparam,
            c_ast.ArrayDecl: self.ast_to_typeid_arraydecl,
        }

        self.ast_parse_rules = {
            c_ast.Struct: self.ast_parse_struct,
            c_ast.Union: self.ast_parse_union,
            c_ast.Typedef: self.ast_parse_typedef,
            c_ast.TypeDecl: self.ast_parse_typedecl,
            c_ast.IdentifierType: self.ast_parse_identifiertype,
            c_ast.Decl: self.ast_parse_decl,
            c_ast.PtrDecl: self.ast_parse_ptrdecl,
            c_ast.Enum: self.ast_parse_enum,
            c_ast.ArrayDecl: self.ast_parse_arraydecl,
            c_ast.FuncDecl: self.ast_parse_funcdecl,
            c_ast.FuncDef: self.ast_parse_funcdef,
            c_ast.Pragma: self.ast_parse_pragma,
        }

    def gen_uniq_name(self):
        """Generate uniq name for unnamed strucs/union"""
        cpt = self.cpt
        self.cpt += 1
        return self.INTERNAL_PREFIX + "%d" % cpt

    def gen_anon_name(self):
        """Generate name for anonymous strucs/union"""
        cpt = self.cpt
        self.cpt += 1
        return self.ANONYMOUS_PREFIX + "%d" % cpt

    def is_generated_name(self, name):
        """Return True if the name is internal"""
        return name.startswith(self.INTERNAL_PREFIX)

    def is_anonymous_name(self, name):
        """Return True if the name is anonymous"""
        return name.startswith(self.ANONYMOUS_PREFIX)

    def add_type(self, type_id, type_obj):
        """Add new C type
        @type_id: Type descriptor (CTypeBase instance)
        @type_obj: Obj* instance"""
        assert isinstance(type_id, CTypeBase)
        if type_id in self._types:
            assert self._types[type_id] == type_obj
        else:
            self._types[type_id] = type_obj

    def add_typedef(self, type_new, type_src):
        """Add new typedef
        @type_new: CTypeBase instance of the new type name
        @type_src: CTypeBase instance of the target type"""
        assert isinstance(type_src, CTypeBase)
        self._typedefs[type_new] = type_src

    def get_type(self, type_id):
        """Get ObjC corresponding to the @type_id
        @type_id: Type descriptor (CTypeBase instance)
        """
        assert isinstance(type_id, CTypeBase)
        if isinstance(type_id, CTypePtr):
            subobj = self.get_type(type_id.target)
            return CTypePtr(subobj)
        if type_id in self._types:
            return self._types[type_id]
        elif type_id in self._typedefs:
            return self.get_type(self._typedefs[type_id])
        return type_id

    def is_known_type(self, type_id):
        """Return true if @type_id is known
        @type_id: Type descriptor (CTypeBase instance)
        """
        if isinstance(type_id, CTypePtr):
            return self.is_known_type(type_id.target)
        if type_id in self._types:
            return True
        if type_id in self._typedefs:
            return self.is_known_type(self._typedefs[type_id])
        return False

    def add_c_decl_from_ast(self, ast):
        """
        Adds types from a C ast
        @ast: C ast
        """
        self.ast_parse_declarations(ast)


    def digest_decl(self, c_str):

        char_id = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"


        # Seek deck
        index_decl = []
        index = 0
        for decl in ['__cdecl__', '__stdcall__']:
            index = 0
            while True:
                index = c_str.find(decl, index)
                if index == -1:
                    break
                decl_off = index
                decl_len = len(decl)

                index = index+len(decl)
                while c_str[index] not in char_id:
                    index += 1

                id_start = index

                while c_str[index] in char_id:
                    index += 1
                id_stop = index

                name = c_str[id_start:id_stop]
                index_decl.append((decl_off, decl_len, id_start, id_stop, decl, ))

        index_decl.sort()

        # Remove decl
        off = 0
        offsets = []
        for decl_off, decl_len, id_start, id_stop, decl in index_decl:
            decl_off -= off
            c_str = c_str[:decl_off] + c_str[decl_off+decl_len:]
            off += decl_len
            offsets.append((id_start-off, id_stop-off, decl))

        index = 0
        lineno = 1

        # Index to lineno, column
        for id_start, id_stop, decl in offsets:
            nbr = c_str.count('\n', index, id_start)
            lineno += nbr
            last_cr = c_str.rfind('\n', 0, id_start)
            # column starts at 1
            column = id_start - last_cr
            index = id_start
            self.loc_to_decl_info[(lineno, column)] = decl
        return c_str


    def add_c_decl(self, c_str):
        """
        Adds types from a C string types declaring
        Note: will ignore lines containing code refs ie:
        '# 23 "miasm.h"'
        Returns the C ast
        @c_str: C string containing C types declarations
        """
        c_str = self.digest_decl(c_str)

        ast = c_to_ast(self.parser, c_str)
        self.add_c_decl_from_ast(ast)

        return ast

    def ast_eval_int(self, ast):
        """Eval a C ast object integer

        @ast: parsed pycparser.c_ast object
        """

        if isinstance(ast, c_ast.BinaryOp):
            left = self.ast_eval_int(ast.left)
            right = self.ast_eval_int(ast.right)
            is_pure_int = (isinstance(left, int) and
                           isinstance(right, int))

            if is_pure_int:
                if ast.op == '*':
                    result = left * right
                elif ast.op == '/':
                    assert left % right == 0
                    result = left // right
                elif ast.op == '+':
                    result = left + right
                elif ast.op == '-':
                    result = left - right
                elif ast.op == '<<':
                    result = left << right
                elif ast.op == '>>':
                    result = left >> right
                else:
                    raise NotImplementedError("Not implemented!")
            else:
                result = CTypeOp(ast.op, left, right)

        elif isinstance(ast, c_ast.UnaryOp):
            if ast.op == 'sizeof' and isinstance(ast.expr, c_ast.Typename):
                subobj = self.ast_to_typeid(ast.expr)
                result = CTypeSizeof(subobj)
            else:
                raise NotImplementedError("Not implemented!")

        elif isinstance(ast, c_ast.Constant):
            result = int(ast.value, 0)
        elif isinstance(ast, c_ast.Cast):
            # TODO: Can trunc integers?
            result = self.ast_eval_int(ast.expr)
        else:
            raise NotImplementedError("Not implemented!")
        return result

    def ast_to_typeid_struct(self, ast):
        """Return the CTypeBase of an Struct ast"""
        name = self.gen_uniq_name() if ast.name is None else ast.name
        args = []
        if ast.decls:
            for arg in ast.decls:
                if arg.name is None:
                    arg_name = self.gen_anon_name()
                else:
                    arg_name = arg.name
                args.append((arg_name, self.ast_to_typeid(arg)))
        decl = CTypeStruct(name, args)
        return decl

    def ast_to_typeid_union(self, ast):
        """Return the CTypeBase of an Union ast"""
        name = self.gen_uniq_name() if ast.name is None else ast.name
        args = []
        if ast.decls:
            for arg in ast.decls:
                if arg.name is None:
                    arg_name = self.gen_anon_name()
                else:
                    arg_name = arg.name
                args.append((arg_name, self.ast_to_typeid(arg)))
        decl = CTypeUnion(name, args)
        return decl

    def ast_to_typeid_identifiertype(self, ast):
        """Return the CTypeBase of an IdentifierType ast"""
        return CTypeId(*ast.names)

    def ast_to_typeid_typedecl(self, ast):
        """Return the CTypeBase of a TypeDecl ast"""
        return self.ast_to_typeid(ast.type)

    def ast_to_typeid_decl(self, ast):
        """Return the CTypeBase of a Decl ast"""
        return self.ast_to_typeid(ast.type)

    def ast_to_typeid_typename(self, ast):
        """Return the CTypeBase of a TypeName ast"""
        return self.ast_to_typeid(ast.type)

    def get_funcname(self, ast):
        """Return the name of a function declaration ast"""
        funcnameid = FuncNameIdentifier()
        funcnameid.visit(ast)
        node_name = funcnameid.node_name
        if node_name.coord is not None:
            lineno, column = node_name.coord.line, node_name.coord.column
            decl_info = self.loc_to_decl_info.get((lineno, column), None)
        else:
            decl_info = None
        return node_name.declname, decl_info

    def ast_to_typeid_funcdecl(self, ast):
        """Return the CTypeBase of an FuncDecl ast"""
        type_ret = self.ast_to_typeid(ast.type)
        name, decl_info = self.get_funcname(ast.type)
        if ast.args:
            args = []
            for arg in ast.args.params:
                typeid = self.ast_to_typeid(arg)
                if isinstance(typeid, CTypeEllipsis):
                    arg_name = None
                else:
                    arg_name = arg.name
                args.append((arg_name, typeid))
        else:
            args = []

        obj = CTypeFunc(name, decl_info, type_ret, args)
        decl = CTypeFunc(name)
        if not self.is_known_type(decl):
            self.add_type(decl, obj)
        return obj

    def ast_to_typeid_enum(self, ast):
        """Return the CTypeBase of an Enum ast"""
        name = self.gen_uniq_name() if ast.name is None else ast.name
        return CTypeEnum(name)

    def ast_to_typeid_ptrdecl(self, ast):
        """Return the CTypeBase of a PtrDecl ast"""
        return CTypePtr(self.ast_to_typeid(ast.type))

    def ast_to_typeid_ellipsisparam(self, _):
        """Return the CTypeBase of an EllipsisParam ast"""
        return CTypeEllipsis()

    def ast_to_typeid_arraydecl(self, ast):
        """Return the CTypeBase of an ArrayDecl ast"""
        target = self.ast_to_typeid(ast.type)
        if ast.dim is None:
            value = None
        else:
            value = self.ast_eval_int(ast.dim)
        return CTypeArray(target, value)

    def ast_to_typeid(self, ast):
        """Return the CTypeBase of the @ast
        @ast: pycparser.c_ast instance"""
        cls = ast.__class__
        if not cls in self.ast_to_typeid_rules:
            raise NotImplementedError("Strange type %r" % ast)
        return self.ast_to_typeid_rules[cls](ast)

    # Ast parse type declarators

    def ast_parse_decl(self, ast):
        """Parse ast Decl"""
        return self.ast_parse_declaration(ast.type)

    def ast_parse_typedecl(self, ast):
        """Parse ast Typedecl"""
        return self.ast_parse_declaration(ast.type)

    def ast_parse_struct(self, ast):
        """Parse ast Struct"""
        obj = self.ast_to_typeid(ast)
        if ast.decls and ast.name is not None:
            # Add struct to types if named
            decl = CTypeStruct(ast.name)
            if not self.is_known_type(decl):
                self.add_type(decl, obj)
        return obj

    def ast_parse_union(self, ast):
        """Parse ast Union"""
        obj = self.ast_to_typeid(ast)
        if ast.decls and ast.name is not None:
            # Add union to types if named
            decl = CTypeUnion(ast.name)
            if not self.is_known_type(decl):
                self.add_type(decl, obj)
        return obj

    def ast_parse_typedef(self, ast):
        """Parse ast TypeDef"""
        decl = CTypeId(ast.name)
        obj = self.ast_parse_declaration(ast.type)
        if (isinstance(obj, (CTypeStruct, CTypeUnion)) and
                self.is_generated_name(obj.name)):
            # Add typedef name to default name
            # for a question of clarity
            obj.name += "__%s" % ast.name
        self.add_typedef(decl, obj)
        # Typedef does not return any object
        return None

    def ast_parse_identifiertype(self, ast):
        """Parse ast IdentifierType"""
        return CTypeId(*ast.names)

    def ast_parse_ptrdecl(self, ast):
        """Parse ast PtrDecl"""
        return CTypePtr(self.ast_parse_declaration(ast.type))

    def ast_parse_enum(self, ast):
        """Parse ast Enum"""
        return self.ast_to_typeid(ast)

    def ast_parse_arraydecl(self, ast):
        """Parse ast ArrayDecl"""
        return self.ast_to_typeid(ast)

    def ast_parse_funcdecl(self, ast):
        """Parse ast FuncDecl"""
        return self.ast_to_typeid(ast)

    def ast_parse_funcdef(self, ast):
        """Parse ast FuncDef"""
        return self.ast_to_typeid(ast.decl)

    def ast_parse_pragma(self, _):
        """Prama does not return any object"""
        return None

    def ast_parse_declaration(self, ast):
        """Add one ast type declaration to the type manager
        (packed style in type manager)

        @ast: parsed pycparser.c_ast object
        """
        cls = ast.__class__
        if not cls in self.ast_parse_rules:
            raise NotImplementedError("Strange declaration %r" % cls)
        return self.ast_parse_rules[cls](ast)

    def ast_parse_declarations(self, ast):
        """Add ast types declaration to the type manager
        (packed style in type manager)

        @ast: parsed pycparser.c_ast object
        """
        for ext in ast.ext:
            ret = self.ast_parse_declaration(ext)

    def parse_c_type(self, c_str):
        """Parse a C string representing a C type and return the associated
        Miasm C object.
        @c_str: C string of a C type
        """

        new_str = "%s __MIASM_INTERNAL_%s;" % (c_str, self._cpt_decl)
        ret = self.parser.cparser.parse(input=new_str, lexer=self.parser.clex)
        self._cpt_decl += 1
        return ret
