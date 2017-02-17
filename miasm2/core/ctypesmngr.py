from pycparser import c_ast
from miasm2.core.objc import ObjCStruct, ObjCUnion, ObjCDecl, ObjCPtr, \
    ObjCArray, _ObjCRecurse, c_to_ast


def fix_recursive_objects(types_mngr, obj):
    """Replace _ObjCRecurse objects by its parent"""

    void_type = types_mngr.void_ptr

    if isinstance(obj, ObjCStruct):
        for i, (name, fieldtype, offset, size) in enumerate(obj.fields):
            fieldtype = fix_recursive_objects(types_mngr, fieldtype)
            obj.fields[i] = (name, fieldtype, offset, size)
    elif isinstance(obj, ObjCDecl):
        return obj
    elif isinstance(obj, ObjCPtr):
        target_obj = fix_recursive_objects(types_mngr, obj.objtype)
        obj = ObjCPtr(obj.name, target_obj, void_type.align, void_type.size)
    elif isinstance(obj, ObjCArray):
        target_obj = fix_recursive_objects(types_mngr, obj.objtype)
        obj = ObjCArray(target_obj, obj.elems)
    elif isinstance(obj, ObjCUnion):
        for i, (name, fieldtype, offset, size) in enumerate(obj.fields):
            fieldtype = fix_recursive_objects(types_mngr, fieldtype)
            obj.fields[i] = (name, fieldtype, offset, size)
    elif isinstance(obj, _ObjCRecurse):
        obj = types_mngr.get_type((obj.name,))
    else:
        raise NotImplementedError("Unknown type")
    return obj


class CTypesManager(object):
    """Store all defined C types"""

    def __init__(self, knowntypes):
        self._types = dict(knowntypes)
        self.cpt = 0

    def gen_uniq_name(self):
        """Generate uniq name for unamed strucs/union"""
        cpt = self.cpt
        self.cpt += 1
        return "__TYPE_INTERNAL__%d" % cpt

    def add_type(self, type_id, type_obj):
        """Add new C type
        @type_id: Type descriptor
        @type_obj: ObjC* instance"""
        self._types[type_id] = type_obj

    def get_type(self, type_id):
        """Get C type
        @type_id: Type descriptor
        """
        return self._types[type_id]

    def is_known_type(self, type_id):
        """Return true if @type_id is known
        @type_id: Type descriptor
        """
        return type_id in self._types

    def add_c_decl_from_ast(self, ast):
        """
        Adds types from a C ast
        @ast: C ast
        """
        self.ast_parse_declarations(ast)

    def add_c_decl(self, c_str):
        """
        Adds types from a C string types declaring
        Note: will ignore lines containing code refs ie:
        '# 23 "miasm.h"'
        Returns the C ast
        @c_str: C string containing C types declarations
        """
        ast = c_to_ast(c_str)
        self.add_c_decl_from_ast(ast)

        return ast

    @property
    def void_ptr(self):
        """Return the void* type"""
        return self.get_type(('void*',))

    def ast_eval_size(self, ast):
        """Evaluates the size of a C ast object

        @ast: parsed pycparser.c_ast object
        """

        if isinstance(ast, c_ast.TypeDecl):
            result = self.ast_eval_size(ast.type)
        elif isinstance(ast, c_ast.PtrDecl):
            void_type = self.void_ptr
            result = void_type.size
        elif isinstance(ast, c_ast.IdentifierType):
            obj = self.get_type(tuple(ast.names))
            result = obj.size
        else:
            raise NotImplementedError('TODO')
        return result

    def ast_eval_int(self, ast):
        """Eval a C ast object integer

        @ast: parsed pycparser.c_ast object
        """

        if isinstance(ast, c_ast.BinaryOp):
            left = self.ast_eval_int(ast.left)
            right = self.ast_eval_int(ast.right)
            if ast.op == '*':
                result = left * right
            elif ast.op == '/':
                assert left % right == 0
                result = left / right
            elif ast.op == '+':
                result = left + right
            elif ast.op == '-':
                result = left - right
            else:
                raise NotImplementedError("Not implemented!")
        elif isinstance(ast, c_ast.UnaryOp):
            if ast.op == 'sizeof' and isinstance(ast.expr, c_ast.Typename):
                result = self.ast_eval_size(ast.expr.type)
            else:
                raise NotImplementedError("Not implemented!")

        elif isinstance(ast, c_ast.Constant):
            result = int(ast.value, 0)
        elif isinstance(ast, c_ast.Cast):
            # TODO: Can trunc intergers?
            result = self.ast_eval_int(ast.expr)
        else:
            raise NotImplementedError("Not implemented!")
        return result


    def ast_get_align_size(self, ast):
        """Evaluates the size/alignment of a C ast object

        @ast: parsed pycparser.c_ast object
        """

        if isinstance(ast, c_ast.Decl):
            return self.ast_get_align_size(ast.type)
        elif isinstance(ast, c_ast.TypeDecl):
            return self.ast_get_align_size(ast.type)
        elif isinstance(ast, c_ast.IdentifierType):
            assert isinstance(ast, c_ast.IdentifierType)
            names = ast.names
            names = tuple(names)
            if not self.is_known_type(names):
                raise RuntimeError("Unknown type %r" % names)
            obj = self.get_type(names)
        elif isinstance(ast, c_ast.ArrayDecl):
            subobj = self.ast_get_align_size(ast.type)
            dim = ast.dim
            value = self.ast_eval_int(dim)
            obj = ObjCArray(subobj, value)
        elif isinstance(ast, c_ast.Union):
            obj = self.ast_gen_union_align_size(ast)
        elif isinstance(ast, c_ast.Struct):
            obj = self.ast_gen_struct_align_size(ast)
        elif isinstance(ast, c_ast.PtrDecl):
            void_type = self.void_ptr
            subobj = self.ast_get_align_size(ast.type)
            obj = ObjCPtr('noname', subobj, void_type.align, void_type.size)
        else:
            raise NotImplementedError("Not implemented!")
        assert isinstance(obj, _ObjCRecurse) or obj.align in [
            1, 2, 4, 8, 16, 32, 64, 128, 256]
        return obj

    def struct_compute_field_offset(self, obj, offset):
        """Compute the offset of the field @obj in the current structure"""
        raise NotImplementedError("Abstract method")

    def struct_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current structure"""
        raise NotImplementedError("Abstract method")

    def union_compute_align_size(self, align_max, size):
        """Compute the alignment and size of the current union"""
        raise NotImplementedError("Abstract method")

    def ast_gen_struct_align_size(self, ast):
        """Evaluates the size/alignment of a C ast structure
        (default packed)

        @ast: parsed pycparser.c_ast object
        """

        offset = 0
        align_max = 1

        if ast.name is None:
            name = self.gen_uniq_name()
        else:
            name = ast.name
        new_obj = ObjCStruct(name)
        if ast.decls is None:
            # If object is unknown, it's a recursive struct
            if self.is_known_type((name,)):
                obj = self.get_type((name,))
            else:
                obj = _ObjCRecurse(name)
            return obj
        for arg in ast.decls:
            obj = self.ast_get_align_size(arg)
            align_max = max(align_max, obj.align)
            offset = self.struct_compute_field_offset(obj, offset)
            new_obj.add_field(arg.name, obj, offset, obj.size)
            offset += obj.size

        # Structure alignement is its field max alignement
        align, size = self.struct_compute_align_size(align_max, offset)
        new_obj.set_align_size(align, size)
        self.add_type((name, ), new_obj)
        return new_obj

    def ast_gen_union_align_size(self, ast):
        """Evaluates the size/alignment of a C ast union
        @ast: parsed pycparser.c_ast object
        """
        offset = 0
        align_max, size_max = 0, 0

        if ast.name is None:
            name = self.gen_uniq_name()
        else:
            name = ast.name
        new_obj = ObjCUnion(name)

        for arg in ast.decls:
            obj = self.ast_get_align_size(arg)
            align_max = max(align_max, obj.align)
            size_max = max(size_max, obj.size)
            new_obj.add_field(arg.name, obj,
                              offset, obj.size)

        align, size = self.union_compute_align_size(align_max, size_max)
        new_obj.set_align_size(align, size)
        self.add_type((name, ), new_obj)
        return new_obj

    def ast_gen_obj_align_size(self, ast):
        """Evaluates the size/alignment of a C ast struct/union
        (packed style in type manager)

        @ast: parsed pycparser.c_ast object
        """

        if isinstance(ast, c_ast.Struct):
            obj = self.ast_gen_struct_align_size(ast)
        elif isinstance(ast, c_ast.Union):
            obj = self.ast_gen_union_align_size(ast)
        else:
            raise NotImplementedError("Not implemented!")

        fix_recursive_objects(self, obj)
        return obj

    def ast_parse_declarations(self, ast):
        """Add ast types declaration to the type manager
        (packed style in type manager)

        @ast: parsed pycparser.c_ast object
        """

        for ext in ast.ext:
            if isinstance(ext, c_ast.Decl) and\
               ext.name is None and\
               isinstance(ext.type, (c_ast.Struct, c_ast.Union)):
                obj = self.ast_gen_obj_align_size(ext.type)
                self.add_type((ext.type.name, ), obj)

            elif isinstance(ext, c_ast.Typedef) and\
                    isinstance(ext.type.type, (c_ast.Struct, c_ast.Union)) and\
                    not ext.type.type.decls:
                new_type = ext.name
                obj = self.get_type((ext.type.type.name,))
                self.add_type((ext.name,), obj)

            elif isinstance(ext, c_ast.Typedef) and\
                    isinstance(ext.type.type, (c_ast.Struct, c_ast.Union)) and\
                    ext.type.type.decls:
                obj = self.ast_gen_obj_align_size(ext.type.type)
                self.add_type((ext.type.declname, ), obj)

            elif isinstance(ext, c_ast.Typedef) and\
                    isinstance(ext.type, c_ast.TypeDecl) and\
                    isinstance(ext.type.type, c_ast.IdentifierType):
                ext.show()
                names = tuple(ext.type.type.names)
                new_type = ext.name

                if not self.is_known_type(names):
                    raise RuntimeError("Unknown type %s" % repr(names))
                obj = self.get_type(names)
                self.add_type((new_type,), obj)

            elif isinstance(ext, c_ast.Typedef) and\
                    isinstance(ext.type.type, c_ast.Enum) and\
                    isinstance(ext.type.type.values, c_ast.EnumeratorList):
                # Enum are ints
                obj = self.get_type(('enum',))
                self.add_type((ext.name,), obj)

            elif isinstance(ext, c_ast.Typedef) and\
                    isinstance(ext.type, c_ast.ArrayDecl) and\
                    isinstance(ext.type.type.type, c_ast.IdentifierType) and\
                    self.is_known_type(tuple(ext.type.type.type.names)):
                obj = self.get_type(tuple(ext.type.type.type.names))
                array = ext.type

                value = self.ast_eval_int(array.dim)
                subobj = self.ast_get_align_size(array.type)

                obj = ObjCArray(subobj, value)
                self.add_type((ext.name,), obj)

            elif isinstance(ext, c_ast.FuncDef) or\
                    isinstance(ext.type, c_ast.FuncDecl):
                continue
            else:
                raise NotImplementedError("strange type %r" % ext)


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
