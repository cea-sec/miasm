"""
Parse C expression to access variables and retrieve information:
* Miasm expression to access this variable
* variable type
"""

from miasm2.core.ctypesmngr import CTypesManagerNotPacked
from miasm2.arch.x86.ctype import CTypeAMD64_unk
from miasm2.core.objc import CHandler
from miasm2.core.objc import ObjCPtr
from miasm2.expression.expression import ExprId


def test():
    """
    C manipulation example
    """

    # Digest C informations
    text = """
    struct line {
            char color[20];
            int size;
    };

    struct rectangle {
            unsigned int width;
            unsigned int length;
            struct line* line;
    };
    """

    # Type manager for x86 64: structures not packed
    my_types = CTypeAMD64_unk()
    types_mngr = CTypesManagerNotPacked(my_types.types)

    # Add C types definition
    types_mngr.add_c_decl(text)

    # Create the ptr variable with type "struct rectangle*"
    void_ptr = types_mngr.void_ptr
    rectangle = types_mngr.get_type(('rectangle',))
    ptr_rectangle = ObjCPtr('noname', rectangle,
                            void_ptr.align, void_ptr.size)


    ptr = ExprId('ptr', 64)
    expr_types = {ptr.name: ptr_rectangle}

    mychandler = CHandler(types_mngr, expr_types)


    # Parse some C accesses
    c_acceses = ["ptr->width",
                 "ptr->length",
                 "ptr->line",
                 "ptr->line->color",
                 "ptr->line->color[3]",
                 "ptr->line->size"
                ]

    for c_str in c_acceses:
        expr = mychandler.c_to_expr(c_str)
        c_type = mychandler.c_to_type(c_str)
        print 'C access:', c_str
        print '\tExpr:', expr
        print '\tType:', c_type

if __name__ == '__main__':
    test()
