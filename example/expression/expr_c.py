"""
Parse C expression to access variables and retrieve information:
* Miasm expression to access this variable
* variable type
"""

from miasm2.core.ctypesmngr import CTypeStruct, CAstTypes, CTypePtr
from miasm2.arch.x86.ctype import CTypeAMD64_unk
from miasm2.core.objc import CTypesManagerNotPacked, CHandler
from miasm2.expression.expression import ExprId


"""
C manipulation example
"""

# Digest C information
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
base_types = CTypeAMD64_unk()
types_ast = CAstTypes()

# Add C types definition
types_ast.add_c_decl(text)

types_mngr = CTypesManagerNotPacked(types_ast, base_types)

# Create the ptr variable with type "struct rectangle*"
ptr_rectangle = types_mngr.get_objc(CTypePtr(CTypeStruct('rectangle')))

ptr = ExprId('ptr', 64)
c_context = {ptr.name: ptr_rectangle}
mychandler = CHandler(types_mngr, {})

# Parse some C accesses
c_acceses = ["ptr->width",
             "ptr->length",
             "ptr->line",
             "ptr->line->color",
             "ptr->line->color[3]",
             "ptr->line->size"
            ]

for c_str in c_acceses:
    expr = mychandler.c_to_expr(c_str, c_context)
    c_type = mychandler.c_to_type(c_str, c_context)
    print 'C access:', c_str
    print '\tExpr:', expr
    print '\tType:', c_type
