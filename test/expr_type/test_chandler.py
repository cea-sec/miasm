"""
Regression test for objc
* ast parsed C to C Miasm expression
* C Miasm expression to native expression
* Miasm expression to type
"""
from __future__ import print_function

from future.utils import viewitems
from past.builtins import cmp
from builtins import str
from miasm.expression.expression import ExprInt, ExprId, ExprMem
from miasm.expression.simplifications import expr_simp

from miasm.core.objc import parse_access
from miasm.core.objc import ast_get_c_access_expr
from miasm.core.objc import ExprCToExpr, ExprToAccessC, CHandler


from miasm.core.ctypesmngr import CTypeStruct, CTypeUnion, CAstTypes, CTypePtr, CTypeId
from miasm.core.objc import CTypesManagerNotPacked

from miasm.arch.x86.ctype import CTypeAMD64_unk


text_1 = """
# 1 "test.h"
typedef enum {
    TMP0,
    TMP1,
    TMP2,
    TMP3,
} MyEnum;


typedef struct mini_st {
        int x;
        int y;
        short z;
} Mini;

typedef union mini_un {
        int x;
        int y;
        short z;
} MiniUnion;

typedef unsigned char block[8];

typedef struct mini_st mini_st_struct;

typedef mini_st_struct mini_st_struct2;


typedef struct test_st {
        int a;
        int b;
        int** ptr;
        short tab1[4*sizeof(int)];
        short* tab2[2*2+4*4-16/4];
        int* xptr;
        int tab3[0x10][0x20];

        Mini f_mini;

        Mini minitab[0x10];

        Mini *minitabptr[0x10];
        int (*(tab4[0x20]))[0x10];
        MyEnum myenum;
        block chunk;

        union testU{
            int  myint;
            char mychars[4];
        } myunion;

        union testV{
            int  myint;
            char mychars[4];
            struct tutu {
                int a;
                unsigned int b;
            } mystruct_x;
        } myunion_x;


        union testW{
            union testX{
                int a;
                unsigned int b;
                char c;
            } u0;
            union testX{
                int a;
                char b;
            } u1;
        } myunion_y;

        union {
            int a1;
        };
        struct {
            int a2;
        };

        Mini (*(tab5[0x20]))[0x10];
        int *tab6[4][4][4][4];

} Test;

typedef int (*func)(int, char);

typedef func (  *(xxx[5])  )[4];

typedef union char_int_st {
    char a;
    int b;
} Char_int;

typedef int array1[4];
typedef int array2[4];
typedef unsigned int array3[4];
typedef Char_int array4[4];

typedef char dummy[((sizeof(char)<<3) >> 1)*4/2 - 1 + 2];

struct recurse {
        struct recurse* next;
        int a;
};

int strlen(const char *s);
    """

text_2 = """
struct test_context {
        int a;
        struct test_st test;
        int b;
};

"""
base_types = CTypeAMD64_unk()
types_ast = CAstTypes()

# Add C types definition
types_ast.add_c_decl(text_1)
types_ast.add_c_decl(text_2)


types_mngr = CTypesManagerNotPacked(types_ast, base_types)

for type_id, type_desc in viewitems(types_mngr.types_ast._types):
    print(type_id)
    obj = types_mngr.get_objc(type_id)
    print(obj)
    print(repr(obj))
    types_mngr.check_objc(obj)

for type_id, type_desc in viewitems(types_mngr.types_ast._typedefs):
    print(type_id)
    obj = types_mngr.get_objc(type_id)
    print(obj)
    print(repr(obj))
    types_mngr.check_objc(obj)

void_ptr = types_mngr.void_ptr

obj_dummy = types_mngr.get_objc(CTypeId("dummy"))
obj_int = types_mngr.get_objc(CTypeId("int"))
obj_uint = types_mngr.get_objc(CTypeId("unsigned", "int"))
obj_long = types_mngr.get_objc(CTypeId("long"))
obj_array1 = types_mngr.get_objc(CTypeId("array1"))
obj_array2 = types_mngr.get_objc(CTypeId("array2"))
obj_array3 = types_mngr.get_objc(CTypeId("array3"))
obj_array4 = types_mngr.get_objc(CTypeId("array4"))

obj_charint = types_mngr.get_objc(CTypeUnion("char_int"))

assert cmp(obj_int, obj_uint) != 0
assert cmp(obj_int, obj_long) != 0

assert cmp(obj_array1, obj_array1) == 0
assert cmp(obj_array1, obj_array2) == 0
assert cmp(obj_array1, obj_array3) != 0
assert cmp(obj_array1, obj_array4) != 0

assert cmp(obj_charint, obj_charint) == 0
assert cmp(obj_charint, obj_uint) != 0

obj_test = types_mngr.get_objc(CTypePtr(CTypeId("Test")))

ptr_test = ExprId("ptr_Test", 64)
obj_recurse = types_mngr.get_objc(CTypePtr(CTypeStruct("recurse")))
# Test cmp same recursive object
obj_recurse_bis = types_mngr.get_objc(CTypePtr(CTypeStruct("recurse")))
assert cmp(obj_recurse, obj_recurse_bis) == 0


set_test = set([obj_recurse, obj_recurse_bis])
assert len(set_test) == 1
ptr_recurse = ExprId("ptr_recurse", 64)


obj_test_st = types_mngr.get_objc(CTypeStruct("test_st"))
print(repr(obj_test_st))
obj_test_context = types_mngr.get_objc(CTypeStruct("test_context"))
print(repr(obj_test_context))
assert obj_test_context.size > obj_test_st.size

assert cmp(obj_test_st, obj_recurse) != 0


expr_types = {ptr_test: set([obj_test]),
              ptr_recurse: set([obj_recurse])}


c_context = {ptr_test.name: obj_test,
             ptr_recurse.name: obj_recurse}


tests = [
    (
        ExprMem(ptr_test, 32),
        [("int", "(ptr_Test)->a")]
    ),
    (
        ptr_test,
        [('struct test_st *', "ptr_Test")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0, 64), 32),
        [("int", "(ptr_Test)->a")]
    ),
    (
        ExprMem(ptr_test + ExprInt(8, 64), 64),
        [("int **", "(ptr_Test)->ptr")]
    ),
    (
        ExprMem(ptr_test + ExprInt(8, 64), 64) + ExprInt(8 * 3, 64),
        [("int **", "&(((ptr_Test)->ptr)[3])")]
    ),
    (
        ExprMem(ExprMem(ptr_test + ExprInt(8, 64), 64) +
                ExprInt(8 * 3, 64), 64),
        [("int *", "((ptr_Test)->ptr)[3]")]
    ),
    (
        ExprMem(
            ExprMem(
                ExprMem(
                    ptr_test + ExprInt(8, 64),
                    64) + ExprInt(8 * 3, 64),
                64) + ExprInt(4 * 9, 64),
            32),
        [("int", "(((ptr_Test)->ptr)[3])[9]")]
    ),
    (
        ptr_test + ExprInt(0x10, 64),
        [("short [16]", "(ptr_Test)->tab1")]
    ),
    (
        ptr_test + ExprInt(0x12, 64),
        [("short *", "&(((ptr_Test)->tab1)[1])")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0x10, 64), 16),
        [("short", "*((ptr_Test)->tab1)")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0x10 + 2 * 3, 64), 16),
        [("short", "((ptr_Test)->tab1)[3]")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0xb8 + 4, 64), 32),
        [("int", "(((ptr_Test)->tab3)[0])[1]")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0xb8 + 32 * 4 * 3 + 4 * 7, 64), 32),
        [("int", "(((ptr_Test)->tab3)[3])[7]")]
    ),
    (
        ptr_test + ExprInt(0xb8 + 4, 64),
        [("int *", "&((((ptr_Test)->tab3)[0])[1])")]
    ),

    # struct of struct
    (
        ptr_test + ExprInt(0x8b8, 64),
        [("struct mini_st *", '&((ptr_Test)->f_mini)')]
    ),
    (
        ptr_test + ExprInt(0x8bc, 64),
        [("int *", "&(((ptr_Test)->f_mini).y)")]
    ),
    (
        ExprMem(ptr_test + ExprInt(0x8bc, 64), 32),
        [("int", "((ptr_Test)->f_mini).y")]
    ),

    # struct of array of struct
    (
        ptr_test + ExprInt(0x8c4, 64),
        [('struct mini_st [16]', '(ptr_Test)->minitab')]
    ),

    (
        ptr_test + ExprInt(0x8c4 + 3 * 4, 64),
        [('struct mini_st *', '&(((ptr_Test)->minitab)[1])')]
    ),

    (
        ExprMem(ptr_test + ExprInt(0x8c4, 64), 32),
        [("int", "((ptr_Test)->minitab)->x")]
    ),

    (
        ExprMem(ptr_test + ExprInt(0x8c4 + 12 * 4, 64), 32),
        [("int", "(((ptr_Test)->minitab)[4]).x")]
    ),


    (
        ExprMem(ptr_test + ExprInt(0x8c4 + 4, 64), 32),
        [("int", "((ptr_Test)->minitab)->y")]
    ),

    (
        ExprMem(ptr_test + ExprInt(0x8c4 + 12 * 4 + 4, 64), 32),
        [("int", "(((ptr_Test)->minitab)[4]).y")]
    ),

    # struct of array of ptr of struct

    (
        ExprMem(ptr_test + ExprInt(0x988 + 8 * 4, 64), 64),
        [('struct mini_st *', "((ptr_Test)->minitabptr)[4]")]
    ),

    (
        ExprMem(
            (ExprMem(ptr_test + ExprInt(0x988 + 8 * 4, 64), 64) +
             ExprInt(8, 64)),
            16),
        [("short", "(((ptr_Test)->minitabptr)[4])->z")]
    ),

    # tab4

    (
        ptr_test + ExprInt(0xa08, 64),
        [("int (*[32])[16]", "(ptr_Test)->tab4")]
    ),

    (
        ExprMem(ptr_test + ExprInt(0xa08 + 0x8 * 2, 64), 64),
        [("int (*)[16]", "((ptr_Test)->tab4)[2]")]
    ),

    (
        ExprMem(ExprMem(ptr_test + ExprInt(0xa08 + 0x8 * 2, 64), 64), 64),
        [("int [16]", "*(((ptr_Test)->tab4)[2])")]
    ),

    (
        ExprMem(ExprMem(ptr_test + ExprInt(0xa08 + 0x8 * 2, 64), 64), 64) + ExprInt(4 * 5, 64),
        [("int *", "&((*(((ptr_Test)->tab4)[2]))[5])")]
    ),

    # enum
    (
        ExprMem(ptr_test + ExprInt(2824, 64), 32),
        [("int", "(ptr_Test)->myenum")]
    ),

    # typedef array
    (
        ExprMem(ptr_test + ExprInt(2828 + 1, 64), 8),
        [("uchar", "((ptr_Test)->chunk)[1]")]
    ),


    # union
    (
        ptr_test + ExprInt(2836, 64),
        [("union testU *", '&((ptr_Test)->myunion)')]
    ),

    (
        ExprMem(ptr_test + ExprInt(2836, 64), 8),
        [("char", "*(((ptr_Test)->myunion).mychars)")]
    ),

    (
        ExprMem(ptr_test + ExprInt(2836 + 1, 64), 8),
        [("char", "(((ptr_Test)->myunion).mychars)[1]")]
    ),

    (
        ExprMem(ptr_test + ExprInt(2836, 64), 32),
        [("int", "((ptr_Test)->myunion).myint")]
    ),

    # union struct
    (
        ExprMem(ptr_test + ExprInt(2840, 64), 8),
        [("char", "*(((ptr_Test)->myunion_x).mychars)")]
    ),

    (
        ExprMem(ptr_test + ExprInt(2840 + 1, 64), 8),
        [("char", "(((ptr_Test)->myunion_x).mychars)[1]")]
    ),

    (
        ExprMem(ptr_test + ExprInt(2840, 64), 32),
        [("int", "((ptr_Test)->myunion_x).myint"),
         ("int", "(((ptr_Test)->myunion_x).mystruct_x).a")]
    ),

    (
        ptr_test + ExprInt(2840, 64),
        [('union testV *', '&((ptr_Test)->myunion_x)')]
    ),


    # union union
    (
        ptr_test + ExprInt(2848, 64),
        [('union testW *', '&((ptr_Test)->myunion_y)')]
    ),

    (
        ExprMem(ptr_test + ExprInt(2848, 64), 32),
        [('int', '(((ptr_Test)->myunion_y).u0).a'),
         ('uint', '(((ptr_Test)->myunion_y).u0).b'),
         ('int', '(((ptr_Test)->myunion_y).u1).a')]
    ),

    # recurse
    (
        ptr_recurse,
        [('struct recurse *', 'ptr_recurse')]
    ),

    (
        ptr_recurse + ExprInt(8, 64),
        [('int *', '&((ptr_recurse)->a)')]
    ),

    (
        ExprMem(ptr_recurse, 64),
        [('struct recurse *', '(ptr_recurse)->next')]
    ),

    (
        ExprMem(ExprMem(ptr_recurse, 64), 64),
        [('struct recurse *', '((ptr_recurse)->next)->next')]
    ),


    (
        ExprMem(ExprMem(ExprMem(ptr_recurse, 64), 64) + ExprInt(8, 64), 32),
        [('int', '(((ptr_recurse)->next)->next)->a')]
    ),



    # tab5

    (
        ptr_test + ExprInt(0xb30, 64),
        [("struct mini_st (*[32])[16]", "(ptr_Test)->tab5")]
    ),

    (
        ExprMem(ptr_test + ExprInt(0xb30 + 0x8 * 2, 64), 64),
        [("struct mini_st (*)[16]", "((ptr_Test)->tab5)[2]")]
    ),

    (
        ExprMem(ExprMem(ptr_test + ExprInt(0xb30 + 0x8 * 2, 64), 64), 64),
        [("struct mini_st [16]", "*(((ptr_Test)->tab5)[2])")]
    ),

    (
        ExprMem(ExprMem(ptr_test + ExprInt(0xb30 + 0x8 * 2, 64), 64), 64) + ExprInt(12*3 + 8, 64),
        [("short *", "&(((*(((ptr_Test)->tab5)[2]))[3]).z)")]
    ),

    (
        ExprMem(ExprMem(ExprMem(ptr_test + ExprInt(0xb30 + 0x8 * 2, 64), 64), 64) +
                ExprInt(12*3 + 8, 64), 16),
        [("short", "((*(((ptr_Test)->tab5)[2]))[3]).z")]
    ),


    # tab 6
    (
        ExprMem(ptr_test + ExprInt(0xc30 + ((((3) * 4 + 2)*4 + 0)*4 + 1)*8, 64), 64),
        [("int *", "(((((ptr_Test)->tab6)[3])[2])[0])[1]")]
    ),

    (
        ExprMem(ExprMem(ptr_test + ExprInt(0xc30 + ((((3) * 4 + 2)*4 + 0)*4 + 1)*8, 64), 64), 32),
        [("int", "*((((((ptr_Test)->tab6)[3])[2])[0])[1])")]
    ),



]

mychandler = CHandler(types_mngr, expr_types=expr_types, C_types=c_context)
exprc2expr = ExprCToExpr(expr_types, types_mngr)
mychandler.updt_expr_types(expr_types)


for (expr, result) in tests:
    print("*" * 80)
    print("Native expr:", expr)
    result = set(result)
    expr_c = mychandler.expr_to_c(expr)
    types = mychandler.expr_to_types(expr)

    target_type = mychandler.expr_to_types(expr)

    access_c_gen = ExprToAccessC(expr_types, types_mngr)
    computed = set()
    for c_str, ctype in mychandler.expr_to_c_and_types(expr):
        print(c_str, ctype)
        computed.add((str(ctype), c_str))
    assert computed == result


    for out_type, out_str in computed:
        parsed_expr = mychandler.c_to_expr(out_str)
        parsed_type = mychandler.c_to_type(out_str)
        print("Access expr:", parsed_expr)
        print("Access type:", parsed_type)

        ast = parse_access(out_str)
        access_c = ast_get_c_access_expr(ast, c_context)
        print("Generated access:", access_c)

        parsed_expr_bis, parsed_type_bis = mychandler.exprc2expr.get_expr(access_c, c_context)
        assert parsed_expr_bis is not None
        assert parsed_expr == parsed_expr_bis
        assert parsed_type == parsed_type_bis

        parsed_expr_3, parsed_type_3 = mychandler.c_to_expr_and_type(out_str)
        assert parsed_expr_3 is not None
        assert parsed_expr == parsed_expr_3
        assert parsed_type == parsed_type_3

        expr_new1 = expr_simp(parsed_expr)
        expr_new2 = expr_simp(expr)
        print("\t", expr_new1)
        assert expr_new1 == expr_new2
