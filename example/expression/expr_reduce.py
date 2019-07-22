from miasm.expression.expression import ExprId, ExprInt, ExprMem
from miasm.expression.expression_reduce import ExprReducer


class StructLookup(ExprReducer):
    """
    ExprReduce example.
    This example retrieve the nature of a given expression
    Input:
    ECX is a pointer on a structure STRUCT_A

    Reduction rules:
    ECX              -> FIELD_A_PTR
    ECX + CST        -> FIELD_A_PTR
    ECX + CST*CST... -> FIELD_A_PTR
    @ECX             -> FIELD_A
    @(ECX + CST)     -> FIELD_A
    """
    CST = "CST"
    FIELD_A_PTR = "FIELD_A_PTR"
    FIELD_A = "FIELD_A"

    def reduce_int(self, node, **kwargs):
        """
        Reduction: int -> CST
        """
        if node.expr.is_int():
            return self.CST
        return None

    def reduce_ptr_struct(self, node, **kwargs):
        """
        Reduction: ECX -> FIELD_A_PTR
        """
        if node.expr.is_id("ECX"):
            return self.FIELD_A_PTR
        return None

    def reduce_ptr_plus_int(self, node, **kwargs):
        """
        Reduction: ECX + CST -> FIELD_A_PTR
        """
        if not node.expr.is_op('+'):
            return None
        if [arg.info for arg in node.args] == [self.FIELD_A_PTR, self.CST]:
            return self.FIELD_A_PTR
        return None

    def reduce_cst_op(self, node, **kwargs):
        """
        Reduction: CST + CST -> CST
        """
        if not node.expr.is_op():
            return None
        if set(arg.info for arg in node.args) == set([self.CST]):
            return self.CST
        return None

    def reduce_at_struct_ptr(self, node, **kwargs):
        """
        Reduction: @FIELD_A_PTR -> FIELD_A
        """
        if not node.expr.is_mem():
            return None
        return self.FIELD_A

    reduction_rules = [reduce_int,
                       reduce_ptr_struct,
                       reduce_ptr_plus_int,
                       reduce_cst_op,
                       reduce_at_struct_ptr
                      ]


def test():
    struct_lookup = StructLookup()

    ptr = ExprId('ECX', 32)
    int4 = ExprInt(4, 32)
    tests = [
        (ptr, StructLookup.FIELD_A_PTR),
        (ptr + int4, StructLookup.FIELD_A_PTR),
        (ptr + int4 * int4, StructLookup.FIELD_A_PTR),
        (ExprMem(ptr, 32), StructLookup.FIELD_A),
        (ExprMem(ptr + int4 * int4, 32), StructLookup.FIELD_A),
    ]

    for expr_in, result in tests:
        assert struct_lookup.reduce(expr_in).info == result


if __name__ == "__main__":
    test()
