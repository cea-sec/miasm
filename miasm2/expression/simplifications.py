#                                                                              #
#                     Simplification methods library                           #
#                                                                              #

from miasm2.expression import simplifications_common
from miasm2.expression import simplifications_cond
from miasm2.expression.expression_helper import fast_unify
import miasm2.expression.expression as m2_expr

# Expression Simplifier
# ---------------------


class ExpressionSimplifier(object):

    """Wrapper on expression simplification passes.

    Instance handle passes lists.

    Available passes lists are:
     - commons: common passes such as constant folding
     - heavy  : rare passes (for instance, in case of obfuscation)
    """

    # Common passes
    PASS_COMMONS = {
        m2_expr.ExprOp: [simplifications_common.simp_cst_propagation,
                         simplifications_common.simp_cond_op_int,
                         simplifications_common.simp_cond_factor],
        m2_expr.ExprSlice: [simplifications_common.simp_slice],
        m2_expr.ExprCompose: [simplifications_common.simp_compose],
        m2_expr.ExprCond: [simplifications_common.simp_cond],
    }

    # Heavy passes
    PASS_HEAVY = {}

    # Cond passes
    PASS_COND = {m2_expr.ExprSlice: [simplifications_cond.expr_simp_inf_signed,
                                     simplifications_cond.expr_simp_inf_unsigned_inversed],
                 m2_expr.ExprOp: [simplifications_cond.exec_inf_unsigned,
                                  simplifications_cond.exec_inf_signed,
                                  simplifications_cond.expr_simp_inverse,
                                  simplifications_cond.exec_equal],
                 m2_expr.ExprCond: [simplifications_cond.expr_simp_equal]
                 }


    def __init__(self):
        self.expr_simp_cb = {}

    def enable_passes(self, passes):
        """Add passes from @passes
        @passes: dict(Expr class : list(callback))

        Callback signature: Expr callback(ExpressionSimplifier, Expr)
        """

        for k, v in passes.items():
            self.expr_simp_cb[k] = fast_unify(self.expr_simp_cb.get(k, []) + v)

    def apply_simp(self, expression):
        """Apply enabled simplifications on expression
        @expression: Expr instance
        Return an Expr instance"""

        cls = expression.__class__
        for simp_func in self.expr_simp_cb.get(cls, []):
            # Apply simplifications
            expression = simp_func(self, expression)

            # If class changes, stop to prevent wrong simplifications
            if expression.__class__ is not cls:
                break

        return expression

    def expr_simp(self, expression):
        """Apply enabled simplifications on expression and find a stable state
        @expression: Expr instance
        Return an Expr instance"""

        if expression.is_simp:
            return expression

        # Find a stable state
        while True:
            # Canonize and simplify
            e_new = self.apply_simp(expression.canonize())
            if e_new == expression:
                break

            # Launch recursivity
            expression = self.expr_simp_wrapper(e_new)
            expression.is_simp = True

        # Mark expression as simplified
        e_new.is_simp = True
        return e_new

    def expr_simp_wrapper(self, expression, callback=None):
        """Apply enabled simplifications on expression
        @expression: Expr instance
        @manual_callback: If set, call this function instead of normal one
        Return an Expr instance"""

        if expression.is_simp:
            return expression

        if callback is None:
            callback = self.expr_simp

        return expression.visit(callback, lambda e: not(e.is_simp))

    def __call__(self, expression, callback=None):
        "Wrapper on expr_simp_wrapper"
        return self.expr_simp_wrapper(expression, callback)


# Public ExprSimplificationPass instance with commons passes
expr_simp = ExpressionSimplifier()
expr_simp.enable_passes(ExpressionSimplifier.PASS_COMMONS)
