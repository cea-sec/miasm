#                                                                              #
#                     Simplification methods library                           #
#                                                                              #

import logging

from miasm2.expression import simplifications_common
from miasm2.expression import simplifications_cond
from miasm2.expression import simplifications_explicit
from miasm2.expression.expression_helper import fast_unify
import miasm2.expression.expression as m2_expr

# Expression Simplifier
# ---------------------

log_exprsimp = logging.getLogger("exprsimp")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_exprsimp.addHandler(console_handler)
log_exprsimp.setLevel(logging.WARNING)


class ExpressionSimplifier(object):

    """Wrapper on expression simplification passes.

    Instance handle passes lists.

    Available passes lists are:
     - commons: common passes such as constant folding
     - heavy  : rare passes (for instance, in case of obfuscation)
    """

    # Common passes
    PASS_COMMONS = {
        m2_expr.ExprOp: [
            simplifications_common.simp_cst_propagation,
            simplifications_common.simp_cond_op_int,
            simplifications_common.simp_cond_factor,
            # CC op
            simplifications_common.simp_cc_conds,
            simplifications_common.simp_subwc_cf,
            simplifications_common.simp_subwc_of,
            simplifications_common.simp_sign_subwc_cf,
            simplifications_common.simp_double_zeroext,
            simplifications_common.simp_double_signext,
            simplifications_common.simp_zeroext_eq_cst,

        ],

        m2_expr.ExprSlice: [simplifications_common.simp_slice],
        m2_expr.ExprCompose: [simplifications_common.simp_compose],
        m2_expr.ExprCond: [
            simplifications_common.simp_cond,
            # CC op
            simplifications_common.simp_cond_flag,
            simplifications_common.simp_cond_int,
            simplifications_common.simp_cmp_int_arg,

            simplifications_common.simp_cond_eq_zero,

        ],
        m2_expr.ExprMem: [simplifications_common.simp_mem],

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


    # Available passes lists are:
    #  - highlevel: transform high level operators to explicit computations
    PASS_HIGH_TO_EXPLICIT = {
        m2_expr.ExprOp: [
            simplifications_explicit.simp_flags,
            simplifications_explicit.simp_ext,
        ],
    }


    def __init__(self):
        self.expr_simp_cb = {}
        self.simplified_exprs = set()

    def enable_passes(self, passes):
        """Add passes from @passes
        @passes: dict(Expr class : list(callback))

        Callback signature: Expr callback(ExpressionSimplifier, Expr)
        """

        # Clear cache of simplifiied expressions when adding a new pass
        self.simplified_exprs.clear()

        for k, v in passes.items():
            self.expr_simp_cb[k] = fast_unify(self.expr_simp_cb.get(k, []) + v)

    def apply_simp(self, expression):
        """Apply enabled simplifications on expression
        @expression: Expr instance
        Return an Expr instance"""

        cls = expression.__class__
        debug_level = log_exprsimp.level >= logging.DEBUG
        for simp_func in self.expr_simp_cb.get(cls, []):
            # Apply simplifications
            before = expression
            expression = simp_func(self, expression)
            after = expression

            if debug_level and before != after:
                log_exprsimp.debug("[%s] %s => %s", simp_func, before, after)

            # If class changes, stop to prevent wrong simplifications
            if expression.__class__ is not cls:
                break

        return expression

    def expr_simp(self, expression):
        """Apply enabled simplifications on expression and find a stable state
        @expression: Expr instance
        Return an Expr instance"""

        if expression in self.simplified_exprs:
            return expression

        # Find a stable state
        while True:
            # Canonize and simplify
            e_new = self.apply_simp(expression.canonize())
            if e_new == expression:
                break

            # Launch recursivity
            expression = self.expr_simp_wrapper(e_new)
            self.simplified_exprs.add(expression)
        # Mark expression as simplified
        self.simplified_exprs.add(e_new)

        return e_new

    def expr_simp_wrapper(self, expression, callback=None):
        """Apply enabled simplifications on expression
        @expression: Expr instance
        @manual_callback: If set, call this function instead of normal one
        Return an Expr instance"""

        if expression in self.simplified_exprs:
            return expression

        if callback is None:
            callback = self.expr_simp

        return expression.visit(callback, lambda e: e not in self.simplified_exprs)

    def __call__(self, expression, callback=None):
        "Wrapper on expr_simp_wrapper"
        return self.expr_simp_wrapper(expression, callback)


# Public ExprSimplificationPass instance with commons passes
expr_simp = ExpressionSimplifier()
expr_simp.enable_passes(ExpressionSimplifier.PASS_COMMONS)



expr_simp_high_to_explicit = ExpressionSimplifier()
expr_simp_high_to_explicit.enable_passes(ExpressionSimplifier.PASS_HIGH_TO_EXPLICIT)

expr_simp_explicit = ExpressionSimplifier()
expr_simp_explicit.enable_passes(ExpressionSimplifier.PASS_COMMONS)
expr_simp_explicit.enable_passes(ExpressionSimplifier.PASS_HIGH_TO_EXPLICIT)
