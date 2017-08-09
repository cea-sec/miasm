"""
Expression reducer:
Apply reduction rules to an Expression ast
"""

import logging
from miasm2.expression.expression import ExprInt, ExprId, ExprOp, ExprSlice,\
    ExprCompose, ExprMem, ExprCond

log_reduce = logging.getLogger("expr_reduce")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_reduce.addHandler(console_handler)
log_reduce.setLevel(logging.WARNING)


class ExprNode(object):
    """Clone of Expression object with additionnal information"""

    def __init__(self, expr):
        self.expr = expr
        # Generic field to store custom node information
        self.info = None

        self.arg, self.args = None, None
        self.cond, self.src1, self.src2 = None, None, None

    def __repr__(self):
        expr = self.expr
        if self.info is not None:
            out = repr(self.info)
        elif expr.is_int() or expr.is_id():
            out = str(expr)
        elif expr.is_mem():
            out = "@%d[%r]" % (self.expr.size, self.arg)
        elif expr.is_slice():
            out = "%r[%d:%d]" % (self.arg, expr.start, expr.stop)
        elif expr.is_op():
            if len(self.args) == 1:
                out = "(%s(%r))" % (expr.op, self.args[0])
            else:
                out = "(%s)" % expr.op.join(repr(arg) for arg in self.args)
        elif expr.is_compose():
            out = "{%s}" % ', '.join(repr(arg) for arg in self.args)
        elif expr.is_cond():
            out = "(%r?%r:%r)" % (self.cond, self.src1, self.src2)
        else:
            raise TypeError("Unknown node Type %r", type(expr))
        return out


class ExprReducer(object):
    """Apply reduction rules to an expr

    reduction_rules: list of ordered reduction rules

    List of function representing reduction rules
    Function API:
    reduction_xxx(self, node, lvl=0)
    with:
    * node: the ExprNode to qualify
    * lvl: [optional] the recursion level
    Returns:
    * None if the reduction rule is not applied
    * the resulting information to store in the ExprNode.info

    allow_none_result: allow missing reduction rules
    """

    reduction_rules = []
    allow_none_result = False

    def expr2node(self, expr):
        """Build ExprNode mirror of @expr

        @expr: Expression to analyze
        """

        if isinstance(expr, (ExprId, ExprInt)):
            node = ExprNode(expr)
        elif isinstance(expr, (ExprMem, ExprSlice)):
            son = self.expr2node(expr.arg)
            node = ExprNode(expr)
            node.arg = son
        elif isinstance(expr, ExprOp):
            sons = [self.expr2node(arg) for arg in expr.args]
            node = ExprNode(expr)
            node.args = sons
        elif isinstance(expr, ExprCompose):
            sons = [self.expr2node(arg) for arg in expr.args]
            node = ExprNode(expr)
            node.args = sons
        elif isinstance(expr, ExprCond):
            node = ExprNode(expr)
            node.cond = self.expr2node(expr.cond)
            node.src1 = self.expr2node(expr.src1)
            node.src2 = self.expr2node(expr.src2)
        else:
            raise TypeError("Unknown Expr Type %r", type(expr))
        return node

    def reduce(self, expr, **kwargs):
        """Returns an ExprNode tree mirroring @expr tree. The ExprNode is
        computed by applying reduction rules to the expression @expr

        @expr: an Expression
        """

        node = self.expr2node(expr)
        return self.categorize(node, lvl=0, **kwargs)

    def categorize(self, node, lvl=0, **kwargs):
        """Recursively apply rules to @node

        @node: ExprNode to analyze
        @lvl: actual recusion level
        """

        expr = node.expr
        log_reduce.debug("\t" * lvl + "Reduce...: %s", node.expr)
        if isinstance(expr, (ExprId, ExprInt)):
            pass
        elif isinstance(expr, ExprMem):
            arg = self.categorize(node.arg, lvl=lvl + 1, **kwargs)
            node = ExprNode(ExprMem(arg.expr, expr.size))
            node.arg = arg
        elif isinstance(expr, ExprSlice):
            arg = self.categorize(node.arg, lvl=lvl + 1, **kwargs)
            node = ExprNode(ExprSlice(arg.expr, expr.start, expr.stop))
            node.arg = arg
        elif isinstance(expr, ExprOp):
            new_args = []
            for arg in node.args:
                new_a = self.categorize(arg, lvl=lvl + 1, **kwargs)
                assert new_a.expr.size == arg.expr.size
                new_args.append(new_a)
            node = ExprNode(ExprOp(expr.op, *[x.expr for x in new_args]))
            node.args = new_args
            expr = node.expr
        elif isinstance(expr, ExprCompose):
            new_args = []
            new_expr_args = []
            for arg in node.args:
                arg = self.categorize(arg, lvl=lvl + 1, **kwargs)
                new_args.append(arg)
                new_expr_args.append(arg.expr)
            new_expr = ExprCompose(*new_expr_args)
            node = ExprNode(new_expr)
            node.args = new_args
        elif isinstance(expr, ExprCond):
            cond = self.categorize(node.cond, lvl=lvl + 1, **kwargs)
            src1 = self.categorize(node.src1, lvl=lvl + 1, **kwargs)
            src2 = self.categorize(node.src2, lvl=lvl + 1, **kwargs)
            node = ExprNode(ExprCond(cond.expr, src1.expr, src2.expr))
            node.cond, node.src1, node.src2 = cond, src1, src2
        else:
            raise TypeError("Unknown Expr Type %r", type(expr))

        node.info = self.apply_rules(node, lvl=lvl, **kwargs)
        log_reduce.debug("\t" * lvl + "Reduce result: %s %r",
                         node.expr, node.info)
        return node

    def apply_rules(self, node, lvl=0, **kwargs):
        """Find and apply reduction rules to @node

        @node: ExprNode to analyse
        @lvl: actuel recusion level
        """

        for rule in self.reduction_rules:
            ret = rule(self, node, lvl=lvl, **kwargs)

            if ret is not None:
                log_reduce.debug("\t" * lvl + "Rule found: %r", rule)
                return ret
        if not self.allow_none_result:
            raise RuntimeError('Missing reduction rule for %r' % node.expr)
