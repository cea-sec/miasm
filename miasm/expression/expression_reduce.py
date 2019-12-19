"""
Expression reducer:
Apply reduction rules to an Expression ast
"""

import logging
from miasm.expression.expression import ExprInt, ExprId, ExprLoc, ExprOp, \
    ExprSlice, ExprCompose, ExprMem, ExprCond

log_reduce = logging.getLogger("expr_reduce")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log_reduce.addHandler(console_handler)
log_reduce.setLevel(logging.WARNING)



class ExprNode(object):
    """Clone of Expression object with additional information"""

    def __init__(self, expr):
        self.expr = expr


class ExprNodeInt(ExprNode):
    def __init__(self, expr):
        assert expr.is_int()
        super(ExprNodeInt, self).__init__(expr)
        self.arg = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = str(self.expr)
        return out


class ExprNodeId(ExprNode):
    def __init__(self, expr):
        assert expr.is_id()
        super(ExprNodeId, self).__init__(expr)
        self.arg = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = str(self.expr)
        return out


class ExprNodeLoc(ExprNode):
    def __init__(self, expr):
        assert expr.is_loc()
        super(ExprNodeLoc, self).__init__(expr)
        self.arg = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = str(self.expr)
        return out


class ExprNodeMem(ExprNode):
    def __init__(self, expr):
        assert expr.is_mem()
        super(ExprNodeMem, self).__init__(expr)
        self.ptr = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = "@%d[%r]" % (self.expr.size, self.ptr)
        return out


class ExprNodeOp(ExprNode):
    def __init__(self, expr):
        assert expr.is_op()
        super(ExprNodeOp, self).__init__(expr)
        self.args = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            if len(self.args) == 1:
                out = "(%s(%r))" % (self.expr.op, self.args[0])
            else:
                out = "(%s)" % self.expr.op.join(repr(arg) for arg in self.args)
        return out


class ExprNodeSlice(ExprNode):
    def __init__(self, expr):
        assert expr.is_slice()
        super(ExprNodeSlice, self).__init__(expr)
        self.arg = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = "%r[%d:%d]" % (self.arg, self.expr.start, self.expr.stop)
        return out


class ExprNodeCompose(ExprNode):
    def __init__(self, expr):
        assert expr.is_compose()
        super(ExprNodeCompose, self).__init__(expr)
        self.args = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = "{%s}" % ', '.join(repr(arg) for arg in self.args)
        return out


class ExprNodeCond(ExprNode):
    def __init__(self, expr):
        assert expr.is_cond()
        super(ExprNodeCond, self).__init__(expr)
        self.cond = None
        self.src1 = None
        self.src2 = None

    def __repr__(self):
        if self.info is not None:
            out = repr(self.info)
        else:
            out = "(%r?%r:%r)" % (self.cond, self.src1, self.src2)
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

        if isinstance(expr, ExprId):
            node = ExprNodeId(expr)
        elif isinstance(expr, ExprLoc):
            node = ExprNodeLoc(expr)
        elif isinstance(expr, ExprInt):
            node = ExprNodeInt(expr)
        elif isinstance(expr, ExprMem):
            son = self.expr2node(expr.ptr)
            node = ExprNodeMem(expr)
            node.ptr = son
        elif isinstance(expr, ExprSlice):
            son = self.expr2node(expr.arg)
            node = ExprNodeSlice(expr)
            node.arg = son
        elif isinstance(expr, ExprOp):
            sons = [self.expr2node(arg) for arg in expr.args]
            node = ExprNodeOp(expr)
            node.args = sons
        elif isinstance(expr, ExprCompose):
            sons = [self.expr2node(arg) for arg in expr.args]
            node = ExprNodeCompose(expr)
            node.args = sons
        elif isinstance(expr, ExprCond):
            node = ExprNodeCond(expr)
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
        @lvl: actual recursion level
        """

        expr = node.expr
        log_reduce.debug("\t" * lvl + "Reduce...: %s", node.expr)
        if isinstance(expr, ExprId):
            node = ExprNodeId(expr)
        elif isinstance(expr, ExprInt):
            node = ExprNodeInt(expr)
        elif isinstance(expr, ExprLoc):
            node = ExprNodeLoc(expr)
        elif isinstance(expr, ExprMem):
            ptr = self.categorize(node.ptr, lvl=lvl + 1, **kwargs)
            node = ExprNodeMem(ExprMem(ptr.expr, expr.size))
            node.ptr = ptr
        elif isinstance(expr, ExprSlice):
            arg = self.categorize(node.arg, lvl=lvl + 1, **kwargs)
            node = ExprNodeSlice(ExprSlice(arg.expr, expr.start, expr.stop))
            node.arg = arg
        elif isinstance(expr, ExprOp):
            new_args = []
            for arg in node.args:
                new_a = self.categorize(arg, lvl=lvl + 1, **kwargs)
                assert new_a.expr.size == arg.expr.size
                new_args.append(new_a)
            node = ExprNodeOp(ExprOp(expr.op, *[x.expr for x in new_args]))
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
            node = ExprNodeCompose(new_expr)
            node.args = new_args
        elif isinstance(expr, ExprCond):
            cond = self.categorize(node.cond, lvl=lvl + 1, **kwargs)
            src1 = self.categorize(node.src1, lvl=lvl + 1, **kwargs)
            src2 = self.categorize(node.src2, lvl=lvl + 1, **kwargs)
            node = ExprNodeCond(ExprCond(cond.expr, src1.expr, src2.expr))
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
        @lvl: actuel recursion level
        """

        for rule in self.reduction_rules:
            ret = rule(self, node, lvl=lvl, **kwargs)

            if ret is not None:
                log_reduce.debug("\t" * lvl + "Rule found: %r", rule)
                return ret
        if not self.allow_none_result:
            raise RuntimeError('Missing reduction rule for %r' % node.expr)
