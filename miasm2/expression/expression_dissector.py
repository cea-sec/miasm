import miasm2.expression.expression as m2_expr


class ExprDissector(object):
    """
    Dissects expressions into subexpressions
    """

    def __init__(self, registers=[], irdst=[]):
        """
        Initialises the architecture variables
        :param registers: registers of an architecture
        :param irdst: IRA instruction pointer of an architecture
        """
        # set architecture variables
        self.arch_vars = set()
        if registers and irdst:
            self.arch_vars.add(registers + irdst)


    def _iterator(self, expr):
        """
        Parses the arguments of an expression
        :param expr: expression
        :return: iterator of a list of expressions
        """
        if isinstance(expr, m2_expr.ExprOp):
            iterator = iter(expr.args)
        elif isinstance(expr, m2_expr.ExprSlice):
            iterator = iter([expr.arg])
        elif isinstance(expr, m2_expr.ExprCond):
            iterator = iter((expr.cond, expr.src1, expr.src2))
        elif isinstance(expr, m2_expr.ExprCompose):
            iterator = iter((t[0] for t in expr.args))
        elif isinstance(expr, m2_expr.ExprMem):
            iterator = iter([expr.arg])
        elif isinstance(expr, m2_expr.ExprAff):
            iterator = iter([expr.dst, expr.src])
        elif isinstance(expr, m2_expr.ExprInt):
            iterator = iter([])
        elif isinstance(expr, m2_expr.ExprId):
            iterator = iter([])
        else:
            raise NotImplementedError()

        return iterator

    def _dissect(self, expr, expr_type):
        """
        Worklist algorithm that dissects an
        expression into subexpressions of
        type @expr_type
        :param expr: expression to dissect
        :param expr_type: miasm2 expression type
        :return: set of expressions
        """
        done = set()
        results = set()
        todo = [expr]

        while todo:
            expr = todo.pop()

            if expr in done:
                continue
            done.add(expr)

            if isinstance(expr, expr_type):
                results.add(expr)
                continue

            iterator = self._iterator(expr)

            if not iterator:
                raise RuntimeError("no handler for {}".format((type(expr))))

            for arg in iterator:
                todo.append(arg)

        return results

    def op(self, expr):
        """
        Dissects an expression into ExprOps
        :param expr: expression
        :return: set of ExprOp in e
        """
        return self._dissect(expr, m2_expr.ExprOp)

    def slice_(self, expr):
        """
        Dissects an expression into ExprSlices
        :param expr: expression
        :return: set of ExprSlice in e
        """
        return self._dissect(expr, m2_expr.ExprSlice)

    def cond(self, expr):
        """
        Dissects an expression into ExprConds
        :param expr: expression
        :return: set of ExprCond in e
        """
        return self._dissect(expr, m2_expr.ExprCond)

    def compose(self, expr):
        """
        Dissects an expression into ExprComposes
        :param expr: expression
        :return: set of ExprCompose in e
        """
        return self._dissect(expr, m2_expr.ExprCompose)

    def mem(self, expr):
        """
        Dissects an expression into ExprMems
        :param expr: expression
        :return: set of ExprMem in e
        """
        return self._dissect(expr, m2_expr.ExprMem)

    def aff(self, expr):
        """
        Dissects an expression into ExprAffs
        :param expr: expression
        :return: set of ExprAff in e
        """
        return self._dissect(expr, m2_expr.ExprAff)

    def int_(self, expr):
        """
        Dissects an expression into ExprInts
        :param expr: expression
        :return: set of ExprInt in e
        """
        return self._dissect(expr, m2_expr.ExprInt)

    def id_(self, expr):
        """
        Dissects an expression into ExprIds
        :param expr: expression
        :return: set of ExprIds in e
        """
        return self._dissect(expr, m2_expr.ExprId)

    def variables(self, expr):
        """
        Dissects an expression into architecture variables
        :param expr: expression
        :return: set of variables in e
        """
        if not self.arch_vars:
            raise RuntimeError("Architecture variables are not defined.")

        # get ExprIDs in e
        ids = self.id_(expr)

        # parse variables
        results = set()
        for v in ids:
            if v in self.arch_vars:
                results.add(v)

        return results
