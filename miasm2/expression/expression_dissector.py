import miasm2.expression.expression as m2_expr


class ExprDissector:
    """
    Dissects expressions into subexpressions
    """

    def __init__(self, registers=None, irdst=None):
        """
        Initialises the architecture variables
        :param registers: registers of an architecture
        :param irdst: IRA instruction pointer of an architecture
        """
        # set architecture variables
        if registers and irdst:
            self.arch_vars = set(registers + [irdst])

    def _iterator(self, e):
        """
        Parses the arguments of an expression
        :param e: expression
        :return: iterator of a list of expressions
        """
        if isinstance(e, m2_expr.ExprOp):
            iterator = iter(e.args)
        elif isinstance(e, m2_expr.ExprSlice):
            iterator = iter([e.arg])
        elif isinstance(e, m2_expr.ExprCond):
            iterator = iter((e.cond, e.src1, e.src2))
        elif isinstance(e, m2_expr.ExprCompose):
            iterator = iter((t[0] for t in e.args))
        elif isinstance(e, m2_expr.ExprMem):
            iterator = iter([e.arg])
        elif isinstance(e, m2_expr.ExprAff):
            iterator = iter([e.dst, e.src])
        elif isinstance(e, m2_expr.ExprInt):
            iterator = iter([])
        elif isinstance(e, m2_expr.ExprId):
            iterator = iter([])
        else:
            raise NotImplementedError()

        return iterator

    def _check_itetator(self, iterator, e):
        """
        Checks if an iterator is defined
        :param iterator: iterator
        :param e: expression
        """
        if not iterator:
            raise NotImplementedError("no handler for {}".format((type(e))))

    def _dissect(self, e, expr_type):
        """
        Worklist algorithm that dissects an
        expression into subexpressions of
        type @expr_type
        :param e: expression to dissect
        :param expr_type: miasm2 expression type
        :return: set of expressions
        """
        done = set()
        results = set()
        todo = [e]

        while todo:
            e = todo.pop()

            if e in done:
                continue
            done.add(e)

            if isinstance(e, expr_type):
                results.add(e)
                continue

            iterator = self._iterator(e)
            self._check_itetator(iterator, e)

            for arg in iterator:
                todo.append(arg)

        return results

    def op(self, e):
        """
        Dissects an expression into ExprOps
        :param e: expression
        :return: set of ExprOp in e
        """
        return self._dissect(e, m2_expr.ExprOp)

    def slice(self, e):
        """
        Dissects an expression into ExprSlices
        :param e: expression
        :return: set of ExprSlice in e
        """
        return self._dissect(e, m2_expr.ExprSlice)

    def cond(self, e):
        """
        Dissects an expression into ExprConds
        :param e: expression
        :return: set of ExprCond in e
        """
        return self._dissect(e, m2_expr.ExprCond)

    def compose(self, e):
        """
        Dissects an expression into ExprComposes
        :param e: expression
        :return: set of ExprCompose in e
        """
        return self._dissect(e, m2_expr.ExprCompose)

    def mem(self, e):
        """
        Dissects an expression into ExprMems
        :param e: expression
        :return: set of ExprMem in e
        """
        return self._dissect(e, m2_expr.ExprMem)

    def aff(self, e):
        """
        Dissects an expression into ExprAffs
        :param e: expression
        :return: set of ExprAff in e
        """
        return self._dissect(e, m2_expr.ExprAff)

    def int(self, e):
        """
        Dissects an expression into ExprInts
        :param e: expression
        :return: set of ExprInt in e
        """
        return self._dissect(e, m2_expr.ExprInt)

    def id(self, e):
        """
        Dissects an expression into ExprIds
        :param e: expression
        :return: set of ExprIds in e
        """
        return self._dissect(e, m2_expr.ExprId)

    def variables(self, e):
        """
        Dissects an expression into architecture variables
        :param e: expression
        :return: set of variables in e
        """
        assert self.arch_vars

        # get ExprIDs in e
        ids = self.id(e)

        # parse variables
        results = set()
        for v in ids:
            if v in self.arch_vars:
                results.add(v)

        return results
