"""Provide dependency graph"""

import miasm2.expression.expression as m2_expr
from miasm2.core.graph import DiGraph
from miasm2.core.asmbloc import asm_label, expr_is_int_or_label, expr_is_label
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.symbexec import symbexec
from miasm2.ir.ir import irbloc, AssignBlock
from miasm2.ir.translators import Translator
from miasm2.expression.expression_helper import possible_values

try:
    import z3
except ImportError:
    pass


class DependencyNode(object):

    """Node elements of a DependencyGraph

    A dependency node stands for the dependency on the @element at line number
    @line_nb in the IRblock named @label, *before* the evaluation of this
    line.
    """

    __slots__ = ["_label", "_element", "_line_nb",
                 "_step", "_nostep_repr", "_hash"]

    def __init__(self, label, element, line_nb):
        """Create a dependency node with:
        @label: asm_label instance
        @element: Expr instance
        @line_nb: int
        """
        self._label = label
        self._element = element
        self._line_nb = line_nb
        self._nostep_repr = (self._label, self._line_nb, self._element)
        self._hash = hash(
            (self._label, self._element, self._line_nb))

    def __hash__(self):
        """Returns a hash of @self to uniquely identify @self"""
        return self._hash

    def __eq__(self, depnode):
        """Returns True if @self and @depnode are equals.
        The attribute 'step' is not considered in the comparison.
        """
        if not isinstance(depnode, self.__class__):
            return False
        return (self.label == depnode.label and
                self.element == depnode.element and
                self.line_nb == depnode.line_nb)

    def __cmp__(self, node):
        """Compares @self with @node. The step attribute is not taken into
        account in the comparison.
        """
        if not isinstance(node, self.__class__):
            raise ValueError("Compare error between %s, %s" % (self.__class__,
                                                               node.__class__))
        return cmp((self.label, self.element, self.line_nb),
                   (node.label, node.element, node.line_nb))

    def __str__(self):
        """Returns a string representation of DependencyNode"""
        return "<%s %s %s %s>" % (self.__class__.__name__,
                                  self.label.name, self.element,
                                  self.line_nb)

    def __repr__(self):
        """Returns a string representation of DependencyNode"""
        return self.__str__()

    @property
    def nostep_repr(self):
        """Returns a representation of @self ignoring the step attribute"""
        return self._nostep_repr

    @property
    def label(self):
        "Name of the current IRBlock"
        return self._label

    @property
    def element(self):
        "Current tracked Expr"
        return self._element

    @property
    def line_nb(self):
        "Line in the current IRBlock"
        return self._line_nb


class DependencyState(object):

    """
    Store intermediate depnodes states during dependencygraph analysis
    """

    def __init__(self, label, inputs, pending, line_nb=None):
        self.label = label
        self.inputs = inputs
        self.history = [label]
        self.pending = {k: set(v) for k, v in pending.iteritems()}
        self.line_nb = line_nb
        self.links = set()

        # Init lazy elements
        self._graph = None

    def __repr__(self):
        return "<State: %r (%r) (%r)>" % (self.label,
                                          self.pending,
                                          self.links)

    def extend(self, label):
        """Return a copy of itself, with itself in history
        @label: asm_label instance for the new DependencyState's label
        """
        new_state = self.__class__(label, self.inputs, self.pending)
        new_state.links = set(self.links)
        new_state.history = self.history + [label]
        return new_state

    def get_done_state(self):
        """Returns immutable object representing current state"""
        return (self.label, frozenset(self.links))

    def as_graph(self):
        """Generates a Digraph of dependencies"""
        graph = DiGraph()
        for node_a, node_b in self.links:
            if not node_b:
                graph.add_node(node_a)
            else:
                graph.add_edge(node_a, node_b)
        for parent, sons in self.pending.iteritems():
            for son in sons:
                graph.add_edge(parent, son)
        return graph

    @property
    def graph(self):
        """Returns a DiGraph instance representing the DependencyGraph"""
        if self._graph is None:
            self._graph = self.as_graph()
        return self._graph

    def remove_pendings(self, nodes):
        """Remove resolved @nodes"""
        for node in nodes:
            del self.pending[node]

    def add_pendings(self, future_pending):
        """Add @future_pending to the state"""
        for node, depnodes in future_pending.iteritems():
            if node not in self.pending:
                self.pending[node] = depnodes
            else:
                self.pending[node].update(depnodes)

    def link_element(self, element, line_nb):
        """Link element to its dependencies
        @element: the element to link
        @line_nb: the element's line
        """

        depnode = DependencyNode(self.label, element, line_nb)
        if not self.pending[element]:
            # Create start node
            self.links.add((depnode, None))
        else:
            # Link element to its known dependencies
            for node_son in self.pending[element]:
                self.links.add((depnode, node_son))

    def link_dependencies(self, element, line_nb, dependencies,
                          future_pending):
        """Link unfollowed dependencies and create remaining pending elements.
        @element: the element to link
        @line_nb: the element's line
        @dependencies: the element's dependencies
        @future_pending: the future dependencies
        """

        depnode = DependencyNode(self.label, element, line_nb)

        # Update pending, add link to unfollowed nodes
        for dependency in dependencies:
            if not dependency.follow:
                # Add non followed dependencies to the dependency graph
                parent = DependencyNode(
                    self.label, dependency.element, line_nb)
                self.links.add((parent, depnode))
                continue
            # Create future pending between new dependency and the current
            # element
            future_pending.setdefault(dependency.element, set()).add(depnode)


class DependencyResult(DependencyState):

    """Container and methods for DependencyGraph results"""

    def __init__(self, state, ira):
        self.label = state.label
        self.inputs = state.inputs
        self.history = state.history
        self.pending = state.pending
        self.line_nb = state.line_nb
        self.links = state.links
        self._ira = ira

        # Init lazy elements
        self._graph = None
        self._has_loop = None

    @property
    def unresolved(self):
        """Set of nodes whose dependencies weren't found"""
        return set(element for element in self.pending
                   if element != self._ira.IRDst)

    @property
    def relevant_nodes(self):
        """Set of nodes directly and indirectly influencing inputs"""
        output = set()
        for node_a, node_b in self.links:
            output.add(node_a)
            if node_b is not None:
                output.add(node_b)
        return output

    @property
    def relevant_labels(self):
        """List of labels containing nodes influencing inputs.
        The history order is preserved."""
        # Get used labels
        used_labels = set(depnode.label for depnode in self.relevant_nodes)

        # Keep history order
        output = []
        for label in self.history:
            if label in used_labels:
                output.append(label)

        return output

    @property
    def has_loop(self):
        """True iff there is at least one data dependencies cycle (regarding
        the associated depgraph)"""
        if self._has_loop is None:
            self._has_loop = self.graph.has_loop()
        return self._has_loop

    def irblock_slice(self, irb):
        """Slice of the dependency nodes on the irblock @irb
        @irb: irbloc instance
        """

        assignblks = []
        line2elements = {}
        for depnode in self.relevant_nodes:
            if depnode.label != irb.label:
                continue
            line2elements.setdefault(depnode.line_nb,
                                     set()).add(depnode.element)

        for line_nb, elements in sorted(line2elements.iteritems()):
            assignblk = AssignBlock()
            for element in elements:
                if element in irb.irs[line_nb]:
                    # constants, label, ... are not in destination
                    assignblk[element] = irb.irs[line_nb][element]
            assignblks.append(assignblk)

        return irbloc(irb.label, assignblks)

    def emul(self, ctx=None, step=False):
        """Symbolic execution of relevant nodes according to the history
        Return the values of inputs nodes' elements
        @ctx: (optional) Initial context as dictionnary
        @step: (optional) Verbose execution
        Warning: The emulation is not sound if the inputs nodes depend on loop
        variant.
        """
        # Init
        ctx_init = self._ira.arch.regs.regs_init
        if ctx is not None:
            ctx_init.update(ctx)
        assignblks = []

        # Build a single affectation block according to history
        for label in self.relevant_labels[::-1]:
            assignblks += self.irblock_slice(self._ira.blocs[label]).irs

        # Eval the block
        temp_label = asm_label("Temp")
        symb_exec = symbexec(self._ira, ctx_init)
        symb_exec.emulbloc(irbloc(temp_label, assignblks), step=step)

        # Return only inputs values (others could be wrongs)
        return {element: symb_exec.symbols[element]
                for element in self.inputs}


class DependencyResultImplicit(DependencyResult):

    """Stand for a result of a DependencyGraph with implicit option

    Provide path constraints using the z3 solver"""
    # Z3 Solver instance
    _solver = None

    unsat_expr = m2_expr.ExprAff(m2_expr.ExprInt(0, 1),
                                 m2_expr.ExprInt(1, 1))

    def _gen_path_constraints(self, translator, expr, expected):
        """Generate path constraint from @expr. Handle special case with
        generated labels
        """
        out = []
        expected_is_label = expr_is_label(expected)
        for consval in possible_values(expr):
            if (expected_is_label and
                    consval.value != expected):
                continue
            if (not expected_is_label and
                    expr_is_label(consval.value)):
                continue

            conds = z3.And(*[translator.from_expr(cond.to_constraint())
                             for cond in consval.constraints])
            if expected != consval.value:
                conds = z3.And(conds,
                               translator.from_expr(
                                   m2_expr.ExprAff(consval.value,
                                                   expected)))
            out.append(conds)

        if out:
            conds = z3.Or(*out)
        else:
            # Ex: expr: lblgen1, expected: 0x1234
            # -> Avoid unconsistent solution lblgen1 = 0x1234
            conds = translator.from_expr(self.unsat_expr)
        return conds

    def emul(self, ctx=None, step=False):
        # Init
        ctx_init = self._ira.arch.regs.regs_init
        if ctx is not None:
            ctx_init.update(ctx)
        solver = z3.Solver()
        symb_exec = symbexec(self._ira, ctx_init)
        history = self.history[::-1]
        history_size = len(history)
        translator = Translator.to_language("z3")
        size = self._ira.IRDst.size

        for hist_nb, label in enumerate(history):
            irb = self.irblock_slice(self._ira.blocs[label])

            # Emul the block and get back destination
            dst = symb_exec.emulbloc(irb, step=step)

            # Add constraint
            if hist_nb + 1 < history_size:
                next_label = history[hist_nb + 1]
                expected = symb_exec.eval_expr(m2_expr.ExprId(next_label,
                                                              size))
                solver.add(
                    self._gen_path_constraints(translator, dst, expected))
        # Save the solver
        self._solver = solver

        # Return only inputs values (others could be wrongs)
        return {element: symb_exec.eval_expr(element)
                for element in self.inputs}

    @property
    def is_satisfiable(self):
        """Return True iff the solution path admits at least one solution
        PRE: 'emul'
        """
        return self._solver.check() == z3.sat

    @property
    def constraints(self):
        """If satisfiable, return a valid solution as a Z3 Model instance"""
        if not self.is_satisfiable:
            raise ValueError("Unsatisfiable")
        return self._solver.model()


class FollowExpr(object):

    "Stand for an element (expression, depnode, ...) to follow or not"
    __slots__ = ["follow", "element"]

    def __init__(self, follow, element):
        self.follow = follow
        self.element = element

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.follow, self.element)

    @staticmethod
    def to_depnodes(follow_exprs, label, line):
        """Build a set of FollowExpr(DependencyNode) from the @follow_exprs set
        of FollowExpr
        @follow_exprs: set of FollowExpr
        @label: asm_label instance
        @line: integer
        """
        dependencies = set()
        for follow_expr in follow_exprs:
            dependencies.add(FollowExpr(follow_expr.follow,
                                        DependencyNode(label,
                                                       follow_expr.element,
                                                       line)))
        return dependencies

    @staticmethod
    def extract_depnodes(follow_exprs, only_follow=False):
        """Extract depnodes from a set of FollowExpr(Depnodes)
        @only_follow: (optional) extract only elements to follow"""
        return set(follow_expr.element
                   for follow_expr in follow_exprs
                   if not(only_follow) or follow_expr.follow)


class DependencyGraph(object):

    """Implementation of a dependency graph

    A dependency graph contains DependencyNode as nodes. The oriented edges
    stand for a dependency.
    The dependency graph is made of the lines of a group of IRblock
    *explicitely* or *implicitely* involved in the equation of given element.
    """

    def __init__(self, ira, implicit=False, apply_simp=True, follow_mem=True,
                 follow_call=True):
        """Create a DependencyGraph linked to @ira
        The IRA graph must have been computed

        @ira: IRAnalysis instance
        @implicit: (optional) Track IRDst for each block in the resulting path

        Following arguments define filters used to generate dependencies
        @apply_simp: (optional) Apply expr_simp
        @follow_mem: (optional) Track memory syntactically
        @follow_call: (optional) Track through "call"
        """
        # Init
        self._ira = ira
        self._implicit = implicit

        # Create callback filters. The order is relevant.
        self._cb_follow = []
        if apply_simp:
            self._cb_follow.append(self._follow_simp_expr)
        self._cb_follow.append(lambda exprs: self._follow_exprs(exprs,
                                                                follow_mem,
                                                                follow_call))
        self._cb_follow.append(self._follow_nolabel)

    @staticmethod
    def _follow_simp_expr(exprs):
        """Simplify expression so avoid tracking useless elements,
        as: XOR EAX, EAX
        """
        follow = set()
        for expr in exprs:
            follow.add(expr_simp(expr))
        return follow, set()

    @staticmethod
    def get_expr(expr, follow, nofollow):
        """Update @follow/@nofollow according to insteresting nodes
        Returns same expression (non modifier visitor).

        @expr: expression to handle
        @follow: set of nodes to follow
        @nofollow: set of nodes not to follow
        """
        if isinstance(expr, m2_expr.ExprId):
            follow.add(expr)
        elif isinstance(expr, m2_expr.ExprInt):
            nofollow.add(expr)
        elif isinstance(expr, m2_expr.ExprMem):
            follow.add(expr)
        return expr

    @staticmethod
    def follow_expr(expr, _, nofollow, follow_mem=False, follow_call=False):
        """Returns True if we must visit sub expressions.
        @expr: expression to browse
        @follow: set of nodes to follow
        @nofollow: set of nodes not to follow
        @follow_mem: force the visit of memory sub expressions
        @follow_call: force the visit of call sub expressions
        """
        if not follow_mem and isinstance(expr, m2_expr.ExprMem):
            nofollow.add(expr)
            return False
        if not follow_call and expr.is_function_call():
            nofollow.add(expr)
            return False
        return True

    @classmethod
    def _follow_exprs(cls, exprs, follow_mem=False, follow_call=False):
        """Extracts subnodes from exprs and returns followed/non followed
        expressions according to @follow_mem/@follow_call

        """
        follow, nofollow = set(), set()
        for expr in exprs:
            expr.visit(lambda x: cls.get_expr(x, follow, nofollow),
                       lambda x: cls.follow_expr(x, follow, nofollow,
                                                 follow_mem, follow_call))
        return follow, nofollow

    @staticmethod
    def _follow_nolabel(exprs):
        """Do not follow labels"""
        follow = set()
        for expr in exprs:
            if not expr_is_int_or_label(expr):
                follow.add(expr)

        return follow, set()

    def _follow_apply_cb(self, expr):
        """Apply callback functions to @expr
        @expr : FollowExpr instance"""
        follow = set([expr])
        nofollow = set()

        for callback in self._cb_follow:
            follow, nofollow_tmp = callback(follow)
            nofollow.update(nofollow_tmp)

        out = set(FollowExpr(True, expr) for expr in follow)
        out.update(set(FollowExpr(False, expr) for expr in nofollow))
        return out

    def _track_exprs(self, state, assignblk, line_nb):
        """Track pending expression in an assignblock"""
        future_pending = {}
        node_resolved = set()
        for dst, src in assignblk.iteritems():
            # Only track pending
            if dst not in state.pending:
                continue
            # Track IRDst in implicit mode only
            if dst == self._ira.IRDst and not self._implicit:
                continue
            assert dst not in node_resolved
            node_resolved.add(dst)
            dependencies = self._follow_apply_cb(src)

            state.link_element(dst, line_nb)
            state.link_dependencies(dst, line_nb,
                                    dependencies, future_pending)

        # Update pending nodes
        state.remove_pendings(node_resolved)
        state.add_pendings(future_pending)

    def _compute_intrablock(self, state):
        """Follow dependencies tracked in @state in the current irbloc
        @state: instance of DependencyState"""

        irb = self._ira.blocs[state.label]
        line_nb = len(irb.irs) if state.line_nb is None else state.line_nb

        for cur_line_nb, assignblk in reversed(list(enumerate(irb.irs[:line_nb]))):
            self._track_exprs(state, assignblk, cur_line_nb)

    def get(self, label, elements, line_nb, heads):
        """Compute the dependencies of @elements at line number @line_nb in
        the block named @label in the current IRA, before the execution of
        this line. Dependency check stop if one of @heads is reached
        @label: asm_label instance
        @element: set of Expr instances
        @line_nb: int
        @heads: set of asm_label instances
        Return an iterator on DiGraph(DependencyNode)
        """
        # Init the algorithm
        pending = {element: set() for element in elements}
        state = DependencyState(label, elements, pending, line_nb)
        todo = set([state])
        done = set()
        dpResultcls = DependencyResultImplicit if self._implicit else DependencyResult

        while todo:
            state = todo.pop()
            self._compute_intrablock(state)
            done_state = state.get_done_state()
            if done_state in done:
                continue
            done.add(done_state)
            if (not state.pending or
                    state.label in heads or
                    not self._ira.graph.predecessors(state.label)):
                yield dpResultcls(state, self._ira)
                if not state.pending:
                    continue

            if self._implicit:
                # Force IRDst to be tracked, except in the input block
                state.pending[self._ira.IRDst] = set()

            # Propagate state to parents
            for pred in self._ira.graph.predecessors_iter(state.label):
                todo.add(state.extend(pred))

    def get_from_depnodes(self, depnodes, heads):
        """Alias for the get() method. Use the attributes of @depnodes as
        argument.
        PRE: Labels and lines of depnodes have to be equals
        @depnodes: set of DependencyNode instances
        @heads: set of asm_label instances
        """
        lead = list(depnodes)[0]
        elements = set(depnode.element for depnode in depnodes)
        return self.get(lead.label, elements, lead.line_nb, heads)
