"""Provide dependency graph"""
import itertools
from collections import namedtuple

try:
    import z3
except ImportError:
    pass

import miasm2.expression.expression as m2_expr
from miasm2.core.graph import DiGraph
from miasm2.core.asmbloc import asm_label, expr_is_label
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.symbexec import symbexec
from miasm2.ir.ir import irbloc
from miasm2.ir.translators import Translator

class DependencyNode(object):
    """Node elements of a DependencyGraph

    A dependency node stands for the dependency on the @element at line number
    @line_nb in the IRblock named @label, *before* the evaluation of this
    line.
    """

    def __init__(self, label, element, line_nb, modifier=False):
        """Create a dependency node with:
        @label: asm_label instance
        @element: Expr instance
        @line_nb: int
        @modifier: bool
        """
        self._label = label
        self._element = element
        self._line_nb = line_nb
        self._modifier = modifier
        self._hash = hash((self._label, self._element, self._line_nb))

    def __hash__(self):
        return self._hash

    def __eq__(self, depnode):
        if not isinstance(depnode, self.__class__):
            return False
        return (self.label == depnode.label and
                self.element == depnode.element and
                self.line_nb == depnode.line_nb)

    def __cmp__(self, node):
        if not isinstance(node, self.__class__):
            raise ValueError("Compare error between %s, %s" % (self.__class__,
                                                               node.__class__))
        return cmp((self.label, self.element, self.line_nb),
                   (node.label, node.element, node.line_nb))

    def __str__(self):
        return "<%s %s %s %s M:%s>"%(self.__class__.__name__,
                                     self.label.name, self.element,
                                     self.line_nb, self.modifier)

    def __repr__(self):
        return self.__str__()

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

    @property
    def modifier(self):
        """Evaluating the current line involves a modification of tracked
        dependencies"""
        return self._modifier

    @modifier.setter
    def modifier(self, value):
        if not isinstance(value, bool):
            raise ValueError("Modifier must be a boolean")
        self._modifier = value


class DependencyDict(object):
    """Internal structure for the DependencyGraph algorithm"""

    def __init__(self, label, history):
        """Create a DependencyDict
        @label: asm_label, current IRblock label
        @history: list of DependencyDict
        """
        self._label = label
        self._history = history
        self._pending = set()

        # DepNode -> set(DepNode)
        self._cache = {}

    def __eq__(self, depdict):
        if not isinstance(depdict, self.__class__):
            return False
        return (self._label == depdict.label and
                self._cache == depdict.cache and
                self._pending == depdict.pending)

    def __cmp__(self, depdict):
        if not isinstance(depdict, self.__class__):
            raise ValueError("Compare error %s != %s" % (self.__class__,
                                                         depdict.__class__))
        return cmp((self._label, self._cache, self._pending),
                   (depdict.label, depdict.cache, depdict.pending))

    def is_head(self, depnode):
        """Return True iff @depnode is at the head of the current block
        @depnode: DependencyNode instance"""
        return (self.label == depnode.label and
                depnode.line_nb == 0)

    def copy(self):
        "Return a copy of itself"

        # Initialize
        new_history = list(self.history)
        depdict = DependencyDict(self.label, new_history)

        # Copy values
        for key, values in self.cache.iteritems():
            depdict.cache[key] = set(values)
        depdict.pending.update(self.pending)

        return depdict

    def extend(self, label):
        """Return a copy of itself, with itself in history and pending clean
        @label: asm_label instance for the new DependencyDict's label
        """
        depdict = DependencyDict(label, list(self.history) + [self])
        for key, values in self.cache.iteritems():
            depdict.cache[key] = set(values)
        return depdict

    def heads(self):
        """Return an iterator on the list of heads as defined in 'is_head'"""
        for key in self.cache:
            if self.is_head(key):
                yield key

    @property
    def label(self):
        "Label of the current block"
        return self._label

    @property
    def history(self):
        """List of DependencyDict needed to reach the current DependencyDict
        The first is the oldest"""
        return self._history

    @property
    def cache(self):
        "Dictionnary of DependencyNode and their dependencies"
        return self._cache

    @property
    def pending(self):
        """Dictionnary of DependencyNode and their dependencies, waiting for
        resolution"""
        return self._pending

    def _get_modifiers_in_cache(self, depnode, force=False):
        """Recursively find nodes in the path of @depnode which are modifiers.
        Update the internal cache
        If @depnode is already managed (ie. in @depnode_queued), abort"""

        # Base case
        if depnode not in self._cache:
            # Constant does not have any dependencies
            return [depnode] if depnode.modifier else []

        if depnode.modifier and not force:
            return [depnode]

        # Recursion
        dependencies = self._cache[depnode]

        out = set()
        ## Launch on each depnodes
        parallels = []
        for depnode in dependencies:
            parallels.append(self._get_modifiers_in_cache(depnode))

        if parallels:
            for parallel in itertools.product(*parallels):
                out.update(parallel)

        return out

    def clean_modifiers_in_cache(self):
        """Remove intermediary states (non modifier depnodes) in the internal
        cache values"""

        cache_out = {}
        for depnode in self._cache.keys():
            cache_out[depnode] = self._get_modifiers_in_cache(depnode,
                                                              force=True)
        self._cache = cache_out

    def _build_depGraph(self, depnode):
        """Recursively build the final list of DiGraph, and clean up unmodifier
        nodes
        @depnode: starting node
        """

        if depnode not in self._cache or \
                not self._cache[depnode]:
            ## There is no dependency
            graph = DiGraph()
            graph.add_node(depnode)
            return graph

        # Recursion
        dependencies = list(self._cache[depnode])

        graphs = []
        for sub_depnode in dependencies:
            graphs.append(self._build_depGraph(sub_depnode))

        # head(graphs[i]) == dependencies[i]
        graph = DiGraph()
        graph.add_node(depnode)
        for head in dependencies:
            graph.add_uniq_edge(head, depnode)

        for subgraphs in itertools.product(graphs):
            for sourcegraph in subgraphs:
                for node in sourcegraph.nodes():
                    graph.add_node(node)
                for edge in sourcegraph.edges():
                    graph.add_uniq_edge(*edge)

        # Update the running queue
        return graph

    def as_graph(self, starting_nodes):
        """Return a DiGraph corresponding to computed dependencies, with
        @starting_nodes as leafs
        @starting_nodes: set of DependencyNode instance
        """

        # Build subgraph for each starting_node
        subgraphs = []
        for starting_node in starting_nodes:
            subgraphs.append(self._build_depGraph(starting_node))

        # Merge subgraphs into a final DiGraph
        graph = DiGraph()
        for sourcegraph in subgraphs:
            for node in sourcegraph.nodes():
                graph.add_node(node)
            for edge in sourcegraph.edges():
                graph.add_uniq_edge(*edge)
        return graph

    def filter_used_nodes(self, node_heads):
        """Keep only depnodes which are in the path of @node_heads in the
        internal cache
        @node_heads: set of DependencyNode instance
        """
        # Init
        todo = set(node_heads)
        used_nodes = set()

        # Map
        while todo:
            node = todo.pop()
            if node in used_nodes:
                continue
            used_nodes.add(node)
            if not node in self._cache:
                continue
            for sub_node in self._cache[node]:
                todo.add(sub_node)

        # Remove unused elements
        for key in list(self._cache.keys()):
            if key not in used_nodes:
                del self._cache[key]


class DependencyResult(object):
    """Container and methods for DependencyGraph results"""

    def __init__(self, ira, final_depdict, input_depnodes):
        """Instance a DependencyResult
        @ira: IRAnalysis instance
        @final_depdict: DependencyDict instance
        @input_depnodes: set of DependencyNode instance
        """
        # Store arguments
        self._ira = ira
        self._depdict = final_depdict
        self._input_depnodes = input_depnodes

        # Init lazy elements
        self._graph = None
        self._has_loop = None

    @property
    def graph(self):
        "Lazy"
        if self._graph is None:
            self._graph = self._depdict.as_graph(self._input_depnodes)
        return self._graph

    @property
    def history(self):
        return list(self._depdict.history) + [self._depdict]

    @property
    def unresolved(self):
        return set(self._depdict.pending)

    @property
    def relevant_nodes(self):
        output = set()
        for depnodes in self._depdict.cache.values():
            output.update(depnodes)
        return output

    @property
    def relevant_labels(self):
        # Get used labels
        used_labels = set([depnode.label for depnode in self.relevant_nodes])

        # Keep history order
        output = []
        for label in [depdict.label for depdict in self.history]:
            if label not in output and label in used_labels:
                output.append(label)

        return output

    @property
    def input(self):
        return self._input_depnodes

    def emul(self, ctx=None, step=False):
        """Symbolic execution of relevant nodes according to the history
        Return the values of input nodes' elements
        @ctx: (optional) Initial context as dictionnary
        @step: (optional) Verbose execution

        /!\ The emulation is not safe if there is a loop in the relevant labels
        """
        # Init
        ctx_init = self._ira.arch.regs.regs_init
        if ctx is not None:
            ctx_init.update(ctx)
        depnodes = self.relevant_nodes
        affects = []

        # Build a single affectation block according to history
        for label in self.relevant_labels[::-1]:
            affected_lines = set(depnode.line_nb for depnode in depnodes
                                 if depnode.label == label)
            irs = self._ira.blocs[label].irs
            for line_nb in sorted(affected_lines):
                affects.append(irs[line_nb])

        # Eval the block
        temp_label = asm_label("Temp")
        sb = symbexec(self._ira, ctx_init)
        sb.emulbloc(irbloc(temp_label, affects), step=step)

        # Return only inputs values (others could be wrongs)
        return {depnode.element: sb.symbols[depnode.element]
                for depnode in self.input}


class DependencyResultImplicit(DependencyResult):
    """Stand for a result of a DependencyGraph with implicit option

    Provide path constraints using the z3 solver"""

    # Z3 Solver instance
    _solver = None

    def emul(self, ctx=None, step=False):
        # Init
        ctx_init = self._ira.arch.regs.regs_init
        if ctx is not None:
            ctx_init.update(ctx)
        depnodes = self.relevant_nodes
        solver = z3.Solver()
        sb = symbexec(self._ira, ctx_init)
        temp_label = asm_label("Temp")
        history = self.relevant_labels[::-1]
        history_size = len(history)

        for hist_nb, label in enumerate(history):
            # Build block with relevant lines only
            affected_lines = set(depnode.line_nb for depnode in depnodes
                                 if depnode.label == label)
            irs = self._ira.blocs[label].irs
            affects = []

            for line_nb in sorted(affected_lines):
                affects.append(irs[line_nb])

            # Emul the block and get back destination
            dst = sb.emulbloc(irbloc(temp_label, affects), step=step)

            # Add constraint
            if hist_nb + 1 < history_size:
                next_label = history[hist_nb + 1]
                expected = sb.eval_expr(m2_expr.ExprId(next_label, 32))
                constraint = m2_expr.ExprAff(dst, expected)
                solver.add(Translator.to_language("z3").from_expr(constraint))

        # Save the solver
        self._solver = solver

        # Return only inputs values (others could be wrongs)
        return {depnode.element: sb.symbols[depnode.element]
                for depnode in self.input}

    @property
    def is_satisfiable(self):
        """Return True iff the solution path admits at least one solution
        PRE: 'emul'
        """
        return self._solver.check().r > 0

    @property
    def constraints(self):
        """If satisfiable, return a valid solution as a Z3 Model instance"""
        if not self.is_satisfiable:
            raise ValueError("Unsatisfiable")
        return self._solver.model()


class FollowExpr(object):
    "Stand for an element (expression, depnode, ...) to follow or not"

    def __init__(self, follow, element):
        self.follow = follow
        self.element = element

    @staticmethod
    def to_depnodes(follow_exprs, label, line, modifier):
        """Build a set of FollowExpr(DependencyNode) from the @follow_exprs set
        of FollowExpr"""
        dependencies = set()
        for follow_expr in follow_exprs:
            dependencies.add(FollowExpr(follow_expr.follow,
                                        DependencyNode(label,
                                                       follow_expr.element,
                                                       line,
                                                       modifier=modifier)))
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
        @implicit: (optional) Imply implicit dependencies

        Following arguments define filters used to generate dependencies
        @apply_simp: (optional) Apply expr_simp
        @follow_mem: (optional) Track memory syntaxically
        @follow_call: (optional) Track throught "call"
        """
        # Init
        self._ira = ira
        self._implicit = implicit

        # The IRA graph must be computed
        assert(hasattr(self._ira, 'g'))

        # Create callback filters. The order is relevant.
        self._cb_follow = []
        if apply_simp:
            self._cb_follow.append(self._follow_simp_expr)
        if follow_mem:
            self._cb_follow.append(self._follow_mem)
        else:
            self._cb_follow.append(self._follow_nomem)
        if not follow_call:
            self._cb_follow.append(self._follow_nocall)
        self._cb_follow.append(self._follow_label)

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
    def _follow_label(exprs):
        """Do not follow labels"""
        follow = set()
        unfollow = set()
        for expr in exprs:
            if expr_is_label(expr):
                unfollow.add(expr)
            else:
                follow.add(expr)
        return follow, unfollow

    @staticmethod
    def _follow_mem_wrapper(exprs, mem_read):
        follow = set()
        for expr in exprs:
            follow.update(expr.get_r(mem_read=mem_read, cst_read=True))
        return follow, set()

    @staticmethod
    def _follow_mem(exprs):
        """Follow expression from memory pointer"""
        return DependencyGraph._follow_mem_wrapper(exprs, True)

    @staticmethod
    def _follow_nomem(exprs):
        """Don't follow expression from memory pointer"""
        return DependencyGraph._follow_mem_wrapper(exprs, False)

    @staticmethod
    def _follow_nocall(exprs):
        """Don't follow expression from sub_call"""
        follow = set()
        nofollow = set()
        for expr in exprs:
            if isinstance(expr, m2_expr.ExprOp) and expr.op.startswith('call'):
                nofollow.add(expr)
            else:
                follow.add(expr)
        return follow, nofollow

    def _follow_apply_cb(self, expr):
        follow = set([expr])
        nofollow = set()

        for cb in self._cb_follow:
            follow, nofollow_tmp = cb(follow)
            nofollow.update(nofollow_tmp)

        out = set(FollowExpr(True, expr) for expr in follow)
        out.update(set(FollowExpr(False, expr) for expr in nofollow))

        return out

    def _get_irs(self, label):
        "Return the irs associated to @label"
        return self._ira.blocs[label].irs

    def _get_affblock(self, depnode):
        """Return the list of ExprAff associtiated to @depnode.
        LINE_NB must be > 0"""
        return self._get_irs(depnode.label)[depnode.line_nb - 1]

    def _resolve_depNode(self, depnode):
        """Compute and return the dependencies involved by @depnode
        Return a set of FollowExpr"""

        if isinstance(depnode.element, m2_expr.ExprInt):
            # A constant does not have any dependency
            output = set()

        elif depnode.line_nb == 0:
            # Beginning of a block, inter-block resolving is not done here
            output = set()

        else:
            # Intra-block resolving
            ## Get dependencies
            read = set()

            modifier = False

            for affect in self._get_affblock(depnode):
                if affect.dst == depnode.element:
                    elements = self._follow_apply_cb(affect.src)
                    read.update(elements)
                    modifier = True

            ## If it's not a modifier affblock, reinject current element
            if not modifier:
                read = set([FollowExpr(True, depnode.element)])

            ## Build output
            output = FollowExpr.to_depnodes(read, depnode.label,
                                            depnode.line_nb - 1, modifier)

        return output

    def _updateDependencyDict(self, depdict):
        """Update DependencyDict until a fixed point is reached
        @depdict: DependencyDict to update"""

        # Prepare the work list
        todo = set(depdict.pending)

        # Pending states will be handled
        depdict.pending.clear()

        while todo:
            depnode = todo.pop()
            if isinstance(depnode.element, m2_expr.ExprInt):
                # A constant does not have any dependency
                continue

            if depdict.is_head(depnode):
                depdict.pending.add(depnode)
                # A head cannot have dependencies inside the current IRblock
                continue

            # Find dependency of the current depnode
            sub_depnodes = self._resolve_depNode(depnode)
            depdict.cache[depnode] = FollowExpr.extract_depnodes(sub_depnodes)

            # Add to the worklist its dependencies
            todo.update(FollowExpr.extract_depnodes(sub_depnodes,
                                                    only_follow=True))

        # Pending states will be override in cache
        for depnode in depdict.pending:
            try:
                del depdict.cache[depnode]
            except KeyError:
                continue

    def _get_previousblocks(self, label):
        """Return an iterator on predecessors blocks of @label, with their
        lengths"""
        preds = self._ira.g.predecessors_iter(label)
        for pred_label in preds:
            length = len(self._get_irs(pred_label))
            yield (pred_label, length)

    def _processInterBloc(self, depnodes, heads):
        """Create a DependencyDict from @depnodes, and propagate DependencyDicts
        through all blocs
        """
        # Create an DependencyDict which will only contain our depnodes
        current_depdict = DependencyDict(list(depnodes)[0].label, [])
        current_depdict.pending.update(depnodes)

        # Init the work list
        done = {}
        todo = [current_depdict]

        while todo:
            depdict = todo.pop()

            # Update the dependencydict until fixed point is reached
            self._updateDependencyDict(depdict)

            # Clean irrelevant path
            depdict.filter_used_nodes(depnodes)

            # Avoid infinite loops
            label = depdict.label
            if depdict in done.get(label, []):
                continue
            done.setdefault(label, []).append(depdict)

            # No more dependencies
            if len(depdict.pending) == 0:
                yield depdict.copy()
                continue

            # Has a predecessor ?
            is_final = True

            # Propagate the DependencyDict to all parents
            for label, irb_len in self._get_previousblocks(depdict.label):
                is_final = False

                ## Duplicate the DependencyDict
                new_depdict = depdict.extend(label)

                if self._implicit:
                    ### Implicit dependencies: IRDst will be link with heads
                    implicit_depnode = DependencyNode(label, self._ira.IRDst,
                                                      irb_len, modifier=False)
                    new_depdict.pending.add(implicit_depnode)

                ## Create links between DependencyDict
                for depnode_head in depdict.pending:
                    ### Follow the head element in the parent
                    new_depnode = DependencyNode(label, depnode_head.element,
                                                 irb_len)
                    ### The new node has to be computed in _updateDependencyDict
                    new_depdict.cache[depnode_head] = set([new_depnode])
                    new_depdict.pending.add(new_depnode)

                    ### Handle implicit dependencies
                    if self._implicit:
                        new_depdict.cache[depnode_head].add(implicit_depnode)


                ## Manage the new element
                todo.append(new_depdict)

            # Return the node if it's a final one, ie. it's a head (in graph
            # or defined by caller)
            if is_final or depdict.label in heads:
                yield depdict.copy()

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
        input_depnodes = set()
        for element in elements:
            input_depnodes.add(DependencyNode(label, element, line_nb))

        # Compute final depdicts
        depdicts = self._processInterBloc(input_depnodes, heads)

        # Unify solutions
        unified = []
        cls_res = DependencyResultImplicit if self._implicit else DependencyResult
        for final_depdict in depdicts:
            ## Keep only relevant nodes
            final_depdict.clean_modifiers_in_cache()
            final_depdict.filter_used_nodes(input_depnodes)

            ## Remove duplicate solutions
            if final_depdict not in unified:
                unified.append(final_depdict)
                ### Return solutions as DiGraph
                yield cls_res(self._ira, final_depdict, input_depnodes)

    def get_fromDepNodes(self, depnodes, heads):
        """Alias for the get() method. Use the attributes of @depnodes as
        argument.
        PRE: Labels and lines of depnodes have to be equals
        @depnodes: set of DependencyNode instances
        @heads: set of asm_label instances
        """
        lead = list(depnodes)[0]
        elements = set([depnode.element for depnode in depnodes])
        return self.get(lead.label, elements, lead.line_nb, heads)

    def get_fromEnd(self, label, elements, heads):
        """Alias for the get() method. Consider that the dependency is asked at
        the end of the block named @label.
        @label: asm_label instance
        @elements: set of Expr instances
        @heads: set of asm_label instances
        """
        return self.get(label, elements, len(self._get_irs(label)), heads)

