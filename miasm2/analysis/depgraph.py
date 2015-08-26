"""Provide dependency graph"""
import itertools
from collections import deque
from UserDict import IterableUserDict

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

    __slots__ = ["_label", "_element", "_line_nb", "_modifier",
                 "_step", "_nostep_repr", "_hash"]
    def __init__(self, label, element, line_nb, step, modifier=False):
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
        self._step = step
        self._nostep_repr = (self._label, self._line_nb, self._element)
        self._hash = hash(
            (self._label, self._element, self._line_nb, self._step))

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
                self.line_nb == depnode.line_nb and
                self.step == depnode.step)

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
        return "<%s %s %s %s M:%s S:%s>" % (self.__class__.__name__,
                                            self.label.name, self.element,
                                            self.line_nb, self.modifier,
                                            self.step)

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

    @property
    def step(self):
        "Step of the current node"
        return self._step

    @property
    def modifier(self):
        """Evaluating the current line involves a modification of tracked
        dependencies"""
        return self._modifier

    @modifier.setter
    def modifier(self, value):
        """Evaluating the current line involves a modification of tracked
        dependencies if @value.
        @value: boolean"""
        self._modifier = value


class CacheWrapper(IterableUserDict):

    """Wrapper class for cache dictionnary"""

    def __init__(self, dct=None):
        """Create a CacheWrapper with value @dct."""
        IterableUserDict.__init__(self, dct)
        self._nostep_cache = None
        self._nostep_keys = None

    def __eq__(self, cache):
        """Returns True if the nostep caches are equals"""
        if self.nostep_keys != cache.nostep_keys:
            return False
        return self.nostep_cache == cache.nostep_cache

    @property
    def nostep_keys(self):
        """List of dictonnary keys without the step attribute.
        The list is generated once when the method is called and not updated
        afterward.
        """
        if self._nostep_keys is None:
            self._nostep_keys = set(key.nostep_repr for key in self.data)
        return self._nostep_keys

    @property
    def nostep_cache(self):
        """Dictionnary of DependencyNode and their dependencies,
        without the step attribute.
        The dictionnary is generated once when the method is called for the
        first time and not updated afterward.
        """
        if self._nostep_cache is None:
            self._nostep_cache = {}
            for (node, values) in self.data.iteritems():
                self._nostep_cache.setdefault(node.nostep_repr, set()).update(
                    set(val.nostep_repr for val in values))
        return self._nostep_cache


class DependencyDict(object):

    """Internal structure for the DependencyGraph algorithm"""
    __slots__ = ["_label", "_history", "_pending", "_cache"]

    def __init__(self, label, history):
        """Create a DependencyDict
        @label: asm_label, current IRblock label
        @history: list of DependencyDict
        """
        self._label = label
        self._history = history
        self._pending = set()

        # DepNode -> set(DepNode)
        self._cache = CacheWrapper()

    def __eq__(self, depdict):
        if not isinstance(depdict, self.__class__):
            return False
        return (self._label == depdict.label and
                self.cache == depdict.cache)

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

    def _get_modifiers_in_cache(self, nodes_heads):
        """Find modifier nodes in cache starting from @nodes_heads.
        Returns new cache"""
        # 'worklist_depnode' order is needed (depth first)
        worklist_depnodes = list(nodes_heads)
        # Temporary cache
        cache = {}
        # Partially resolved 'cache' elements
        worklist = []

        # Build worklist and cache for non modifiers
        while worklist_depnodes:
            depnode = worklist_depnodes.pop()
            # Resolve node dependencies
            if depnode in cache:
                # Depnode previously resolved
                continue

            if depnode not in self._cache:
                # Final node
                if not depnode.modifier:
                    cache[depnode] = []
                continue

            # Propagate to son
            dependencies = self._cache[depnode]
            for son in dependencies:
                worklist_depnodes.append(son)
            # Save partially resolved dependency
            worklist.append((depnode, dependencies))

        # Convert worklist to cache
        while worklist:
            depnode, dependencies = worklist.pop()
            parallels = []
            for node in dependencies:
                if node.modifier:
                    parallels.append([node])
                else:
                    parallels.append(cache[node])
            out = set()
            for parallel in itertools.product(*[p for p in parallels if p]):
                out.update(parallel)
            cache[depnode] = out

        return cache

    def clean_modifiers_in_cache(self, node_heads):
        """Remove intermediary states (non modifier depnodes) in the internal
        cache values"""

        self._cache = CacheWrapper(self._get_modifiers_in_cache(node_heads))


    def _build_depgraph(self, depnode):
        """Recursively build the final list of DiGraph, and clean up unmodifier
        nodes
        @depnode: starting node
        """

        if depnode not in self._cache or \
                not self._cache[depnode]:
            # There is no dependency
            graph = DiGraph()
            graph.add_node(depnode)
            return graph

        # Recursion
        dependencies = list(self._cache[depnode])

        graphs = []
        for sub_depnode in dependencies:
            graphs.append(self._build_depgraph(sub_depnode))

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
            subgraphs.append(self._build_depgraph(starting_node))

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

    def filter_unmodifier_loops(self, implicit, irdst):
        """
        Remove unmodifier node creating dependency loops over
        pending elements in cache.
        @implicit: boolean
        @irdst: ExprId instance of IRDst register
        """

        previous_dict = None
        # Get pending nodes of last time the label was handled
        for hist_dict in reversed(self.history):
            if hist_dict.label == self.label:
                previous_dict = hist_dict
                break

        if not previous_dict:
            return

        nostep_pending = [node.nostep_repr for node in self.pending]

        to_remove = set()
        for depnode in previous_dict.pending:
            if (depnode.nostep_repr not in nostep_pending or
                    implicit and depnode.element == irdst):
                continue

            to_remove.update(self._non_modifier_in_loop(depnode))

            # Replace unused keys by previous ones
            for key in to_remove:
                if depnode.nostep_repr == key.nostep_repr:
                    self._cache[depnode] = self._cache.get(key, set()).copy()
                    self.pending.discard(key)
                    self.pending.add(depnode)

                    # Replace occurences of key to remove
                    for dependencies in self._cache.itervalues():
                        if key in dependencies:
                            dependencies.remove(key)
                            dependencies.add(depnode)

                if self._cache.has_key(key):
                    del self._cache[key]

    def _non_modifier_in_loop(self, depnode):
        """
        Walk from @depnode until a node with the same nostep_repr is
        encountered.
        Returns a set of unmodifier nodes met in the path if no modifier was
        found.
        Returns set() if there exist a modifier node on the path.
        """
        if not self.cache.has_key(depnode):
            return set()
        # Init
        todo = set(self.cache[depnode])
        unmodifier_nodes = []

        # Map
        while todo:
            node = todo.pop()
            if node in unmodifier_nodes:
                continue
            if node.modifier:
                return set()
            unmodifier_nodes.append(node)
            if not node in self._cache:
                continue
            if node.nostep_repr == depnode.nostep_repr:
                unmodifier_nodes.append(node)
                break

            for sub_node in self._cache[node]:
                todo.add(sub_node)

        return unmodifier_nodes


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
        """Returns a DiGraph instance representing the DependencyGraph"""
        if self._graph is None:
            self._graph = self._depdict.as_graph(self._input_depnodes)
        return self._graph

    @property
    def history(self):
        """List of depdict corresponding to the blocks encountered in the
        analysis"""
        return list(self._depdict.history) + [self._depdict]

    @property
    def unresolved(self):
        """Set of nodes whose dependencies weren't found"""
        return set(node.nostep_repr for node in self._depdict.pending
                    if node.element != self._ira.IRDst)

    @property
    def relevant_nodes(self):
        """Set of nodes directly and indirectly influencing
        @self.input_depnodes"""
        output = set()
        for depnodes in self._depdict.cache.values():
            output.update(depnodes)
        return output

    @property
    def relevant_labels(self):
        """List of labels containing nodes influencing @self.input_depnodes.
        The history order is preserved.
        """
        # Get used labels
        used_labels = set(depnode.label for depnode in self.relevant_nodes)

        # Keep history order
        output = []
        for label in [depdict.label for depdict in self.history]:
            if label in used_labels:
                output.append(label)

        return output

    @property
    def input(self):
        """Set of DependencyGraph start nodes"""
        return self._input_depnodes

    @property
    def has_loop(self):
        """True if current dictionnary has a loop"""
        if self._has_loop is None:
            self._has_loop = (len(self.relevant_labels) !=
                              len(set(self.relevant_labels)))
        return self._has_loop

    def emul(self, ctx=None, step=False):
        """Symbolic execution of relevant nodes according to the history
        Return the values of input nodes' elements
        @ctx: (optional) Initial context as dictionnary
        @step: (optional) Verbose execution

        Warning: The emulation is not sound if the input nodes depend on loop
        variant.
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
        symb_exec = symbexec(self._ira, ctx_init)
        symb_exec.emulbloc(irbloc(temp_label, affects), step=step)

        # Return only inputs values (others could be wrongs)
        return {depnode.element: symb_exec.symbols[depnode.element]
                for depnode in self.input}


class DependencyResultImplicit(DependencyResult):

    """Stand for a result of a DependencyGraph with implicit option

    Provide path constraints using the z3 solver"""
    __slots__ = ["_ira", "_depdict", "_input_depnodes", "_graph",
                 "_has_loop", "_solver"]

    # Z3 Solver instance
    _solver = None

    def emul(self, ctx=None, step=False):
        # Init
        ctx_init = self._ira.arch.regs.regs_init
        if ctx is not None:
            ctx_init.update(ctx)
        depnodes = self.relevant_nodes
        solver = z3.Solver()
        symb_exec = symbexec(self._ira, ctx_init)
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
            dst = symb_exec.emulbloc(irbloc(temp_label, affects), step=step)

            # Add constraint
            if hist_nb + 1 < history_size:
                next_label = history[hist_nb + 1]
                expected = symb_exec.eval_expr(m2_expr.ExprId(next_label, 32))
                constraint = m2_expr.ExprAff(dst, expected)
                solver.add(Translator.to_language("z3").from_expr(constraint))

        # Save the solver
        self._solver = solver

        # Return only inputs values (others could be wrongs)
        return {depnode.element: symb_exec.symbols[depnode.element]
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
    __slots__ = ["follow", "element"]

    def __init__(self, follow, element):
        self.follow = follow
        self.element = element

    @staticmethod
    def to_depnodes(follow_exprs, label, line, modifier, step):
        """Build a set of FollowExpr(DependencyNode) from the @follow_exprs set
        of FollowExpr
        @follow_exprs: set of FollowExpr
        @label: asm_label instance
        @line: integer
        @modifier: boolean
        @step: integer
        """
        dependencies = set()
        for follow_expr in follow_exprs:
            dependencies.add(FollowExpr(follow_expr.follow,
                                        DependencyNode(label,
                                                       follow_expr.element,
                                                       line,
                                                       step,
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
        @follow_mem: (optional) Track memory syntactically
        @follow_call: (optional) Track through "call"
        """
        # Init
        self._ira = ira
        self._implicit = implicit
        self._step_counter = itertools.count()
        self._current_step = next(self._step_counter)

        # The IRA graph must be computed
        assert hasattr(self._ira, 'g')

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

    @property
    def step_counter(self):
        "Iteration counter"
        return self._step_counter

    @property
    def current_step(self):
        "Current value of iteration counter"
        return self._current_step

    def inc_step(self):
        "Increment and return the current step"
        self._current_step = next(self._step_counter)
        return self._current_step

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
        for expr in exprs:
            if not expr_is_label(expr):
                follow.add(expr)

        return follow, set()

    @staticmethod
    def _follow_mem_wrapper(exprs, mem_read):
        """Wrapper to follow or not expression from memory pointer"""
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
            if expr.is_function_call():
                nofollow.add(expr)
            else:
                follow.add(expr)
        return follow, nofollow

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

    def _get_irs(self, label):
        "Return the irs associated to @label"
        return self._ira.blocs[label].irs

    def _get_affblock(self, depnode):
        """Return the list of ExprAff associtiated to @depnode.
        LINE_NB must be > 0"""
        return self._get_irs(depnode.label)[depnode.line_nb - 1]

    def _direct_depnode_dependencies(self, depnode):
        """Compute and return the dependencies involved by @depnode,
        over the instruction @depnode.line_,.
        Return a set of FollowExpr"""

        if isinstance(depnode.element, m2_expr.ExprInt):
            # A constant does not have any dependency
            output = set()

        elif depnode.line_nb == 0:
            # Beginning of a block, inter-block resolving is not done here
            output = set()

        else:
            # Intra-block resolving
            # Get dependencies
            read = set()
            modifier = False

            for affect in self._get_affblock(depnode):
                if affect.dst == depnode.element:
                    elements = self._follow_apply_cb(affect.src)
                    read.update(elements)
                    modifier = True

            # If it's not a modifier affblock, reinject current element
            if not modifier:
                read = set([FollowExpr(True, depnode.element)])

            # Build output
            output = FollowExpr.to_depnodes(read, depnode.label,
                                            depnode.line_nb - 1, modifier,
                                            self.current_step)
        return output

    def _resolve_intrablock_dep(self, depdict):
        """Resolve the dependencies of nodes in @depdict.pending inside
        @depdict.label until a fixed point is reached.
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
            sub_depnodes = self._direct_depnode_dependencies(depnode)
            depdict.cache[depnode] = FollowExpr.extract_depnodes(sub_depnodes)

            # Add to the worklist its dependencies
            todo.update(FollowExpr.extract_depnodes(sub_depnodes,
                                                    only_follow=True))

        # Pending states will be overriden in cache
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

    def _compute_interblock_dep(self, depnodes, heads):
        """Create a DependencyDict from @depnodes, and propagate
        DependencyDicts through all blocs
        """
        # Create a DependencyDict which will only contain our depnodes
        current_depdict = DependencyDict(list(depnodes)[0].label, [])
        current_depdict.pending.update(depnodes)

        # Init the work list
        done = {}
        todo = deque([current_depdict])

        while todo:
            depdict = todo.popleft()

            # Update the dependencydict until fixed point is reached
            self._resolve_intrablock_dep(depdict)
            self.inc_step()

            # Clean irrelevant path
            depdict.filter_unmodifier_loops(self._implicit, self._ira.IRDst)

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

                # Duplicate the DependencyDict
                new_depdict = depdict.extend(label)

                if self._implicit:
                    # Implicit dependencies: IRDst will be link with heads
                    implicit_depnode = DependencyNode(label, self._ira.IRDst,
                                                      irb_len,
                                                      self.current_step,
                                                      modifier=False)

                # Create links between DependencyDict
                for depnode_head in depdict.pending:
                    # Follow the head element in the parent
                    new_depnode = DependencyNode(label, depnode_head.element,
                                                 irb_len,
                                                 self.current_step)
                    # The new node has to be analysed
                    new_depdict.cache[depnode_head] = set([new_depnode])
                    new_depdict.pending.add(new_depnode)

                    # Handle implicit dependencies
                    if self._implicit:
                        new_depdict.cache[depnode_head].add(implicit_depnode)
                        new_depdict.pending.add(implicit_depnode)

                # Manage the new element
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
            input_depnodes.add(DependencyNode(label, element, line_nb,
                                              self.current_step))

        # Compute final depdicts
        depdicts = self._compute_interblock_dep(input_depnodes, heads)

        # Unify solutions
        unified = []
        cls_res = DependencyResultImplicit if self._implicit else \
            DependencyResult

        for final_depdict in depdicts:
            # Keep only relevant nodes
            final_depdict.clean_modifiers_in_cache(input_depnodes)
            final_depdict.filter_used_nodes(input_depnodes)

            # Remove duplicate solutions
            if final_depdict not in unified:
                unified.append(final_depdict)

                # Return solutions as DiGraph
                yield cls_res(self._ira, final_depdict, input_depnodes)

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

    def get_from_end(self, label, elements, heads):
        """Alias for the get() method. Consider that the dependency is asked at
        the end of the block named @label.
        @label: asm_label instance
        @elements: set of Expr instances
        @heads: set of asm_label instances
        """
        return self.get(label, elements, len(self._get_irs(label)), heads)
