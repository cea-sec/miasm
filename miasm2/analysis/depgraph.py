"""Provide dependency graph"""
import itertools
import miasm2.expression.expression as m2_expr
from miasm2.core.graph import DiGraph
from miasm2.core.asmbloc import asm_label
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.symbexec import symbexec
from miasm2.ir.ir import irbloc


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

    def emul(self):
        """Symbolic execution of relevant nodes according to the history
        Return the values of input nodes' elements

        /!\ The emulation is not safe if there is a loop in the relevant labels
        """
        # Init
        new_ira = (self._ira.__class__)()
        lines = self.relevant_nodes
        affects = []

        # Build a single affectation block according to history
        for label in self.relevant_labels[::-1]:
            affected_lines = [line.line_nb for line in lines
                              if line.label == label]
            irs = self._ira.blocs[label].irs
            for line_nb in sorted(affected_lines):
                affects.append(irs[line_nb])

        # Eval the block
        temp_label = asm_label("Temp")
        sb = symbexec(new_ira, new_ira.arch.regs.regs_init)
        sb.emulbloc(irbloc(temp_label, affects))

        # Return only inputs values (others could be wrongs)
        return {depnode.element: sb.symbols[depnode.element]
                for depnode in self.input}


class DependencyGraph(object):
    """Implementation of a dependency graph

    A dependency graph contains DependencyNode as nodes. The oriented edges
    stand for a dependency.
    The dependency graph is made of the lines of a group of IRblock
    *explicitely* involved in the equation of given element.
    """

    def __init__(self, ira):
        """Create a DependencyGraph linked to @ira
        @ira: IRAnalysis instance
        """
        # Init
        self._ira = ira

        # The IRA graph must be computed
        self._ira.gen_graph()

    def _get_irs(self, label):
        "Return the irs associated to @label"
        return self._ira.blocs[label].irs

    def _get_affblock(self, depnode):
        """Return the list of ExprAff associtiated to @depnode.
        LINE_NB must be > 0"""
        return self._get_irs(depnode.label)[depnode.line_nb - 1]

    def _resolve_depNode(self, depnode):
        """Compute and return the dependencies involved by @depnode"""

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
                    ### Avoid tracking useless elements, as XOR EAX, EAX
                    src = expr_simp(affect.src)

                    read.update(src.get_r(mem_read=True, cst_read=True))
                    modifier = True

            ## If it's not a modifier affblock, reinject current element
            if not modifier:
                read = set([depnode.element])

            ## Build output
            dependencies = set()
            for element in read:
                dependencies.add(DependencyNode(depnode.label,
                                                element,
                                                depnode.line_nb - 1,
                                                modifier=modifier))
            output = dependencies

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
            depdict.cache[depnode] = sub_depnodes

            # Add to the worklist its dependencies
            todo.update(sub_depnodes)

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
        done = []
        todo = [current_depdict]

        while todo:
            depdict = todo.pop()

            # Update the dependencydict until fixed point is reached
            self._updateDependencyDict(depdict)

            # Avoid infinite loops
            if depdict in done:
                continue
            done.append(depdict)

            # No more dependencies
            if len(depdict.pending) == 0:
                yield depdict
                continue

            # Propagate the DependencyDict to all parents
            for label, irb_len in self._get_previousblocks(depdict.label):

                ## Duplicate the DependencyDict
                new_depdict = depdict.extend(label)

                ## Create links between DependencyDict
                for depnode_head in depdict.pending:
                    ### Follow the head element in the parent
                    new_depnode = DependencyNode(label, depnode_head.element,
                                                 irb_len)
                    ### The new node has to be computed in _updateDependencyDict
                    new_depdict.cache[depnode_head] = set([new_depnode])
                    new_depdict.pending.add(new_depnode)

                ## Manage the new element
                todo.append(new_depdict)

            # Return the node if it's a final one, ie. it's a head
            if depdict.label in heads:
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
        for final_depdict in depdicts:
            ## Keep only relevant nodes
            final_depdict.clean_modifiers_in_cache()
            final_depdict.filter_used_nodes(input_depnodes)

            ## Remove duplicate solutions
            if final_depdict not in unified:
                unified.append(final_depdict)
                ### Return solutions as DiGraph
                yield DependencyResult(self._ira, final_depdict, input_depnodes)

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


class DependencyGraph_NoMemory(DependencyGraph):
    """Dependency graph without memory tracking.

    That way, the output has following properties:
    - Only explicit dependencies are followed
    - Soundness: all results are corrects
    - Completeness: all possible solutions are founds
    """

    def _resolve_depNode(self, depnode):
        """Compute and return the dependencies involved by @depnode"""
        # Get inital elements
        result = super(DependencyGraph_NoMemory, self)._resolve_depNode(depnode)

        # If @depnode depends on a memory element, give up
        for node in result:
            if isinstance(node.element, m2_expr.ExprMem):
                return set()

        return result
