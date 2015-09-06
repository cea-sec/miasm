from collections import defaultdict, namedtuple

class DiGraph(object):
    """Implementation of directed graph"""

    def __init__(self):
        self._nodes = set()
        self._edges = []
        # N -> Nodes N2 with a edge (N -> N2)
        self._nodes_succ = {}
        # N -> Nodes N2 with a edge (N2 -> N)
        self._nodes_pred = {}

    def __repr__(self):
        out = []
        for node in self._nodes:
            out.append(str(node))
        for src, dst in self._edges:
            out.append("%s -> %s" % (src, dst))
        return '\n'.join(out)

    def nodes(self):
        return self._nodes

    def edges(self):
        return self._edges

    def add_node(self, node):
        if node in self._nodes:
            return
        self._nodes.add(node)
        self._nodes_succ[node] = []
        self._nodes_pred[node] = []

    def del_node(self, node):
        """Delete the @node of the graph; Also delete every edge to/from this
        @node"""

        if node in self._nodes:
            self._nodes.remove(node)
        for pred in self.predecessors(node):
            self.del_edge(pred, node)
        for succ in self.successors(node):
            self.del_edge(node, succ)

    def add_edge(self, src, dst):
        if not src in self._nodes:
            self.add_node(src)
        if not dst in self._nodes:
            self.add_node(dst)
        self._edges.append((src, dst))
        self._nodes_succ[src].append(dst)
        self._nodes_pred[dst].append(src)

    def add_uniq_edge(self, src, dst):
        """Add an edge from @src to @dst if it doesn't already exist"""
        if (src not in self._nodes_succ or
            dst not in self._nodes_succ[src]):
            self.add_edge(src, dst)

    def del_edge(self, src, dst):
        self._edges.remove((src, dst))
        self._nodes_succ[src].remove(dst)
        self._nodes_pred[dst].remove(src)

    def predecessors_iter(self, node):
        if not node in self._nodes_pred:
            raise StopIteration
        for n_pred in self._nodes_pred[node]:
            yield n_pred

    def predecessors(self, node):
        return [x for x in self.predecessors_iter(node)]

    def successors_iter(self, node):
        if not node in self._nodes_succ:
            raise StopIteration
        for n_suc in self._nodes_succ[node]:
            yield n_suc

    def successors(self, node):
        return [x for x in self.successors_iter(node)]

    def leaves_iter(self):
        for node in self._nodes:
            if not self._nodes_succ[node]:
                yield node

    def leaves(self):
        return [x for x in self.leaves_iter()]

    def heads_iter(self):
        for node in self._nodes:
            if not self._nodes_pred[node]:
                yield node

    def heads(self):
        return [x for x in self.heads_iter()]

    def find_path(self, src, dst, cycles_count=0, done=None):
        if done is None:
            done = {}
        if dst in done and done[dst] > cycles_count:
            return [[]]
        if src == dst:
            return [[src]]
        out = []
        for node in self.predecessors(dst):
            done_n = dict(done)
            done_n[dst] = done_n.get(dst, 0) + 1
            for path in self.find_path(src, node, cycles_count, done_n):
                if path and path[0] == src:
                    out.append(path + [dst])
        return out

    @staticmethod
    def node2str(node):
        return str(node)

    @staticmethod
    def edge2str(src, dst):
        return ""

    def dot(self):
        out = """
digraph asm_graph {
graph [
splines=polyline,
];
node [
fontsize = "16",
shape = "box"
];
"""
        for node in self.nodes():
            out += '%s [label="%s"];\n' % (
                hash(node) & 0xFFFFFFFFFFFFFFFF, self.node2str(node))

        for src, dst in self.edges():
            out += '%s -> %s [label="%s"]\n' % (hash(src) & 0xFFFFFFFFFFFFFFFF,
                                                hash(dst) & 0xFFFFFFFFFFFFFFFF,
                                                self.edge2str(src, dst))
        out += "}"
        return out

    @staticmethod
    def _reachable_nodes(head, next_cb):
        """Generic algorithm to compute all nodes reachable from/to node
        @head"""

        todo = set([head])
        reachable = set()
        while todo:
            node = todo.pop()
            if node in reachable:
                continue
            reachable.add(node)
            yield node
            for next_node in next_cb(node):
                todo.add(next_node)

    def reachable_sons(self, head):
        """Compute all nodes reachable from node @head. Each son is an
        immediate successor of an arbitrary, already yielded son of @head"""
        return self._reachable_nodes(head, self.successors_iter)

    def reachable_parents(self, leaf):
        """Compute all parents of node @leaf. Each parent is an immediate
        predecessor of an arbitrary, already yielded parent of @leaf"""
        return self._reachable_nodes(leaf, self.predecessors_iter)

    @staticmethod
    def _compute_generic_dominators(head, reachable_cb, prev_cb, next_cb):
        """Generic algorithm to compute either the dominators or postdominators
        of the graph.
        @head: the head/leaf of the graph
        @reachable_cb: sons/parents of the head/leaf
        @prev_cb: return predecessors/succesors of a node
        @next_cb: return succesors/predecessors of a node
        """

        nodes = set(reachable_cb(head))
        dominators = {}
        for node in nodes:
            dominators[node] = set(nodes)

        dominators[head] = set([head])
        modified = True
        todo = set(nodes)

        while todo:
            node = todo.pop()

            # Heads state must not be changed
            if node == head:
                continue

            # Compute intersection of all predecessors'dominators
            new_dom = None
            for pred in prev_cb(node):
                if not pred in nodes:
                    continue
                if new_dom is None:
                    new_dom = set(dominators[pred])
                new_dom.intersection_update(dominators[pred])

            # We are not a head to we have at least one dominator
            assert(new_dom is not None)

            new_dom.update(set([node]))

            # If intersection has changed, add sons to the todo list
            if new_dom == dominators[node]:
                continue

            dominators[node] = new_dom
            for succ in next_cb(node):
                todo.add(succ)
        return dominators

    def compute_dominators(self, head):
        """Compute the dominators of the graph"""
        return self._compute_generic_dominators(head,
                                                self.reachable_sons,
                                                self.predecessors_iter,
                                                self.successors_iter)

    def compute_postdominators(self, leaf):
        """Compute the postdominators of the graph"""
        return self._compute_generic_dominators(leaf,
                                                self.reachable_parents,
                                                self.successors_iter,
                                                self.predecessors_iter)

    @staticmethod
    def _walk_generic_dominator(node, gen_dominators, succ_cb):
        """Generic algorithm to return an iterator of the ordered list of
        @node's dominators/post_dominator.

        The function doesn't return the self reference in dominators.
        @node: The start node
        @gen_dominators: The dictionnary containing at least node's
        dominators/post_dominators
        @succ_cb: return predecessors/succesors of a node

        """
        # Init
        done = set()
        if node not in gen_dominators:
            # We are in a branch which doesn't reach head
            return
        node_gen_dominators = set(gen_dominators[node])
        todo = set([node])

        # Avoid working on itself
        node_gen_dominators.remove(node)

        # For each level
        while node_gen_dominators:
            new_node = None

            # Worklist pattern
            while todo:
                node = todo.pop()
                if node in done:
                    continue
                if node in node_gen_dominators:
                    new_node = node
                    break

                # Avoid loops
                done.add(node)

                # Look for the next level
                for pred in succ_cb(node):
                    todo.add(pred)

            # Return the node; it's the next starting point
            assert(new_node is not None)
            yield new_node
            node_gen_dominators.remove(new_node)
            todo = set([new_node])

    def walk_dominators(self, node, dominators):
        """Return an iterator of the ordered list of @node's dominators
        The function doesn't return the self reference in dominators.
        @node: The start node
        @dominators: The dictionnary containing at least node's dominators
        """
        return self._walk_generic_dominator(node,
                                            dominators,
                                            self.predecessors_iter)

    def walk_postdominators(self, node, postdominators):
        """Return an iterator of the ordered list of @node's postdominators
        The function doesn't return the self reference in postdominators.
        @node: The start node
        @postdominators: The dictionnary containing at least node's
        postdominators

        """
        return self._walk_generic_dominator(node,
                                            postdominators,
                                            self.successors_iter)

    def compute_immediate_dominators(self, head):
        """Compute the immediate dominators of the graph"""
        dominators = self.compute_dominators(head)
        idoms = {}

        for node in dominators:
            for predecessor in self.walk_dominators(node, dominators):
                if predecessor in dominators[node] and node != predecessor:
                    idoms[node] = predecessor
                    break
        return idoms

    def compute_dominance_frontier(self, head):
        """
        Compute the dominance frontier of the graph

        Source: Cooper, Keith D., Timothy J. Harvey, and Ken Kennedy.
        "A simple, fast dominance algorithm."
        Software Practice & Experience 4 (2001), p. 9
        """
        idoms = self.compute_immediate_dominators(head)
        frontier = {}

        for node in idoms:
            if self._nodes_pred[node] >= 2:
                for predecessor in self.predecessors_iter(node):
                    runner = predecessor
                    if runner not in idoms:
                        continue
                    while runner != idoms[node]:
                        if runner not in frontier:
                            frontier[runner] = set()

                        frontier[runner].add(node)
                        runner = idoms[runner]
        return frontier

    def _walk_generic_first(self, head, flag, succ_cb):
        """
        Generic algorithm to compute breadth or depth first search
        for a node.
        @head: the head of the graph
        @flag: denotes if @todo is used as queue or stack
        @succ_cb: returns a node's predecessors/successors
        :return: next node
        """
        todo = [head]
        done = set()

        while todo:
            node = todo.pop(flag)
            if node in done:
                continue
            done.add(node)

            for succ in succ_cb(node):
                todo.append(succ)

            yield node

    def walk_breadth_first_forward(self, head):
        """Performs a breadth first search on the graph from @head"""
        return self._walk_generic_first(head, 0, self.successors_iter)

    def walk_depth_first_forward(self, head):
        """Performs a depth first search on the graph from @head"""
        return self._walk_generic_first(head, -1, self.successors_iter)

    def walk_breadth_first_backward(self, head):
        """Performs a breadth first search on the reversed graph from @head"""
        return self._walk_generic_first(head, 0, self.predecessors_iter)

    def walk_depth_first_backward(self, head):
        """Performs a depth first search on the reversed graph from @head"""
        return self._walk_generic_first(head, -1, self.predecessors_iter)

    def compute_natural_loops(self, head):
        """
        Computes all natural loops in the graph.

        Source: Aho, Alfred V., Lam, Monica S., Sethi, R. and Jeffrey Ullman.
        "Compilers: Principles, Techniques, & Tools, Second Edition"
        Pearson/Addison Wesley (2007), Chapter 9.6.6
        :param head: head of the graph
        :return: yield a tuple of the form (back edge, loop body)
        """
        for a, b in self.compute_back_edges(head):
            body = self._compute_natural_loop_body(b, a)
            yield ((b, a), body)

    def compute_back_edges(self, head):
        """
        Computes all back edges from a node to a
        dominator in the graph.
        :param head: head of graph
        :return: yield a back edge
        """
        dominators = self.compute_dominators(head)

        # traverse graph
        for node in self.walk_depth_first_forward(head):
            for successor in self.successors_iter(node):
                # check for a back edge to a dominator
                if successor in dominators[node]:
                    edge = (node, successor)
                    yield edge

    def _compute_natural_loop_body(self, head, leaf):
        """
        Computes the body of a natural loop by a depth-first
        search on the reversed control flow graph.
        :param head: leaf of the loop
        :param leaf: header of the loop
        :return: set containing loop body
        """
        todo = [leaf]
        done = {head}

        while todo:
            node = todo.pop()
            if node in done:
                continue
            done.add(node)

            for predecessor in self.predecessors_iter(node):
                todo.append(predecessor)
        return done

    def compute_strongly_connected_components(self):
        """
        Partitions the graph into strongly connected components.

        Iterative implementation of Gabow's path-based SCC algorithm.
        Source: Gabow, Harold N.
        "Path-based depth-first search for strong and biconnected components."
        Information Processing Letters 74.3 (2000), pp. 109--110

        The iterative implementation is inspired by Mark Dickinson's
        code:
        http://code.activestate.com/recipes/
        578507-strongly-connected-components-of-a-directed-graph/
        :return: yield a strongly connected component
        """
        stack = []
        boundaries = []
        counter = len(self.nodes())

        # init index with 0
        index = {v: 0 for v in self.nodes()}

        # state machine for worklist algorithm
        VISIT, HANDLE_RECURSION, MERGE = 0, 1, 2
        NodeState = namedtuple('NodeState', ['state', 'node'])

        for node in self.nodes():
            # next node if node was already visited
            if index[node]:
                continue

            todo = [NodeState(VISIT, node)]
            done = set()

            while todo:
                current = todo.pop()

                if current.node in done:
                    continue

                # node is unvisited
                if current.state == VISIT:
                    stack.append(current.node)
                    index[current.node] = len(stack)
                    boundaries.append(index[current.node])

                    todo.append(NodeState(MERGE, current.node))
                    # follow successors
                    for successor in self.successors_iter(current.node):
                        todo.append(NodeState(HANDLE_RECURSION, successor))

                # iterative handling of recursion algorithm
                elif current.state == HANDLE_RECURSION:
                    # visit unvisited successor
                    if index[current.node] == 0:
                        todo.append(NodeState(VISIT, current.node))
                    else:
                        # contract cycle if necessary
                        while index[current.node] < boundaries[-1]:
                            boundaries.pop()

                # merge strongly connected component
                else:
                    if index[current.node] == boundaries[-1]:
                        boundaries.pop()
                        counter += 1
                        scc = set()

                        while index[current.node] <= len(stack):
                            popped = stack.pop()
                            index[popped] = counter
                            scc.add(popped)

                            done.add(current.node)

                        yield scc
