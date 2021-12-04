from collections import defaultdict, namedtuple

from future.utils import viewitems, viewvalues
import re


class DiGraph(object):

    """Implementation of directed graph"""

    # Stand for a cell in a dot node rendering
    DotCellDescription = namedtuple("DotCellDescription",
                                    ["text", "attr"])

    def __init__(self):
        self._nodes = set()
        self._edges = []
        # N -> Nodes N2 with a edge (N -> N2)
        self._nodes_succ = {}
        # N -> Nodes N2 with a edge (N2 -> N)
        self._nodes_pred = {}

        self.escape_chars = re.compile('[' + re.escape('{}') + '&|<>' + ']')


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

    def merge(self, graph):
        """Merge the current graph with @graph
        @graph: DiGraph instance
        """
        for node in graph._nodes:
            self.add_node(node)
        for edge in graph._edges:
            self.add_edge(*edge)

    def __add__(self, graph):
        """Wrapper on `.merge`"""
        self.merge(graph)
        return self

    def copy(self):
        """Copy the current graph instance"""
        graph = self.__class__()
        return graph + self

    def __eq__(self, graph):
        if not isinstance(graph, self.__class__):
            return False
        if self._nodes != graph.nodes():
            return False
        return sorted(self._edges) == sorted(graph.edges())

    def __ne__(self, other):
        return not self.__eq__(other)

    def add_node(self, node):
        """Add the node @node to the graph.
        If the node was already present, return False.
        Otherwise, return True
        """
        if node in self._nodes:
            return False
        self._nodes.add(node)
        self._nodes_succ[node] = []
        self._nodes_pred[node] = []
        return True

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

    def discard_edge(self, src, dst):
        """Remove edge between @src and @dst if it exits"""
        if (src, dst) in self._edges:
            self.del_edge(src, dst)

    def predecessors_iter(self, node):
        if not node in self._nodes_pred:
            return
        for n_pred in self._nodes_pred[node]:
            yield n_pred

    def predecessors(self, node):
        return [x for x in self.predecessors_iter(node)]

    def successors_iter(self, node):
        if not node in self._nodes_succ:
            return
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
        """
        Searches for paths from @src to @dst
        @src: loc_key of basic block from which it should start
        @dst: loc_key of basic block where it should stop
        @cycles_count: maximum number of times a basic block can be processed
        @done: dictionary of already processed loc_keys, it's value is number of times it was processed
        @out: list of paths from @src to @dst
        """
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

    def find_path_from_src(self, src, dst, cycles_count=0, done=None):
        """
        This function does the same as function find_path.
        But it searches the paths from src to dst, not vice versa like find_path.
        This approach might be more efficient in some cases.
        @src: loc_key of basic block from which it should start
        @dst: loc_key of basic block where it should stop
        @cycles_count: maximum number of times a basic block can be processed
        @done: dictionary of already processed loc_keys, it's value is number of times it was processed
        @out: list of paths from @src to @dst
        """

        if done is None:
            done = {}
        if src == dst:
            return [[src]]
        if src in done and done[src] > cycles_count:
            return [[]]
        out = []
        for node in self.successors(src):
            done_n = dict(done)
            done_n[src] = done_n.get(src, 0) + 1
            for path in self.find_path_from_src(node, dst, cycles_count, done_n):
                if path and path[len(path)-1] == dst:
                    out.append([src] + path)
        return out

    def nodeid(self, node):
        """
        Returns uniq id for a @node
        @node: a node of the graph
        """
        return hash(node) & 0xFFFFFFFFFFFFFFFF

    def node2lines(self, node):
        """
        Returns an iterator on cells of the dot @node.
        A DotCellDescription or a list of DotCellDescription are accepted
        @node: a node of the graph
        """
        yield self.DotCellDescription(text=str(node), attr={})

    def node_attr(self, node):
        """
        Returns a dictionary of the @node's attributes
        @node: a node of the graph
        """
        return {}

    def edge_attr(self, src, dst):
        """
        Return a dictionary of attributes for the edge between @src and @dst
        @src: the source node of the edge
        @dst: the destination node of the edge
        """
        return {}

    @staticmethod
    def _fix_chars(token):
        return "&#%04d;" % ord(token.group())

    @staticmethod
    def _attr2str(default_attr, attr):
        return ' '.join(
            '%s="%s"' % (name, value)
            for name, value in
            viewitems(dict(default_attr,
                           **attr))
        )

    def escape_text(self, text):
        return self.escape_chars.sub(self._fix_chars, text)

    def dot(self):
        """Render dot graph with HTML"""

        td_attr = {'align': 'left'}
        nodes_attr = {'shape': 'Mrecord',
                      'fontname': 'Courier New'}

        out = ["digraph asm_graph {"]

        # Generate basic nodes
        out_nodes = []
        for node in self.nodes():
            node_id = self.nodeid(node)
            out_node = '%s [\n' % node_id
            out_node += self._attr2str(nodes_attr, self.node_attr(node))
            out_node += 'label =<<table border="0" cellborder="0" cellpadding="3">'

            node_html_lines = []

            for lineDesc in self.node2lines(node):
                out_render = ""
                if isinstance(lineDesc, self.DotCellDescription):
                    lineDesc = [lineDesc]
                for col in lineDesc:
                    out_render += "<td %s>%s</td>" % (
                        self._attr2str(td_attr, col.attr),
                        self.escape_text(str(col.text)))
                node_html_lines.append(out_render)

            node_html_lines = ('<tr>' +
                               ('</tr><tr>').join(node_html_lines) +
                               '</tr>')

            out_node += node_html_lines + "</table>> ];"
            out_nodes.append(out_node)

        out += out_nodes

        # Generate links
        for src, dst in self.edges():
            attrs = self.edge_attr(src, dst)

            attrs = ' '.join(
                '%s="%s"' % (name, value)
                for name, value in viewitems(attrs)
            )

            out.append('%s -> %s' % (self.nodeid(src), self.nodeid(dst)) +
                       '[' + attrs + '];')

        out.append("}")
        return '\n'.join(out)


    def graphviz(self):
        try:
            import re
            import graphviz


            self.gv = graphviz.Digraph('html_table')
            self._dot_offset = False
            td_attr = {'align': 'left'}
            nodes_attr = {'shape': 'Mrecord',
                          'fontname': 'Courier New'}

            for node in self.nodes():
                elements = [x for x in self.node2lines(node)]
                node_id = self.nodeid(node)
                out_node = '<<table border="0" cellborder="0" cellpadding="3">'

                node_html_lines = []
                for lineDesc in elements:
                    out_render = ""
                    if isinstance(lineDesc, self.DotCellDescription):
                        lineDesc = [lineDesc]
                    for col in lineDesc:
                        out_render += "<td %s>%s</td>" % (
                            self._attr2str(td_attr, col.attr),
                            self.escape_text(str(col.text)))
                    node_html_lines.append(out_render)

                node_html_lines = ('<tr>' +
                                   ('</tr><tr>').join(node_html_lines) +
                                   '</tr>')

                out_node += node_html_lines + "</table>>"
                attrs = dict(nodes_attr)
                attrs.update(self.node_attr(node))
                self.gv.node(
                    "%s" % node_id,
                    out_node,
                    attrs,
                )


            for src, dst in self.edges():
                attrs = self.edge_attr(src, dst)
                self.gv.edge(
                    str(self.nodeid(src)),
                    str(self.nodeid(dst)),
                    "",
                    attrs,
                )

            return self.gv
        except ImportError:
            # Skip as graphviz is not installed
            return None


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

    def predecessors_stop_node_iter(self, node, head):
        if node == head:
            return
        for next_node in self.predecessors_iter(node):
            yield next_node

    def reachable_sons(self, head):
        """Compute all nodes reachable from node @head. Each son is an
        immediate successor of an arbitrary, already yielded son of @head"""
        return self._reachable_nodes(head, self.successors_iter)

    def reachable_parents(self, leaf):
        """Compute all parents of node @leaf. Each parent is an immediate
        predecessor of an arbitrary, already yielded parent of @leaf"""
        return self._reachable_nodes(leaf, self.predecessors_iter)

    def reachable_parents_stop_node(self, leaf, head):
        """Compute all parents of node @leaf. Each parent is an immediate
        predecessor of an arbitrary, already yielded parent of @leaf.
        Do not compute reachables past @head node"""
        return self._reachable_nodes(
            leaf,
            lambda node_cur: self.predecessors_stop_node_iter(
                node_cur, head
            )
        )


    @staticmethod
    def _compute_generic_dominators(head, reachable_cb, prev_cb, next_cb):
        """Generic algorithm to compute either the dominators or postdominators
        of the graph.
        @head: the head/leaf of the graph
        @reachable_cb: sons/parents of the head/leaf
        @prev_cb: return predecessors/successors of a node
        @next_cb: return successors/predecessors of a node
        """

        nodes = set(reachable_cb(head))
        dominators = {}
        for node in nodes:
            dominators[node] = set(nodes)

        dominators[head] = set([head])
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




    def compute_dominator_tree(self, head):
        """
        Computes the dominator tree of a graph
        :param head: head of graph
        :return: DiGraph
        """
        idoms = self.compute_immediate_dominators(head)
        dominator_tree = DiGraph()
        for node in idoms:
            dominator_tree.add_edge(idoms[node], node)

        return dominator_tree

    @staticmethod
    def _walk_generic_dominator(node, gen_dominators, succ_cb):
        """Generic algorithm to return an iterator of the ordered list of
        @node's dominators/post_dominator.

        The function doesn't return the self reference in dominators.
        @node: The start node
        @gen_dominators: The dictionary containing at least node's
        dominators/post_dominators
        @succ_cb: return predecessors/successors of a node

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
        @dominators: The dictionary containing at least node's dominators
        """
        return self._walk_generic_dominator(node,
                                            dominators,
                                            self.predecessors_iter)

    def walk_postdominators(self, node, postdominators):
        """Return an iterator of the ordered list of @node's postdominators
        The function doesn't return the self reference in postdominators.
        @node: The start node
        @postdominators: The dictionary containing at least node's
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

    def compute_immediate_postdominators(self,tail):
        """Compute the immediate postdominators of the graph"""
        postdominators = self.compute_postdominators(tail)
        ipdoms = {}

        for node in postdominators:
            for successor in self.walk_postdominators(node, postdominators):
                if successor in postdominators[node] and node != successor:
                    ipdoms[node] = successor
                    break
        return ipdoms

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
            if len(self._nodes_pred[node]) >= 2:
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

    def has_loop(self):
        """Return True if the graph contains at least a cycle"""
        todo = list(self.nodes())
        # tested nodes
        done = set()
        # current DFS nodes
        current = set()
        while todo:
            node = todo.pop()
            if node in done:
                continue

            if node in current:
                # DFS branch end
                for succ in self.successors_iter(node):
                    if succ in current:
                        return True
                # A node cannot be in current AND in done
                current.remove(node)
                done.add(node)
            else:
                # Launch DFS from node
                todo.append(node)
                current.add(node)
                todo += self.successors(node)

        return False

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
            yield ((a, b), body)

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


    def compute_weakly_connected_components(self):
        """
        Return the weakly connected components
        """
        remaining = set(self.nodes())
        components = []
        while remaining:
            node = remaining.pop()
            todo = set()
            todo.add(node)
            component = set()
            done = set()
            while todo:
                node = todo.pop()
                if node in done:
                    continue
                done.add(node)
                remaining.discard(node)
                component.add(node)
                todo.update(self.predecessors(node))
                todo.update(self.successors(node))
            components.append(component)
        return components



    def replace_node(self, node, new_node):
        """
        Replace @node by @new_node
        """

        predecessors = self.predecessors(node)
        successors = self.successors(node)
        self.del_node(node)
        for predecessor in predecessors:
            if predecessor == node:
                predecessor = new_node
            self.add_uniq_edge(predecessor, new_node)
        for successor in successors:
            if successor == node:
                successor = new_node
            self.add_uniq_edge(new_node, successor)

class DiGraphSimplifier(object):

    """Wrapper on graph simplification passes.

    Instance handle passes lists.
    """

    def __init__(self):
        self.passes = []

    def enable_passes(self, passes):
        """Add @passes to passes to applied
        @passes: sequence of function (DiGraphSimplifier, DiGraph) -> None
        """
        self.passes += passes

    def apply_simp(self, graph):
        """Apply enabled simplifications on graph @graph
        @graph: DiGraph instance
        """
        while True:
            new_graph = graph.copy()
            for simp_func in self.passes:
                simp_func(self, new_graph)

            if new_graph == graph:
                break
            graph = new_graph
        return new_graph

    def __call__(self, graph):
        """Wrapper on 'apply_simp'"""
        return self.apply_simp(graph)


class MatchGraphJoker(object):

    """MatchGraphJoker are joker nodes of MatchGraph, that is to say nodes which
    stand for any node. Restrictions can be added to jokers.

    If j1, j2 and j3 are MatchGraphJoker, one can quickly build a matcher for
    the pattern:
                                         |
                                    +----v----+
                                    |  (j1)   |
                                    +----+----+
                                         |
                                    +----v----+
                                    |  (j2)   |<---+
                                    +----+--+-+    |
                                         |  +------+
                                    +----v----+
                                    |  (j3)   |
                                    +----+----+
                                         |
                                         v
    Using:
    >>> matcher = j1 >> j2 >> j3
    >>> matcher += j2 >> j2
    Or:
    >>> matcher = j1 >> j2 >> j2 >> j3

    """

    def __init__(self, restrict_in=True, restrict_out=True, filt=None,
                 name=None):
        """Instantiate a MatchGraphJoker, with restrictions
        @restrict_in: (optional) if set, the number of predecessors of the
                      matched node must be the same than the joker node in the
                      associated MatchGraph
        @restrict_out: (optional) counterpart of @restrict_in for successors
        @filt: (optional) function(graph, node) -> boolean for filtering
        candidate node
        @name: (optional) helper for displaying the current joker
        """
        if filt is None:
            filt = lambda graph, node: True
        self.filt = filt
        if name is None:
            name = str(id(self))
        self._name = name
        self.restrict_in = restrict_in
        self.restrict_out = restrict_out

    def __rshift__(self, joker):
        """Helper for describing a MatchGraph from @joker
        J1 >> J2 stands for an edge going to J2 from J1
        @joker: MatchGraphJoker instance
        """
        assert isinstance(joker, MatchGraphJoker)

        graph = MatchGraph()
        graph.add_node(self)
        graph.add_node(joker)
        graph.add_edge(self, joker)

        # For future "A >> B" idiom construction
        graph._last_node = joker

        return graph

    def __str__(self):
        info = []
        if not self.restrict_in:
            info.append("In:*")
        if not self.restrict_out:
            info.append("Out:*")
        return "Joker %s %s" % (self._name,
                                "(%s)" % " ".join(info) if info else "")


class MatchGraph(DiGraph):

    """MatchGraph intends to be the counterpart of match_expr, but for DiGraph

    This class provides API to match a given DiGraph pattern, with addidionnal
    restrictions.
    The implemented algorithm is a naive approach.

    The recommended way to instantiate a MatchGraph is the use of
    MatchGraphJoker.
    """

    def __init__(self, *args, **kwargs):
        super(MatchGraph, self).__init__(*args, **kwargs)
        # Construction helper
        self._last_node = None

    # Construction helpers
    def __rshift__(self, joker):
        """Construction helper, adding @joker to the current graph as a son of
        _last_node
        @joker: MatchGraphJoker instance"""
        assert isinstance(joker, MatchGraphJoker)
        assert isinstance(self._last_node, MatchGraphJoker)

        self.add_node(joker)
        self.add_edge(self._last_node, joker)
        self._last_node = joker
        return self

    def __add__(self, graph):
        """Construction helper, merging @graph with self
        @graph: MatchGraph instance
        """
        assert isinstance(graph, MatchGraph)

        # Reset helpers flag
        self._last_node = None
        graph._last_node = None

        # Merge graph into self
        for node in graph.nodes():
            self.add_node(node)
        for edge in graph.edges():
            self.add_edge(*edge)

        return self

    # Graph matching
    def _check_node(self, candidate, expected, graph, partial_sol=None):
        """Check if @candidate can stand for @expected in @graph, given @partial_sol
        @candidate: @graph's node
        @expected: MatchGraphJoker instance
        @graph: DiGraph instance
        @partial_sol: (optional) dictionary of MatchGraphJoker -> @graph's node
        standing for a partial solution
        """
        # Avoid having 2 different joker for the same node
        if partial_sol and candidate in viewvalues(partial_sol):
            return False

        # Check lambda filtering
        if not expected.filt(graph, candidate):
            return False

        # Check arity
        # If filter_in/out, then arity must be the same
        # Otherwise, arity of the candidate must be at least equal
        if ((expected.restrict_in == True and
             len(self.predecessors(expected)) != len(graph.predecessors(candidate))) or
            (expected.restrict_in == False and
             len(self.predecessors(expected)) > len(graph.predecessors(candidate)))):
            return False
        if ((expected.restrict_out == True and
             len(self.successors(expected)) != len(graph.successors(candidate))) or
            (expected.restrict_out == False and
             len(self.successors(expected)) > len(graph.successors(candidate)))):
            return False

        # Check edges with partial solution if any
        if not partial_sol:
            return True
        for pred in self.predecessors(expected):
            if (pred in partial_sol and
                    partial_sol[pred] not in graph.predecessors(candidate)):
                return False

        for succ in self.successors(expected):
            if (succ in partial_sol and
                    partial_sol[succ] not in graph.successors(candidate)):
                return False

        # All checks OK
        return True

    def _propagate_sol(self, node, partial_sol, graph, todo, propagator):
        """
        Try to extend the current @partial_sol by propagating the solution using
        @propagator on @node.
        New solutions are added to @todo
        """
        real_node = partial_sol[node]
        for candidate in propagator(self, node):
            # Edge already in the partial solution, skip it
            if candidate in partial_sol:
                continue

            # Check candidate
            for candidate_real in propagator(graph, real_node):
                if self._check_node(candidate_real, candidate, graph,
                                    partial_sol):
                    temp_sol = partial_sol.copy()
                    temp_sol[candidate] = candidate_real
                    if temp_sol not in todo:
                        todo.append(temp_sol)

    @staticmethod
    def _propagate_successors(graph, node):
        """Propagate through @node successors in @graph"""
        return graph.successors_iter(node)

    @staticmethod
    def _propagate_predecessors(graph, node):
        """Propagate through @node predecessors in @graph"""
        return graph.predecessors_iter(node)

    def match(self, graph):
        """Naive subgraph matching between graph and self.
        Iterator on matching solution, as dictionary MatchGraphJoker -> @graph
        @graph: DiGraph instance
        In order to obtained correct and complete results, @graph must be
        connected.
        """
        # Partial solution: nodes corrects, edges between these nodes corrects
        # A partial solution is a dictionary MatchGraphJoker -> @graph's node
        todo = list()  # Dictionaries containing partial solution
        done = list()  # Already computed partial solutions

        # Elect first candidates
        to_match = next(iter(self._nodes))
        for node in graph.nodes():
            if self._check_node(node, to_match, graph):
                to_add = {to_match: node}
                if to_add not in todo:
                    todo.append(to_add)

        while todo:
            # When a partial_sol is computed, if more precise partial solutions
            # are found, they will be added to 'todo'
            # -> using last entry of todo first performs a "depth first"
            # approach on solutions
            # -> the algorithm may converge faster to a solution, a desired
            # behavior while doing graph simplification (stopping after one
            # sol)
            partial_sol = todo.pop()

            # Avoid infinite loop and recurrent work
            if partial_sol in done:
                continue
            done.append(partial_sol)

            # If all nodes are matching, this is a potential solution
            if len(partial_sol) == len(self._nodes):
                yield partial_sol
                continue

            # Find node to tests using edges
            for node in partial_sol:
                self._propagate_sol(node, partial_sol, graph, todo,
                                    MatchGraph._propagate_successors)
                self._propagate_sol(node, partial_sol, graph, todo,
                                    MatchGraph._propagate_predecessors)
