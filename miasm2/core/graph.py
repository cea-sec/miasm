from collections import defaultdict

class DiGraph(object):
    """Implementation of directed graph"""

    def __init__(self):
        self._nodes = set()
        self._edges = []
        self._nodes_to = {}
        self._nodes_from = {}

    def __repr__(self):
        out = []
        for n in self._nodes:
            out.append(str(n))
        for a, b in self._edges:
            out.append("%s -> %s" % (a, b))
        return '\n'.join(out)

    def nodes(self):
        return self._nodes

    def edges(self):
        return self._edges

    def add_node(self, n):
        if n in self._nodes:
            return
        self._nodes.add(n)
        self._nodes_to[n] = []
        self._nodes_from[n] = []

    def del_node(self, node):
        """Delete the @node of the graph; Also delete every edge to/from this
        @node"""

        if node in self._nodes:
            self._nodes.remove(node)
        for pred in self.predecessors(node):
            self.del_edge(pred, node)
        for succ in self.successors(node):
            self.del_edge(node, succ)

    def add_edge(self, a, b):
        if not a in self._nodes:
            self.add_node(a)
        if not b in self._nodes:
            self.add_node(b)
        self._edges.append((a, b))
        self._nodes_to[a].append((a, b))
        self._nodes_from[b].append((a, b))

    def add_uniq_edge(self, a, b):
        if (a, b) in self._edges:
            return
        else:
            self.add_edge(a, b)

    def del_edge(self, a, b):
        self._edges.remove((a, b))
        self._nodes_to[a].remove((a, b))
        self._nodes_from[b].remove((a, b))

    def predecessors_iter(self, n):
        if not n in self._nodes_from:
            raise StopIteration
        for a, _ in self._nodes_from[n]:
            yield a

    def predecessors(self, n):
        return [x for x in self.predecessors_iter(n)]

    def successors_iter(self, n):
        if not n in self._nodes_to:
            raise StopIteration
        for _, b in self._nodes_to[n]:
            yield b

    def successors(self, n):
        return [x for x in self.successors_iter(n)]

    def leaves_iter(self):
        for n in self._nodes:
            if len(self._nodes_to[n]) == 0:
                yield n

    def leaves(self):
        return [x for x in self.leaves_iter()]

    def heads_iter(self):
        for node in self._nodes:
            if len(self._nodes_from[node]) == 0:
                yield node

    def heads(self):
        return [node for node in self.heads_iter()]

    def roots_iter(self):
        for n in self._nodes:
            if len(self._nodes_from[n]) == 0:
                yield n

    def roots(self):
        return [x for x in self.roots_iter()]

    def find_path(self, a, b, cycles_count=0, done=None):
        if done is None:
            done = {}
        if b in done and done[b] > cycles_count:
            return [[]]
        if a == b:
            return [[a]]
        out = []
        for n in self.predecessors(b):
            done_n = dict(done)
            done_n[b] = done_n.get(b, 0) + 1
            for path in self.find_path(a, n, cycles_count, done_n):
                if path and path[0] == a:
                    out.append(path + [b])
        return out

    def node2str(self, n):
        return str(n)

    def edge2str(self, a, b):
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
        for n in self.nodes():
            out += '%s [label="%s"];\n' % (
                hash(n) & 0xFFFFFFFFFFFFFFFF, self.node2str(n))

        for a, b in self.edges():
            out += '%s -> %s [label="%s"]\n' % (hash(a) & 0xFFFFFFFFFFFFFFFF,
                                                hash(b) & 0xFFFFFFFFFFFFFFFF,
                                                self.edge2str(a, b))
        out += "}"
        return out


    def _reachable_nodes(self, head, next_cb):
        """Generic algorithm to compute every nodes reachable from/to node
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
        """Compute every nodes reachable from node @head"""
        return self._reachable_nodes(head, self.successors_iter)

    def reachable_parents(self, leaf):
        """Compute every parents of node @leaf"""
        return self._reachable_nodes(leaf, self.predecessors_iter)

    def _compute_generic_dominators(self, head, reachable_cb, prev_cb, next_cb):
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
