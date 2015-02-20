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

    def get_all_parents(self, node):
        """Return every parents nodes for a given @node"""

        todo = set([node])
        done = set()
        while todo:
            node = todo.pop()
            if node in done:
                continue
            done.add(node)
            for parent in self.predecessors(node):
                todo.add(parent)
        return done

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



    def compute_dominators(self):
        """Compute dominators of the graph"""
        nodes = self.nodes()
        heads = self.heads()

        dominators = defaultdict(set)
        for node in self.nodes():
            dominators[node].update(nodes)
        for node in heads:
            dominators[node] = set([node])

        modified = True
        todo = nodes.difference(heads)

        while todo:
            node = todo.pop()

            # Heads state must not be changed
            if node in heads:
                continue

            # Compute intersection of all predecessors'dominators
            new_dom = None
            for pred in self.predecessors(node):
                if new_dom is None:
                    new_dom = set(dominators[pred])
                new_dom.intersection_update(dominators[pred])
            if new_dom is None:
                new_dom = set()
            new_dom.update(set([node]))

            # If intersection has changed, add sons to the todo list
            if new_dom == dominators[node]:
                continue
            dominators[node] = new_dom
            for succ in self.successors(node):
                todo.add(succ)
        return dict(dominators)
