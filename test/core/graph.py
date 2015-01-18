from miasm2.core.graph import *

g = DiGraph()
g.add_node('a')
g.add_node('b')

g.add_edge('a', 'b')
g.add_edge('a', 'c')
g.add_edge('a', 'c')
g.add_edge('c', 'c')

print g

print [x for x in g.successors('a')]
print [x for x in g.predecessors('a')]
print [x for x in g.predecessors('b')]
print [x for x in g.predecessors('c')]
print [x for x in g.successors('c')]


"""
Test from: https://en.wikipedia.org/wiki/Dominator_(graph_theory)
"""

g1 = DiGraph()
g1.add_edge(1, 2)
g1.add_edge(2, 3)
g1.add_edge(2, 4)
g1.add_edge(3, 5)
g1.add_edge(4, 5)
g1.add_edge(5, 2)
g1.add_edge(2, 6)


dominators = g1.compute_dominators()
assert(dominators[1] == set([1]))
assert(dominators[2] == set([1, 2]))
assert(dominators[3] == set([1, 2, 3]))
assert(dominators[4] == set([1, 2, 4]))
assert(dominators[5] == set([1, 2, 5]))
assert(dominators[6] == set([1, 2, 6]))
