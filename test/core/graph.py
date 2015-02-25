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


dominators = g1.compute_dominators(1)
assert(dominators == {1: set([1]),
                      2: set([1, 2]),
                      3: set([1, 2, 3]),
                      4: set([1, 2, 4]),
                      5: set([1, 2, 5]),
                      6: set([1, 2, 6])})

# Regression test with multiple heads
g2 = DiGraph()
g2.add_edge(1, 2)
g2.add_edge(2, 3)
g2.add_edge(3, 4)
g2.add_edge(5, 6)
g2.add_edge(6, 3)

dominators = g2.compute_dominators(5)
assert(dominators == {3: set([3, 5, 6]),
                      4: set([3, 4, 5, 6]),
                      5: set([5]),
                      6: set([5, 6])})


postdominators = g1.compute_postdominators(6)
assert(postdominators == {1: set([1, 2, 6]),
                          2: set([2, 6]),
                          3: set([2, 3, 5, 6]),
                          4: set([2, 4, 5, 6]),
                          5: set([2, 5, 6]),
                          6: set([6])})

postdominators = g1.compute_postdominators(5)
assert(postdominators == {1: set([1, 2, 5]),
                          2: set([2, 5]),
                          3: set([3, 5]),
                          4: set([4, 5]),
                          5: set([5])})

postdominators = g2.compute_postdominators(4)
assert(postdominators == {1: set([1, 2, 3, 4]),
                          2: set([2, 3, 4]),
                          3: set([3, 4]),
                          4: set([4]),
                          5: set([3, 4, 5, 6]),
                          6: set([3, 4, 6])})
