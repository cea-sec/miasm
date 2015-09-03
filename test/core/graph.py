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

assert(list(g1.walk_dominators(1, dominators)) == [])
assert(list(g1.walk_dominators(2, dominators)) == [1])
assert(list(g1.walk_dominators(3, dominators)) == [2, 1])
assert(list(g1.walk_dominators(4, dominators)) == [2, 1])
assert(list(g1.walk_dominators(5, dominators)) == [2, 1])
assert(list(g1.walk_dominators(6, dominators)) == [2, 1])

# Regression test with multiple heads
g2 = DiGraph()
g2.add_edge(1, 2)
g2.add_edge(2, 3)
g2.add_edge(3, 4)
g2.add_edge(5, 6)
g2.add_edge(6, 3)
g2.add_edge(4, 7)
g2.add_edge(4, 8)
g2.add_edge(7, 9)
g2.add_edge(8, 9)

dominators = g2.compute_dominators(5)
assert(dominators == {3: set([3, 5, 6]),
                      4: set([3, 4, 5, 6]),
                      5: set([5]),
                      6: set([5, 6]),
                      7: set([3, 4, 5, 6, 7]),
                      8: set([3, 4, 5, 6, 8]),
                      9: set([3, 4, 5, 6, 9])})


assert(list(g2.walk_dominators(1, dominators)) == [])
assert(list(g2.walk_dominators(2, dominators)) == [])
assert(list(g2.walk_dominators(3, dominators)) == [6, 5])
assert(list(g2.walk_dominators(4, dominators)) == [3, 6, 5])
assert(list(g2.walk_dominators(5, dominators)) == [])
assert(list(g2.walk_dominators(6, dominators)) == [5])
assert(list(g2.walk_dominators(7, dominators)) == [4, 3, 6, 5])
assert(list(g2.walk_dominators(8, dominators)) == [4, 3, 6, 5])
assert(list(g2.walk_dominators(9, dominators)) == [4, 3, 6, 5])

postdominators = g1.compute_postdominators(6)
assert(postdominators == {1: set([1, 2, 6]),
                          2: set([2, 6]),
                          3: set([2, 3, 5, 6]),
                          4: set([2, 4, 5, 6]),
                          5: set([2, 5, 6]),
                          6: set([6])})

assert(list(g1.walk_postdominators(1, postdominators)) == [2, 6])
assert(list(g1.walk_postdominators(2, postdominators)) == [6])
assert(list(g1.walk_postdominators(3, postdominators)) == [5, 2, 6])
assert(list(g1.walk_postdominators(4, postdominators)) == [5, 2, 6])
assert(list(g1.walk_postdominators(5, postdominators)) == [2, 6])
assert(list(g1.walk_postdominators(6, postdominators)) == [])


postdominators = g1.compute_postdominators(5)
assert(postdominators == {1: set([1, 2, 5]),
                          2: set([2, 5]),
                          3: set([3, 5]),
                          4: set([4, 5]),
                          5: set([5])})

assert(list(g1.walk_postdominators(1, postdominators)) == [2, 5])
assert(list(g1.walk_postdominators(2, postdominators)) == [5])
assert(list(g1.walk_postdominators(3, postdominators)) == [5])
assert(list(g1.walk_postdominators(4, postdominators)) == [5])
assert(list(g1.walk_postdominators(5, postdominators)) == [])
assert(list(g1.walk_postdominators(6, postdominators)) == [])

postdominators = g2.compute_postdominators(4)
assert(postdominators == {1: set([1, 2, 3, 4]),
                          2: set([2, 3, 4]),
                          3: set([3, 4]),
                          4: set([4]),
                          5: set([3, 4, 5, 6]),
                          6: set([3, 4, 6])})

assert(list(g2.walk_postdominators(1, postdominators)) == [2, 3, 4])
assert(list(g2.walk_postdominators(2, postdominators)) == [3, 4])
assert(list(g2.walk_postdominators(3, postdominators)) == [4])
assert(list(g2.walk_postdominators(4, postdominators)) == [])
assert(list(g2.walk_postdominators(5, postdominators)) == [6, 3, 4])
assert(list(g2.walk_postdominators(6, postdominators)) == [3, 4])
assert(list(g2.walk_postdominators(7, postdominators)) == [])
assert(list(g2.walk_postdominators(8, postdominators)) == [])
assert(list(g2.walk_postdominators(9, postdominators)) == [])


idoms = g1.compute_immediate_dominators(1)
assert(idoms == {2: 1,
                 3: 2,
                 4: 2,
                 5: 2,
                 6: 2})

idoms = g2.compute_immediate_dominators(1)
assert(idoms == {2: 1,
                 3: 2,
                 4: 3,
                 7: 4,
                 8: 4,
                 9: 4})

idoms = g2.compute_immediate_dominators(5)
assert(idoms == {3: 6,
                 4: 3,
                 6: 5,
                 7: 4,
                 8: 4,
                 9: 4})

frontier = g1.compute_dominance_frontier(1)
assert(frontier == {2: set([2]),
                    3: set([5]),
                    4: set([5]),
                    5: set([2])})

frontier = g2.compute_dominance_frontier(1)
assert(frontier == {7: set([9]),
                    8: set([9])})

frontier = g2.compute_dominance_frontier(5)
assert(frontier == {7: set([9]),
                    8: set([9])})

# Regression test with natural loops and irreducible loops
g3 = DiGraph()
g3.add_edge(1, 2)
g3.add_edge(1, 3)
g3.add_edge(2, 4)
g3.add_edge(2, 5)
g3.add_edge(3, 7)
g3.add_edge(3, 8)
g3.add_edge(4, 9)
g3.add_edge(5, 9)
g3.add_edge(7, 6)
g3.add_edge(8, 6)
g3.add_edge(9, 6)
g3.add_edge(9, 2)
g3.add_edge(9, 1)
g3.add_edge(7, 8)
g3.add_edge(8, 7)

loops = set([(backedge, frozenset(body)) for backedge, body in g3.compute_natural_loops(1)])
assert(loops == {((1, 9), frozenset({1, 2, 4, 5, 9})),
                 ((2, 9), frozenset({2, 4, 5, 9}))})

sccs = set([frozenset(scc) for scc in g3.compute_strongly_connected_components()])
assert(sccs == {frozenset({6}),
                frozenset({7, 8}),
                frozenset({3}),
                frozenset({1, 2, 4, 5, 9})})
