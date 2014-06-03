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
