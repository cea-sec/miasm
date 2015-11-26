"""Provide influence graph"""

import itertools
from collections import deque

import miasm2.expression.expression as m2_expr
from miasm2.analysis.depgraph import DependencyNode, DependencyDict, \
    DependencyResult, DependencyResultImplicit, FollowExpr, DependencyGraph
from miasm2.expression.simplifications import expr_simp
from miasm2.core.asmbloc import expr_is_label
from miasm2.core.graph import DiGraph

class InfluencyDict(DependencyDict):

    """Internal structure for the InfluenceGraph algorithm"""

    def __init__(self, label, history):
        """Create a DependencyDict
        @label: asm_label, current IRblock label
        @history: list of DependencyDict
        """
        super(self.__class__, self).__init__(label, history)

    def is_tail(self, depnode, blocksize):
        """Return True iff @depnode is at the tail of the current block
        @depnode: DependencyNode instance
        @blocksize: number of instructions in @depnode's block"""

        return (self.label == depnode.label and
                depnode.line_nb == blocksize)

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
            graph.add_uniq_edge(depnode, head)

        for subgraphs in itertools.product(graphs):
            for sourcegraph in subgraphs:
                for node in sourcegraph.nodes():
                    graph.add_node(node)
                for edge in sourcegraph.edges():
                    graph.add_uniq_edge(*edge)

        # Update the running queue
        return graph


class InfluenceGraph(DependencyGraph):

    """Implementation of an influence graph, a forward dependency graph

    An influence graph contains DependencyNode as nodes. The oriented edges
    stand for an influence.
    The influence graph is made of the lines of a group of IRblock
    *explicitely* or *implicitely* involved in the equation of given element.
    """

    @staticmethod
    def follow_expr(expr, follow, nofollow, follow_mem=False, follow_call=False):
        """Returns True if we must visit sub expressions.
        @expr: expression to browse
        @follow: set of nodes to follow
        @nofollow: set of nodes not to follow
        @follow_mem: force the visit of memory sub expressions
        @follow_call: force the visit of call sub expressions
        """
        if isinstance(expr, m2_expr.ExprMem):
            follow.add(expr)
            return False
        if not follow_call and expr.is_function_call():
            nofollow.add(expr)
            return False
        return True
    
    def _get_affblock(self, depnode):
        """Return the list of ExprAff associtiated to @depnode.
        LINE_NB must be >= 0"""
        return self._get_irs(depnode.label)[depnode.line_nb]

    def _direct_depnode_dependencies(self, depnode):
        """Compute and return the influencies involved by @depnode,
        over the instruction @depnode.line_,.
        Return a set of FollowExpr"""

        if depnode.line_nb == len(self._get_irs(depnode.label)):
            # End of a block, inter-block resolving is not done here
            output = set()

        else:
            output = set([depnode])
            # Intra-block resolving
            # Get influences
            write = set()
            end_influence = set()

            influenced = False
            for affect in self._get_affblock(depnode):
                if depnode.element in affect.get_r(False, True):
                    influenced = True
                    elements = self._follow_apply_cb(affect.dst)

                    write.update(elements)
                if affect.dst == depnode.element:
                    # Influence end here
                    end_influence.add(depnode)

            # Build output : new variable written by depnode
            output = FollowExpr.to_depnodes(write, depnode.label,
                                            depnode.line_nb + 1, influenced,
                                            self.current_step)

            new_depnode = DependencyNode(depnode.label, depnode.element,
                                         depnode.line_nb + 1,
                                         self.current_step,
                                         modifier=depnode in end_influence)
            if depnode not in end_influence:
                output.add(FollowExpr(True, new_depnode))

        return output

    def _get_nextblocks(self, label):
        """Return an iterator on successors blocks of @label, with their
        lengths"""
        succs = self._ira.g.successors_iter(label)
        for succ_label in succs:
            length = len(self._get_irs(succ_label))
            yield (succ_label, length)

    def _compute_interblock_dep(self, depnodes, tails):
        """
        Create a InfluencyDict to represent the influence of @depnodes
        through all blocks.
        @depnodes : set of DependencyNode instances
        @tails : set of asm_label instances
        """
        # Create an InfluencyDict which will only contain our depnodes
        current_depdict = InfluencyDict(list(depnodes)[0].label, [])
        current_depdict.pending.update(depnodes)

        # Init the work list
        done = {}
        todo = deque([current_depdict])

        while todo:
            depdict = todo.popleft()

            # Update the dependencydict until fixed point is reached
            self._resolve_intrablock_infl(depdict)

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

            # Has a successor ?
            is_final = True

            # Propagate the InfluencyDict to all children
            for label, irb_len in self._get_nextblocks(depdict.label):
                is_final = False

                # Duplicate the InfluencyDict
                new_depdict = depdict.extend(label)

                if self._implicit:
                    # Implicit dependencies: IRDst will be link with heads
                    implicit_depnode = DependencyNode(label, self._ira.IRDst,
                                                      irb_len,
                                                      self.inc_step(),
                                                      modifier=False)
                self.inc_step()
                # Create links between InfluencyDict
                for depnode_tail in depdict.pending:
                    # Follow the tail element in the child
                    new_depnode = DependencyNode(label, depnode_tail.element,
                                                 0,
                                                 self.current_step)

                    # The new node has to be analysed

                    new_depdict.cache[depnode_tail] = set([new_depnode])
                    new_depdict.pending.add(new_depnode)

                    # Handle implicit dependencies
                    if self._implicit:
                        new_depdict.cache[depnode_tail].add(implicit_depnode)
                        new_depdict.pending.add(implicit_depnode)

                # Manage the new element
                todo.append(new_depdict)

            # Return the node if it's a final one, ie. it's a tail (in graph
            # or defined by caller)
            if is_final or depdict.label in tails:
                yield depdict.copy()

    def _resolve_intrablock_infl(self, depdict):
        """Resolve the dependencies of nodes in @depdict.pending inside
        @depdict.label until a fixed point is reached.
        @depdict: DependencyDict to update"""

        self.inc_step()
        # Prepare the work list
        todo = set(depdict.pending)

        # Pending states will be handled
        depdict.pending.clear()

        while todo:
            depnode = todo.pop()

            if depdict.is_tail(depnode, len(self._get_irs(depnode.label))):
                depdict.pending.add(depnode)
                # A head cannot have dependencies inside the current IRblock
                continue

            # Find dependency of the current depnode
            sub_depnodes = self._direct_depnode_dependencies(
                depnode)
            depdict.cache[depnode] = FollowExpr.extract_depnodes(sub_depnodes)

            # Add to the worklist its dependencies
            todo.update(FollowExpr.extract_depnodes(sub_depnodes))

        # Pending states will be overriden in cache
        for depnode in depdict.pending:
            try:
                del depdict.cache[depnode]
            except KeyError:
                continue

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

        self.inc_step()
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
