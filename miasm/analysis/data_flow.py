"""Data flow analysis based on miasm intermediate representation"""
from builtins import range
from collections import namedtuple

from future.utils import viewitems, viewvalues
from miasm.core.utils import encode_hex
from miasm.core.graph import DiGraph
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.expression.expression import ExprLoc, ExprMem, ExprId, ExprInt,\
    ExprAssign, ExprOp
from miasm.expression.simplifications import expr_simp
from miasm.core.interval import interval
from miasm.expression.expression_helper import possible_values
from miasm.analysis.ssa import get_phi_sources_parent_block, \
    irblock_has_phi
from miasm.expression.expression_helper import get_expr_base_offset, \
    INTERNAL_INTBASE_NAME
from miasm.ir.symbexec import SymbolicExecutionEngine

class ReachingDefinitions(dict):
    """
    Computes for each assignblock the set of reaching definitions.
    Example:
    IR block:
    lbl0:
       0 A = 1
         B = 3
       1 B = 2
       2 A = A + B + 4

    Reach definition of lbl0:
    (lbl0, 0) => {}
    (lbl0, 1) => {A: {(lbl0, 0)}, B: {(lbl0, 0)}}
    (lbl0, 2) => {A: {(lbl0, 0)}, B: {(lbl0, 1)}}
    (lbl0, 3) => {A: {(lbl0, 2)}, B: {(lbl0, 1)}}

    Source set 'REACHES' in: Kennedy, K. (1979).
    A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division,  Algorithm MK

    This class is usable as a dictionary whose structure is
    { (block, index): { lvalue: set((block, index)) } }
    """

    ircfg = None

    def __init__(self, ircfg):
        super(ReachingDefinitions, self).__init__()
        self.ircfg = ircfg
        self.compute()

    def get_definitions(self, block_lbl, assignblk_index):
        """Returns the dict { lvalue: set((def_block_lbl, def_index)) }
        associated with self.ircfg.@block.assignblks[@assignblk_index]
        or {} if it is not yet computed
        """
        return self.get((block_lbl, assignblk_index), {})

    def compute(self):
        """This is the main fixpoint"""
        modified = True
        while modified:
            modified = False
            for block in viewvalues(self.ircfg.blocks):
                modified |= self.process_block(block)

    def process_block(self, block):
        """
        Fetch reach definitions from predecessors and propagate it to
        the assignblk in block @block.
        """
        predecessor_state = {}
        for pred_lbl in self.ircfg.predecessors(block.loc_key):
            if pred_lbl not in self.ircfg.blocks:
                continue
            pred = self.ircfg.blocks[pred_lbl]
            for lval, definitions in viewitems(self.get_definitions(pred_lbl, len(pred))):
                predecessor_state.setdefault(lval, set()).update(definitions)

        modified = self.get((block.loc_key, 0)) != predecessor_state
        if not modified:
            return False
        self[(block.loc_key, 0)] = predecessor_state

        for index in range(len(block)):
            modified |= self.process_assignblock(block, index)
        return modified

    def process_assignblock(self, block, assignblk_index):
        """
        Updates the reach definitions with values defined at
        assignblock @assignblk_index in block @block.
        NB: the effect of assignblock @assignblk_index in stored at index
        (@block, @assignblk_index + 1).
        """

        assignblk = block[assignblk_index]
        defs = self.get_definitions(block.loc_key, assignblk_index).copy()
        for lval in assignblk:
            defs.update({lval: set([(block.loc_key, assignblk_index)])})

        modified = self.get((block.loc_key, assignblk_index + 1)) != defs
        if modified:
            self[(block.loc_key, assignblk_index + 1)] = defs

        return modified

ATTR_DEP = {"color" : "black",
            "_type" : "data"}

AssignblkNode = namedtuple('AssignblkNode', ['label', 'index', 'var'])


class DiGraphDefUse(DiGraph):
    """Representation of a Use-Definition graph as defined by
    Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division.
    Example:
    IR block:
    lbl0:
       0 A = 1
         B = 3
       1 B = 2
       2 A = A + B + 4

    Def use analysis:
    (lbl0, 0, A) => {(lbl0, 2, A)}
    (lbl0, 0, B) => {}
    (lbl0, 1, B) => {(lbl0, 2, A)}
    (lbl0, 2, A) => {}

    """


    def __init__(self, reaching_defs,
                 deref_mem=False, *args, **kwargs):
        """Instantiate a DiGraph
        @blocks: IR blocks
        """
        self._edge_attr = {}

        # For dot display
        self._filter_node = None
        self._dot_offset = None
        self._blocks = reaching_defs.ircfg.blocks

        super(DiGraphDefUse, self).__init__(*args, **kwargs)
        self._compute_def_use(reaching_defs,
                              deref_mem=deref_mem)

    def edge_attr(self, src, dst):
        """
        Return a dictionary of attributes for the edge between @src and @dst
        @src: the source node of the edge
        @dst: the destination node of the edge
        """
        return self._edge_attr[(src, dst)]

    def _compute_def_use(self, reaching_defs,
                         deref_mem=False):
        for block in viewvalues(self._blocks):
            self._compute_def_use_block(block,
                                        reaching_defs,
                                        deref_mem=deref_mem)

    def _compute_def_use_block(self, block, reaching_defs, deref_mem=False):
        for index, assignblk in enumerate(block):
            assignblk_reaching_defs = reaching_defs.get_definitions(block.loc_key, index)
            for lval, expr in viewitems(assignblk):
                self.add_node(AssignblkNode(block.loc_key, index, lval))

                read_vars = expr.get_r(mem_read=deref_mem)
                if deref_mem and lval.is_mem():
                    read_vars.update(lval.ptr.get_r(mem_read=deref_mem))
                for read_var in read_vars:
                    for reach in assignblk_reaching_defs.get(read_var, set()):
                        self.add_data_edge(AssignblkNode(reach[0], reach[1], read_var),
                                           AssignblkNode(block.loc_key, index, lval))

    def del_edge(self, src, dst):
        super(DiGraphDefUse, self).del_edge(src, dst)
        del self._edge_attr[(src, dst)]

    def add_uniq_labeled_edge(self, src, dst, edge_label):
        """Adds the edge (@src, @dst) with label @edge_label.
        if edge (@src, @dst) already exists, the previous label is overridden
        """
        self.add_uniq_edge(src, dst)
        self._edge_attr[(src, dst)] = edge_label

    def add_data_edge(self, src, dst):
        """Adds an edge representing a data dependency
        and sets the label accordingly"""
        self.add_uniq_labeled_edge(src, dst, ATTR_DEP)

    def node2lines(self, node):
        lbl, index, reg = node
        yield self.DotCellDescription(text="%s (%s)" % (lbl, index),
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})
        src = self._blocks[lbl][index][reg]
        line = "%s = %s" % (reg, src)
        yield self.DotCellDescription(text=line, attr={})
        yield self.DotCellDescription(text="", attr={})


class DeadRemoval(object):
    """
    Do dead removal
    """

    def __init__(self, ir_arch, expr_to_original_expr=None):
        self.ir_arch = ir_arch
        if expr_to_original_expr is None:
            expr_to_original_expr = {}
        self.expr_to_original_expr = expr_to_original_expr


    def add_expr_to_original_expr(self, expr_to_original_expr):
        self.expr_to_original_expr.update(expr_to_original_expr)

    def is_unkillable_destination(self, lval, rval):
        if (
                lval.is_mem() or
                self.ir_arch.IRDst == lval or
                lval.is_id("exception_flags") or
                rval.is_function_call()
        ):
            return True
        return False

    def get_block_useful_destinations(self, block):
        """
        Force keeping of specific cases
        block: IRBlock instance
        """
        useful = set()
        for index, assignblk in enumerate(block):
            for lval, rval in viewitems(assignblk):
                if self.is_unkillable_destination(lval, rval):
                    useful.add(AssignblkNode(block.loc_key, index, lval))
        return useful

    def is_tracked_var(self, lval, variable):
        new_lval = self.expr_to_original_expr.get(lval, lval)
        return new_lval == variable

    def find_definitions_from_worklist(self, worklist, ircfg):
        """
        Find variables definition in @worklist by browsing the @ircfg
        """
        locs_done = set()

        defs = set()

        while worklist:
            found = False
            elt = worklist.pop()
            if elt in locs_done:
                continue
            locs_done.add(elt)
            variable, loc_key = elt
            block = ircfg.get_block(loc_key)

            if block is None:
                # Consider no sources in incomplete graph
                continue

            for index, assignblk in reversed(list(enumerate(block))):
                for dst, src in viewitems(assignblk):
                    if self.is_tracked_var(dst, variable):
                        defs.add(AssignblkNode(loc_key, index, dst))
                        found = True
                        break
                if found:
                    break

            if not found:
                for predecessor in ircfg.predecessors(loc_key):
                    worklist.add((variable, predecessor))

        return defs

    def find_out_regs_definitions_from_block(self, block, ircfg):
        """
        Find definitions of out regs starting from @block
        """
        worklist = set()
        for reg in self.ir_arch.get_out_regs(block):
            worklist.add((reg, block.loc_key))
        ret = self.find_definitions_from_worklist(worklist, ircfg)
        return ret


    def add_def_for_incomplete_leaf(self, block, ircfg, reaching_defs):
        """
        Add valid definitions at end of @block plus out regs
        """
        valid_definitions = reaching_defs.get_definitions(
            block.loc_key,
            len(block)
        )
        worklist = set()
        for lval, definitions in viewitems(valid_definitions):
            for definition in definitions:
                new_lval = self.expr_to_original_expr.get(lval, lval)
                worklist.add((new_lval, block.loc_key))
        ret = self.find_definitions_from_worklist(worklist, ircfg)
        useful = ret
        useful.update(self.find_out_regs_definitions_from_block(block, ircfg))
        return useful

    def get_useful_assignments(self, ircfg, defuse, reaching_defs):
        """
        Mark useful statements using previous reach analysis and defuse

        Return a set of triplets (block, assignblk number, lvalue) of
        useful definitions
        PRE: compute_reach(self)

        """

        useful = set()

        for block_lbl, block in viewitems(ircfg.blocks):
            block = ircfg.get_block(block_lbl)
            if block is None:
                # skip unknown blocks: won't generate dependencies
                continue

            block_useful = self.get_block_useful_destinations(block)
            useful.update(block_useful)


            successors = ircfg.successors(block_lbl)
            for successor in successors:
                if successor not in ircfg.blocks:
                    keep_all_definitions = True
                    break
            else:
                keep_all_definitions = False

            if keep_all_definitions:
                useful.update(self.add_def_for_incomplete_leaf(block, ircfg, reaching_defs))
                continue

            if len(successors) == 0:
                useful.update(self.find_out_regs_definitions_from_block(block, ircfg))
            else:
                continue



        # Useful nodes dependencies
        for node in useful:
            for parent in defuse.reachable_parents(node):
                yield parent

    def do_dead_removal(self, ircfg):
        """
        Remove useless assignments.

        This function is used to analyse relation of a * complete function *
        This means the blocks under study represent a solid full function graph.

        Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
        IBM Thomas J. Watson Research Division, page 43

        @ircfg: IntermediateRepresentation instance
        """

        modified = False
        reaching_defs = ReachingDefinitions(ircfg)
        defuse = DiGraphDefUse(reaching_defs, deref_mem=True)
        useful = self.get_useful_assignments(ircfg, defuse, reaching_defs)
        useful = set(useful)
        for block in list(viewvalues(ircfg.blocks)):
            irs = []
            for idx, assignblk in enumerate(block):
                new_assignblk = dict(assignblk)
                for lval in assignblk:
                    if AssignblkNode(block.loc_key, idx, lval) not in useful:
                        del new_assignblk[lval]
                        modified = True
                irs.append(AssignBlock(new_assignblk, assignblk.instr))
            ircfg.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
        return modified

    def __call__(self, ircfg):
        ret = self.do_dead_removal(ircfg)
        return ret


def _test_merge_next_block(ircfg, loc_key):
    """
    Test if the irblock at @loc_key can be merge with its son
    @ircfg: IRCFG instance
    @loc_key: LocKey instance of the candidate parent irblock
    """

    if loc_key not in ircfg.blocks:
        return None
    sons = ircfg.successors(loc_key)
    if len(sons) != 1:
        return None
    son = list(sons)[0]
    if ircfg.predecessors(son) != [loc_key]:
        return None
    if son not in ircfg.blocks:
        return None

    return son


def _do_merge_blocks(ircfg, loc_key, son_loc_key):
    """
    Merge two irblocks at @loc_key and @son_loc_key

    @ircfg: DiGrpahIR
    @loc_key: LocKey instance of the parent IRBlock
    @loc_key: LocKey instance of the son IRBlock
    """

    assignblks = []
    for assignblk in ircfg.blocks[loc_key]:
        if ircfg.IRDst not in assignblk:
            assignblks.append(assignblk)
            continue
        affs = {}
        for dst, src in viewitems(assignblk):
            if dst != ircfg.IRDst:
                affs[dst] = src
        if affs:
            assignblks.append(AssignBlock(affs, assignblk.instr))

    assignblks += ircfg.blocks[son_loc_key].assignblks
    new_block = IRBlock(loc_key, assignblks)

    ircfg.discard_edge(loc_key, son_loc_key)

    for son_successor in ircfg.successors(son_loc_key):
        ircfg.add_uniq_edge(loc_key, son_successor)
        ircfg.discard_edge(son_loc_key, son_successor)
    del ircfg.blocks[son_loc_key]
    ircfg.del_node(son_loc_key)
    ircfg.blocks[loc_key] = new_block


def _test_jmp_only(ircfg, loc_key, heads):
    """
    If irblock at @loc_key sets only IRDst to an ExprLoc, return the
    corresponding loc_key target.
    Avoid creating predecssors for heads LocKeys
    None in other cases.

    @ircfg: IRCFG instance
    @loc_key: LocKey instance of the candidate irblock
    @heads: LocKey heads of the graph

    """

    if loc_key not in ircfg.blocks:
        return None
    irblock = ircfg.blocks[loc_key]
    if len(irblock.assignblks) != 1:
        return None
    items = list(viewitems(dict(irblock.assignblks[0])))
    if len(items) != 1:
        return None
    if len(ircfg.successors(loc_key)) != 1:
        return None
    # Don't create predecessors on heads
    dst, src = items[0]
    assert dst.is_id("IRDst")
    if not src.is_loc():
        return None
    dst = src.loc_key
    if loc_key in heads:
        predecessors = set(ircfg.predecessors(dst))
        predecessors.difference_update(set([loc_key]))
        if predecessors:
            return None
    return dst


def _relink_block_node(ircfg, loc_key, son_loc_key, replace_dct):
    """
    Link loc_key's parents to parents directly to son_loc_key
    """
    for parent in set(ircfg.predecessors(loc_key)):
        parent_block = ircfg.blocks.get(parent, None)
        if parent_block is None:
            continue

        new_block = parent_block.modify_exprs(
            lambda expr:expr.replace_expr(replace_dct),
            lambda expr:expr.replace_expr(replace_dct)
        )

        # Link parent to new dst
        ircfg.add_uniq_edge(parent, son_loc_key)

        # Unlink block
        ircfg.blocks[new_block.loc_key] = new_block
        ircfg.del_node(loc_key)


def _remove_to_son(ircfg, loc_key, son_loc_key):
    """
    Merge irblocks; The final block has the @son_loc_key loc_key
    Update references

    Condition:
    - irblock at @loc_key is a pure jump block
    - @loc_key is not an entry point (can be removed)

    @irblock: IRCFG instance
    @loc_key: LocKey instance of the parent irblock
    @son_loc_key: LocKey instance of the son irblock
    """

    # Ircfg loop => don't mess
    if loc_key == son_loc_key:
        return False

    # Unlink block destinations
    ircfg.del_edge(loc_key, son_loc_key)

    replace_dct = {
        ExprLoc(loc_key, ircfg.IRDst.size):ExprLoc(son_loc_key, ircfg.IRDst.size)
    }

    _relink_block_node(ircfg, loc_key, son_loc_key, replace_dct)

    ircfg.del_node(loc_key)
    del ircfg.blocks[loc_key]

    return True


def _remove_to_parent(ircfg, loc_key, son_loc_key):
    """
    Merge irblocks; The final block has the @loc_key loc_key
    Update references

    Condition:
    - irblock at @loc_key is a pure jump block
    - @son_loc_key is not an entry point (can be removed)

    @irblock: IRCFG instance
    @loc_key: LocKey instance of the parent irblock
    @son_loc_key: LocKey instance of the son irblock
    """

    # Ircfg loop => don't mess
    if loc_key == son_loc_key:
        return False

    # Unlink block destinations
    ircfg.del_edge(loc_key, son_loc_key)

    old_irblock = ircfg.blocks[son_loc_key]
    new_irblock = IRBlock(loc_key, old_irblock.assignblks)

    ircfg.blocks[son_loc_key] = new_irblock

    ircfg.add_irblock(new_irblock)

    replace_dct = {
        ExprLoc(son_loc_key, ircfg.IRDst.size):ExprLoc(loc_key, ircfg.IRDst.size)
    }

    _relink_block_node(ircfg, son_loc_key, loc_key, replace_dct)


    ircfg.del_node(son_loc_key)
    del ircfg.blocks[son_loc_key]

    return True


def merge_blocks(ircfg, heads):
    """
    This function modifies @ircfg to apply the following transformations:
    - group an irblock with its son if the irblock has one and only one son and
      this son has one and only one parent (spaghetti code).
    - if an irblock is only made of an assignment to IRDst with a given label,
      this irblock is dropped and its parent destination targets are
      updated. The irblock must have a parent (avoid deleting the function head)
    - if an irblock is a head of the graph and is only made of an assignment to
      IRDst with a given label, this irblock is dropped and its son becomes the
      head. References are fixed

    This function avoid creating predecessors on heads

    Return True if at least an irblock has been modified

    @ircfg: IRCFG instance
    @heads: loc_key to keep
    """

    modified = False
    todo = set(ircfg.nodes())
    while todo:
        loc_key = todo.pop()

        # Test merge block
        son = _test_merge_next_block(ircfg, loc_key)
        if son is not None and son not in heads:
            _do_merge_blocks(ircfg, loc_key, son)
            todo.add(loc_key)
            modified = True
            continue

        # Test jmp only block
        son = _test_jmp_only(ircfg, loc_key, heads)
        if son is not None and loc_key not in heads:
            ret = _remove_to_son(ircfg, loc_key, son)
            modified |= ret
            if ret:
                todo.add(loc_key)
                continue

        # Test head jmp only block
        if (son is not None and
            son not in heads and
            son in ircfg.blocks):
            # jmp only test done previously
            ret = _remove_to_parent(ircfg, loc_key, son)
            modified |= ret
            if ret:
                todo.add(loc_key)
                continue


    return modified


def remove_empty_assignblks(ircfg):
    """
    Remove empty assignblks in irblocks of @ircfg
    Return True if at least an irblock has been modified

    @ircfg: IRCFG instance
    """
    modified = False
    for loc_key, block in list(viewitems(ircfg.blocks)):
        irs = []
        block_modified = False
        for assignblk in block:
            if len(assignblk):
                irs.append(assignblk)
            else:
                block_modified = True
        if block_modified:
            new_irblock = IRBlock(loc_key, irs)
            ircfg.blocks[loc_key] = new_irblock
            modified = True
    return modified


class SSADefUse(DiGraph):
    """
    Generate DefUse information from SSA transformation
    Links are not valid for ExprMem.
    """

    def add_var_def(self, node, src):
        index2dst = self._links.setdefault(node.label, {})
        dst2src = index2dst.setdefault(node.index, {})
        dst2src[node.var] = src

    def add_def_node(self, def_nodes, node, src):
        if node.var.is_id():
            def_nodes[node.var] = node

    def add_use_node(self, use_nodes, node, src):
        sources = set()
        if node.var.is_mem():
            sources.update(node.var.ptr.get_r(mem_read=True))
        sources.update(src.get_r(mem_read=True))
        for source in sources:
            if not source.is_mem():
                use_nodes.setdefault(source, set()).add(node)

    def get_node_target(self, node):
        return self._links[node.label][node.index][node.var]

    def set_node_target(self, node, src):
        self._links[node.label][node.index][node.var] = src

    @classmethod
    def from_ssa(cls, ssa):
        """
        Return a DefUse DiGraph from a SSA graph
        @ssa: SSADiGraph instance
        """

        graph = cls()
        # First pass
        # Link line to its use and def
        def_nodes = {}
        use_nodes = {}
        graph._links = {}
        for lbl in ssa.graph.nodes():
            block = ssa.graph.blocks.get(lbl, None)
            if block is None:
                continue
            for index, assignblk in enumerate(block):
                for dst, src in viewitems(assignblk):
                    node = AssignblkNode(lbl, index, dst)
                    graph.add_var_def(node, src)
                    graph.add_def_node(def_nodes, node, src)
                    graph.add_use_node(use_nodes, node, src)

        for dst, node in viewitems(def_nodes):
            graph.add_node(node)
            if dst not in use_nodes:
                continue
            for use in use_nodes[dst]:
                graph.add_uniq_edge(node, use)

        return graph




def expr_test_visit(expr, test):
    result = set()
    expr.visit(
        lambda expr: expr,
        lambda expr: test(expr, result)
    )
    if result:
        return True
    else:
        return False


def expr_has_mem_test(expr, result):
    if result:
        # Don't analyse if we already found a candidate
        return False
    if expr.is_mem():
        result.add(expr)
        return False
    return True


def expr_has_mem(expr):
    """
    Return True if expr contains at least one memory access
    @expr: Expr instance
    """
    return expr_test_visit(expr, expr_has_mem_test)


class PropagateThroughExprId(object):
    """
    Propagate expressions though ExprId
    """

    def has_propagation_barrier(self, assignblks):
        """
        Return True if propagation cannot cross the @assignblks
        @assignblks: list of AssignBlock to check
        """
        for assignblk in assignblks:
            for dst, src in viewitems(assignblk):
                if src.is_function_call():
                    return True
                if dst.is_mem():
                    return True
        return False

    def is_mem_written(self, ssa, node_a, node_b):
        """
        Return True if memory is written at least once between @node_a and
        @node_b

        @node: AssignblkNode representing the start position
        @successor: AssignblkNode representing the end position
        """

        block_b = ssa.graph.blocks[node_b.label]
        nodes_to_do = self.compute_reachable_nodes_from_a_to_b(ssa.graph, node_a.label, node_b.label)

        if node_a.label == node_b.label:
            # src is dst
            assert nodes_to_do == set([node_a.label])
            if self.has_propagation_barrier(block_b.assignblks[node_a.index:node_b.index]):
                return True
        else:
            # Check everyone but node_a.label and node_b.label
            for loc in nodes_to_do - set([node_a.label, node_b.label]):
                if loc not in ssa.graph.blocks:
                    continue
                block = ssa.graph.blocks[loc]
                if self.has_propagation_barrier(block.assignblks):
                    return True
            # Check node_a.label partially
            block_a = ssa.graph.blocks[node_a.label]
            if self.has_propagation_barrier(block_a.assignblks[node_a.index:]):
                return True
            if nodes_to_do.intersection(ssa.graph.successors(node_b.label)):
                # There is a path from node_b.label to node_b.label => Check node_b.label fully
                if self.has_propagation_barrier(block_b.assignblks):
                    return True
            else:
                # Check node_b.label partially
                if self.has_propagation_barrier(block_b.assignblks[:node_b.index]):
                    return True
        return False

    def compute_reachable_nodes_from_a_to_b(self, ssa, loc_a, loc_b):
        reachables_a = set(ssa.reachable_sons(loc_a))
        reachables_b = set(ssa.reachable_parents_stop_node(loc_b, loc_a))
        return reachables_a.intersection(reachables_b)

    def propagation_allowed(self, ssa, to_replace, node_a, node_b):
        """
        Return True if we can replace @node_a source present in @to_replace into
        @node_b

        @node_a: AssignblkNode position
        @node_b: AssignblkNode position
        """
        if not expr_has_mem(to_replace[node_a.var]):
            return True
        if self.is_mem_written(ssa, node_a, node_b):
            return False
        return True


    def get_var_definitions(self, ssa):
        """
        Return a dictionary linking variable to its assignment location
        @ssa: SSADiGraph instance
        """
        ircfg = ssa.graph
        def_dct = {}
        for node in ircfg.nodes():
            block = ircfg.blocks.get(node, None)
            if block is None:
                continue
            for index, assignblk in enumerate(block):
                for dst, src in viewitems(assignblk):
                    if not dst.is_id():
                        continue
                    if dst in ssa.immutable_ids:
                        continue
                    assert dst not in def_dct
                    def_dct[dst] = node, index
        return def_dct

    def get_candidates(self, ssa, head, max_expr_depth):
        def_dct = self.get_var_definitions(ssa)
        defuse = SSADefUse.from_ssa(ssa)
        to_replace = {}
        node_to_reg = {}
        for node in defuse.nodes():
            if node.var in ssa.immutable_ids:
                continue
            if node.var.is_id() and node.var.name.startswith("tmp"):
                continue
            src = defuse.get_node_target(node)
            if max_expr_depth is not None and len(str(src)) > max_expr_depth:
                continue
            if src.is_function_call():
                continue
            if expr_has_mem(src):
                continue
            if node.var.is_mem():
                continue
            if src.is_op('Phi'):
                continue
            to_replace[node.var] = src
            node_to_reg[node] = node.var
        return node_to_reg, to_replace, defuse

    def propagate(self, ssa, head, max_expr_depth=None):
        """
        Do expression propagation
        @ssa: SSADiGraph instance
        @head: the head location of the graph
        @max_expr_depth: the maximum allowed depth of an expression
        """
        node_to_reg, to_replace, defuse = self.get_candidates(ssa, head, max_expr_depth)
        modified = False
        for node, reg in viewitems(node_to_reg):
            for successor in defuse.successors(node):
                if not self.propagation_allowed(ssa, to_replace, node, successor):
                    continue

                node_a = node
                node_b = successor
                block = ssa.graph.blocks[node_b.label]

                replace = {node_a.var: to_replace[node_a.var]}
                # Replace
                assignblks = list(block)
                assignblk = block[node_b.index]
                out = {}
                for dst, src in viewitems(assignblk):
                    if src.is_op('Phi'):
                        out[dst] = src
                        continue

                    if src.is_mem():
                        ptr = src.ptr.replace_expr(replace)
                        new_src = ExprMem(ptr, src.size)
                    else:
                        new_src = src.replace_expr(replace)

                    if dst.is_id():
                        new_dst = dst
                    elif dst.is_mem():
                        ptr = dst.ptr.replace_expr(replace)
                        new_dst = ExprMem(ptr, dst.size)
                    else:
                        new_dst = dst.replace_expr(replace)
                        if not (new_dst.is_id() or new_dst.is_mem()):
                            new_dst = dst
                    new_dst = expr_simp(new_dst)
                    new_src = expr_simp(new_src)
                    if src != new_src or dst != new_dst:
                        modified = True
                    out[new_dst] = new_src
                out = AssignBlock(out, assignblk.instr)
                assignblks[node_b.index] = out
                new_block = IRBlock(block.loc_key, assignblks)
                ssa.graph.blocks[block.loc_key] = new_block

        return modified



class PropagateExprIntThroughExprId(PropagateThroughExprId):
    """
    Propagate ExprInt though ExprId: classic constant propagation
    This is a sub family of PropagateThroughExprId.
    It reduces leaves in expressions of a program.
    """

    def get_candidates(self, ssa, head, max_expr_depth):
        defuse = SSADefUse.from_ssa(ssa)

        to_replace = {}
        node_to_reg = {}
        for node in defuse.nodes():
            src = defuse.get_node_target(node)
            if not src.is_int():
                continue
            if src.is_function_call():
                continue
            if node.var.is_mem():
                continue
            to_replace[node.var] = src
            node_to_reg[node] = node.var
        return node_to_reg, to_replace, defuse

    def propagation_allowed(self, ssa, to_replace, node_a, node_b):
        """
        Propagating ExprInt is always ok
        """
        return True


class PropagateThroughExprMem(object):
    """
    Propagate through ExprMem in very simple cases:
    - if no memory write between source and target
    - if source does not contain any memory reference
    """

    def propagate(self, ssa, head, max_expr_depth=None):
        ircfg = ssa.graph
        todo = set()
        modified = False
        for block in viewvalues(ircfg.blocks):
            for i, assignblk in enumerate(block):
                for dst, src in viewitems(assignblk):
                    if not dst.is_mem():
                        continue
                    if expr_has_mem(src):
                        continue
                    todo.add((block.loc_key, i + 1, dst, src))
                    ptr = dst.ptr
                    for size in range(8, dst.size, 8):
                        todo.add((block.loc_key, i + 1, ExprMem(ptr, size), src[:size]))

        while todo:
            loc_key, index, mem_dst, mem_src = todo.pop()
            block = ircfg.blocks.get(loc_key, None)
            if block is None:
                continue
            assignblks = list(block)
            block_modified = False
            for i in range(index, len(block)):
                assignblk = block[i]
                write_mem = False
                assignblk_modified = False
                out = dict(assignblk)
                out_new = {}
                for dst, src in viewitems(out):
                    if dst.is_id() and dst.name.startswith("tmp"):
                        out_new[dst] = src
                        continue

                    if dst.is_mem():
                        write_mem = True
                        ptr = dst.ptr.replace_expr({mem_dst:mem_src})
                        dst = ExprMem(ptr, dst.size)
                    src = src.replace_expr({mem_dst:mem_src})
                    out_new[dst] = src
                if out != out_new:
                    assignblk_modified = True

                if assignblk_modified:
                    assignblks[i] = AssignBlock(out_new, assignblk.instr)
                    block_modified = True
                if write_mem:
                    break
            else:
                # If no memory written, we may propagate to sons
                # if son has only parent
                for successor in ircfg.successors(loc_key):
                    predecessors = ircfg.predecessors(successor)
                    if len(predecessors) != 1:
                        continue
                    todo.add((successor, 0, mem_dst, mem_src))

            if block_modified:
                modified = True
                new_block = IRBlock(block.loc_key, assignblks)
                ircfg.blocks[block.loc_key] = new_block
        return modified


def stack_to_reg(expr):
    if expr.is_mem():
        ptr = expr.arg
        SP = ir_arch_a.sp
        if ptr == SP:
            return ExprId("STACK.0", expr.size)
        elif (ptr.is_op('+') and
              len(ptr.args) == 2 and
              ptr.args[0] == SP and
              ptr.args[1].is_int()):
            diff = int(ptr.args[1])
            assert diff % 4 == 0
            diff = (0 - diff) & 0xFFFFFFFF
            return ExprId("STACK.%d" % (diff // 4), expr.size)
    return False


def is_stack_access(ir_arch_a, expr):
    if not expr.is_mem():
        return False
    ptr = expr.ptr
    diff = expr_simp(ptr - ir_arch_a.sp)
    if not diff.is_int():
        return False
    return expr


def visitor_get_stack_accesses(ir_arch_a, expr, stack_vars):
    if is_stack_access(ir_arch_a, expr):
        stack_vars.add(expr)
    return expr


def get_stack_accesses(ir_arch_a, expr):
    result = set()
    expr.visit(lambda expr:visitor_get_stack_accesses(ir_arch_a, expr, result))
    return result


def get_interval_length(interval_in):
    length = 0
    for start, stop in interval_in.intervals:
        length += stop + 1 - start
    return length


def check_expr_below_stack(ir_arch_a, expr):
    """
    Return False if expr pointer is below original stack pointer
    @ir_arch_a: ira instance
    @expr: Expression instance
    """
    ptr = expr.ptr
    diff = expr_simp(ptr - ir_arch_a.sp)
    if not diff.is_int():
        return True
    if int(diff) == 0 or int(expr_simp(diff.msb())) == 0:
        return False
    return True


def retrieve_stack_accesses(ir_arch_a, ircfg):
    """
    Walk the ssa graph and find stack based variables.
    Return a dictionary linking stack base address to its size/name
    @ir_arch_a: ira instance
    @ircfg: IRCFG instance
    """
    stack_vars = set()
    for block in viewvalues(ircfg.blocks):
        for assignblk in block:
            for dst, src in viewitems(assignblk):
                stack_vars.update(get_stack_accesses(ir_arch_a, dst))
                stack_vars.update(get_stack_accesses(ir_arch_a, src))
    stack_vars = [expr for expr in stack_vars if check_expr_below_stack(ir_arch_a, expr)]

    base_to_var = {}
    for var in stack_vars:
        base_to_var.setdefault(var.ptr, set()).add(var)


    base_to_interval = {}
    for addr, vars in viewitems(base_to_var):
        var_interval = interval()
        for var in vars:
            offset = expr_simp(addr - ir_arch_a.sp)
            if not offset.is_int():
                # skip non linear stack offset
                continue

            start = int(offset)
            stop = int(expr_simp(offset + ExprInt(var.size // 8, offset.size)))
            mem = interval([(start, stop-1)])
            var_interval += mem
        base_to_interval[addr] = var_interval
    if not base_to_interval:
        return {}
    # Check if not intervals overlap
    _, tmp = base_to_interval.popitem()
    while base_to_interval:
        addr, mem = base_to_interval.popitem()
        assert (tmp & mem).empty
        tmp += mem

    base_to_info = {}
    for addr, vars in viewitems(base_to_var):
        name = "var_%d" % (len(base_to_info))
        size = max([var.size for var in vars])
        base_to_info[addr] = size, name
    return base_to_info


def fix_stack_vars(expr, base_to_info):
    """
    Replace local stack accesses in expr using information in @base_to_info
    @expr: Expression instance
    @base_to_info: dictionary linking stack base address to its size/name
    """
    if not expr.is_mem():
        return expr
    ptr = expr.ptr
    if ptr not in base_to_info:
        return expr
    size, name = base_to_info[ptr]
    var = ExprId(name, size)
    if size == expr.size:
        return var
    assert expr.size < size
    return var[:expr.size]


def replace_mem_stack_vars(expr, base_to_info):
    return expr.visit(lambda expr:fix_stack_vars(expr, base_to_info))


def replace_stack_vars(ir_arch_a, ircfg):
    """
    Try to replace stack based memory accesses by variables.

    Hypothesis: the input ircfg must have all it's accesses to stack explicitly
    done through the stack register, ie every aliases on those variables is
    resolved.

    WARNING: may fail

    @ir_arch_a: ira instance
    @ircfg: IRCFG instance
    """

    base_to_info = retrieve_stack_accesses(ir_arch_a, ircfg)
    modified = False
    for block in list(viewvalues(ircfg.blocks)):
        assignblks = []
        for assignblk in block:
            out = {}
            for dst, src in viewitems(assignblk):
                new_dst = dst.visit(lambda expr:replace_mem_stack_vars(expr, base_to_info))
                new_src = src.visit(lambda expr:replace_mem_stack_vars(expr, base_to_info))
                if new_dst != dst or new_src != src:
                    modified |= True

                out[new_dst] = new_src

            out = AssignBlock(out, assignblk.instr)
            assignblks.append(out)
        new_block = IRBlock(block.loc_key, assignblks)
        ircfg.blocks[block.loc_key] = new_block
    return modified


def memlookup_test(expr, bs, is_addr_ro_variable, result):
    if expr.is_mem() and expr.ptr.is_int():
        ptr = int(expr.ptr)
        if is_addr_ro_variable(bs, ptr, expr.size):
            result.add(expr)
        return False
    return True


def memlookup_visit(expr, bs, is_addr_ro_variable):
    result = set()
    expr.visit(lambda expr: expr,
               lambda expr: memlookup_test(expr, bs, is_addr_ro_variable, result))
    return result


def get_memlookup(expr, bs, is_addr_ro_variable):
    return memlookup_visit(expr, bs, is_addr_ro_variable)


def read_mem(bs, expr):
    ptr = int(expr.ptr)
    var_bytes = bs.getbytes(ptr, expr.size // 8)[::-1]
    try:
        value = int(encode_hex(var_bytes), 16)
    except ValueError:
        return expr
    return ExprInt(value, expr.size)


def load_from_int(ir_arch, bs, is_addr_ro_variable):
    """
    Replace memory read based on constant with static value
    @ir_arch: ira instance
    @bs: binstream instance
    @is_addr_ro_variable: callback(addr, size) to test memory candidate
    """

    modified = False
    for block in list(viewvalues(ir_arch.blocks)):
        assignblks = list()
        for assignblk in block:
            out = {}
            for dst, src in viewitems(assignblk):
                # Test src
                mems = get_memlookup(src, bs, is_addr_ro_variable)
                src_new = src
                if mems:
                    replace = {}
                    for mem in mems:
                        value = read_mem(bs, mem)
                        replace[mem] = value
                    src_new = src.replace_expr(replace)
                    if src_new != src:
                        modified = True
                # Test dst pointer if dst is mem
                if dst.is_mem():
                    ptr = dst.ptr
                    mems = get_memlookup(ptr, bs, is_addr_ro_variable)
                    if mems:
                        replace = {}
                        for mem in mems:
                            value = read_mem(bs, mem)
                            replace[mem] = value
                        ptr_new = ptr.replace_expr(replace)
                        if ptr_new != ptr:
                            modified = True
                            dst = ExprMem(ptr_new, dst.size)
                out[dst] = src_new
            out = AssignBlock(out, assignblk.instr)
            assignblks.append(out)
        block = IRBlock(block.loc_key, assignblks)
        ir_arch.blocks[block.loc_key] = block
    return modified


class AssignBlockLivenessInfos(object):
    """
    Description of live in / live out of an AssignBlock
    """

    __slots__ = ["gen", "kill", "var_in", "var_out", "live", "assignblk"]

    def __init__(self, assignblk, gen, kill):
        self.gen = gen
        self.kill = kill
        self.var_in = set()
        self.var_out = set()
        self.live = set()
        self.assignblk = assignblk

    def __str__(self):
        out = []
        out.append("\tVarIn:" + ", ".join(str(x) for x in self.var_in))
        out.append("\tGen:" + ", ".join(str(x) for x in self.gen))
        out.append("\tKill:" + ", ".join(str(x) for x in self.kill))
        out.append(
            '\n'.join(
                "\t%s = %s" % (dst, src)
                for (dst, src) in viewitems(self.assignblk)
            )
        )
        out.append("\tVarOut:" + ", ".join(str(x) for x in self.var_out))
        return '\n'.join(out)


class IRBlockLivenessInfos(object):
    """
    Description of live in / live out of an AssignBlock
    """
    __slots__ = ["loc_key", "infos", "assignblks"]


    def __init__(self, irblock):
        self.loc_key = irblock.loc_key
        self.infos = []
        self.assignblks = []
        for assignblk in irblock:
            gens, kills = set(), set()
            for dst, src in viewitems(assignblk):
                expr = ExprAssign(dst, src)
                read = expr.get_r(mem_read=True)
                write = expr.get_w()
                gens.update(read)
                kills.update(write)
            self.infos.append(AssignBlockLivenessInfos(assignblk, gens, kills))
            self.assignblks.append(assignblk)

    def __getitem__(self, index):
        """Getitem on assignblks"""
        return self.assignblks.__getitem__(index)

    def __str__(self):
        out = []
        out.append("%s:" % self.loc_key)
        for info in self.infos:
            out.append(str(info))
            out.append('')
        return "\n".join(out)


class DiGraphLiveness(DiGraph):
    """
    DiGraph representing variable liveness
    """

    def __init__(self, ircfg, loc_db=None):
        super(DiGraphLiveness, self).__init__()
        self.ircfg = ircfg
        self.loc_db = loc_db
        self._blocks = {}
        # Add irblocks gen/kill
        for node in ircfg.nodes():
            irblock = ircfg.blocks.get(node, None)
            if irblock is None:
                continue
            irblockinfos = IRBlockLivenessInfos(irblock)
            self.add_node(irblockinfos.loc_key)
            self.blocks[irblockinfos.loc_key] = irblockinfos
            for succ in ircfg.successors(node):
                self.add_uniq_edge(node, succ)
            for pred in ircfg.predecessors(node):
                self.add_uniq_edge(pred, node)

    @property
    def blocks(self):
        return self._blocks

    def init_var_info(self):
        """Add ircfg out regs"""
        raise NotImplementedError("Abstract method")

    def node2lines(self, node):
        """
        Output liveness information in dot format
        """
        if self.loc_db is None:
            node_name = str(node)
        else:
            names = self.loc_db.get_location_names(node)
            if not names:
                node_name = self.loc_db.pretty_str(node)
            else:
                node_name = "".join("%s:\n" % name for name in names)
        yield self.DotCellDescription(
            text="%s" % node_name,
            attr={
                'align': 'center',
                'colspan': 2,
                'bgcolor': 'grey',
            }
        )
        if node not in self._blocks:
            yield [self.DotCellDescription(text="NOT PRESENT", attr={})]
            return

        for i, info in enumerate(self._blocks[node].infos):
            var_in = "VarIn:" + ", ".join(str(x) for x in info.var_in)
            var_out = "VarOut:" + ", ".join(str(x) for x in info.var_out)

            assignmnts = ["%s = %s" % (dst, src) for (dst, src) in viewitems(info.assignblk)]

            if i == 0:
                yield self.DotCellDescription(
                    text=var_in,
                    attr={
                        'bgcolor': 'green',
                    }
                )

            for assign in assignmnts:
                yield self.DotCellDescription(text=assign, attr={})
            yield self.DotCellDescription(
                text=var_out,
                attr={
                    'bgcolor': 'green',
                }
            )
            yield self.DotCellDescription(text="", attr={})

    def back_propagate_compute(self, block):
        """
        Compute the liveness information in the @block.
        @block: AssignBlockLivenessInfos instance
        """
        infos = block.infos
        modified = False
        for i in reversed(range(len(infos))):
            new_vars = set(infos[i].gen.union(infos[i].var_out.difference(infos[i].kill)))
            if infos[i].var_in != new_vars:
                modified = True
                infos[i].var_in = new_vars
            if i > 0 and infos[i - 1].var_out != set(infos[i].var_in):
                modified = True
                infos[i - 1].var_out = set(infos[i].var_in)
        return modified

    def back_propagate_to_parent(self, todo, node, parent):
        """
        Back propagate the liveness information from @node to @parent.
        @node: loc_key of the source node
        @parent: loc_key of the node to update
        """
        parent_block = self.blocks[parent]
        cur_block = self.blocks[node]
        if cur_block.infos[0].var_in == parent_block.infos[-1].var_out:
            return
        var_info = cur_block.infos[0].var_in.union(parent_block.infos[-1].var_out)
        parent_block.infos[-1].var_out = var_info
        todo.add(parent)

    def compute_liveness(self):
        """
        Compute the liveness information for the digraph.
        """
        todo = set(self.leaves())
        while todo:
            node = todo.pop()
            cur_block = self.blocks.get(node, None)
            if cur_block is None:
                continue
            modified = self.back_propagate_compute(cur_block)
            if not modified:
                continue
            # We modified parent in, propagate to parents
            for pred in self.predecessors(node):
                self.back_propagate_to_parent(todo, node, pred)
        return True


class DiGraphLivenessIRA(DiGraphLiveness):
    """
    DiGraph representing variable liveness for IRA
    """

    def init_var_info(self, ir_arch_a):
        """Add ircfg out regs"""

        for node in self.leaves():
            irblock = self.ircfg.blocks.get(node, None)
            if irblock is None:
                continue
            var_out = ir_arch_a.get_out_regs(irblock)
            irblock_liveness = self.blocks[node]
            irblock_liveness.infos[-1].var_out = var_out


def discard_phi_sources(ircfg, deleted_vars):
    """
    Remove phi sources in @ircfg belonging to @deleted_vars set
    @ircfg: IRCFG instance in ssa form
    @deleted_vars: unused phi sources
    """
    for block in list(viewvalues(ircfg.blocks)):
        if not block.assignblks:
            continue
        assignblk = block[0]
        todo = {}
        modified = False
        for dst, src in viewitems(assignblk):
            if not src.is_op('Phi'):
                todo[dst] = src
                continue
            srcs = set(expr for expr in src.args if expr not in deleted_vars)
            assert(srcs)
            if len(srcs) > 1:
                todo[dst] = ExprOp('Phi', *srcs)
                continue
            todo[dst] = srcs.pop()
            modified = True
        if not modified:
            continue
        assignblks = list(block)
        assignblk = dict(assignblk)
        assignblk.update(todo)
        assignblk = AssignBlock(assignblk, assignblks[0].instr)
        assignblks[0] = assignblk
        new_irblock = IRBlock(block.loc_key, assignblks)
        ircfg.blocks[block.loc_key] = new_irblock
    return True


def get_unreachable_nodes(ircfg, edges_to_del, heads):
    """
    Return the unreachable nodes starting from heads and the associated edges to
    be deleted.

    @ircfg: IRCFG instance
    @edges_to_del: edges already marked as deleted
    heads: locations of graph heads
    """
    todo = set(heads)
    visited_nodes = set()
    new_edges_to_del = set()
    while todo:
        node = todo.pop()
        if node in visited_nodes:
            continue
        visited_nodes.add(node)
        for successor in ircfg.successors(node):
            if (node, successor) not in edges_to_del:
                todo.add(successor)
    all_nodes = set(ircfg.nodes())
    nodes_to_del = all_nodes.difference(visited_nodes)
    for node in nodes_to_del:
        for successor in ircfg.successors(node):
            if successor not in nodes_to_del:
                # Frontier: link from a deleted node to a living node
                new_edges_to_del.add((node, successor))
    return nodes_to_del, new_edges_to_del


def update_phi_with_deleted_edges(ircfg, edges_to_del):
    """
    Update phi which have a source present in @edges_to_del
    @ssa: IRCFG instance in ssa form
    @edges_to_del: edges to delete
    """


    phi_locs_to_srcs = {}
    for loc_src, loc_dst in edges_to_del:
        phi_locs_to_srcs.setdefault(loc_dst, set()).add(loc_src)

    modified = False
    blocks = dict(ircfg.blocks)
    for loc_dst, loc_srcs in viewitems(phi_locs_to_srcs):
        block = ircfg.blocks[loc_dst]
        if not irblock_has_phi(block):
            continue
        assignblks = list(block)
        assignblk = assignblks[0]
        out = {}
        for dst, phi_sources in viewitems(assignblk):
            if not phi_sources.is_op('Phi'):
                out[dst] = phi_sources
                continue
            var_to_parents = get_phi_sources_parent_block(
                ircfg,
                loc_dst,
                phi_sources.args
            )
            to_keep = set(phi_sources.args)
            for src in phi_sources.args:
                parents = var_to_parents[src]
                remaining = parents.difference(loc_srcs)
                if not remaining:
                    to_keep.discard(src)
                    modified = True
            assert to_keep
            if len(to_keep) == 1:
                out[dst] = to_keep.pop()
            else:
                out[dst] = ExprOp('Phi', *to_keep)
        assignblk = AssignBlock(out, assignblks[0].instr)
        assignblks[0] = assignblk
        new_irblock = IRBlock(loc_dst, assignblks)
        blocks[block.loc_key] = new_irblock

    for loc_key, block in viewitems(blocks):
        ircfg.blocks[loc_key] = block
    return modified


def del_unused_edges(ircfg, heads):
    """
    Delete non accessible edges in the @ircfg graph.
    @ircfg: IRCFG instance in ssa form
    @heads: location of the heads of the graph
    """

    deleted_vars = set()
    modified = False
    edges_to_del_1 = set()
    for node in ircfg.nodes():
        successors = set(ircfg.successors(node))
        block = ircfg.blocks.get(node, None)
        if block is None:
            continue
        dst = block.dst
        possible_dsts = set(solution.value for solution in possible_values(dst))
        if not all(dst.is_loc() for dst in possible_dsts):
            continue
        possible_dsts = set(dst.loc_key for dst in possible_dsts)
        if len(possible_dsts) == len(successors):
            continue
        dsts_to_del = successors.difference(possible_dsts)
        for dst in dsts_to_del:
            edges_to_del_1.add((node, dst))

    # Remove edges and update phi accordingly
    # Two cases here:
    # - edge is directly linked to a phi node
    # - edge is indirect linked to a phi node
    nodes_to_del, edges_to_del_2 = get_unreachable_nodes(ircfg, edges_to_del_1, heads)
    modified |= update_phi_with_deleted_edges(ircfg, edges_to_del_1.union(edges_to_del_2))

    for src, dst in edges_to_del_1.union(edges_to_del_2):
        ircfg.del_edge(src, dst)
    for node in nodes_to_del:
        block = ircfg.blocks[node]
        ircfg.del_node(node)
        del ircfg.blocks[node]

        for assignblock in block:
            for dst in assignblock:
                deleted_vars.add(dst)

    if deleted_vars:
        modified |= discard_phi_sources(ircfg, deleted_vars)

    return modified


class DiGraphLivenessSSA(DiGraphLivenessIRA):
    """
    DiGraph representing variable liveness is a SSA graph
    """
    def __init__(self, ircfg):
        super(DiGraphLivenessSSA, self).__init__(ircfg)

        self.loc_key_to_phi_parents = {}
        for irblock in viewvalues(self.blocks):
            if not irblock_has_phi(irblock):
                continue
            out = {}
            for sources in viewvalues(irblock[0]):
                if not sources.is_op('Phi'):
                    # Some phi sources may have already been resolved to an
                    # expression
                    continue
                var_to_parents = get_phi_sources_parent_block(self, irblock.loc_key, sources.args)
                for var, var_parents in viewitems(var_to_parents):
                    out.setdefault(var, set()).update(var_parents)
            self.loc_key_to_phi_parents[irblock.loc_key] = out

    def back_propagate_to_parent(self, todo, node, parent):
        if parent not in self.blocks:
            return
        parent_block = self.blocks[parent]
        cur_block = self.blocks[node]
        irblock = self.ircfg.blocks[node]
        if cur_block.infos[0].var_in == parent_block.infos[-1].var_out:
            return
        var_info = cur_block.infos[0].var_in.union(parent_block.infos[-1].var_out)

        if irblock_has_phi(irblock):
            # Remove phi special case
            out = set()
            phi_sources = self.loc_key_to_phi_parents[irblock.loc_key]
            for var in var_info:
                if var not in phi_sources:
                    out.add(var)
                    continue
                if parent in phi_sources[var]:
                    out.add(var)
            var_info = out

        parent_block.infos[-1].var_out = var_info
        todo.add(parent)



class ExprPropagationHelper(object):
    """
    Compute and store interferences between expressions
    """

    def __init__(self, ir_arch):
        self.ir_arch = ir_arch
        self.variable_values = {}
        self.dependencies = {}

    def extract_interferences(self, dst, src):
        """
        Extract interference sources from @expr (here, ExprMem)
        """
        exprs = src.get_r(mem_read=True)
        interferences = set([expr for expr in exprs if expr.is_mem()])

        if dst.is_mem():
            exprs = dst.ptr.get_r(mem_read=True)
            interferences.update(expr for expr in exprs if expr.is_mem())
        return interferences


    def test_interference(self, expr_a, expr_b):
        """
        Return True if @expr_a interfers with @expr_b
        """
        if not expr_a.is_mem():
            return False
        if not expr_b.is_mem():
            return False
        ptr_a = expr_a.ptr
        ptr_b = expr_b.ptr

        ptr_base_a, ptr_offset_a = get_expr_base_offset(ptr_a)
        ptr_base_b, ptr_offset_b = get_expr_base_offset(ptr_b)


        if ptr_base_a == ptr_base_b:
            # Same symbolic based ExprMem
            diff = ptr_offset_b - ptr_offset_a

            mem_a, mem_b = expr_a, expr_b
            if diff < 0:
                mem_a, mem_b = mem_b, mem_a
                diff = -diff

            base1, base2 = 0, diff
            size1, size2 = mem_a.size // 8, mem_b.size // 8
            interval1 = interval([(base1, base1 + size1 - 1)])
            interval2 = interval([(base2, base2 + size2 - 1)])
            result = interval1 & interval2
            if result.empty:
                return False
            return True

        # Case: two memories with different symbolic bases

        if ((ptr_a.is_int() and ptr_base_b == self.ir_arch.sp) or
            (ptr_b.is_int() and ptr_base_a == self.ir_arch.sp)):
            # Stack based versus global => consider don't interfere
            return False
        return True

    def can_propagate(self, dst, src):
        """
        Return True if @src can be propagated in @dst
        """
        if src.is_op("Phi"):
            # Do not propagate phi
            return False
        if src.is_function_call():
            # Do not propagate function call
            return False
        if dst.is_id() and dst.name.startswith("tmp"):
            return False
        return True


    def del_interfered_variables(self, assignblk):
        """
        Del variables which interfer with @assignblk
        """
        interferences = set()
        for dst, src in viewitems(assignblk):
            # For each assignment, check if destination interfer with mem store
            for mem, mem_deps in viewitems(self.dependencies):
                for mem_dep in mem_deps:
                    if self.test_interference(dst, mem_dep):
                        interferences.add(mem)
                        break

        # Remove interfered variables from store
        for dst in interferences:
            del self.variable_values[dst]
            del self.dependencies[dst]

    def update_interferences(self, assignblk):
        """
        Compute and apply interferences from @assignblk
        """
        self.del_interfered_variables(assignblk)

        # Compute mem dependencies
        assignment_dependencies = {}
        for dst, src in viewitems(assignblk):
            assignment_dependencies[dst] = self.extract_interferences(dst, src)

        # Filter out self interferences
        out = {}
        for dst, src in viewitems(assignblk):
            if not self.can_propagate(dst, src):
                continue
            var_dependencies = assignment_dependencies[dst]
            interfer = False
            for var_dependency in var_dependencies:
                for var_dst in assignblk:
                    if self.test_interference(var_dst, var_dependency):
                        # Self assignblock interference
                        interfer = True
                        break
                if interfer:
                    break
            if not interfer:
                # No interference found, keep assignment
                out[dst] = src

        for dst, src in viewitems(out):
            self.variable_values[dst] = src
            self.dependencies[dst] = assignment_dependencies[dst].union(set([dst]))

    def propagate_intra_block(self, block):
        assignblks = []
        modified = False

        self.variable_values = {}
        self.dependencies = {}

        for index, assignblk in enumerate(block):
            out = {}
            interferences = set()
            for dst, src in viewitems(assignblk):
                if src.is_op('Phi'):
                    new_src = src
                else:
                    new_src = expr_simp(src.replace_expr(self.variable_values))
                if src != new_src:
                    modified = True
                if dst.is_mem():
                    new_dst = expr_simp(ExprMem(dst.ptr.replace_expr(self.variable_values), dst.size))
                    if dst != new_dst:
                        modified = True
                else:
                    new_dst = dst

                src = new_src
                dst = new_dst
                out[dst] = src
            self.update_interferences(out)
            assignblks.append(AssignBlock(out, assignblk.instr))
        if modified:
            block = IRBlock(block.loc_key, assignblks)
        return modified, block


    def propagage_memory_block(self, ssa, block):
        assignblks = []
        modified, block = self.propagate_intra_block(block)
        if modified:
            ssa.graph.blocks[block.loc_key] = block
        return modified

    def propagage_memory(self, ssa, head):
        modified = False
        for block in ssa.graph.blocks.values():
            modified |= self.propagage_memory_block(ssa, block)
        return modified


def get_phi_sources(phi_src, phi_dsts, ids_to_src):
    true_values = set()
    for src in phi_src.args:
        if src in phi_dsts:
            # Source is phi dst => skip
            continue
        true_src = ids_to_src[src]
        if true_src in phi_dsts:
            # Source is phi dst => skip
            continue
        # Chec if src is not also a phi
        if true_src.is_op('Phi'):
            phi_dsts.add(src)
            true_src = get_phi_sources(true_src, phi_dsts, ids_to_src)
        if true_src is False:
            return False
        if true_src is True:
            continue
        true_values.add(true_src)
        if len(true_values) != 1:
            return False
    if not true_values:
        return True
    if len(true_values) != 1:
        return False
    true_value = true_values.pop()
    return true_value


def del_dummy_phi(ssa, head):
    """
    Remove phi with unique source
    Handle interdependent Phi variables
    """
    ids_to_src = {}
    for block in viewvalues(ssa.graph.blocks):
        for index, assignblock in enumerate(block):
            for dst, src in viewitems(assignblock):
                if not dst.is_id():
                    continue
                ids_to_src[dst] = src

    modified = False
    for block in ssa.graph.blocks.values():
        if not irblock_has_phi(block):
            continue
        assignblk = block[0]
        final_phis = dict(assignblk)
        fixed_values = {}
        local_modified = False
        for dst, phi_src in viewitems(assignblk):
            assert phi_src.is_op('Phi')
            true_value = get_phi_sources(phi_src, set([dst]), ids_to_src)
            if true_value is False:
                continue
            assert true_value != True
            if expr_has_mem(true_value):
                continue

            del(final_phis[dst])
            fixed_values[dst] = true_value
            local_modified = True

        if not local_modified:
            continue
        assignblks = list(block)
        assignblks[0] = AssignBlock(final_phis, assignblk.instr)
        assignblks[1:1] = [AssignBlock(fixed_values, assignblk.instr)]
        new_irblock = IRBlock(block.loc_key, assignblks)
        ssa.graph.blocks[block.loc_key] = new_irblock
        modified = True

    return modified




class DelDupMemWrite(object):
    """
    Remove duplicate memory write to the same target without reference between
    writes
    """
    def __init__(self, ir_arch, stk_lvl):
        self.ir_arch = ir_arch
        self.stk_lvl = stk_lvl
        self.compute_alias = AliasMngr(self.ir_arch)


    def is_dup_write_mem_candidate(self, dst, stk_lvl_base):
        """
        Return True if @dst could be removed in case of positive duplicate write
        """
        if not dst.is_mem():
            return False
        return True

        # ptr = dst.ptr
        # if ptr.is_int():
        #     return True

        # base, offset = get_expr_base_offset(ptr)
        # return base == stk_lvl_base

    def is_known_read_memory(self, mem, stk_lvl_base):
        """
        Return True if @mem is at a known destination
        """
        base, offset = get_expr_base_offset(mem.ptr)
        return base == stk_lvl_base

    def filter_deads(self, assignblk, read_mems, deads, stk_lvl_base):
        all_reads_known = True
        deads_to_del = set()
        for mem in read_mems:
            """
            if not self.is_known_read_memory(mem, stk_lvl_base):
                deads.clear()
                return
            """
            for dead in deads:
                if self.compute_alias.test_may_alias(mem, dead):
                    deads_to_del.add(dead)
        deads.difference_update(deads_to_del)

        # If we have function call, we may have unknown memory reads
        for src in assignblk.values():
            if src.is_function_call():
                deads.clear()
                return

    def get_memory_reads(self, assignblk):
        """
        Return read memory from @assignblk
        """
        reads = assignblk.get_r(mem_read=True)
        read_mems = [expr for expr in reads if expr.is_mem()]
        return read_mems

    def remove_dup_writes(self, block, deads):
        # Remove unused stack assignments
        assignblks = []
        modified = False
        for index, assignblk in enumerate(block):
            out = {}
            for dst, src in viewitems(assignblk):
                if dst in deads[index]:
                    modified = True
                else:
                    out[dst] = src
            assignblks.append(AssignBlock(out, assignblk.instr))

        if modified:
            block = IRBlock(block.loc_key, assignblks)
            modified = True
        return block, modified

    def del_dup_write_mem(self, ssa, head):
        modified = False
        for block in ssa.graph.blocks.values():
            block_modified = False
            cur_dead = set()
            # Last block has no dead
            deads = []
            for index, assignblk in list(enumerate(list(block)))[::-1]:
                if self.stk_lvl in assignblk:
                    stk_lvl_cur = assignblk[self.stk_lvl]
                    stk_lvl_base, _ = get_expr_base_offset(stk_lvl_cur)
                else:
                    stk_lvl_base = None

                unknown_read = False
                write_mems = set()
                read_mems = self.get_memory_reads(assignblk)
                self.filter_deads(assignblk, read_mems, cur_dead, stk_lvl_base)

                for dst in assignblk:
                    if self.is_dup_write_mem_candidate(dst, stk_lvl_base):
                        write_mems.add(dst)

                cur_dead.update(write_mems)
                cur_dead.difference_update(read_mems)
                deads.append(set(cur_dead))

            # No dead in entry
            deads.pop()

            deads.reverse()
            deads.append(set())

            block, block_modified = self.remove_dup_writes(block, deads)
            if block_modified:
                ssa.graph.blocks[block.loc_key] = block
                modified = True

        return modified


class AliasMngr(object):
    def __init__(self, ir_arch):
        self.ir_arch = ir_arch

    def test_same_base(self, expr_a, expr_b):
        """
        Return True if @expr_a overlap @expr_b (@expr_a and @expr_b are ExprMem)
        """
        ptr_base_a, ptr_offset_a = get_expr_base_offset(expr_a.ptr)
        ptr_base_b, ptr_offset_b = get_expr_base_offset(expr_b.ptr)

        assert ptr_base_a == ptr_base_b
        mask = int(ptr_base_a.mask)

        # Same symbolic based ExprMem
        diff = ptr_offset_b - ptr_offset_a

        mem_a, mem_b = expr_a, expr_b
        if diff < 0:
            mem_a, mem_b = mem_b, mem_a
            diff = -diff

        base1, base2 = 0, diff
        size1, size2 = mem_a.size // 8, mem_b.size // 8

        assert size1 <= mask
        assert size2 <= mask

        if base1 <= base2 < base1 + size1:
            return True
        if base2 + size2 > mask + 1:
            # Overflow, so overlap
            return True
        return False

    def test_different_base(self, expr_a, expr_b):
        # By default, different bases may alias
        return True
        #print("diff base", expr_a, expr_b)
        ptr_base_a, ptr_offset_a = get_expr_base_offset(expr_a.ptr)
        ptr_base_b, ptr_offset_b = get_expr_base_offset(expr_b.ptr)

        sp_p4 = ExprMem(self.ir_arch.arch.regs.ESP + ExprInt(4, 32), 32)
        # XXX TODO: move custom rulez to extern code
        if set([ptr_base_a, ptr_base_b]) == set([self.ir_arch.arch.regs.ESP, self.ir_arch.arch.regs.EBP]):
            return False
        if ExprId('arg0', 32) in set([ptr_base_a, ptr_base_b]):
            return False
        #if (sp_p4 in ptr_base_a or
        #    sp_p4 in ptr_base_b):
        #    return False
        #print("MAY ALIAS", ptr_base_a, ptr_base_b)
        return True


    def test_may_alias(self, expr_a, expr_b):
        """
        Return True if @expr_a overlap with @expr_b
        """
        if expr_a.is_id() and expr_b.is_id():
            return expr_a == expr_b
        elif expr_a.is_id() or expr_b.is_id():
            return False

        assert expr_a.is_mem()
        assert expr_b.is_mem()

        ptr_a = expr_a.ptr
        ptr_b = expr_b.ptr

        ptr_base_a, ptr_offset_a = get_expr_base_offset(ptr_a)
        ptr_base_b, ptr_offset_b = get_expr_base_offset(ptr_b)

        if ptr_base_a == ptr_base_b:
            return self.test_same_base(expr_a, expr_b)

        return self.test_different_base(expr_a, expr_b)




class SymbexecDelInterferences(SymbolicExecutionEngine):
    def eval_updt_assignblk(self, assignblk):
        """
        Apply an AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        mem_dst = []
        #print("EXEC")
        #print(assignblk)
        dst_src = self.eval_assignblk(assignblk)
        self.do_dst_src(dst_src)
        """
        for dst, src in viewitems(dst_src):
            self.apply_change(dst, src)
            if dst.is_mem():
                mem_dst.append(dst)
        """
        return []

    def test_dependency(self, assignblk):
        all_dsts = set(dst_src.keys())
        to_del = set()
        for dst, src in viewitems(assignblk):
            uses = key.get_r(mem_read=True).union(value.get_r(mem_read=True))
            if uses & all_dsts:
                to_del.add(dst)
        return to_del

    def do_dst_src(self, dst_src):
        compute_alias = AliasMngr(self.ir_arch)
        out = {}
        all_dsts = set(dst_src.keys())
        to_del = set()
        # First remove known symbols with updated sources
        for dst, src in viewitems(self.symbols):
            #if dst.is_id() and dst.name.startswith("tmp"):
            #    to_del.add(dst)
            #    continue


            uses = src.get_r(mem_read=True)
            if dst.is_mem():
                uses.update(dst.ptr.get_r(mem_read=True))
            if uses & all_dsts:
                to_del.add(dst)
        for dst in to_del:
            del(self.symbols[dst])


        to_del = set()
        # Then remove known symbols which may alias to updated sources
        for dst, src in viewitems(self.symbols):
            uses = src.get_r(mem_read=True)
            if dst.is_mem():
                uses.update(dst.ptr.get_r(mem_read=True))
            skip = False
            for dst_test in all_dsts:
                for use in uses:
                    if compute_alias.test_may_alias(dst_test, use):
                        to_del.add(dst)
                        skip = True
                        break
                if skip:
                    break
        for dst in to_del:
            del(self.symbols[dst])

        to_del = set()
        # Then remove update with self reference
        for dst, src in viewitems(dst_src):
            uses = src.get_r(mem_read=True)
            if dst.is_mem():
                uses.update(dst.ptr.get_r(mem_read=True))
            if uses & all_dsts:
                to_del.add(dst)
        for dst in to_del:
            del(dst_src[dst])
            try:
                del(self.symbols[dst])
            except:
                pass



        # Don't propagate local stack after their stack high limit
        #stk_lvl_cur = self.symbols[ExprId("stk_lvl", 32)]
        stk_lvl_cur = dst_src.get(ExprId("stk_lvl", 32), None)
        if stk_lvl_cur is not None:
            sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)
        else:
            sp_base = None

        to_del = set()
        for dst, src in viewitems(dst_src):
            #uses = src.get_r(mem_read=True)
            #if dst.is_mem():
            #    uses.update(dst.ptr.get_r(mem_read=True))
            uses = set([dst])
            uses = set(use for use in uses if use.is_mem())
            for use in uses:
                mem_base, mem_offset = get_expr_base_offset(use.ptr)
                if mem_base != sp_base:
                    print("Dont1 propagate stack after stk limit high")
                    print("%s = %s" % (dst, src))
                    to_del.add(dst)
                    break
                #print("LVLS", use.ptr, stk_lvl_cur)
                diff = expr_simp((use.ptr - stk_lvl_cur).msb())
                if diff.is_int() and int(diff) == 1:
                    print("Dont2 propagate stack after stk limit high")
                    print("%s = %s" % (dst, src))
                    to_del.add(dst)
                    break
        for dst in to_del:
            del(dst_src[dst])
            try:
                del(self.symbols[dst])
            except:
                pass


        # Don't propagate read memory with undetermined offset from stack
        to_del = set()
        for dst, src in viewitems(dst_src):
            #uses = src.get_r(mem_read=True)
            #if dst.is_mem():
            #    uses.update(dst.ptr.get_r(mem_read=True))
            assign = ExprAssign(dst, src)
            uses = assign.get_r(mem_read=True)
            uses = set(use for use in uses if use.is_mem())

            for use in uses:
                mem_base, mem_offset = get_expr_base_offset(use.ptr)
                if mem_base != sp_base:
                    print("READ: Dont1 propagate stack after stk limit high")
                    print("%s = %s" % (dst, src))
                    to_del.add(dst)
                    break
        for dst in to_del:
            del(dst_src[dst])
            try:
                del(self.symbols[dst])
            except:
                pass




        # Don't update store if dst may alias with it's own sources
        for dst, src in dst_src.items():
            #if dst.is_id() and dst.name.startswith("tmp"):


            uses = src.get_r(mem_read=True)
            if dst.is_mem():
                uses.update(dst.ptr.get_r(mem_read=True))
            skip = False
            for dst_test in all_dsts:
                for use in uses:
                    if compute_alias.test_may_alias(dst_test, use):
                        skip = True
                        break
                if skip:
                    break
            if skip:
                if dst in self.symbols:
                    del self.symbols[dst]
                continue
            if src.is_op('Phi') or src.is_function_call():
                continue
            out[dst] = src

        all_dsts = set(out.keys())

        for dst, src in out.items():
            super(SymbexecDelInterferences, self).apply_change(dst, src)


class SymbexecDelInterferencesAndFix(SymbexecDelInterferences):

    def eval_exprloc(self, expr, **kwargs):
        """[DEV]: Evaluate an ExprLoc using the current state"""
        return expr

    def eval_updt_irblock(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: irbloc instance
        @step: display intermediate steps
        """
        irs = []
        modified = False
        for assignblk in irb:
            if step:
                print('Instr', assignblk.instr)
                print('Assignblk:')
                print(assignblk)
                print('_' * 80)

            out = {}
            for dst, src in viewitems(assignblk):
                #if dst.is_id() and dst.name.startswith("tmp"):
                #    continue
                if src.is_op('Phi'):
                    new_src = src
                else:
                    # TEST propag memory tmp_x
                    # XXX
                    if dst.is_mem():
                        replace = {}
                        uses = src.get_r(mem_read=True)
                        uses = set(expr for expr in uses if expr.is_id() and expr.name.startswith('tmp'))
                        if uses:
                            xxx = dict((expr, expr) for expr in uses)
                            new_src = self.eval_expr(src, xxx)
                        else:
                            new_src = self.eval_expr(src)
                    else:
                        new_src = self.eval_expr(src)
                if dst.is_mem():

                    ptr = dst.ptr
                    replace = {}
                    uses = ptr.get_r(mem_read=True)
                    uses = set(expr for expr in uses if expr.is_id() and expr.name.startswith('tmp'))
                    if uses:
                        xxx = dict((expr, expr) for expr in uses)
                        new_ptr = self.eval_expr(ptr, xxx)
                    else:
                        new_ptr = self.eval_expr(ptr)


                    new_dst = ExprMem(new_ptr, dst.size)
                else:
                    new_dst = dst
                if new_dst == new_src:
                    continue
                out[new_dst] = new_src
                if new_src != src or new_dst != dst:
                    modified = True

            irs.append(AssignBlock(out, assignblk.instr))
            self.eval_updt_assignblk(assignblk)
            if step:
                self.dump(mems=False)
                self.dump(ids=False)
                print('_' * 80)

        return modified, IRBlock(irb.loc_key, irs)


class PropagateWithSymbolicExec(object):
    def __init__(self, ir_arch):
        self.ir_arch = ir_arch

    def merge_states(self, states):
        if len(states) == 1:
            return states[0]
        dct = set([(expr_simp(dst), expr_simp(src)) for (dst, src) in dict(states.pop()).items()])
        for state in states:
            dct.intersection_update(set([(expr_simp(dst), expr_simp(src)) for (dst, src) in dict(state).items()]))

        return dict(dct)

    def emul_block(self, block, state):
        symb_exec = SymbexecDelInterferences(self.ir_arch, state=state)
        symb_exec.eval_updt_irblock(block)
        return symb_exec.state

    def get_states(self, head):
        todo = set([head])
        self.states = {}
        for loc_key in todo:
            self.states[loc_key] = {}

        while todo:
            loc_key = todo.pop()
            if loc_key not in self.ircfg.blocks:
                continue
            if loc_key == head:
                merged_state = self.states[loc_key]
                new_state = self.emul_block(self.ircfg.blocks[loc_key],
                                            dict(self.states[loc_key]))
            else:
                """
                We are emulating the current block with each of the
                predecessor states.
                We then merge the states resulting from those emulations to
                only keep information consistent accross all states.

                We could have choosen to merge predecessor states and then
                emulate the current block with those merged states.  But with
                this algorithm, we could have changing values for a variable
                (which could prevent reaching a fix point). For example:

                              ----1-----            -----2----
                             |          |          |          |
                             | @[A] = 1 |          | @[A] = 2 |
                             |          |          |          |
                              ----------            ----------
                                  |                      |
                                  |________      ________|
                                           |    |
                                           v    v
                                         ----3-----
                                        |          |
                                        | X = @[A] |
                                        |          |
                                         ----------
                                             |

                1. Emulating with merged predecessor states

                   - We start by emulating block 1 which gives us the state {
                     @[A] = 1 }.
                   - We emulate block 3 using block 1 state which gives us the
                     state { X = 1 }.
                   - Then we emulate block 2 which gives us the state { @[A] =
                     2 }.
                   - We emulate again block 3 but now using state {} (merge
                     between { @[A] = 1 } and { @[A] = 2 }) which gives us the
                     state { X = @[A] }.

                   To sum up, for block 3 we first had the state { X = 1 } then
                   { X = @[A] }.

                2. Merging states resulting from emulation with each
                predecessor states

                   - We start by emulating block 1 which gives us the state {
                     @[A] = 1 }.
                   - We emulate block 3 using block 1 state (block 2 state is
                     not yet computed) which gives us the state { X = 1 }.
                   - Then we emulate block 2 which gives us the state { @[A] =
                     2 }.
                   - We emulate again block 3 using state { @[A] = 1 } and then
                     state { @[A] = 2 }. Resulting states ({ X = 1 } and { X =
                     2}) are merged which gives us the state {}.

                   To sum up, for block 3 we first had state { X = 1 } then {}.
                """
                new_states = []
                for pred in self.ircfg.predecessors(loc_key):
                    pred_state = self.states.get(pred, None)
                    if pred_state is None:
                        continue
                    new_states.append(self.emul_block(self.ircfg.blocks[loc_key],
                                                      dict(pred_state)))
                new_state = self.merge_states(new_states)

            if self.states.get(loc_key, None) == new_state:
                # Fix point
                continue

            self.states[loc_key] = new_state
            for succ in self.ircfg.successors(loc_key):
                todo.add(succ)

    def do_replacement(self, head):
        modified = False
        for loc_key, state in viewitems(self.states):
            if loc_key == head:
                merged_state = self.states[loc_key]
            else:
                pred_states = []
                for pred in self.ircfg.predecessors(loc_key):
                    pred_state = self.states.get(pred, None)
                    if pred_state is None:
                        continue
                    pred_states.append(pred_state)
                merged_state = self.merge_states(pred_states)

            symb_exec = SymbexecDelInterferencesAndFix(
                self.ir_arch,
                state=dict(merged_state),
                sb_expr_simp = expr_simp
            )
            irblock = self.ircfg.blocks[loc_key]
            modified_block, new_irblock = symb_exec.eval_updt_irblock(irblock)
            modified |= modified_block
            self.ircfg.blocks[new_irblock.loc_key] = new_irblock
        return modified

    def simplify(self, ssa, head):
        print("Papag with symb exec")
        for block in ssa.graph.blocks.values():
            print(block)
        self.ircfg = ssa.graph
        self.get_states(head)
        modified = self.do_replacement(head)
        return modified


"""
XXXXXXXXXX
XXXXXXXXXX
il faut creer un stk_lvl en meme temps que les tmpX
"""

def insert_stk_lvl(ir_arch, ircfg, stk_lvl):
    """
    Insert in each assignblock the stack level *after* it's execution
    """
    for block in list(viewvalues(ircfg.blocks)):
        irs = []
        for assignblk in block:
            if ir_arch.sp not in assignblk:
                stk_value = ir_arch.sp
            else:
                stk_value = assignblk[ir_arch.sp]
            out = dict(assignblk)
            out[stk_lvl] = stk_value
            new_assignblk = AssignBlock(out, assignblk.instr)
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        ircfg.blocks[block.loc_key] = IRBlock(block.loc_key, irs)



def propagate_stk_lvl(alias_mngr, ssa, head, stk_lvl):
    """
    Upward propagate the stk_lvl for each block.
    Conditions of propagation:
    - no memory access which may alias to stack
    """
    print("START STK LVL PROPAG")
    worklist = set((loc_key, None) for loc_key in ssa.graph.blocks)
    done = set()
    modified = False
    while worklist:
        job = worklist.pop()
        if job in done:
            continue
        done.add(job)

        loc_key, stk_lvl_cur = job
        block = ssa.graph.blocks[loc_key]
        print("Analyse stk", stk_lvl_cur)
        print(block)
        irs = list(block)
        block_modified = False
        for idx, assignblk in reversed(list(enumerate(block))):
            print('XXX')
            print(assignblk)
            if stk_lvl not in assignblk:
                # Should be Phi assignblk
                if idx == 0:
                    # XXX TODO: check if stk_lvl does not come from a Phi
                    # => In this case, don't propagate to predecessors
                    continue
                else:
                    stk_lvl_cur = None
                    continue

            if stk_lvl_cur is None:
                if can_assignblock_read_stk(alias_mngr, stk_lvl, assignblk):
                    continue
                stk_lvl_cur = assignblk[stk_lvl]
                continue


            stk_lvl_local = assignblk[stk_lvl]
            #print('*'*30, stk_lvl_cur)
            #print(assignblk)
            print("yyy")
            print(stk_lvl_cur)
            print(stk_lvl_local)

            diff = expr_simp((stk_lvl_local - stk_lvl_cur).msb())
            if diff.is_int() and int(diff) == 1:
                # The stack level of the next block is above us
                # so we can set our new stack level
                print('REPLACE')
                print(assignblk)
                out = dict(assignblk)
                out[stk_lvl] = stk_lvl_cur
                new_assignblk = AssignBlock(out, assignblk.instr)
                # XXXXXXXXXXXXXXXXXXX DEL
                #new_assignblk = do_del_stk_above(new_assignblk)
                irs[idx] = new_assignblk
                assignblk = new_assignblk
                block_modified = True
                #print(irs[idx])

            if can_assignblock_read_stk_above(alias_mngr, stk_lvl, stk_lvl_local, assignblk):
                print("read stk!! del stk cur")
                stk_lvl_cur = None
        if block_modified:
            ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
            modified = True
        # Propagate to predecessors
        if stk_lvl_cur is not None:
            print("Propagate stk lvl to predecessors", stk_lvl_cur)
            print(block)
            for pred in ssa.graph.predecessors(loc_key):
                worklist.add((pred, stk_lvl_cur))
    print("TTT")
    for block in ssa.graph.blocks.values():
        print(block)
    return modified




def can_assignblock_read_stk_above(alias_mngr, stk_lvl, stk_lvl_cur, assignblk):
    stk_lvl_cur = assignblk[stk_lvl]
    sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)
    reads = assignblk.get_r(mem_read=True)
    mems = set(expr for expr in reads if expr.is_mem())
    offset = 1 << (sp_base.size - 1)
    offset_expr = ExprInt(offset, sp_base.size)
    test_mem = ExprMem(sp_base + offset_expr, 8*offset)
    for mem in mems:
        # Test alias against whole stack
        print("MAY ALIAS", mem, test_mem)
        if alias_mngr.test_may_alias(mem, test_mem):
            print("TRU!!")
            return True

    return False


def can_assignblock_read_stk(alias_mngr, stk_lvl, assignblk):
    stk_lvl_cur = assignblk[stk_lvl]
    sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)
    reads = assignblk.get_r(mem_read=True)
    mems = set(expr for expr in reads if expr.is_mem())
    for mem in mems:
        # Test alias against whole stack
        if alias_mngr.test_may_alias(mem, ExprMem(sp_base, 8*int(sp_base.mask))):
            return True

    return False

def can_assignblock_write_stk(alias_mngr, stk_lvl, assignblk):
    stk_lvl_cur = assignblk[stk_lvl]
    sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)
    for dst in assignblk:
        if not dst.is_mem():
            continue
        # Test alias against whole stack
        if alias_mngr.test_may_alias(dst, ExprMem(sp_base, 8*int(sp_base.mask))):
            return True
    return False

def do_del_stk_above(alias_mngr, assignblk, stk_lvl):
    if not stk_lvl in assignblk:
        return assignblk, False
    if not can_assignblock_write_stk(alias_mngr, stk_lvl, assignblk):
        return assignblk, False
    #if can_assignblock_read_stk(alias_mngr, stk_lvl, assignblk):
    #    return assignblk, False
    stk_lvl_cur = assignblk[stk_lvl]

    if can_assignblock_read_stk_above(alias_mngr, stk_lvl, stk_lvl_cur, assignblk):
        return assignblk, False

    out = {}

    sp_base, sp_offset = get_expr_base_offset(stk_lvl_cur)

    modified = False
    for dst, src in viewitems(assignblk):
        if not dst.is_mem():
            out[dst] = src
            continue
        base, offset = get_expr_base_offset(dst.ptr)
        if base != sp_base:
            out[dst] = src
            continue
        ptr = dst.ptr
        diff = expr_simp((ptr - stk_lvl_cur).msb())
        if diff.is_int() and int(diff) == 1:
            modified = True
            continue
    if not modified:
        return assignblk, False
    return AssignBlock(out, assignblk.instr), True



def del_above_stk_write(alias_mngr, ssa, head, stk_lvl):
    """
    Del writes to memory above stack level
    """
    print("TEST DEL ABOVE")
    modified = False
    for block in list(viewvalues(ssa.graph.blocks)):
        irs = []
        modified_block = False
        for assignblk in block:
            new_assignblk, assignblk_modified = do_del_stk_above(alias_mngr, assignblk, stk_lvl)
            irs.append(new_assignblk)
            if assignblk_modified:
                modified_block = True
        if modified_block:
            ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
            modified = True
    return modified


def remove_self_interference(ssa, head, stk_lvl, alias_mngr, interfer_index):
    modified = False
    stk_lvl_last = None
    for block in list(viewvalues(ssa.graph.blocks)):
        #print(block)
        irs = []
        for idx, assignblk in enumerate(block):
            #print(idx)
            all_dsts = set(assignblk.keys())
            aliasing_mems = set()
            for dst, src in viewitems(assignblk):
                uses = src.get_r(mem_read=True)
                if dst.is_mem():
                    uses.update(dst.ptr.get_r(mem_read=True))
                uses = set(expr for expr in uses if expr.is_mem())
                for use in uses:
                    for dst in all_dsts:
                        if alias_mngr.test_may_alias(dst, use):
                            aliasing_mems.add(use)
            if aliasing_mems:
                out = {}
                interfer_srcs = {}
                for expr in aliasing_mems:
                    interfer_srcs[expr] = ExprId("tmp_%d" % interfer_index, expr.size)
                    interfer_index += 1
                #print(interfer_srcs)
                for dst, src in viewitems(assignblk):
                    if dst.is_mem():
                        dst = ExprMem(dst.ptr.replace_expr(interfer_srcs), dst.size)
                    src = src.replace_expr(interfer_srcs)
                    out[dst] = src
                new_vars = dict((src, dst) for dst, src in viewitems(interfer_srcs))
                #print("NEW", new_vars)
                assert stk_lvl_last is not None
                new_vars[stk_lvl] = stk_lvl_last
                irs.append(
                    AssignBlock(
                        new_vars,
                        assignblk.instr
                    )
                )
                irs.append(AssignBlock(out, assignblk.instr))
                modified = True
            else:
                irs.append(assignblk)

            if stk_lvl in assignblk:
                stk_lvl_last = assignblk[stk_lvl]
            else:
                stk_lvl_last = None

        #print(irs)
        ssa.graph.blocks[block.loc_key] = IRBlock(block.loc_key, irs)
    if modified:
        open('ttt.dot', 'w').write(ssa.graph.dot())
    return interfer_index, modified
