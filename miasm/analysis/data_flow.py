"""Data flow analysis based on miasm intermediate representation"""
from builtins import range
from collections import namedtuple, Counter
from pprint import pprint as pp
from future.utils import viewitems, viewvalues
from miasm.core.utils import encode_hex
from miasm.core.graph import DiGraph
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.expression.expression import ExprLoc, ExprMem, ExprId, ExprInt,\
    ExprAssign, ExprOp, ExprWalk, ExprSlice, \
    is_function_call, ExprVisitorCallbackBottomToTop
from miasm.expression.simplifications import expr_simp, expr_simp_explicit
from miasm.core.interval import interval
from miasm.expression.expression_helper import possible_values
from miasm.analysis.ssa import get_phi_sources_parent_block, \
    irblock_has_phi
from miasm.ir.symbexec import get_expr_base_offset
from collections import deque

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
                 deref_mem=False, apply_simp=False, *args, **kwargs):
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
                              deref_mem=deref_mem,
                              apply_simp=apply_simp)

    def edge_attr(self, src, dst):
        """
        Return a dictionary of attributes for the edge between @src and @dst
        @src: the source node of the edge
        @dst: the destination node of the edge
        """
        return self._edge_attr[(src, dst)]

    def _compute_def_use(self, reaching_defs,
                         deref_mem=False, apply_simp=False):
        for block in viewvalues(self._blocks):
            self._compute_def_use_block(block,
                                        reaching_defs,
                                        deref_mem=deref_mem,
                                        apply_simp=apply_simp)

    def _compute_def_use_block(self, block, reaching_defs, deref_mem=False, apply_simp=False):
        for index, assignblk in enumerate(block):
            assignblk_reaching_defs = reaching_defs.get_definitions(block.loc_key, index)
            for lval, expr in viewitems(assignblk):
                self.add_node(AssignblkNode(block.loc_key, index, lval))

                expr = expr_simp_explicit(expr) if apply_simp else expr
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

    def __init__(self, lifter, expr_to_original_expr=None):
        self.lifter = lifter
        if expr_to_original_expr is None:
            expr_to_original_expr = {}
        self.expr_to_original_expr = expr_to_original_expr


    def add_expr_to_original_expr(self, expr_to_original_expr):
        self.expr_to_original_expr.update(expr_to_original_expr)

    def is_unkillable_destination(self, lval, rval):
        if (
                lval.is_mem() or
                self.lifter.IRDst == lval or
                lval.is_id("exception_flags") or
                is_function_call(rval)
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
        for reg in self.lifter.get_out_regs(block):
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

        @ircfg: Lifter instance
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
            ircfg.blocks[block.loc_key] = IRBlock(block.loc_db, block.loc_key, irs)
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
    new_block = IRBlock(ircfg.loc_db, loc_key, assignblks)

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
    new_irblock = IRBlock(ircfg.loc_db, loc_key, old_irblock.assignblks)

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
            new_irblock = IRBlock(ircfg.loc_db, loc_key, irs)
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



def expr_has_mem(expr):
    """
    Return True if expr contains at least one memory access
    @expr: Expr instance
    """

    def has_mem(self):
        return self.is_mem()
    visitor = ExprWalk(has_mem)
    return visitor.visit(expr)


def stack_to_reg(expr):
    if expr.is_mem():
        ptr = expr.arg
        SP = lifter.sp
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


def is_stack_access(lifter, expr):
    if not expr.is_mem():
        return False
    ptr = expr.ptr
    diff = expr_simp(ptr - lifter.sp)
    if not diff.is_int():
        return False
    return expr


def visitor_get_stack_accesses(lifter, expr, stack_vars):
    if is_stack_access(lifter, expr):
        stack_vars.add(expr)
    return expr


def get_stack_accesses(lifter, expr):
    result = set()
    def get_stack(expr_to_test):
        visitor_get_stack_accesses(lifter, expr_to_test, result)
        return None
    visitor = ExprWalk(get_stack)
    visitor.visit(expr)
    return result


def get_interval_length(interval_in):
    length = 0
    for start, stop in interval_in.intervals:
        length += stop + 1 - start
    return length


def check_expr_below_stack(lifter, expr):
    """
    Return False if expr pointer is below original stack pointer
    @lifter: lifter_model_call instance
    @expr: Expression instance
    """
    ptr = expr.ptr
    diff = expr_simp(ptr - lifter.sp)
    if not diff.is_int():
        return True
    if int(diff) == 0 or int(expr_simp(diff.msb())) == 0:
        return False
    return True


def retrieve_stack_accesses(lifter, ircfg):
    """
    Walk the ssa graph and find stack based variables.
    Return a dictionary linking stack base address to its size/name
    @lifter: lifter_model_call instance
    @ircfg: IRCFG instance
    """
    stack_vars = set()
    for block in viewvalues(ircfg.blocks):
        for assignblk in block:
            for dst, src in viewitems(assignblk):
                stack_vars.update(get_stack_accesses(lifter, dst))
                stack_vars.update(get_stack_accesses(lifter, src))
    stack_vars = [expr for expr in stack_vars if check_expr_below_stack(lifter, expr)]

    base_to_var = {}
    for var in stack_vars:
        base_to_var.setdefault(var.ptr, set()).add(var)


    base_to_interval = {}
    for addr, vars in viewitems(base_to_var):
        var_interval = interval()
        for var in vars:
            offset = expr_simp(addr - lifter.sp)
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


def replace_stack_vars(lifter, ircfg):
    """
    Try to replace stack based memory accesses by variables.

    Hypothesis: the input ircfg must have all it's accesses to stack explicitly
    done through the stack register, ie every aliases on those variables is
    resolved.

    WARNING: may fail

    @lifter: lifter_model_call instance
    @ircfg: IRCFG instance
    """

    base_to_info = retrieve_stack_accesses(lifter, ircfg)
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
        new_block = IRBlock(block.loc_db, block.loc_key, assignblks)
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
    def retrieve_memlookup(expr_to_test):
        memlookup_test(expr_to_test, bs, is_addr_ro_variable, result)
        return None
    visitor = ExprWalk(retrieve_memlookup)
    visitor.visit(expr)
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


def load_from_int(ircfg, bs, is_addr_ro_variable):
    """
    Replace memory read based on constant with static value
    @ircfg: IRCFG instance
    @bs: binstream instance
    @is_addr_ro_variable: callback(addr, size) to test memory candidate
    """

    modified = False
    for block in list(viewvalues(ircfg.blocks)):
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
        block = IRBlock(block.loc_db, block.loc_key, assignblks)
        ircfg.blocks[block.loc_key] = block
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

    def __init__(self, ircfg):
        super(DiGraphLiveness, self).__init__()
        self.ircfg = ircfg
        self.loc_db = ircfg.loc_db
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

    def init_var_info(self, lifter):
        """Add ircfg out regs"""

        for node in self.leaves():
            irblock = self.ircfg.blocks.get(node, None)
            if irblock is None:
                continue
            var_out = lifter.get_out_regs(irblock)
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
        new_irblock = IRBlock(block.loc_db, block.loc_key, assignblks)
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
        if loc_dst not in ircfg.blocks:
            continue
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
        new_irblock = IRBlock(block.loc_db, loc_dst, assignblks)
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
        if node not in ircfg.blocks:
            continue
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


def get_phi_sources(phi_src, phi_dsts, ids_to_src):
    """
    Return False if the @phi_src has more than one non-phi source
    Else, return its source
    @ids_to_src: Dictionary linking phi source to its definition
    """
    true_values = set()
    for src in phi_src.args:
        if src in phi_dsts:
            # Source is phi dst => skip
            continue
        true_src = ids_to_src[src]
        if true_src in phi_dsts:
            # Source is phi dst => skip
            continue
        # Check if src is not also a phi
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


class DelDummyPhi(object):
    """
    Del dummy phi
    Find nodes which are in the same equivalence class and replace phi nodes by
    the class representative.
    """

    def src_gen_phi_node_srcs(self, equivalence_graph):
        for node in equivalence_graph.nodes():
            if not node.is_op("Phi"):
                continue
            phi_successors = equivalence_graph.successors(node)
            for head in phi_successors:
                # Walk from head to find if we have a phi merging node
                known = set([node])
                todo = set([head])
                done = set()
                while todo:
                    node = todo.pop()
                    if node in done:
                        continue

                    known.add(node)
                    is_ok = True
                    for parent in equivalence_graph.predecessors(node):
                        if parent not in known:
                            is_ok = False
                            break
                    if not is_ok:
                        continue
                    if node.is_op("Phi"):
                        successors = equivalence_graph.successors(node)
                        phi_node = successors.pop()
                        return set([phi_node]), phi_node, head, equivalence_graph
                    done.add(node)
                    for successor in equivalence_graph.successors(node):
                        todo.add(successor)
        return None

    def get_equivalence_class(self, node, ids_to_src):
        todo = set([node])
        done = set()
        defined = set()
        equivalence = set()
        src_to_dst = {}
        equivalence_graph = DiGraph()
        while todo:
            dst = todo.pop()
            if dst in done:
                continue
            done.add(dst)
            equivalence.add(dst)
            src = ids_to_src.get(dst)
            if src is None:
                # Node is not defined
                continue
            src_to_dst[src] = dst
            defined.add(dst)
            if src.is_id():
                equivalence_graph.add_uniq_edge(src, dst)
                todo.add(src)
            elif src.is_op('Phi'):
                equivalence_graph.add_uniq_edge(src, dst)
                for arg in src.args:
                    assert arg.is_id()
                    equivalence_graph.add_uniq_edge(arg, src)
                    todo.add(arg)
            else:
                if src.is_mem() or (src.is_op() and src.op.startswith("call")):
                    if src in equivalence_graph.nodes():
                        return None
                equivalence_graph.add_uniq_edge(src, dst)
                equivalence.add(src)

        if len(equivalence_graph.heads()) == 0:
            raise RuntimeError("Inconsistent graph")
        elif len(equivalence_graph.heads()) == 1:
            # Every nodes in the equivalence graph may be equivalent to the root
            head = equivalence_graph.heads().pop()
            successors = equivalence_graph.successors(head)
            if len(successors) == 1:
                # If successor is an id
                successor = successors.pop()
                if successor.is_id():
                    nodes = equivalence_graph.nodes()
                    nodes.discard(head)
                    nodes.discard(successor)
                    nodes = [node for node in nodes if node.is_id()]
                    return nodes, successor, head, equivalence_graph
            else:
                # Walk from head to find if we have a phi merging node
                known = set()
                todo = set([head])
                done = set()
                while todo:
                    node = todo.pop()
                    if node in done:
                        continue
                    known.add(node)
                    is_ok = True
                    for parent in equivalence_graph.predecessors(node):
                        if parent not in known:
                            is_ok = False
                            break
                    if not is_ok:
                        continue
                    if node.is_op("Phi"):
                        successors = equivalence_graph.successors(node)
                        assert len(successors) == 1
                        phi_node = successors.pop()
                        return set([phi_node]), phi_node, head, equivalence_graph
                    done.add(node)
                    for successor in equivalence_graph.successors(node):
                        todo.add(successor)

        return self.src_gen_phi_node_srcs(equivalence_graph)

    def del_dummy_phi(self, ssa, head):
        ids_to_src = {}
        def_to_loc = {}
        for block in viewvalues(ssa.graph.blocks):
            for index, assignblock in enumerate(block):
                for dst, src in viewitems(assignblock):
                    if not dst.is_id():
                        continue
                    ids_to_src[dst] = src
                    def_to_loc[dst] = block.loc_key


        modified = False
        for loc_key in ssa.graph.blocks.keys():
            block = ssa.graph.blocks[loc_key]
            if not irblock_has_phi(block):
                continue
            assignblk = block[0]
            for dst, phi_src in viewitems(assignblk):
                assert phi_src.is_op('Phi')
                result = self.get_equivalence_class(dst, ids_to_src)
                if result is None:
                    continue
                defined, node, true_value, equivalence_graph = result
                if expr_has_mem(true_value):
                    # Don't propagate ExprMem
                    continue
                if true_value.is_op() and true_value.op.startswith("call"):
                    # Don't propagate call
                    continue
                # We have an equivalence of nodes
                to_del = set(defined)
                # Remove all implicated phis
                for dst in to_del:
                    loc_key = def_to_loc[dst]
                    block = ssa.graph.blocks[loc_key]

                    assignblk = block[0]
                    fixed_phis = {}
                    for old_dst, old_phi_src in viewitems(assignblk):
                        if old_dst in defined:
                            continue
                        fixed_phis[old_dst] = old_phi_src

                    assignblks = list(block)
                    assignblks[0] = AssignBlock(fixed_phis, assignblk.instr)
                    assignblks[1:1] = [AssignBlock({dst: true_value}, assignblk.instr)]
                    new_irblock = IRBlock(block.loc_db, block.loc_key, assignblks)
                    ssa.graph.blocks[loc_key] = new_irblock
                modified = True
        return modified


def replace_expr_from_bottom(expr_orig, dct):
    def replace(expr):
        if expr in dct:
            return dct[expr]
        return expr
    visitor = ExprVisitorCallbackBottomToTop(lambda expr:replace(expr))
    return visitor.visit(expr_orig)


def is_mem_sub_part(needle, mem):
    """
    If @needle is a sub part of @mem, return the offset of @needle in @mem
    Else, return False
    @needle: ExprMem
    @mem: ExprMem
    """
    ptr_base_a, ptr_offset_a = get_expr_base_offset(needle.ptr)
    ptr_base_b, ptr_offset_b = get_expr_base_offset(mem.ptr)
    if ptr_base_a != ptr_base_b:
        return False
    # Test if sub part starts after mem
    if not (ptr_offset_b <= ptr_offset_a < ptr_offset_b + mem.size // 8):
        return False
    # Test if sub part ends before mem
    if not (ptr_offset_a + needle.size // 8 <= ptr_offset_b + mem.size // 8):
        return False
    return ptr_offset_a - ptr_offset_b

class UnionFind(object):
    """
    Implementation of UnionFind structure
    __classes: a list of Set of equivalent elements
    node_to_class: Dictionary linkink an element to its equivalent class
    order: Dictionary link an element to it's weight

    The order attributes is used to allow the selection of a representative
    element of an equivalence class
    """

    def __init__(self):
        self.index = 0
        self.__classes = []
        self.node_to_class = {}
        self.order = dict()

    def copy(self):
        """
        Return a copy of the object
        """
        unionfind = UnionFind()
        unionfind.index = self.index
        unionfind.__classes = [set(known_class) for known_class in self.__classes]
        node_to_class = {}
        for class_eq in unionfind.__classes:
            for node in class_eq:
                node_to_class[node] = class_eq
        unionfind.node_to_class = node_to_class
        unionfind.order = dict(self.order)
        return unionfind

    def replace_node(self, old_node, new_node):
        """
        Replace the @old_node by the @new_node
        """
        classes = self.get_classes()

        new_classes = []
        replace_dct = {old_node:new_node}
        for eq_class in classes:
            new_class = set()
            for node in eq_class:
                new_class.add(replace_expr_from_bottom(node, replace_dct))
            new_classes.append(new_class)

        node_to_class = {}
        for class_eq in new_classes:
            for node in class_eq:
                node_to_class[node] = class_eq
        self.__classes = new_classes
        self.node_to_class = node_to_class
        new_order = dict()
        for node,index in self.order.items():
            new_node = replace_expr_from_bottom(node, replace_dct)
            new_order[new_node] = index
        self.order = new_order

    def get_classes(self):
        """
        Return a list of the equivalent classes
        """
        classes = []
        for class_tmp in self.__classes:
            classes.append(set(class_tmp))
        return classes

    def nodes(self):
        for known_class in self.__classes:
            for node in known_class:
                yield node

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ is not other.__class__:
            return False

        return Counter(frozenset(known_class) for known_class in self.__classes) == Counter(frozenset(known_class) for known_class in other.__classes)

    def __ne__(self, other):
        # required Python 2.7.14
        return not self == other

    def __str__(self):
        components = self.__classes
        out = ['UnionFind<']
        for component in components:
            out.append("\t" + (", ".join([str(node) for node in component])))
        out.append('>')
        return "\n".join(out)

    def add_equivalence(self, node_a, node_b):
        """
        Add the new equivalence @node_a == @node_b
        @node_a is equivalent to @node_b, but @node_b is more representative
        than @node_a
        """
        if node_b not in self.order:
            self.order[node_b] = self.index
            self.index += 1
        # As node_a is destination, we always replace its index
        self.order[node_a] = self.index
        self.index += 1

        if node_a not in self.node_to_class and node_b not in self.node_to_class:
            new_class = set([node_a, node_b])
            self.node_to_class[node_a] = new_class
            self.node_to_class[node_b] = new_class
            self.__classes.append(new_class)
        elif node_a in self.node_to_class and node_b not in self.node_to_class:
            known_class = self.node_to_class[node_a]
            known_class.add(node_b)
            self.node_to_class[node_b] = known_class
        elif node_a not in self.node_to_class and node_b in self.node_to_class:
            known_class = self.node_to_class[node_b]
            known_class.add(node_a)
            self.node_to_class[node_a] = known_class
        else:
            raise RuntimeError("Two nodes cannot be in two classes")

    def _get_master(self, node):
        if node not in self.node_to_class:
            return None
        known_class = self.node_to_class[node]
        best_node = node
        for node in known_class:
            if self.order[node] < self.order[best_node]:
                best_node = node
        return best_node

    def get_master(self, node):
        """
        Return the representative element of the equivalence class containing
        @node
        @node: ExprMem or ExprId
        """
        if not node.is_mem():
            return self._get_master(node)
        if node in self.node_to_class:
            # Full expr mem is known
            return self._get_master(node)
        # Test if mem is sub part of known node
        for expr in self.node_to_class:
            if not expr.is_mem():
                continue
            ret = is_mem_sub_part(node, expr)
            if ret is False:
                continue
            master = self._get_master(expr)
            master = master[ret * 8 : ret * 8 + node.size]
            return master

        return self._get_master(node)


    def del_element(self, node):
        """
        Remove @node for the equivalence classes
        """
        assert node in self.node_to_class
        known_class = self.node_to_class[node]
        known_class.discard(node)
        del(self.node_to_class[node])
        del(self.order[node])

    def del_get_new_master(self, node):
        """
        Remove @node for the equivalence classes and return it's representative
        equivalent element
        @node: Element to delete
        """
        if node not in self.node_to_class:
            return None
        known_class = self.node_to_class[node]
        known_class.discard(node)
        del(self.node_to_class[node])
        del(self.order[node])

        if not known_class:
            return None
        best_node = list(known_class)[0]
        for node in known_class:
            if self.order[node] < self.order[best_node]:
                best_node = node
        return best_node

class ExprToGraph(ExprWalk):
    """
    Transform an Expression into a tree and add link nodes to an existing tree
    """
    def __init__(self, graph):
        super(ExprToGraph, self).__init__(self.link_nodes)
        self.graph = graph

    def link_nodes(self, expr, *args, **kwargs):
        """
        Transform an Expression @expr into a tree and add link nodes to the
        current tree
        @expr: Expression
        """
        if expr in self.graph.nodes():
            return None
        self.graph.add_node(expr)
        if expr.is_mem():
            self.graph.add_uniq_edge(expr, expr.ptr)
        elif expr.is_slice():
            self.graph.add_uniq_edge(expr, expr.arg)
        elif expr.is_cond():
            self.graph.add_uniq_edge(expr, expr.cond)
            self.graph.add_uniq_edge(expr, expr.src1)
            self.graph.add_uniq_edge(expr, expr.src2)
        elif expr.is_compose():
            for arg in expr.args:
                self.graph.add_uniq_edge(expr, arg)
        elif expr.is_op():
            for arg in expr.args:
                self.graph.add_uniq_edge(expr, arg)
        return None

class State(object):
    """
    Object representing the state of a program at a given point
    The state is represented using equivalence classes

    Each assignment can create/destroy equivalence classes. Interferences
    between expression is computed using `may_interfer` function
    """

    def __init__(self):
        self.equivalence_classes = UnionFind()
        self.undefined = set()

    def __str__(self):
        return "{0.equivalence_classes}\n{0.undefined}".format(self)

    def copy(self):
        state = self.__class__()
        state.equivalence_classes = self.equivalence_classes.copy()
        state.undefined = self.undefined.copy()
        return state

    def __eq__(self, other):
        if self is other:
            return True
        if self.__class__ is not other.__class__:
            return False
        return (
            set(self.equivalence_classes.nodes()) == set(other.equivalence_classes.nodes()) and
            sorted(self.equivalence_classes.edges()) == sorted(other.equivalence_classes.edges()) and
            self.undefined == other.undefined
        )

    def __ne__(self, other):
        # required Python 2.7.14
        return not self == other

    def may_interfer(self, dsts, src):
        """
        Return True is @src may interfer with expressions in @dsts
        @dsts: Set of Expressions
        @src: expression to test
        """

        srcs = src.get_r()
        for src in srcs:
            for dst in dsts:
                if dst in src:
                    return True
                if dst.is_mem() and src.is_mem():
                    dst_base, dst_offset = get_expr_base_offset(dst.ptr)
                    src_base, src_offset = get_expr_base_offset(src.ptr)
                    if dst_base != src_base:
                        return True
                    dst_size = dst.size // 8
                    src_size = src.size // 8
                    # Special case:
                    # @32[ESP + 0xFFFFFFFE], @32[ESP]
                    # Both memories alias
                    if dst_offset + dst_size <= int(dst_base.mask) + 1:
                        # @32[ESP + 0xFFFFFFFC] => [0xFFFFFFFC, 0xFFFFFFFF]
                        interval1 = interval([(dst_offset, dst_offset + dst.size // 8 - 1)])
                    else:
                        # @32[ESP + 0xFFFFFFFE] => [0x0, 0x1] U [0xFFFFFFFE, 0xFFFFFFFF]
                        interval1 = interval([(dst_offset, int(dst_base.mask))])
                        interval1 += interval([(0, dst_size - (int(dst_base.mask) + 1 - dst_offset) - 1 )])
                    if src_offset + src_size <= int(src_base.mask) + 1:
                        # @32[ESP + 0xFFFFFFFC] => [0xFFFFFFFC, 0xFFFFFFFF]
                        interval2 = interval([(src_offset, src_offset + src.size // 8 - 1)])
                    else:
                        # @32[ESP + 0xFFFFFFFE] => [0x0, 0x1] U [0xFFFFFFFE, 0xFFFFFFFF]
                        interval2 = interval([(src_offset, int(src_base.mask))])
                        interval2 += interval([(0, src_size - (int(src_base.mask) + 1 - src_offset) - 1)])
                    if (interval1 & interval2).empty:
                        continue
                    return True
        return False

    def _get_representative_expr(self, expr):
        representative = self.equivalence_classes.get_master(expr)
        if representative is None:
            return expr
        return representative

    def get_representative_expr(self, expr):
        """
        Replace each sub expression of @expr by its representative element
        @expr: Expression to analyse
        """
        new_expr = expr.visit(self._get_representative_expr)
        return new_expr

    def propagation_allowed(self, expr):
        """
        Return True if @expr can be propagated
        Don't propagate:
        - Phi nodes
        - call_func_ret / call_func_stack operants
        """

        if (
                expr.is_op('Phi') or
                (expr.is_op() and expr.op.startswith("call_func"))
        ):
            return False
        return True

    def eval_assignblock(self, assignblock):
        """
        Evaluate the @assignblock on the current state
        @assignblock: AssignBlock instance
        """

        out = dict(assignblock.items())
        new_out = dict()
        # Replace sub expression by their equivalence class repesentative
        for dst, src in out.items():
            if src.is_op('Phi'):
                # Don't replace in phi
                new_src = src
            else:
                new_src = self.get_representative_expr(src)
            if dst.is_mem():
                new_ptr = self.get_representative_expr(dst.ptr)
                new_dst = ExprMem(new_ptr, dst.size)
            else:
                new_dst = dst
            new_dst = expr_simp(new_dst)
            new_src = expr_simp(new_src)
            new_out[new_dst] = new_src

        # For each destination, update (or delete) dependent's node according to
        # equivalence classes
        classes = self.equivalence_classes

        for dst in new_out:

            replacement = classes.del_get_new_master(dst)
            if replacement is None:
                to_del = set([dst])
                to_replace = {}
            else:
                to_del = set()
                to_replace = {dst:replacement}

            graph = DiGraph()
            # Build en expression graph linking all classes
            has_parents = False
            for node in classes.nodes():
                if dst in node:
                    # Only dependent nodes are interesting here
                    has_parents = True
                    expr_to_graph = ExprToGraph(graph)
                    expr_to_graph.visit(node)

            if not has_parents:
                continue

            todo = graph.leaves()
            done = set()

            while todo:
                node = todo.pop(0)
                if node in done:
                    continue
                # If at least one son is not done, re do later
                if [son for son in graph.successors(node) if son not in done]:
                    todo.append(node)
                    continue
                done.add(node)

                # If at least one son cannot be replaced (deleted), our last
                # chance is to have an equivalence
                if any(son in to_del for son in graph.successors(node)):
                    # One son has been deleted!
                    # Try to find a replacement of the whole expression
                    replacement = classes.del_get_new_master(node)
                    if replacement is None:
                        to_del.add(node)
                        for predecessor in graph.predecessors(node):
                            if predecessor not in todo:
                                todo.append(predecessor)
                        continue
                    else:
                        to_replace[node] = replacement
                        # Continue with replacement

                # Everyson is live or has been replaced
                new_node = node.replace_expr(to_replace)

                if new_node == node:
                    # If node is not touched (Ex: leaf node)
                    for predecessor in graph.predecessors(node):
                        if predecessor not in todo:
                            todo.append(predecessor)
                    continue

                # Node has been modified, update equivalence classes
                classes.replace_node(node, new_node)
                to_replace[node] = new_node

                for predecessor in graph.predecessors(node):
                    if predecessor not in todo:
                        todo.append(predecessor)

                continue

        new_assignblk = AssignBlock(new_out, assignblock.instr)
        dsts = new_out.keys()

        # Remove interfering known classes
        to_del = set()
        for node in list(classes.nodes()):
            if self.may_interfer(dsts, node):
                # Interfer with known equivalence class
                self.equivalence_classes.del_element(node)
                if node.is_id() or node.is_mem():
                    self.undefined.add(node)


        # Update equivalence classes
        for dst, src in new_out.items():
            # Delete equivalence class interfering with dst
            to_del = set()
            classes = self.equivalence_classes
            for node in classes.nodes():
                if dst in node:
                    to_del.add(node)
            for node in to_del:
                self.equivalence_classes.del_element(node)
                if node.is_id() or node.is_mem():
                    self.undefined.add(node)

            # Don't create equivalence if self interfer
            if self.may_interfer(dsts, src):
                if dst in self.equivalence_classes.nodes():
                    self.equivalence_classes.del_element(dst)
                    if dst.is_id() or dst.is_mem():
                        self.undefined.add(dst)
                continue

            if not self.propagation_allowed(src):
                continue

            self.undefined.discard(dst)
            if dst in self.equivalence_classes.nodes():
                self.equivalence_classes.del_element(dst)
            self.equivalence_classes.add_equivalence(dst, src)

        return new_assignblk


    def merge(self, other):
        """
        Merge the current state with @other
        Merge rules:
        - if two nodes are equal in both states => in equivalence class
        - if node value is different or non present in another state => undefined
        @other: State instance
        """
        classes1 = self.equivalence_classes
        classes2 = other.equivalence_classes

        undefined = set(node for node in self.undefined if node.is_id() or node.is_mem())
        undefined.update(set(node for node in other.undefined if node.is_id() or node.is_mem()))
        # Should we compute interference between srcs and undefined ?
        # Nop => should already interfer in other state
        components1 = classes1.get_classes()
        components2 = classes2.get_classes()

        node_to_component2 = {}
        for component in components2:
            for node in component:
                node_to_component2[node] = component

        # Compute intersection of equivalence classes of states
        out = []
        nodes_ok = set()
        while components1:
            component1 = components1.pop()
            for node in component1:
                if node in undefined:
                    continue
                component2 = node_to_component2.get(node)
                if component2 is None:
                    if node.is_id() or node.is_mem():
                        assert(node not in nodes_ok)
                        undefined.add(node)
                    continue
                if node not in component2:
                    continue
                # Found two classes containing node
                common = component1.intersection(component2)
                if len(common) == 1:
                    # Intersection contains only one node => undefine node
                    if node.is_id() or node.is_mem():
                        assert(node not in nodes_ok)
                        undefined.add(node)
                        component2.discard(common.pop())
                    continue
                if common:
                    # Intersection contains multiple nodes
                    # Here, common nodes don't interfer with any undefined
                    nodes_ok.update(common)
                    out.append(common)
                diff = component1.difference(common)
                if diff:
                    components1.append(diff)
                component2.difference_update(common)
                break

        # Discard remaining components2 elements
        for component in components2:
            for node in component:
                if node.is_id() or node.is_mem():
                    assert(node not in nodes_ok)
                    undefined.add(node)

        all_nodes = set()
        for common in out:
            all_nodes.update(common)

        new_order = dict(
            (node, index) for (node, index) in classes1.order.items()
            if node in all_nodes
        )

        unionfind = UnionFind()
        new_classes = []
        global_max_index = 0
        for common in out:
            min_index = None
            master = None
            for node in common:
                index = new_order[node]
                global_max_index = max(index, global_max_index)
                if min_index is None or min_index > index:
                    min_index = index
                    master = node
            for node in common:
                if node == master:
                    continue
                unionfind.add_equivalence(node, master)

        unionfind.index = global_max_index
        unionfind.order = new_order
        state = self.__class__()
        state.equivalence_classes = unionfind
        state.undefined = undefined

        return state


class PropagateExpressions(object):
    """
    Propagate expressions

    The algorithm propagates equivalence classes expressions from the entry
    point. During the analyse, we replace source nodes by its equivalence
    classes representative. Equivalence classes can be modified during analyse
    due to memory aliasing.

    For example:
    B = A+1
    C = A
    A = 6
    D = [B]

    Will result in:
    B = A+1
    C = A
    A = 6
    D = [C+1]
    """

    @staticmethod
    def new_state():
        return State()

    def merge_prev_states(self, ircfg, states, loc_key):
        """
        Merge predecessors states of irblock at location @loc_key
        @ircfg: IRCfg instance
        @states: Dictionary linking locations to state
        @loc_key: location of the current irblock
        """

        prev_states = []
        for predecessor in ircfg.predecessors(loc_key):
            prev_states.append((predecessor, states[predecessor]))

        filtered_prev_states = []
        for (_, prev_state) in prev_states:
            if prev_state is not None:
                filtered_prev_states.append(prev_state)

        prev_states = filtered_prev_states
        if not prev_states:
            state = self.new_state()
        elif len(prev_states) == 1:
            state = prev_states[0].copy()
        else:
            while prev_states:
                state = prev_states.pop()
                if state is not None:
                    break
            for prev_state in prev_states:
                state = state.merge(prev_state)

        return state

    def update_state(self, irblock, state):
        """
        Propagate the @state through the @irblock
        @irblock: IRBlock instance
        @state: State instance
        """
        new_assignblocks = []
        modified = False

        for assignblock in irblock:
            if not assignblock.items():
                continue
            new_assignblk = state.eval_assignblock(assignblock)
            new_assignblocks.append(new_assignblk)
            if new_assignblk != assignblock:
                modified = True

        new_irblock = IRBlock(irblock.loc_db, irblock.loc_key, new_assignblocks)

        return new_irblock, modified

    def propagate(self, ssa, head, max_expr_depth=None):
        """
        Apply algorithm on the @ssa graph
        """
        ircfg = ssa.ircfg
        self.loc_db = ircfg.loc_db
        irblocks = ssa.ircfg.blocks
        states = {}
        for loc_key, irblock in irblocks.items():
            states[loc_key] = None

        todo = deque([head])
        while todo:
            loc_key = todo.popleft()
            irblock = irblocks.get(loc_key)
            if irblock is None:
                continue

            state_orig = states[loc_key]
            state = self.merge_prev_states(ircfg, states, loc_key)
            state = state.copy()

            new_irblock, modified_irblock = self.update_state(irblock, state)
            if state_orig is not None:
                # Merge current and previous state
                state = state.merge(state_orig)
                if (state.equivalence_classes == state_orig.equivalence_classes and
                    state.undefined == state_orig.undefined
                    ):
                    continue

            states[loc_key] = state
            # Propagate to sons
            for successor in ircfg.successors(loc_key):
                todo.append(successor)

        # Update blocks
        todo = set(loc_key for loc_key in irblocks)
        modified = False
        while todo:
            loc_key = todo.pop()
            irblock = irblocks.get(loc_key)
            if irblock is None:
                continue

            state = self.merge_prev_states(ircfg, states, loc_key)
            new_irblock, modified_irblock = self.update_state(irblock, state)
            modified |= modified_irblock
            irblocks[new_irblock.loc_key] = new_irblock

        return modified
