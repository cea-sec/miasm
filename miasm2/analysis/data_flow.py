"""Data flow analysis based on miasm intermediate representation"""

from collections import namedtuple
from miasm2.core.graph import DiGraph
from miasm2.ir.ir import AssignBlock, IRBlock
from miasm2.expression.expression import ExprLoc, ExprMem, ExprId, ExprInt,\
    ExprAssign, ExprOp
from miasm2.expression.simplifications import expr_simp
from miasm2.core.interval import interval
from miasm2.expression.expression_helper import possible_values
from miasm2.analysis.ssa import get_phi_sources_parent_block, \
    irblock_has_phi

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
            for block in self.ircfg.blocks.itervalues():
                modified |= self.process_block(block)

    def process_block(self, block):
        """
        Fetch reach definitions from predecessors and propagate it to
        the assignblk in block @block.
        """
        predecessor_state = {}
        for pred_lbl in self.ircfg.predecessors(block.loc_key):
            pred = self.ircfg.blocks[pred_lbl]
            for lval, definitions in self.get_definitions(pred_lbl, len(pred)).iteritems():
                predecessor_state.setdefault(lval, set()).update(definitions)

        modified = self.get((block.loc_key, 0)) != predecessor_state
        if not modified:
            return False
        self[(block.loc_key, 0)] = predecessor_state

        for index in xrange(len(block)):
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
        for block in self._blocks.itervalues():
            self._compute_def_use_block(block,
                                        reaching_defs,
                                        deref_mem=deref_mem)

    def _compute_def_use_block(self, block, reaching_defs, deref_mem=False):
        for index, assignblk in enumerate(block):
            assignblk_reaching_defs = reaching_defs.get_definitions(block.loc_key, index)
            for lval, expr in assignblk.iteritems():
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
        """Adds an edge representing a data dependencie
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


def dead_simp_useful_assignblks(irarch, defuse, reaching_defs):
    """Mark useful statements using previous reach analysis and defuse

    Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division,  Algorithm MK

    Return a set of triplets (block, assignblk number, lvalue) of
    useful definitions
    PRE: compute_reach(self)

    """
    ircfg = reaching_defs.ircfg
    useful = set()

    for block_lbl, block in ircfg.blocks.iteritems():
        successors = ircfg.successors(block_lbl)
        for successor in successors:
            if successor not in ircfg.blocks:
                keep_all_definitions = True
                break
        else:
            keep_all_definitions = False

        # Block has a nonexistent successor or is a leaf
        if keep_all_definitions or (len(successors) == 0):
            valid_definitions = reaching_defs.get_definitions(block_lbl,
                                                              len(block))
            for lval, definitions in valid_definitions.iteritems():
                if lval in irarch.get_out_regs(block) or keep_all_definitions:
                    for definition in definitions:
                        useful.add(AssignblkNode(definition[0], definition[1], lval))

        # Force keeping of specific cases
        for index, assignblk in enumerate(block):
            for lval, rval in assignblk.iteritems():
                if (lval.is_mem() or
                    irarch.IRDst == lval or
                    lval.is_id("exception_flags") or
                    rval.is_function_call()):
                    useful.add(AssignblkNode(block_lbl, index, lval))

    # Useful nodes dependencies
    for node in useful:
        for parent in defuse.reachable_parents(node):
            yield parent


def dead_simp(irarch, ircfg):
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
    useful = set(dead_simp_useful_assignblks(irarch, defuse, reaching_defs))
    for block in ircfg.blocks.itervalues():
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
        for dst, src in assignblk.iteritems():
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


def _test_jmp_only(ircfg, loc_key):
    """
    If irblock at @loc_key sets only IRDst to an ExprLoc, return the
    corresponding loc_key target.
    None in other cases.

    @ircfg: IRCFG instance
    @loc_key: LocKey instance of the candidate irblock

    """

    if loc_key not in ircfg.blocks:
        return None
    irblock = ircfg.blocks[loc_key]
    if len(irblock.assignblks) != 1:
        return None
    items = dict(irblock.assignblks[0]).items()
    if len(items) != 1:
        return None
    dst, src = items[0]
    assert dst.is_id("IRDst")
    if not src.is_loc():
        return None
    return src.loc_key


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
    del ircfg.blocks[loc_key]

    replace_dct = {
        ExprLoc(loc_key, ircfg.IRDst.size):ExprLoc(son_loc_key, ircfg.IRDst.size)
    }

    _relink_block_node(ircfg, loc_key, son_loc_key, replace_dct)

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

    del ircfg.blocks[son_loc_key]
    ircfg.add_irblock(new_irblock)

    replace_dct = {
        ExprLoc(son_loc_key, ircfg.IRDst.size):ExprLoc(loc_key, ircfg.IRDst.size)
    }

    _relink_block_node(ircfg, son_loc_key, loc_key, replace_dct)

    return True


def merge_blocks(ircfg, loc_key_entries):
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

    Return True if at least an irblock has been modified

    @ircfg: IRCFG instance
    @loc_key_entries: loc_key to keep
    """

    modified = False
    todo = set(ircfg.nodes())
    while todo:
        loc_key = todo.pop()

        # Test merge block
        son = _test_merge_next_block(ircfg, loc_key)
        if son is not None and son not in loc_key_entries:
            _do_merge_blocks(ircfg, loc_key, son)
            todo.add(loc_key)
            modified = True
            continue

        # Test jmp only block
        son = _test_jmp_only(ircfg, loc_key)
        if son is not None and loc_key not in loc_key_entries:
            ret = _remove_to_son(ircfg, loc_key, son)
            modified |= ret
            if ret:
                todo.add(loc_key)
                continue

        # Test head jmp only block
        if (son is not None and
            son not in loc_key_entries and
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
    for loc_key, block in ircfg.blocks.iteritems():
        irs = []
        for assignblk in block:
            if len(assignblk):
                irs.append(assignblk)
            else:
                modified = True
        ircfg.blocks[loc_key] = IRBlock(loc_key, irs)

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
                for dst, src in assignblk.iteritems():
                    node = AssignblkNode(lbl, index, dst)
                    graph.add_var_def(node, src)
                    graph.add_def_node(def_nodes, node, src)
                    graph.add_use_node(use_nodes, node, src)

        for dst, node in def_nodes.iteritems():
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


def expr_has_call_test(expr, result):
    if result:
        # Don't analyse if we already found a candidate
        return False
    if expr.is_op() and expr.op.startswith("call"):
        result.add(expr)
        return False
    return True


def expr_has_call(expr):
    """
    Return True if expr contains at least one "call" operator
    @expr: Expr instance
    """
    return expr_test_visit(expr, expr_has_call_test)


class PropagateExpr(object):

    def assignblk_is_propagation_barrier(self, assignblk):
        for dst, src in assignblk.iteritems():
            if expr_has_call(src):
                return True
            if dst.is_mem():
                return True
        return False

    def has_propagation_barrier(self, assignblks):
        for assignblk in assignblks:
            for dst, src in assignblk.iteritems():
                if expr_has_call(src):
                    return True
                if dst.is_mem():
                    return True
        return False

    def is_mem_written(self, ssa, node, successor):
        loc_a, index_a, reg_a = node
        loc_b, index_b, reg_b = successor
        block_b = ssa.graph.blocks[loc_b]

        nodes_to_do = self.compute_reachable_nodes_from_a_to_b(ssa.graph, loc_a, loc_b)


        if loc_a == loc_b:
            # src is dst
            assert nodes_to_do == set([loc_a])
            if self.has_propagation_barrier(block_b.assignblks[index_a:index_b]):
                return True
        else:
            # Check everyone but loc_a and loc_b
            for loc in nodes_to_do - set([loc_a, loc_b]):
                block = ssa.graph.blocks[loc]
                if self.has_propagation_barrier(block.assignblks):
                    return True
            # Check loc_a partially
            block_a = ssa.graph.blocks[loc_a]
            if self.has_propagation_barrier(block_a.assignblks[index_a:]):
                return True
            if nodes_to_do.intersection(ssa.graph.successors(loc_b)):
                # There is a path from loc_b to loc_b => Check loc_b fully
                if self.has_propagation_barrier(block_b.assignblks):
                    return True
            else:
                # Check loc_b partially
                if self.has_propagation_barrier(block_b.assignblks[:index_b]):
                    return True
        return False

    def compute_reachable_nodes_from_a_to_b(self, ssa, loc_a, loc_b):
        reachables_a = set(ssa.reachable_sons(loc_a))
        reachables_b = set(ssa.reachable_parents_stop_node(loc_b, loc_a))
        return reachables_a.intersection(reachables_b)

    def propagation_allowed(self, ssa, to_replace, node_a, node_b):
        """
        Return True if we can replace @node source into @node_b
        """
        loc_a, index_a, reg_a = node_a
        if not expr_has_mem(to_replace[reg_a]):
            return True
        if self.is_mem_written(ssa, node_a, node_b):
            return False
        return True

    def propagate(self, ssa, head):
        defuse = SSADefUse.from_ssa(ssa)
        to_replace = {}
        node_to_reg = {}
        for node in defuse.nodes():
            if node.var in ssa.immutable_ids:
                continue
            src = defuse.get_node_target(node)
            if expr_has_call(src):
                continue
            if src.is_op('Phi'):
                continue
            if node.var.is_mem():
                continue
            to_replace[node.var] = src
            node_to_reg[node] = node.var

        modified = False
        for node, reg in node_to_reg.iteritems():
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
                for dst, src in assignblk.iteritems():
                    if src.is_op('Phi'):
                        out[dst] = src
                        continue

                    if src.is_mem():
                        ptr = src.ptr
                        ptr = ptr.replace_expr(replace)
                        new_src = ExprMem(ptr, src.size)
                    else:
                        new_src = src.replace_expr(replace)

                    if dst.is_id():
                        new_dst = dst
                    elif dst.is_mem():
                        ptr = dst.ptr
                        ptr = ptr.replace_expr(replace)
                        new_dst = ExprMem(ptr, dst.size)
                    else:
                        new_dst = dst.replace_expr(replace)
                        if not (new_dst.is_id() or new_dst.is_mem()):
                            new_dst = dst
                    if src != new_src or dst != new_dst:
                        modified = True
                    out[new_dst] = new_src
                out = AssignBlock(out, assignblk.instr)
                assignblks[node_b.index] = out
                new_block = IRBlock(block.loc_key, assignblks)
                ssa.graph.blocks[block.loc_key] = new_block
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
            return ExprId("STACK.%d" % (diff / 4), expr.size)
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


def retrieve_stack_accesses(ir_arch_a, ssa):
    """
    Walk the ssa graph and find stack based variables.
    Return a dictionary linking stack base address to its size/name
    @ir_arch_a: ira instance
    @ssa: SSADiGraph instance
    """
    stack_vars = set()
    for block in ssa.graph.blocks.itervalues():
        for assignblk in block:
            for dst, src in assignblk.iteritems():
                stack_vars.update(get_stack_accesses(ir_arch_a, dst))
                stack_vars.update(get_stack_accesses(ir_arch_a, src))
    stack_vars = filter(lambda expr: check_expr_below_stack(ir_arch_a, expr), stack_vars)

    base_to_var = {}
    for var in stack_vars:
        base_to_var.setdefault(var.ptr, set()).add(var)


    base_to_interval = {}
    for addr, vars in base_to_var.iteritems():
        var_interval = interval()
        for var in vars:
            offset = expr_simp(addr - ir_arch_a.sp)
            if not offset.is_int():
                # skip non linear stack offset
                continue

            start = int(offset)
            stop = int(expr_simp(offset + ExprInt(var.size / 8, offset.size)))
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
    for addr, vars in base_to_var.iteritems():
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


def replace_stack_vars(ir_arch_a, ssa):
    """
    Try to replace stack based memory accesses by variables.
    WARNING: may fail

    @ir_arch_a: ira instance
    @ssa: SSADiGraph instance
    """

    base_to_info = retrieve_stack_accesses(ir_arch_a, ssa)
    modified = False
    for block in ssa.graph.blocks.itervalues():
        assignblks = []
        for assignblk in block:
            out = {}
            for dst, src in assignblk.iteritems():
                new_dst = dst.visit(lambda expr:replace_mem_stack_vars(expr, base_to_info))
                new_src = src.visit(lambda expr:replace_mem_stack_vars(expr, base_to_info))
                if new_dst != dst or new_src != src:
                    modified |= True

                out[new_dst] = new_src

            out = AssignBlock(out, assignblk.instr)
            assignblks.append(out)
        new_block = IRBlock(block.loc_key, assignblks)
        ssa.graph.blocks[block.loc_key] = new_block
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
    var_bytes = bs.getbytes(ptr, expr.size / 8)[::-1]
    try:
        value = int(var_bytes.encode('hex'), 16)
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
    for label, block in ir_arch.blocks.iteritems():
        assignblks = list()
        for assignblk in block:
            out = {}
            for dst, src in assignblk.iteritems():
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
                for (dst, src) in self.assignblk.iteritems()
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
            for dst, src in assignblk.iteritems():
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
            irblock = ircfg.blocks[node]
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
            raise StopIteration

        for i, info in enumerate(self._blocks[node].infos):
            var_in = "VarIn:" + ", ".join(str(x) for x in info.var_in)
            var_out = "VarOut:" + ", ".join(str(x) for x in info.var_out)

            assignmnts = ["%s = %s" % (dst, src) for (dst, src) in info.assignblk.iteritems()]

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
        for i in reversed(xrange(len(infos))):
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
            cur_block = self.blocks[node]
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
            irblock = self.ircfg.blocks[node]
            var_out = ir_arch_a.get_out_regs(irblock)
            irblock_liveness = self.blocks[node]
            irblock_liveness.infos[-1].var_out = var_out


def discard_phi_sources(ircfg, deleted_vars):
    """
    Remove phi sources in @ircfg belonging to @deleted_vars set
    @ircfg: IRCFG instance in ssa form
    @deleted_vars: unused phi sources
    """
    for block in ircfg.blocks.values():
        if not block.assignblks:
            continue
        assignblk = block[0]
        todo = {}
        modified = False
        for dst, src in assignblk.iteritems():
            if not src.is_op('Phi'):
                todo[dst] = src
                continue
            srcs = set(expr for expr in src.args if expr not in deleted_vars)
            assert(srcs)
            if len(srcs) > 1:
                todo[dst] = srcs
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

    modified = False
    blocks = dict(ircfg.blocks)
    for loc_src, loc_dst in edges_to_del:
        block = ircfg.blocks[loc_dst]
        assert block.assignblks
        assignblks = list(block)
        assignblk = assignblks[0]
        out = {}
        for dst, phi_sources in assignblk.iteritems():
            if not phi_sources.is_op('Phi'):
                out = assignblk
                break
            var_to_parents = get_phi_sources_parent_block(
                ircfg,
                loc_dst,
                phi_sources.args
            )
            to_keep = set(phi_sources.args)
            for src in phi_sources.args:
                parents = var_to_parents[src]
                if loc_src in parents:
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

    for loc_key, block in blocks.iteritems():
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
        block = ircfg.blocks[node]
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
        for irblock in self.blocks.values():
            if not irblock_has_phi(irblock):
                continue
            out = {}
            for sources in irblock[0].itervalues():
                var_to_parents = get_phi_sources_parent_block(self, irblock.loc_key, sources.args)
                for var, var_parents in var_to_parents.iteritems():
                    out.setdefault(var, set()).update(var_parents)
            self.loc_key_to_phi_parents[irblock.loc_key] = out

    def back_propagate_to_parent(self, todo, node, parent):
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
