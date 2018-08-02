"""Data flow analysis based on miasm intermediate representation"""

from collections import namedtuple
from miasm2.core.graph import DiGraph
from miasm2.ir.ir import AssignBlock, IRBlock
from miasm2.expression.expression import ExprLoc


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

    This class is usable as a dictionnary whose struture is
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
        """Instanciate a DiGraph
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
                    read_vars.update(lval.arg.get_r(mem_read=deref_mem))
                for read_var in read_vars:
                    for reach in assignblk_reaching_defs.get(read_var, set()):
                        self.add_data_edge(AssignblkNode(reach[0], reach[1], read_var),
                                           AssignblkNode(block.loc_key, index, lval))

    def del_edge(self, src, dst):
        super(DiGraphDefUse, self).del_edge(src, dst)
        del self._edge_attr[(src, dst)]

    def add_uniq_labeled_edge(self, src, dst, edge_label):
        """Adds the edge (@src, @dst) with label @edge_label.
        if edge (@src, @dst) already exists, the previous label is overriden
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

        # Block has a nonexistant successor or is a leaf
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
    Remove useless affectations.

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
        ircfg.add_edge(parent, son_loc_key)

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
