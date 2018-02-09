"""Data flow analysis based on miasm intermediate representation"""

from collections import namedtuple
from miasm2.core.graph import DiGraph
from miasm2.ir.ir import AssignBlock, IRBlock

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

    ir_a = None

    def __init__(self, ir_a):
        super(ReachingDefinitions, self).__init__()
        self.ir_a = ir_a
        self.compute()

    def get_definitions(self, block_lbl, assignblk_index):
        """Returns the dict { lvalue: set((def_block_lbl, def_index)) }
        associated with self.ir_a.@block.assignblks[@assignblk_index]
        or {} if it is not yet computed
        """
        return self.get((block_lbl, assignblk_index), {})

    def compute(self):
        """This is the main fixpoint"""
        modified = True
        while modified:
            modified = False
            for block in self.ir_a.blocks.itervalues():
                modified |= self.process_block(block)

    def process_block(self, block):
        """
        Fetch reach definitions from predecessors and propagate it to
        the assignblk in block @block.
        """
        predecessor_state = {}
        for pred_lbl in self.ir_a.graph.predecessors(block.label):
            pred = self.ir_a.blocks[pred_lbl]
            for lval, definitions in self.get_definitions(pred_lbl, len(pred)).iteritems():
                predecessor_state.setdefault(lval, set()).update(definitions)

        modified = self.get((block.label, 0)) != predecessor_state
        if not modified:
            return False
        self[(block.label, 0)] = predecessor_state

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
        defs = self.get_definitions(block.label, assignblk_index).copy()
        for lval in assignblk:
            defs.update({lval: set([(block.label, assignblk_index)])})

        modified = self.get((block.label, assignblk_index + 1)) != defs
        if modified:
            self[(block.label, assignblk_index + 1)] = defs

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
        """Instanciate a DiGraphIR
        @blocks: IR blocks
        """
        self._edge_attr = {}

        # For dot display
        self._filter_node = None
        self._dot_offset = None
        self._blocks = reaching_defs.ir_a.blocks

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
            assignblk_reaching_defs = reaching_defs.get_definitions(block.label, index)
            for lval, expr in assignblk.iteritems():
                self.add_node(AssignblkNode(block.label, index, lval))

                read_vars = expr.get_r(mem_read=deref_mem)
                if deref_mem and lval.is_mem():
                    read_vars.update(lval.arg.get_r(mem_read=deref_mem))
                for read_var in read_vars:
                    for reach in assignblk_reaching_defs.get(read_var, set()):
                        self.add_data_edge(AssignblkNode(reach[0], reach[1], read_var),
                                           AssignblkNode(block.label, index, lval))

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


def dead_simp_useful_assignblks(defuse, reaching_defs):
    """Mark useful statements using previous reach analysis and defuse

    Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division,  Algorithm MK

    Return a set of triplets (block, assignblk number, lvalue) of
    useful definitions
    PRE: compute_reach(self)

    """
    ir_a = reaching_defs.ir_a
    useful = set()

    for block_lbl, block in ir_a.blocks.iteritems():
        successors = ir_a.graph.successors(block_lbl)
        for successor in successors:
            if successor not in ir_a.blocks:
                keep_all_definitions = True
                break
        else:
            keep_all_definitions = False

        # Block has a nonexistant successor or is a leaf
        if keep_all_definitions or (len(successors) == 0):
            valid_definitions = reaching_defs.get_definitions(block_lbl,
                                                              len(block))
            for lval, definitions in valid_definitions.iteritems():
                if (lval in ir_a.get_out_regs(block)
                    or keep_all_definitions):
                    for definition in definitions:
                        useful.add(AssignblkNode(definition[0], definition[1], lval))

        # Force keeping of specific cases
        for index, assignblk in enumerate(block):
            for lval, rval in assignblk.iteritems():
                if (lval.is_mem()
                    or ir_a.IRDst == lval
                    or rval.is_function_call()):
                    useful.add(AssignblkNode(block_lbl, index, lval))

    # Useful nodes dependencies
    for node in useful:
        for parent in defuse.reachable_parents(node):
            yield parent

def dead_simp(ir_a):
    """
    Remove useless affectations.

    This function is used to analyse relation of a * complete function *
    This means the blocks under study represent a solid full function graph.

    Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division, page 43

    @ir_a: IntermediateRepresentation instance
    """

    modified = False
    reaching_defs = ReachingDefinitions(ir_a)
    defuse = DiGraphDefUse(reaching_defs, deref_mem=True)
    useful = set(dead_simp_useful_assignblks(defuse, reaching_defs))
    for block in ir_a.blocks.itervalues():
        irs = []
        for idx, assignblk in enumerate(block):
            new_assignblk = dict(assignblk)
            for lval in assignblk:
                if AssignblkNode(block.label, idx, lval) not in useful:
                    del new_assignblk[lval]
                    modified = True
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        ir_a.blocks[block.label] = IRBlock(block.label, irs)
    return modified
