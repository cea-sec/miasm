"""Data flow analysis based on miasm intermediate representation"""

from collections import namedtuple
from miasm2.core.graph import DiGraph

class ReachingDefinitions(dict):
    """
    Computes for each instruction the set of reaching definitions.
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
    { (block, instr_index): { lvalue: set((block, instr_index)) } }
    """

    ir_a = None

    def __init__(self, ir_a):
        super(ReachingDefinitions, self).__init__()
        self.ir_a = ir_a
        self.compute()

    def get_definitions(self, block_lbl, instruction):
        """Returns the dict { lvalue: set((def_block_lbl, def_instr_index)) }
        associated with self.ir_a.@block.irs[@instruction]
        or {} if it is not yet computed
        """
        return self.get((block_lbl, instruction), {})

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
        the instruction in block @block.
        """
        predecessor_state = {}
        for pred_lbl in self.ir_a.graph.predecessors(block.label):
            pred = self.ir_a.blocks[pred_lbl]
            for lval, definitions in self.get_definitions(pred_lbl, len(pred.irs)).iteritems():
                predecessor_state.setdefault(lval, set()).update(definitions)

        modified = self.get((block.label, 0)) != predecessor_state
        if not modified:
            return False
        self[(block.label, 0)] = predecessor_state

        for instr_index in xrange(len(block.irs)):
            modified |= self.process_instruction(block, instr_index)
        return modified

    def process_instruction(self, block, instr_index):
        """
        Updates the reach definitions with values defined at
        instruction @instr_index in block @block.
        NB: the effect of instruction @instr_index in stored at index
        (@block, @instr_index + 1).
        """

        instr = block.irs[instr_index]
        defs = self.get_definitions(block.label, instr_index).copy()
        for lval in instr:
            defs.update({lval: set([(block.label, instr_index)])})

        modified = self.get((block.label, instr_index + 1)) != defs
        if modified:
            self[(block.label, instr_index + 1)] = defs

        return modified

ATTR_DEP = {"color" : "black",
            "_type" : "data"}

InstrNode = namedtuple('InstructionNode', ['label', 'index', 'var'])

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
        for ind, instr in enumerate(block.irs):
            instruction_reaching_defs = reaching_defs.get_definitions(block.label, ind)
            for lval, expr in instr.iteritems():
                self.add_node(InstrNode(block.label, ind, lval))

                read_vars = expr.get_r(mem_read=deref_mem)
                if deref_mem and lval.is_mem():
                    read_vars.update(lval.arg.get_r(mem_read=deref_mem))
                for read_var in read_vars:
                    for reach in instruction_reaching_defs.get(read_var, set()):
                        self.add_data_edge(InstrNode(reach[0], reach[1], read_var),
                                           InstrNode(block.label, ind, lval))

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
        lbl, ind, reg = node
        yield self.DotCellDescription(text="%s (%s)" % (lbl, ind),
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})
        src = self._blocks[lbl].irs[ind][reg]
        line = "%s = %s" % (reg, src)
        yield self.DotCellDescription(text=line, attr={})
        yield self.DotCellDescription(text="", attr={})


def dead_simp_useful_instrs(defuse, reaching_defs):
    """Mark useful statements using previous reach analysis and defuse

    Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division,  Algorithm MK

    Return a set of triplets (block, instruction number, instruction) of
    useful instructions
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
                                                              len(block.irs))
            for lval, definitions in valid_definitions.iteritems():
                if (lval in ir_a.get_out_regs(block)
                    or keep_all_definitions):
                    for definition in definitions:
                        useful.add(InstrNode(definition[0], definition[1], lval))

        # Force keeping of specific cases
        for instr_index, instr in enumerate(block.irs):
            for lval, rval in instr.iteritems():
                if (lval.is_mem()
                    or ir_a.IRDst == lval
                    or rval.is_function_call()):
                    useful.add(InstrNode(block_lbl, instr_index, lval))

    # Useful nodes dependencies
    for node in useful:
        for parent in defuse.reachable_parents(node):
            yield parent

def dead_simp(ir_a):
    """
    This function is used to analyse relation of a * complete function *
    This means the blocks under study represent a solid full function graph.

    Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
    IBM Thomas J. Watson Research Division, page 43
    """
    reaching_defs = ReachingDefinitions(ir_a)
    defuse = DiGraphDefUse(reaching_defs, deref_mem=True)
    useful = set(dead_simp_useful_instrs(defuse, reaching_defs))
    for block in ir_a.blocks.itervalues():
        for idx, assignblk in enumerate(block.irs):
            for lval in assignblk.keys():
                if InstrNode(block.label, idx, lval) not in useful:
                    del assignblk[lval]
