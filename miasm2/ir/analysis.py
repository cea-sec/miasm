#-*- coding:utf-8 -*-

import logging

from miasm2.ir.symbexec import symbexec
from miasm2.ir.ir import ir, AssignBlock
from miasm2.expression.expression \
    import ExprAff, ExprCond, ExprId, ExprInt, ExprMem, ExprOp

log = logging.getLogger("analysis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)


class ira(ir):
    """IR Analysis
    This class provides higher level manipulations on IR, such as dead
    instruction removals.

    This class can be used as a common parent with `miasm2.ir.ir::ir` class.
    For instance:
        class ira_x86_16(ir_x86_16, ira)
    """

    def ira_regs_ids(self):
        """Returns ids of all registers used in the IR"""
        return self.arch.regs.all_regs_ids + [self.IRDst]

    def call_effects(self, ad, instr):
        """Default modelisation of a function call to @ad. This may be used to:

        * insert dependencies to arguments (stack base, registers, ...)
        * add some side effects (stack clean, return value, ...)

        @ad: (Expr) address of the called function
        @instr: native instruction which is responsible of the call
        """

        return [AssignBlock(
            [ExprAff(self.ret_reg, ExprOp('call_func_ret', ad, self.sp)),
             ExprAff(self.sp, ExprOp(
                 'call_func_stack', ad, self.sp)),
             ])]

    def pre_add_instr(self, block, instr, irb_cur, ir_blocks_all, gen_pc_update):
        """Replace function call with corresponding call effects,
        inside the IR block"""
        if not instr.is_subcall():
            return irb_cur
        call_effects = self.call_effects(instr.args[0], instr)
        for assignblk in call_effects:
            irb_cur.irs.append(assignblk)
            irb_cur.lines.append(instr)
        return None

    def remove_dead_instr(self, irb, useful):
        """Remove dead affectations using previous reaches analysis
        @irb: irbloc instance
        @useful: useful statements from previous reach analysis
        Return True iff the block state has changed
        PRE: compute_reach(self)
        """
        modified = False
        for idx, assignblk in enumerate(irb.irs):
            for dst in assignblk.keys():
                if (isinstance(dst, ExprId) and
                        (irb.label, idx, dst) not in useful):
                    del assignblk[dst]
                    modified = True
        return modified

    def init_useful_instr(self):
        """Computes a set of triples (block, instruction number, instruction)
        containing initially useful instructions :
          - Instructions affecting final value of return registers
          - Instructions affecting IRDst register
          - Instructions writing in memory
          - Function call instructions
        Return set of intial useful instructions
        """

        useful = set()

        for node in self.graph.nodes():
            if node not in self.blocs:
                continue

            block = self.blocs[node]
            successors = self.graph.successors(node)
            has_son = bool(successors)
            for p_son in successors:
                if p_son not in self.blocs:
                    # Leaf has lost its son: don't remove anything
                    # reaching this block
                    for r in self.ira_regs_ids():
                        useful.update(block.irs[-1]._cur_reach[r].union(
                            block.irs[-1].defout[r]))

            # Function call, memory write or IRDst affectation
            for idx, assignblk in enumerate(block.irs):
                for dst, src in assignblk.iteritems():
                    if src.is_function_call():
                        # /!\ never remove ir calls
                        useful.add((block.label, idx, dst))
                    if isinstance(dst, ExprMem):
                        useful.add((block.label, idx, dst))
                    useful.update(block.irs[idx].defout[self.IRDst])

            # Affecting return registers
            if not has_son:
                for r in self.get_out_regs(block):
                    useful.update(block.irs[-1].defout[r]
                                  if block.irs[-1].defout[r] else
                                  block.irs[-1]._cur_reach[r])

        return useful

    def _mark_useful_code(self):
        """Mark useful statements using previous reach analysis

        Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
        IBM Thomas J. Watson Research Division,  Algorithm MK

        Return a set of triplets (block, instruction number, instruction) of
        useful instructions
        PRE: compute_reach(self)

        """

        useful = self.init_useful_instr()
        worklist = useful.copy()
        while worklist:
            elem = worklist.pop()
            useful.add(elem)
            irb_label, irs_ind, dst = elem

            assignblk = self.blocs[irb_label].irs[irs_ind]
            ins = assignblk.dst2ExprAff(dst)

            # Handle dependencies of used variables in ins
            for reg in ins.get_r(True).intersection(self.ira_regs_ids()):
                worklist.update(
                    assignblk._cur_reach[reg].difference(useful).difference(
                        assignblk._cur_kill[reg]
                        if not assignblk.defout[reg] else
                        set()))
                for _, _, defout_dst in assignblk.defout[reg]:
                    # Loop case (dst in defout of current irb)
                    if defout_dst == dst:
                        worklist.update(
                            assignblk._cur_reach[reg].difference(useful))
        return useful

    def remove_dead_code(self):
        """Remove dead instructions in each block of the graph using the reach
        analysis .
        Returns True if a block has been modified
        PRE : compute_reach(self)
        """
        useful = self._mark_useful_code()
        modified = False
        for block in self.blocs.values():
            modified |= self.remove_dead_instr(block, useful)
            # Remove useless structures
            for assignblk in block.irs:
                del assignblk._cur_kill
                del assignblk._prev_kill
                del assignblk._cur_reach
                del assignblk._prev_reach
        return modified

    def set_dead_regs(self, b):
        pass

    def add_unused_regs(self):
        pass

    @staticmethod
    def print_set(v_set):
        """Print each triplet contained in a set
        @v_set: set containing triplets elements
        """
        for p in v_set:
            print '    (%s, %s, %s)' % p

    def dump_bloc_state(self, irb):
        print '*' * 80
        for irs in irb.irs:
            for assignblk in irs:
                print 5 * "-"
                print 'instr', assignblk
                print 5 * "-"
                for v in self.ira_regs_ids():
                    if assignblk._cur_reach[v]:
                        print 'REACH[%d][%s]' % (k, v)
                        self.print_set(assignblk._cur_reach[v])
                    if assignblk._cur_kill[v]:
                        print 'KILL[%d][%s]' % (k, v)
                        self.print_set(assignblk._cur_kill[v])
                    if assignblk.defout[v]:
                        print 'DEFOUT[%d][%s]' % (k, v)
                        self.print_set(assignblk.defout[v])

    def compute_reach_block(self, irb):
        """Variable influence computation for a single block
        @irb: irbloc instance
        PRE: init_reach()
        """

        reach_block = {key: value.copy()
                       for key, value in irb.irs[0]._cur_reach.iteritems()}

        # Compute reach from predecessors
        for n_pred in self.graph.predecessors(irb.label):
            p_block = self.blocs[n_pred]

            # Handle each register definition
            for c_reg in self.ira_regs_ids():
                # REACH(n) = U[p in pred] DEFOUT(p) U REACH(p)\KILL(p)
                pred_through = p_block.irs[-1].defout[c_reg].union(
                    p_block.irs[-1]._cur_reach[c_reg].difference(
                        p_block.irs[-1]._cur_kill[c_reg]))
                reach_block[c_reg].update(pred_through)

        # If a predecessor has changed
        if reach_block != irb.irs[0]._cur_reach:
            irb.irs[0]._cur_reach = reach_block
            for c_reg in self.ira_regs_ids():
                if irb.irs[0].defout[c_reg]:
                    # KILL(n) = DEFOUT(n) ? REACH(n)\DEFOUT(n) : EMPTY
                    irb.irs[0]._cur_kill[c_reg].update(
                        reach_block[c_reg].difference(irb.irs[0].defout[c_reg]))

        # Compute reach and kill for block's instructions
        for i in xrange(1, len(irb.irs)):
            for c_reg in self.ira_regs_ids():
                # REACH(n) = U[p in pred] DEFOUT(p) U REACH(p)\KILL(p)
                pred_through = irb.irs[i - 1].defout[c_reg].union(
                    irb.irs[i - 1]._cur_reach[c_reg].difference(
                        irb.irs[i - 1]._cur_kill[c_reg]))
                irb.irs[i]._cur_reach[c_reg].update(pred_through)
                if irb.irs[i].defout[c_reg]:
                    # KILL(n) = DEFOUT(n) ? REACH(n)\DEFOUT(n) : EMPTY
                    irb.irs[i]._cur_kill[c_reg].update(
                        irb.irs[i]._cur_reach[c_reg].difference(
                            irb.irs[i].defout[c_reg]))

    def _test_kill_reach_fix(self):
        """Return True iff a fixed point has been reached during reach
        analysis"""

        fixed = True
        for node in self.graph.nodes():
            if node in self.blocs:
                irb = self.blocs[node]
                for assignblk in irb.irs:
                    if (assignblk._cur_reach != assignblk._prev_reach or
                            assignblk._cur_kill != assignblk._prev_kill):
                        fixed = False
                        # This is not a deepcopy, but cur_reach is assigned to a
                        # new dictionnary on change in `compute_reach_block`
                        assignblk._prev_reach = assignblk._cur_reach.copy()
                        assignblk._prev_kill = assignblk._cur_kill.copy()
        return fixed

    def compute_reach(self):
        """
        Compute reach, defout and kill sets until a fixed point is reached.

        Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
        IBM Thomas J. Watson Research Division, page 43
        """
        fixed_point = False
        log.debug('iteration...')
        while not fixed_point:
            for node in self.graph.nodes():
                if node in self.blocs:
                    self.compute_reach_block(self.blocs[node])
            fixed_point = self._test_kill_reach_fix()

    def dead_simp(self):
        """
        This function is used to analyse relation of a * complete function *
        This means the blocks under study represent a solid full function graph.

        Source : Kennedy, K. (1979). A survey of data flow analysis techniques.
        IBM Thomas J. Watson Research Division, page 43
        """
        # Update r/w variables for all irblocs
        self.get_rw(self.ira_regs_ids())
        # Liveness step
        self.compute_reach()
        self.remove_dead_code()
        # Simplify expressions
        self.simplify_blocs()

    def gen_equations(self):
        for irb in self.blocs.values():
            symbols_init = dict(self.arch.regs.all_regs_ids_init)

            sb = symbexec(self, dict(symbols_init))
            sb.emulbloc(irb)
            eqs = []
            for n_w in sb.symbols:
                v = sb.symbols[n_w]
                if n_w in symbols_init and symbols_init[n_w] == v:
                    continue
                eqs.append(ExprAff(n_w, v))
            print '*' * 40
            print irb
            irb.irs = [eqs]
            irb.lines = [None]

    def sizeof_char(self):
        "Return the size of a char in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_short(self):
        "Return the size of a short in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_int(self):
        "Return the size of an int in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_long(self):
        "Return the size of a long in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_pointer(self):
        "Return the size of a void* in bits"
        raise NotImplementedError("Abstract method")
