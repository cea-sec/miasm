#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging

from miasm2.ir.symbexec import symbexec
from miasm2.ir.ir import ir
from miasm2.expression.expression \
    import ExprAff, ExprCond, ExprId, ExprInt, ExprMem

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

    def remove_dead_instr(self, irb, useful):
        """Remove dead affectations using previous reaches analysis
        @irb: irbloc instance
        @useful: useful statements from previous reach analysis
        Return True iff the block state has changed
        PRE: compute_reach(self)
        """
        modified = False
        for k, ir in enumerate(irb.irs):
            j = 0
            while j < len(ir):
                cur_instr = ir[j]
                if (isinstance(cur_instr.dst, ExprId)
                    and (irb.label, k, cur_instr) not in useful):
                    del ir[j]
                    modified = True
                else:
                    j += 1
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
                        useful.update(block.cur_reach[-1][r].union(
                                block.defout[-1][r]))

            # Function call, memory write or IRDst affectation
            for k, ir in enumerate(block.irs):
                for i_cur in ir:
                    if i_cur.src.is_function_call():
                        # /!\ never remove ir calls
                        useful.add((block.label, k, i_cur))
                    if isinstance(i_cur.dst, ExprMem):
                        useful.add((block.label, k, i_cur))
                    useful.update(block.defout[k][self.IRDst])

            # Affecting return registers
            if not has_son:
                for r in self.get_out_regs(block):
                    useful.update(block.defout[-1][r]
                                  if block.defout[-1][r] else
                                  block.cur_reach[-1][r])

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
            irb, irs_ind, ins = elem

            block = self.blocs[irb]
            instr_defout = block.defout[irs_ind]
            cur_kill = block.cur_kill[irs_ind]
            cur_reach = block.cur_reach[irs_ind]

            # Handle dependencies of used variables in ins
            for reg in ins.get_r(True).intersection(self.ira_regs_ids()):
                worklist.update(
                    cur_reach[reg].difference(useful).difference(
                        cur_kill[reg]
                        if not instr_defout[reg] else
                        set()))
                for _, _, i in instr_defout[reg]:
                    # Loop case (i in defout of current block)
                    if i == ins:
                        worklist.update(cur_reach[reg].difference(useful))
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
        print '*'*80
        for k, irs in enumerate(irb.irs):
            for i in xrange(len(irs)):
                print 5*"-"
                print 'instr', k, irs[i]
                print 5*"-"
                for v in self.ira_regs_ids():
                    if irb.cur_reach[k][v]:
                        print 'REACH[%d][%s]' % (k, v)
                        self.print_set(irb.cur_reach[k][v])
                    if irb.cur_kill[k][v]:
                        print 'KILL[%d][%s]' % (k, v)
                        self.print_set(irb.cur_kill[k][v])
                    if irb.defout[k][v]:
                        print 'DEFOUT[%d][%s]' % (k, v)
                        self.print_set(irb.defout[k][v])

    def compute_reach_block(self, irb):
        """Variable influence computation for a single block
        @irb: irbloc instance
        PRE: init_reach()
        """

        reach_block = {key: value.copy()
                      for key, value in irb.cur_reach[0].iteritems()}

        # Compute reach from predecessors
        for n_pred in self.graph.predecessors(irb.label):
            p_block = self.blocs[n_pred]

            # Handle each register definition
            for c_reg in self.ira_regs_ids():
                # REACH(n) = U[p in pred] DEFOUT(p) U REACH(p)\KILL(p)
                pred_through = p_block.defout[-1][c_reg].union(
                    p_block.cur_reach[-1][c_reg].difference(
                        p_block.cur_kill[-1][c_reg]))
                reach_block[c_reg].update(pred_through)

        # If a predecessor has changed
        if reach_block != irb.cur_reach[0]:
            irb.cur_reach[0] = reach_block
            for c_reg in self.ira_regs_ids():
                if irb.defout[0][c_reg]:
                    # KILL(n) = DEFOUT(n) ? REACH(n)\DEFOUT(n) : EMPTY
                    irb.cur_kill[0][c_reg].update(
                        reach_block[c_reg].difference(irb.defout[0][c_reg]))

        # Compute reach and kill for block's instructions
        for i in xrange(1, len(irb.irs)):
            for c_reg in self.ira_regs_ids():
                # REACH(n) = U[p in pred] DEFOUT(p) U REACH(p)\KILL(p)
                pred_through = irb.defout[i - 1][c_reg].union(
                    irb.cur_reach[i - 1][c_reg].difference(
                        irb.cur_kill[i - 1][c_reg]))
                irb.cur_reach[i][c_reg].update(pred_through)
                if irb.defout[i][c_reg]:
                    # KILL(n) = DEFOUT(n) ? REACH(n)\DEFOUT(n) : EMPTY
                    irb.cur_kill[i][c_reg].update(
                        irb.cur_reach[i][c_reg].difference(
                            irb.defout[i][c_reg]))

    def _test_kill_reach_fix(self):
        """Return True iff a fixed point has been reached during reach
        analysis"""

        fixed = True
        for node in self.graph.nodes():
            if node in self.blocs:
                irb = self.blocs[node]
                if (irb.cur_reach != irb.prev_reach or
                    irb.cur_kill != irb.prev_kill):
                    fixed = False
                    irb.prev_reach = irb.cur_reach[:]
                    irb.prev_kill = irb.cur_kill[:]
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
            symbols_init = {}
            for r in self.arch.regs.all_regs_ids:
                x = ExprId(r.name, r.size)
                x.is_term = True
                symbols_init[r] = x
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
