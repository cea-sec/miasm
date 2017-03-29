#-*- coding:utf-8 -*-

import logging

from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.ir.ir import IntermediateRepresentation, AssignBlock
from miasm2.expression.expression \
    import ExprAff, ExprCond, ExprId, ExprInt, ExprMem, ExprOp
from miasm2.analysis.data_flow import dead_simp as new_dead_simp_imp
import warnings

log = logging.getLogger("analysis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)


class ira(IntermediateRepresentation):
    """IR Analysis
    This class provides higher level manipulations on IR, such as dead
    instruction removals.

    This class can be used as a common parent with
    `miasm2.ir.ir::IntermediateRepresentation` class.

    For instance:
        class ira_x86_16(ir_x86_16, ira)

    """

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

    def gen_equations(self):
        for irb in self.blocks.values():
            symbols_init = dict(self.arch.regs.all_regs_ids_init)

            sb = SymbolicExecutionEngine(self, dict(symbols_init))
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

    def dead_simp(self):
        """Deprecated: See miasm2.analysis.data_flow.dead_simp()"""
        warnings.warn('DEPRECATION WARNING: Please use miasm2.analysis.data_flow.dead_simp(ira) instead of ira.dead_simp()')
        new_dead_simp_imp(self)
