#-*- coding:utf-8 -*-

import warnings
import logging

from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.ir.ir import IntermediateRepresentation, AssignBlock
from miasm2.expression.expression import ExprAff, ExprOp
from miasm2.analysis.data_flow import dead_simp as new_dead_simp_imp

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

    def call_effects(self, addr, instr):
        """Default modelisation of a function call to @addr. This may be used to:

        * insert dependencies to arguments (stack base, registers, ...)
        * add some side effects (stack clean, return value, ...)

        @addr: (Expr) address of the called function
        @instr: native instruction which is responsible of the call
        """

        assignblk = AssignBlock({
            self.ret_reg: ExprOp('call_func_ret', addr, self.sp),
            self.sp: ExprOp('call_func_stack', addr, self.sp)},
            instr)
        return [assignblk]

    def pre_add_instr(self, block, instr, assignments, ir_blocks_all, gen_pc_update):
        """Replace function call with corresponding call effects,
        inside the IR block"""
        if not instr.is_subcall():
            return False
        call_effects = self.call_effects(instr.args[0], instr)
        assignments+= call_effects
        return True

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
