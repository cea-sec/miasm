#-*- coding:utf-8 -*-

import warnings
import logging

from miasm.ir.ir import Lifter, AssignBlock
from miasm.expression.expression import ExprOp, ExprAssign


log = logging.getLogger("analysis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)


class LifterModelCall(Lifter):
    """IR Analysis
    This class provides higher level manipulations on IR, such as dead
    instruction removals.

    This class can be used as a common parent with
    `miasm.ir.ir::Lifter` class.

    For instance:
        class LifterModelCall_x86_16(Lifter_X86_16, LifterModelCall)

    """
    ret_reg = None

    def call_effects(self, addr, instr):
        """Default modelisation of a function call to @addr. This may be used to:

        * insert dependencies to arguments (stack base, registers, ...)
        * add some side effects (stack clean, return value, ...)

        Return a couple:
        * list of assignments to add to the current irblock
        * list of additional irblocks

        @addr: (Expr) address of the called function
        @instr: native instruction which is responsible of the call
        """

        call_assignblk = AssignBlock(
            [
                ExprAssign(self.ret_reg, ExprOp('call_func_ret', addr, self.sp)),
                ExprAssign(self.sp, ExprOp('call_func_stack', addr, self.sp))
            ],
            instr
        )
        return [call_assignblk], []

    def add_instr_to_current_state(self, instr, block, assignments, ir_blocks_all, gen_pc_updt):
        """
        Add the IR effects of an instruction to the current state.
        If the instruction is a function call, replace the original IR by a
        model of the sub function

        Returns a bool:
        * True if the current assignments list must be split
        * False in other cases.

        @instr: native instruction
        @block: native block source
        @assignments: current irbloc
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions
        """
        if instr.is_subcall():
            call_assignblks, extra_irblocks = self.call_effects(
                instr.args[0],
                instr
            )
            assignments += call_assignblks
            ir_blocks_all += extra_irblocks
            return True

        if gen_pc_updt is not False:
            self.gen_pc_update(assignments, instr)

        assignblk, ir_blocks_extra = self.instr2ir(instr)
        assignments.append(assignblk)
        ir_blocks_all += ir_blocks_extra
        if ir_blocks_extra:
            return True
        return False

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



class ira(LifterModelCall):
    """
    DEPRECATED object
    Use LifterModelCall instead of ira
    """

    def __init__(self, arch, attrib, loc_db):
        warnings.warn('DEPRECATION WARNING: use "LifterModelCall" instead of "ira"')
        super(ira, self).__init__(arch, attrib, loc_db)
