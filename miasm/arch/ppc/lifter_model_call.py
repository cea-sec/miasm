from miasm.expression.expression import ExprAssign, ExprOp
from miasm.ir.ir import AssignBlock
from miasm.ir.analysis import LifterModelCall
from miasm.arch.ppc.sem import Lifter_PPC32b


class LifterModelCallPpc32b(Lifter_PPC32b, LifterModelCall):

    def __init__(self, loc_db, *args):
        super(LifterModelCallPpc32b, self).__init__(loc_db, *args)
        self.ret_reg = self.arch.regs.R3

    # for test XXX TODO
    def set_dead_regs(self, irblock):
        pass

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

    def add_unused_regs(self):
        leaves = [self.blocks[label] for label in self.g.leafs()]
        for irblock in leaves:
            self.set_dead_regs(irblock)

    def call_effects(self, ad, instr):
        call_assignblks = AssignBlock(
            [
                ExprAssign(
                    self.ret_reg,
                    ExprOp(
                        'call_func_ret',
                        ad,
                        self.sp,
                        self.arch.regs.R3,
                        self.arch.regs.R4,
                        self.arch.regs.R5,
                    )
                ),
                ExprAssign(self.sp, ExprOp('call_func_stack', ad, self.sp)),
            ],
            instr
        )
        return [call_assignblks], []

    def add_instr_to_current_state(self, instr, block, assignments, ir_blocks_all, gen_pc_updt):
        """
        Add the IR effects of an instruction to the current state.

        @instr: native instruction
        @block: native block source
        @assignments: list of current AssignBlocks
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions
        """
        if instr.is_subcall():
            call_assignblks, extra_irblocks = self.call_effects(
                instr.getdstflow(None)[0],
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
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 32

    def sizeof_pointer(self):
        return 32
