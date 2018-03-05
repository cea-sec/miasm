from miasm2.expression.expression import ExprAff, ExprOp
from miasm2.ir.ir import AssignBlock
from miasm2.ir.analysis import ira
from miasm2.arch.ppc.sem import ir_ppc32b


class ir_a_ppc32b(ir_ppc32b, ira):

    def __init__(self, *args):
        super(ir_a_ppc32b, self).__init__(*args)
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
        return [AssignBlock([ExprAff(self.ret_reg, ExprOp('call_func_ret', ad,
                                                          self.sp,
                                                          self.arch.regs.R3,
                                                          self.arch.regs.R4,
                                                          self.arch.regs.R5,
                                                          )),
                             ExprAff(self.sp, ExprOp('call_func_stack',
                                                     ad, self.sp)),
                            ],
                             instr
                           )]

    def pre_add_instr(self, block, instr, assignments, ir_blocks_all, gen_pc_update):
        """Replace function call with corresponding call effects,
        inside the IR block"""
        if not instr.is_subcall():
            return False
        call_effects = self.call_effects(instr.getdstflow(None)[0], instr)
        assignments+= call_effects
        return True

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
