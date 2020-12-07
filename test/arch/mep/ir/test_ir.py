# Toshiba MeP-c4 - Misc unit tests
# Guillaume Valadon <guillaume@valadon.net>

from __future__ import print_function

from miasm.core.utils import decode_hex
from miasm.arch.mep.arch import mn_mep
from miasm.arch.mep.regs import regs_init
from miasm.arch.mep.lifter_model_call import Lifter_MEPb, LifterModelCallMepb
from miasm.expression.expression import ExprId, ExprInt, ExprMem
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.core.locationdb import LocationDB


class TestMisc(object):

    def test(self):

        """Simple symbolic execution examples"""

        def exec_instruction(hex_asm, init_values):
            """Symbolically execute an instruction"""

            print("Hex:", hex_asm)

            # Disassemble an instruction
            mn = mn_mep.dis(decode_hex(hex_asm), "b")
            print("Dis:", mn)

            loc_db = LocationDB()

            # Get the IR
            im = Lifter_MEPb(loc_db)
            iir, eiir, = im.get_ir(mn)
            print("\nInternal representation:", iir)

            # Symbolic execution
            sb = SymbolicExecutionEngine(LifterModelCallMepb(loc_db), regs_init)

            # Assign register values before symbolic evaluation
            for reg_expr_id, reg_expr_value in init_values:
                sb.symbols[reg_expr_id] = reg_expr_value

            print("\nModified registers:", [reg for reg in sb.modified(mems=False)])
            print("Modified memories:", [mem for mem in sb.modified()])

            print("\nFinal registers:")
            sb.dump(mems=False)

            print("\nFinal mems:")
            sb.dump()

        for hex_asm, init_values in [("6108", [(ExprId("R1", 32), ExprInt(0x40, 32))]),
                                     ("08a2", [(ExprId("R8", 32), ExprInt(0x40, 32)),
                                               (ExprId("R10", 32), ExprInt(0x41, 32))]),
                                     ("0948", [(ExprId("R4", 32), ExprInt(0x41, 32)),
                                               (ExprId("R9", 32), ExprInt(0x28, 32)),
                                               (ExprMem(ExprInt(0x41, 32), 8), ExprInt(0, 8))])]:
            print("-" * 49)  # Tests separation
            exec_instruction(hex_asm, init_values)
