#! /usr/bin/env python
#-*- coding:utf-8 -*-
"""Thumb IT blocks that end in a PC-writing instruction.

Regression for issue #1578: the disassembler stopped at the predicated
PC writer (silently dropping the instructions after it), and the lifter
raised "Multiple destinations!" because the IT wrapper appended a
fallthrough assignment to a block that already branched.
"""
import unittest
import struct
import logging

logging.getLogger('cpuhelper').setLevel(logging.ERROR)

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream import bin_stream_str
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt
import miasm.arch.arm.regs as R

# objdump output (arm-none-eabi-objdump, from the issue)
A1 = bytes([
    0x00, 0x28,              # cmp   r0, #0
    0x48, 0xbf,              # it    mi
    0x70, 0x47,              # bxmi  lr
    0x80, 0xb5,              # push  {r7, lr}
    0x00, 0xf0, 0x04, 0xf8,  # bl    g
    0x02, 0x20,              # movs  r0, #2
    0xbd, 0xe8, 0x80, 0x40,  # pop.w {r7, lr}
    0x70, 0x47,              # bx    lr
])

EXPECTED = ["CMP", "IT", "BX", "PUSH", "BL", "MOVS", "POP", "BX"]


class TestThumbITBranch(unittest.TestCase):
    def machine(self):
        return Machine("armtl"), LocationDB()

    def dis_insns(self):
        mach, ldb = self.machine()
        mdis = mach.dis_engine(bin_stream_str(A1), loc_db=ldb)
        cfg = mdis.dis_multiblock(0)
        lines = []
        for b in sorted(cfg.blocks,
                        key=lambda b: b.lines[0].offset if b.lines else -1):
            lines.extend(b.lines)
        return lines

    def test_all_instructions_disassembled(self):
        lines = self.dis_insns()
        self.assertEqual([l.name.upper() for l in lines], EXPECTED)

    def test_bxmi_remains_a_split_block(self):
        lines = self.dis_insns()
        bxmi = next(l for l in lines if l.name == "BX" and l.offset == 0x4)
        self.assertNotEqual(bxmi.additional_info.cond, 14)  # MI
        self.assertTrue(bxmi.splitflow())
        self.assertTrue(bxmi.breakflow())

    def test_ir_lift_ok(self):
        mach, ldb = self.machine()
        mdis = mach.dis_engine(bin_stream_str(A1), loc_db=ldb)
        cfg = mdis.dis_multiblock(0)
        # must not raise (was "Multiple destinations!")
        mach.lifter_model_call(ldb).new_ircfg_from_asmcfg(cfg)

    def test_symbolic_both_paths(self):
        # LR points at a distinguished, unmapped return address so both
        # paths terminate (taken path branches to LR; fall-through path
        # reaches the closing BX LR and the engine stops there).
        for r0, want in ((0x5, 2), (0xfffffffb, 0xfffffffb)):
            mach, ldb = self.machine()
            st = {R.regs32_expr[i]: ExprInt(0, 32) for i in range(13)}
            st[R.regs32_expr[0]] = ExprInt(r0, 32)
            st[R.regs32_expr[14]] = ExprInt(0xdead, 32)   # LR
            st[R.regs32_expr[13]] = ExprInt(0x8000, 32)   # SP
            mdis = mach.dis_engine(bin_stream_str(A1), loc_db=ldb)
            cfg = mdis.dis_multiblock(0)
            ir = mach.lifter_model_call(ldb).new_ircfg_from_asmcfg(cfg)
            se = SymbolicExecutionEngine(mach.lifter_model_call(ldb), st)
            se.run_at(ir, 0)
            r0out = se.eval_expr(R.regs32_expr[0])
            self.assertTrue(r0out.is_int())
            self.assertEqual(int(r0out) & 0xffffffff, want)


if __name__ == "__main__":
    unittest.main()
