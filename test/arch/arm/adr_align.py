#! /usr/bin/env python
#-*- coding:utf-8 -*-
"""Thumb PC-relative address computations (issue #1561).

Arm ARM (AArch32 ISA): reads of PC in Thumb state see AlignDown(addr + 4, 4).
A 16-bit ADR (T1, ADD Rd, PC, #imm) at a 2-mod-4 address was computed with
the unaligned PC, producing a result 2 bytes high.
"""
import unittest
import logging

logging.getLogger('cpuhelper').setLevel(logging.ERROR)

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream import bin_stream_str
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt
import miasm.arch.arm.regs as R

BASE = 0x400000
FLAGS_END = BASE  # set in helper below


def symbolic_r0(machinename, code, entry):
    mach = Machine(machinename)
    ldb = LocationDB()
    mdis = mach.dis_engine(bin_stream_str(code, base_address=BASE), loc_db=ldb)
    mdis.dont_dis = [BASE + len(code)]
    cfg = mdis.dis_multiblock(BASE if entry is None else entry)
    lifter = mach.lifter_model_call(ldb)
    ircfg = lifter.new_ircfg_from_asmcfg(cfg)
    st = {R.regs32_expr[i]: ExprInt(0, 32) for i in range(13)}
    st[R.SP] = ExprInt(0x30001000, 32)
    st[R.LR] = ExprInt(0, 32)
    se = SymbolicExecutionEngine(lifter, st)
    se.run_at(ircfg, BASE if entry is None else entry,
              lbl_stop=ldb.get_offset_location(BASE + len(code)))
    return int(se.eval_expr(R.R0))


class TestThumbPcAlign(unittest.TestCase):
    def test_adr_t1_at_2_mod_4(self):
        # nop ; adr r0, #4 ; movs r1, #1 ; bx lr   (ADR at offset 2)
        code = bytes([0xc0, 0x46, 0x01, 0xa0, 0x01, 0x21, 0x70, 0x47])
        # Arm ARM: AlignDown(addr + 4, 4) + imm*4 = 0x400004 + 4 = 0x400008
        self.assertEqual(symbolic_r0("armtl", code, BASE + 2), 0x400008)

    def test_adr_t1_aligned(self):
        # adr r0, #4 ; movs r1, #1 ; bx lr   (ADR at offset 0)
        code = bytes([0x01, 0xa0, 0x01, 0x21, 0x70, 0x47])
        self.assertEqual(symbolic_r0("armtl", code, BASE), 0x400008)

    def test_adr_t1_at_2_mod_4_w(self):
        # nop ; adr r0, #8 ; bx lr  (ADR at offset 2)
        code = bytes([0xc0, 0x46, 0x02, 0xa0, 0x70, 0x47])
        # AlignDown(BASE+2+4, 4) + (2<<2) = 0x400004 + 8 = 0x40000C
        self.assertEqual(symbolic_r0("armtl", code, BASE + 2), 0x40000C)


if __name__ == "__main__":
    unittest.main()
