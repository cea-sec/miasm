#! /usr/bin/env python
#-*- coding:utf-8 -*-
"""Thumb 16-bit ADD (high reg) / ADD (SP plus register), 0x44xx.

Regression for issue #1560: these T2 encodings have setflags = FALSE,
but miasm decoded them as ADDS, corrupting NZCV and flipping later
conditional branches (e.g. GCC -mthumb -O2 PIC-base "add r3, pc" between
cmp and ble).
"""
import unittest
import logging

logging.getLogger('cpuhelper').setLevel(logging.ERROR)

from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream import bin_stream_str
from miasm.expression.expression import ExprInt
from miasm.ir.symbexec import SymbolicExecutionEngine
import miasm.arch.arm.regs as R

CODE = 0x400000
FLAGS = (R.nf, R.zf, R.cf, R.of)


def symb(mach, code, regs, f, stop=None):
    ldb = LocationDB()
    mdis = mach.dis_engine(bin_stream_str(code, base_address=CODE), loc_db=ldb)
    end = CODE + len(code)
    mdis.dont_dis = [end]
    cfg = mdis.dis_multiblock(CODE)
    lifter = mach.lifter_model_call(ldb)
    ircfg = lifter.new_ircfg_from_asmcfg(cfg)
    st = {R.regs32_expr[i]: ExprInt(0, 32) for i in range(13)}
    for i, v in enumerate(regs):
        st[R.regs32_expr[i]] = ExprInt(v, 32)
    st[R.SP] = ExprInt(0x30001000, 32)
    st[R.LR] = ExprInt(0, 32)
    if "R8" in f:  # sentinel channel kept simple: see EXTRA below
        pass
    for b, e in zip(f, FLAGS):
        st[e] = ExprInt(int(b), 1)
    se = SymbolicExecutionEngine(lifter, st)
    se.run_at(ircfg, CODE, lbl_stop=ldb.get_offset_location(end))
    return (int(se.eval_expr(R.R0)),
            "".join(str(int(se.eval_expr(e))) for e in FLAGS))


class TestHiregAddNoFlags(unittest.TestCase):
    def mach(self):
        return Machine("armtl")

    def test_decodes_as_add_not_adds(self):
        mach = self.mach()
        for hexb in ("4044", "6844", "7b44"):
            i = mach.mn.dis(bytes.fromhex(hexb)[:2], 'l')
            self.assertEqual(i.name, "ADD")

    def test_adds_t1_unchanged(self):
        mach = self.mach()
        i = mach.mn.dis(bytes.fromhex("4018"), 'l')
        self.assertEqual(i.name, "ADDS")

    def test_cmp_add_pc_ble_takes_ble(self):
        # Full reduced case: cmp r0, #5 ; add r3, pc ; ble 1f ...
        code = bytes.fromhex("05287b4401dd012000e00220")
        r0, nzcv = symb(self.mach(), code, [3, 0, 0, 0], "0000")
        self.assertEqual(r0, 2)

    def test_add_r0_r8_flags_untouched(self):
        mach = self.mach()
        ldb = LocationDB()
        # add r0, r8 with r8=0xffffffff: result 0, NZCV must stay 0000
        code = bytes.fromhex("4044")
        mdis = mach.dis_engine(bin_stream_str(code, base_address=CODE), loc_db=ldb)
        mdis.dont_dis = [CODE + len(code)]
        cfg = mdis.dis_multiblock(CODE)
        lifter = mach.lifter_model_call(ldb)
        ircfg = lifter.new_ircfg_from_asmcfg(cfg)
        st = {R.regs32_expr[i]: ExprInt(0, 32) for i in range(13)}
        st[R.regs32_expr[0]] = ExprInt(1, 32)
        st[R.R8] = ExprInt(0xffffffff, 32)
        for e in FLAGS:
            st[e] = ExprInt(0, 1)
        se = SymbolicExecutionEngine(lifter, st)
        se.run_at(ircfg, CODE, lbl_stop=ldb.get_offset_location(CODE + len(code)))
        self.assertEqual(int(se.eval_expr(R.R0)), 0)
        self.assertEqual("".join(str(int(se.eval_expr(e))) for e in FLAGS),
                         "0000")

    def test_add_r0_sp_flags_preserved(self):
        mach = self.mach()
        ldb = LocationDB()
        code = bytes.fromhex("6844")
        mdis = mach.dis_engine(bin_stream_str(code, base_address=CODE), loc_db=ldb)
        mdis.dont_dis = [CODE + len(code)]
        cfg = mdis.dis_multiblock(CODE)
        lifter = mach.lifter_model_call(ldb)
        ircfg = lifter.new_ircfg_from_asmcfg(cfg)
        st = {R.regs32_expr[i]: ExprInt(0, 32) for i in range(13)}
        st[R.SP] = ExprInt(0x1000, 32)
        for b, e in zip("1001", FLAGS):
            st[e] = ExprInt(int(b), 1)
        se = SymbolicExecutionEngine(lifter, st)
        se.run_at(ircfg, CODE, lbl_stop=ldb.get_offset_location(CODE + len(code)))
        self.assertEqual(int(se.eval_expr(R.R0)), 0x1000)
        self.assertEqual("".join(str(int(se.eval_expr(e))) for e in FLAGS),
                         "1001")


if __name__ == "__main__":
    unittest.main()
