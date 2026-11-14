# -*- coding:utf-8 -*-
"""Regression tests for Thumb-2 literal loads with U=0 (negative offset).

Bug report: Miasm decoded LDR/LDRB literal with U=0 as register-offset or
immediate forms instead of literal negative-offset loads (silent wrong decode,
no exception). Bytes were validated against capstone and Arm ARM (LDR/LDRB (literal) T2).
Decoder-only scope: Miasm cannot encode ANY [PC, #imm] literal today (positive
forms fail identically), so this test does not exercise the assembler.
"""
from __future__ import print_function
import unittest

from future.utils import viewitems
import logging

from miasm.arch.arm.arch import mn_armt
from miasm.core.locationdb import LocationDB
from miasm.core.bin_stream import bin_stream_str

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
loc_db = LocationDB()


def dis_one(bstr):
    bs = bin_stream_str(bytes.fromhex(bstr))
    return mn_armt.dis(bs, 'l', 0)


class TestThumbLdrLiteralNeg(unittest.TestCase):

    def test_ldr_literal_neg_0x8(self):
        """f85f 0008 = ldr.w r0, [pc, #-8]"""
        self.assertEqual(str(dis_one('5ff80800')),
                         "LDR        R0, [PC, 0xFFFFFFF8]")
        self.assertEqual(dis_one('5ff80800').l, 4)

    def test_ldrb_literal_neg_0xa(self):
        """f81f 000a = ldrb.w r0, [pc, #-10]"""
        self.assertEqual(str(dis_one('1ff80a00')),
                         "LDRB       R0, [PC, 0xFFFFFFF6]")
        self.assertEqual(dis_one('1ff80a00').l, 4)

    def test_ldr_literal_neg_0x904(self):
        """f85f 0904 = ldr.w r0, [pc, #-2308]"""
        self.assertEqual(str(dis_one('5ff80409')),
                         "LDR        R0, [PC, 0xFFFFF6FC]")
        self.assertEqual(dis_one('5ff80409').l, 4)

    def test_ldr_literal_pos_control_unchanged(self):
        """f8df 0008 = ldr.w r0, [pc, #8] (control case, already worked)"""
        self.assertEqual(str(dis_one('dff80800')),
                         "LDR        R0, [PC, 0x8]")
        self.assertEqual(dis_one('dff80800').l, 4)


if __name__ == '__main__':
    unittest.main()
