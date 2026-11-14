# -*- coding:utf-8 -*-
"""Regression tests for #1566: opcodes that must be rejected in 64-bit mode.

Intel SDM (325462-084US, Vol. 2A) lists these opcodes as "Invalid" in 64-bit
mode (#UD). Miasm accepted them, diverging from any CPU. The 64-bit push/pop
rules for the legacy segment registers and the legacy data-processing opcodes
now require bs_modeno64, like the existing far-call / far-jump rules.
"""
from __future__ import print_function
import unittest

from miasm.analysis.machine import Machine

# legacy opcodes that are invalid in 64-bit mode
INVALID_64_BYTES = {
    b"\x27": "DAA", b"\x2f": "DAS", b"\x37": "AAA", b"\x3f": "AAS",
    b"\xd4\x0a": "AAM", b"\xd5\x0a": "AAD",
    b"\x06": "PUSH ES", b"\x07": "POP ES",
    b"\x0e": "PUSH CS",
    b"\x16": "PUSH SS", b"\x17": "POP SS",
    b"\x1e": "PUSH DS", b"\x1f": "POP DS",
    b"\xce": "INTO",
}
# previously rejected controls; must stay rejected
INVALID_CONTROL = {b"\x60": "PUSHA/PUSHAD", b"\x61": "POPA/POPAD",
                   b"\x9a": "far call", b"\xea": "far jmp"}

# neighbour opcodes that remain legal in 64-bit mode (must still decode)
VALID_64 = {
    b"\x0f\xa0": "PUSH FS", b"\x0f\xa1": "POP FS",
    b"\x0f\xa8": "PUSH GS", b"\x0f\xa9": "POP GS",
    b"\x9c": "PUSHFQ", b"\x9d": "POPFQ",
}


class TestNo64IllegalOpcodes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.m64 = Machine("x86_64").mn
        cls.m16 = Machine("x86_16").mn
        cls.m32 = Machine("x86_32").mn

    def test_invalid_in_64_bit(self):
        for opcode in sorted(INVALID_64_BYTES):
            with self.subTest(opcode.hex()):
                self.assertRaises(Exception, self.m64.dis, opcode, 64)

    def test_invalid_controls_stay_rejected(self):
        for opcode in INVALID_CONTROL:
            with self.subTest(opcode.hex()):
                self.assertRaises(Exception, self.m64.dis, opcode, 64)

    def test_legal_in_64_bit_still_decode(self):
        for opcode in sorted(VALID_64):
            with self.subTest(opcode.hex()):
                self.assertIsNotNone(self.m64.dis(opcode, 64))

    def test_legal_in_16_32_bit_still_decode(self):
        for opcode in sorted(INVALID_64_BYTES):
            with self.subTest(opcode.hex()):
                self.assertIsNotNone(self.m16.dis(opcode, 16))
                self.assertIsNotNone(self.m32.dis(opcode, 32))


if __name__ == '__main__':
    unittest.main()
