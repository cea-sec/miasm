#!/usr/bin/env python
#-*- coding:utf-8 -*-

import unittest


class TestParseAsm(unittest.TestCase):

    def test_ParseTxt(self):
        from miasm2.arch.x86.arch import mn_x86
        from miasm2.core.parse_asm import parse_txt

        ASM0 = '''
        ;
        .LFB0:
        .LA:
        .text
        .data
        .bss
        .string
        .ustring
        .byte 0 0x0
        .byte a
        .comm
        .split
        .dontsplit
        .file
        .cfi_0
        label:
            JMP EAX  ;comment
        '''
        ASM1 = '''
        .XXX
        '''
        self.assertTrue(parse_txt(mn_x86, 32, ASM0))
        self.assertRaises(ValueError, parse_txt, mn_x86, 32, ASM1)

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestParseAsm)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
