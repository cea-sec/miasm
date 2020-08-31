#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from builtins import range
import unittest
from miasm.core.locationdb import LocationDB


class TestParseAsm(unittest.TestCase):

    def test_ParseTxt(self):
        from miasm.arch.x86.arch import mn_x86
        from miasm.core.parse_asm import parse_txt
        loc_db = LocationDB()

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
        self.assertTrue(parse_txt(mn_x86, 32, ASM0, loc_db))
        self.assertRaises(ValueError, parse_txt, mn_x86, 32, ASM1, loc_db)

    def test_DirectiveDontSplit(self):
        from miasm.arch.x86.arch import mn_x86
        from miasm.core.parse_asm import parse_txt
        from miasm.core.asmblock import asm_resolve_final
        loc_db = LocationDB()

        ASM0 = '''
        lbl0:
            INC   EAX
            JNZ   lbl0
            INC   EAX
            JZ    lbl2
        lbl1:
            NOP
            JMP   lbl0
        .dontsplit
        lbl2:
            MOV   EAX, ECX
            RET
        .dontsplit
        lbl3:
            ADD   EAX, EBX
        .dontsplit
        lbl4:
        .align 0x10
        .string "test"
        lbl5:
        .string "toto"
        '''

        asmcfg = parse_txt(mn_x86, 32, ASM0, loc_db)
        patches = asm_resolve_final(mn_x86, asmcfg)
        lbls = []
        for i in range(6):
            lbls.append(loc_db.get_name_location('lbl%d' % i))
        # align test
        offset = loc_db.get_location_offset(lbls[5])
        assert(offset % 0x10 == 0)
        lbl2block = {}
        for block in asmcfg.blocks:
            lbl2block[block.loc_key] = block
        # dontsplit test
        assert(lbls[2] == lbl2block[lbls[1]].get_next())
        assert(lbls[3] == lbl2block[lbls[2]].get_next())
        assert(lbls[4] == lbl2block[lbls[3]].get_next())
        assert(lbls[5] == lbl2block[lbls[4]].get_next())

    def test_DirectiveSplit(self):
        from miasm.arch.x86.arch import mn_x86
        from miasm.core.parse_asm import parse_txt
        loc_db = LocationDB()

        ASM0 = '''
        lbl0:
            JNZ   lbl0
        .split
        lbl1:
            RET
        '''

        asmcfg = parse_txt(mn_x86, 32, ASM0, loc_db)
        lbls = []
        for i in range(2):
            lbls.append(loc_db.get_name_location('lbl%d' % i))
        lbl2block = {}
        for block in asmcfg.blocks:
            lbl2block[block.loc_key] = block
        # split test
        assert(lbl2block[lbls[1]].get_next() is None)

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestParseAsm)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
