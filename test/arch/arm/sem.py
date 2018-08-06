#! /usr/bin/env python2
#-*- coding:utf-8 -*-

import unittest
import logging

from miasm2.ir.symbexec import SymbolicExecutionEngine
from miasm2.arch.arm.arch import mn_arm as mn
from miasm2.arch.arm.sem import ir_arml as ir_arch
from miasm2.arch.arm.regs import *
from miasm2.expression.expression import *
from miasm2.core.locationdb import LocationDB
from pdb import pm

logging.getLogger('cpuhelper').setLevel(logging.ERROR)
EXCLUDE_REGS = set([ir_arch().IRDst])


def M(addr):
    return ExprMem(ExprInt(addr, 16), 16)


def compute(asm, inputstate={}, debug=False):
    loc_db = LocationDB()
    sympool = dict(regs_init)
    sympool.update({k: ExprInt(v, k.size) for k, v in inputstate.iteritems()})
    ir_tmp = ir_arch(loc_db)
    ircfg = ir_tmp.new_ircfg()
    symexec = SymbolicExecutionEngine(ir_tmp, sympool)
    instr = mn.fromstring(asm, loc_db, "l")
    code = mn.asm(instr)[0]
    instr = mn.dis(code, "l")
    instr.offset = inputstate.get(PC, 0)
    lbl = ir_tmp.add_instr_to_ircfg(instr, ircfg)
    symexec.run_at(ircfg, lbl)
    if debug:
        for k, v in symexec.symbols.items():
            if regs_init.get(k, None) != v:
                print k, v
    out = {}
    for k, v in symexec.symbols.items():
        if k in EXCLUDE_REGS:
            continue
        elif regs_init.get(k, None) == v:
            continue
        elif isinstance(v, ExprInt):
            out[k] = long(v)
        else:
            out[k] = v
    return out

class TestARMSemantic(unittest.TestCase):

    # def test_condition(self):
    # §A8.3:                   Conditional execution
    #    pass

    def test_shift(self):
        # §A8.4:                   Shifts applied to a register
        self.assertEqual(
            compute('MOV R4, R4       ', {R4: 0xDEADBEEFL, }), {R4: 0xDEADBEEFL, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 LSL  0')
        self.assertEqual(
            compute('MOV R4, R4 LSL  1', {R4: 0xDEADBEEFL, }), {R4: 0xBD5B7DDEL, })
        self.assertEqual(
            compute('MOV R4, R4 LSL 16', {R4: 0xDEADBEEFL, }), {R4: 0xBEEF0000L, })
        self.assertEqual(
            compute('MOV R4, R4 LSL 31', {R4: 0xDEADBEEFL, }), {R4: 0x80000000L, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 LSL 32')
        self.assertEqual(
            compute('MOV R4, R4 LSL R5', {R4: 0xDEADBEEFL, R5: 0xBADBAD01L, }), {R4: 0xBD5B7DDEL, R5: 0xBADBAD01L, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 LSR  0')
        self.assertEqual(
            compute('MOV R4, R4 LSR  1', {R4: 0xDEADBEEFL, }), {R4: 0x6F56DF77L, })
        self.assertEqual(
            compute('MOV R4, R4 LSR 16', {R4: 0xDEADBEEFL, }), {R4: 0x0000DEADL, })
        self.assertEqual(
            compute('MOV R4, R4 LSR 31', {R4: 0xDEADBEEFL, }), {R4: 0x00000001L, })
        self.assertEqual(
            compute('MOV R4, R4 LSR 32', {R4: 0xDEADBEEFL, }), {R4: 0xDEADBEEFL, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 LSR 33')
        self.assertEqual(
            compute('MOV R4, R4 LSR R5', {R4: 0xDEADBEEFL, R5: 0xBADBAD01L, }), {R4: 0x6F56DF77L, R5: 0xBADBAD01L, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 ASR  0')
        self.assertEqual(
            compute('MOV R4, R4 ASR  1', {R4: 0xDEADBEEFL, }), {R4: 0xEF56DF77L, })
        self.assertEqual(
            compute('MOV R4, R4 ASR 16', {R4: 0xDEADBEEFL, }), {R4: 0xFFFFDEADL, })
        self.assertEqual(
            compute('MOV R4, R4 ASR 31', {R4: 0xDEADBEEFL, }), {R4: 0xFFFFFFFFL, })
        self.assertEqual(
            compute('MOV R4, R4 ASR 32', {R4: 0xDEADBEEFL, }), {R4: 0xDEADBEEFL, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 ASR 33')
        self.assertEqual(
            compute('MOV R4, R4 ASR R5', {R4: 0xDEADBEEFL, R5: 0xBADBAD01L, }), {R4: 0xEF56DF77L, R5: 0xBADBAD01L, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 ROR  0')
        self.assertEqual(
            compute('MOV R4, R4 ROR  1', {R4: 0xDEADBEEFL, }), {R4: 0xEF56DF77L, })
        self.assertEqual(
            compute('MOV R4, R4 ROR 16', {R4: 0xDEADBEEFL, }), {R4: 0xBEEFDEADL, })
        self.assertEqual(
            compute('MOV R4, R4 ROR 31', {R4: 0xDEADBEEFL, }), {R4: 0xBD5B7DDFL, })
        self.assertRaises(ValueError, compute, 'MOV R4, R4 ROR 32')
        self.assertEqual(
            compute('MOV R4, R4 ROR R5', {R4: 0xDEADBEEFL, R5: 0xBADBAD01L, }), {R4: 0xEF56DF77L, R5: 0xBADBAD01L, })
        self.assertEqual(compute('MOV R4, R4 RRX   ', {cf: 0L, R4: 0xDEADBEEFL, }), {
                         cf: 0L, R4: 0x6F56DF77L, })
        self.assertEqual(compute('MOV R4, R4 RRX   ', {cf: 1L, R4: 0xDEADBEEFL, }), {
                         cf: 1L, R4: 0xEF56DF77L, })

    def test_ADC(self):
        # §A8.8.1:                 ADC{S}{<c>}{<q>} {<Rd>,} <Rn>, #<const>
        self.assertRaises(
            ValueError, compute, 'ADC          R4,   0x00000001 ')
        self.assertEqual(compute('ADC                R4,    R4,   0x00000001 ',   {
                                 cf: 0L, R4: 0x00000000L, }), {cf: 0L,     R4: 0x00000001L, })
        self.assertEqual(compute('ADC                R4,    R4,   0x00000000 ',   {
                                 cf: 1L, R4: 0x00000000L, }), {cf: 1L,     R4: 0x00000001L, })
        self.assertEqual(compute('ADC                PC,    R4,   0x00000001 ',   {
                                 cf: 0L, R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {cf: 0L,     R4: 0xFFFFFFFFL, PC: 0x00000000L, })
        self.assertEqual(compute('ADC                PC,    R4,   0x00000000 ',   {
                                 cf: 1L, R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {cf: 1L,     R4: 0xFFFFFFFFL, PC: 0x00000000L, })
        self.assertEqual(compute('ADCS               R4,    R4,   0x80000000 ',   {cf: 0L, R4: 0x80000000L, }), {
                         nf: 0L, zf: 1L, cf: 1L, of: 1L, R4: 0x00000000L, })
        self.assertEqual(compute('ADCS               R4,    R4,   0xFF000000 ',   {cf: 1L, R4: 0x00FFFFFEL, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xFFFFFFFFL, })
        self.assertEqual(compute('ADCS               PC,    R4,   0x00000000 ',   {
                                 cf: 0L, R4: 0x00000000L, PC: 0x55555555L, }), {cf: 0L,     R4: 0x00000000L, PC: 0x00000000L, })
        self.assertEqual(compute('ADCS               PC,    R4,   0xFF000000 ',   {
                                 cf: 1L, R4: 0x01000000L, PC: 0x55555555L, }), {cf: 1L,     R4: 0x01000000L, PC: 0x00000001L, })

        # §A8.8.2:                 ADC{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm> {,<shift>}
        self.assertRaises(
            ValueError, compute, 'ADC          R4,   R5          ')
        self.assertEqual(compute('ADC                R4,    R4,   R5          ',  {
                                 cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000000L, }), {cf: 1L,     R4: 0x00000000L, R5: 0x00000000L, })
        self.assertEqual(compute('ADC                R4,    R4,   R5    LSL 1 ',  {
                                 cf: 0L, R4: 0x00000001L, R5: 0x00000008L, }), {cf: 0L,     R4: 0x00000011L, R5: 0x00000008L, })
        self.assertEqual(compute('ADC                R4,    R4,   R5    LSR 2 ',  {
                                 cf: 1L, R4: 0x00000000L, R5: 0x80000041L, }), {cf: 1L,     R4: 0x20000011L, R5: 0x80000041L, })
        self.assertEqual(compute('ADC                R4,    R4,   R5    ASR 3 ',  {
                                 cf: 0L, R4: 0x00000001L, R5: 0x80000081L, }), {cf: 0L,     R4: 0xF0000011L, R5: 0x80000081L, })
        self.assertEqual(compute('ADC                R4,    R4,   R5    ROR 4 ',  {
                                 cf: 1L, R4: 0xFFFFFFFFL, R5: 0x0000010FL, }), {cf: 1L,     R4: 0xF0000010L, R5: 0x0000010FL, })
        self.assertEqual(compute('ADC                R4,    R4,   R5    RRX   ',  {
                                 cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000101L, }), {cf: 1L,     R4: 0x80000080L, R5: 0x00000101L, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5          ',  {cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000000L, }), {
                         nf: 0L, zf: 1L, cf: 1L, of: 0L, R4: 0x00000000L, R5: 0x00000000L, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5    LSL 1 ',  {cf: 0L, R4: 0x00000001L, R5: 0x00000008L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000011L, R5: 0x00000008L, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5    LSR 2 ',  {cf: 1L, R4: 0x00000000L, R5: 0x80000041L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x20000011L, R5: 0x80000041L, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5    ASR 3 ',  {cf: 0L, R4: 0x00000001L, R5: 0x80000081L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xF0000011L, R5: 0x80000081L, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5    ROR 4 ',  {cf: 1L, R4: 0xFFFFFFFFL, R5: 0x0000010FL, }), {
                         nf: 1L, zf: 0L, cf: 1L, of: 0L, R4: 0xF0000010L, R5: 0x0000010FL, })
        self.assertEqual(compute('ADCS               R4,    R4,   R5    RRX   ',  {cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000101L, }), {
                         nf: 1L, zf: 0L, cf: 1L, of: 0L, R4: 0x80000080L, R5: 0x00000101L, })

        # §A8.8.3:                 ADC{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm>, <type> <Rs>
        self.assertEqual(compute('ADC                R4,    R6,   R4    LSL R5',  {
                                 cf: 0L, R4: 0x00000001L, R5: 0x00000004L, R6: 0L, }), {cf: 0L,     R4: 0x00000010L, R5: 0x00000004L, R6: 0L, })
        self.assertEqual(compute('ADC                R4,    R6,   R4    LSR R5',  {
                                 cf: 1L, R4: 0x00000110L, R5: 0x80000004L, R6: 0L, }), {cf: 1L,     R4: 0x00000012L, R5: 0x80000004L, R6: 0L, })
        self.assertEqual(compute('ADC                R4,    R6,   R4    ASR R5',  {
                                 cf: 0L, R4: 0x80000010L, R5: 0xF0000001L, R6: 0L, }), {cf: 0L,     R4: 0xC0000008L, R5: 0xF0000001L, R6: 0L, })
        self.assertEqual(compute('ADC                R4,    R6,   R4    ROR R5',  {
                                 cf: 1L, R4: 0x000000FFL, R5: 0x00000F04L, R6: 0L, }), {cf: 1L,     R4: 0xF0000010L, R5: 0x00000F04L, R6: 0L, })
        self.assertEqual(compute('ADCS               R4,    R6,   R4    LSL R5',  {cf: 0L, R4: 0x00000001L, R5: 0x00000004L, R6: 0L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000010L, R5: 0x00000004L, R6: 0L, })
        self.assertEqual(compute('ADCS               R4,    R6,   R4    LSR R5',  {cf: 1L, R4: 0x00000110L, R5: 0x80000004L, R6: 0L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000012L, R5: 0x80000004L, R6: 0L, })
        self.assertEqual(compute('ADCS               R4,    R6,   R4    ASR R5',  {cf: 0L, R4: 0x80000010L, R5: 0xF0000001L, R6: 0L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xC0000008L, R5: 0xF0000001L, R6: 0L, })
        self.assertEqual(compute('ADCS               R4,    R6,   R4    ROR R5',  {cf: 1L, R4: 0x000000FFL, R5: 0x00000F04L, R6: 0L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xF0000010L, R5: 0x00000F04L, R6: 0L, })

    def test_ADD(self):
        # §A8.8.{5,9}:             ADD{S}{<c>}{<q>} {<Rd>,} <Rn>, #<const>
        self.assertRaises(
            ValueError, compute, 'ADD          R4,   0x00000001L ')
        self.assertEqual(compute('ADD                R4,    R4,   0x00000001 ',   {
                                 R4: 0x00000000L, }), {R4: 0x00000001L, })
        self.assertEqual(compute('ADD                R4,    R4,   0x00000000 ',   {
                                 R4: 0x00000000L, }), {R4: 0x00000000L, })
        self.assertEqual(compute('ADD                PC,    R4,   0x00000001 ',   {
                                 R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {R4: 0xFFFFFFFFL, PC: 0x00000000L, })
        self.assertEqual(compute('ADD                PC,    R4,   0x00000000 ',   {
                                 R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {R4: 0xFFFFFFFFL, PC: 0xFFFFFFFFL, })
        self.assertEqual(compute('ADDS               R4,    R4,   0x80000000 ',   {R4: 0x80000000L, }), {
                         nf: 0L, zf: 1L, cf: 1L, of: 1L, R4: 0x00000000L, })
        self.assertEqual(compute('ADDS               R4,    R4,   0xFF000000 ',   {R4: 0x00FFFFFEL, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xFFFFFFFEL, })
        self.assertEqual(compute('ADDS               PC,    R4,   0x00000000 ',   {
                                 R4: 0x00000000L, PC: 0x55555555L, }), {R4: 0x00000000L, PC: 0x00000000L, })
        self.assertEqual(compute('ADDS               PC,    R4,   0xFF000000 ',   {
                                 R4: 0x01000000L, PC: 0x55555555L, }), {R4: 0x01000000L, PC: 0x00000000L, })
        # SP special part
        self.assertEqual(compute('ADD                R4,    SP,   0x00000001 ',   {
                                 R4: 0x00000000L, SP: 0x00000000L, }), {R4: 0x00000001L, SP: 0x00000000L, })

        # §A8.8.{7,11}:            ADD{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm> {,<shift>}
        self.assertRaises(
            ValueError, compute, 'ADD          R4,   R5          ')
        self.assertEqual(compute('ADD                R4,    R4,   R5          ',  {
                                 R4: 0xFFFFFFFFL, R5: 0x00000001L, }), {R4: 0x00000000L, R5: 0x00000001L, })
        self.assertEqual(compute('ADD                R4,    R4,   R5    LSL 1 ',  {
                                 R4: 0x00000001L, R5: 0x00000008L, }), {R4: 0x00000011L, R5: 0x00000008L, })
        self.assertEqual(compute('ADD                R4,    R4,   R5    LSR 2 ',  {
                                 R4: 0x00000000L, R5: 0x80000041L, }), {R4: 0x20000010L, R5: 0x80000041L, })
        self.assertEqual(compute('ADD                R4,    R4,   R5    ASR 3 ',  {
                                 R4: 0x00000001L, R5: 0x80000081L, }), {R4: 0xF0000011L, R5: 0x80000081L, })
        self.assertEqual(compute('ADD                R4,    R4,   R5    ROR 4 ',  {
                                 R4: 0xFFFFFFFFL, R5: 0x0000010FL, }), {R4: 0xF000000FL, R5: 0x0000010FL, })
        self.assertEqual(compute('ADD                R4,    R4,   R5    RRX   ',  {
                                 cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000101L, }), {cf: 1L,     R4: 0x8000007FL, R5: 0x00000101L, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5          ',  {R4: 0xFFFFFFFFL, R5: 0x00000001L, }), {
                         nf: 0L, zf: 1L, cf: 1L, of: 0L, R4: 0x00000000L, R5: 0x00000001L, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5    LSL 1 ',  {R4: 0x00000001L, R5: 0x00000008L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000011L, R5: 0x00000008L, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5    LSR 2 ',  {R4: 0x00000000L, R5: 0x80000041L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x20000010L, R5: 0x80000041L, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5    ASR 3 ',  {R4: 0x00000001L, R5: 0x80000081L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xF0000011L, R5: 0x80000081L, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5    ROR 4 ',  {R4: 0xFFFFFFFFL, R5: 0x0000010FL, }), {
                         nf: 1L, zf: 0L, cf: 1L, of: 0L, R4: 0xF000000FL, R5: 0x0000010FL, })
        self.assertEqual(compute('ADDS               R4,    R4,   R5    RRX   ',  {cf: 1L, R4: 0xFFFFFFFFL, R5: 0x00000101L, }), {
                         nf: 1L, zf: 0L, cf: 1L, of: 0L, R4: 0x8000007FL, R5: 0x00000101L, })
        # SP special part
        self.assertEqual(compute('ADD                R4,    SP,   R4    LSR 1 ',  {
                                 R4: 0x00000002L, SP: 0x00000000L, }), {R4: 0x00000001L, SP: 0x00000000L, })

        # §A8.8.8:                 ADD{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm>, <type> <Rs>
        self.assertEqual(compute('ADD                R4,    R6,   R4    LSL R5',  {
                                 R4: 0x00000001L, R5: 0x00000004L, R6: 0L, }), {R4: 0x00000010L, R5: 0x00000004L, R6: 0L, })
        self.assertEqual(compute('ADD                R4,    R6,   R4    LSR R5',  {
                                 R4: 0x00000110L, R5: 0x80000004L, R6: 0L, }), {R4: 0x00000011L, R5: 0x80000004L, R6: 0L, })
        self.assertEqual(compute('ADD                R4,    R6,   R4    ASR R5',  {
                                 R4: 0x80000010L, R5: 0xF0000001L, R6: 0L, }), {R4: 0xC0000008L, R5: 0xF0000001L, R6: 0L, })
        self.assertEqual(compute('ADD                R4,    R6,   R4    ROR R5',  {
                                 R4: 0x000000FFL, R5: 0x00000F04L, R6: 0L, }), {R4: 0xF000000FL, R5: 0x00000F04L, R6: 0L, })
        self.assertEqual(compute('ADDS               R4,    R6,   R4    LSL R5',  {R4: 0x00000001L, R5: 0x00000004L, R6: 0L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000010L, R5: 0x00000004L, R6: 0L, })
        self.assertEqual(compute('ADDS               R4,    R6,   R4    LSR R5',  {R4: 0x00000110L, R5: 0x80000004L, R6: 0L, }), {
                         nf: 0L, zf: 0L, cf: 0L, of: 0L, R4: 0x00000011L, R5: 0x80000004L, R6: 0L, })
        self.assertEqual(compute('ADDS               R4,    R6,   R4    ASR R5',  {R4: 0x80000010L, R5: 0xF0000001L, R6: 0L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xC0000008L, R5: 0xF0000001L, R6: 0L, })
        self.assertEqual(compute('ADDS               R4,    R6,   R4    ROR R5',  {R4: 0x000000FFL, R5: 0x00000F04L, R6: 0L, }), {
                         nf: 1L, zf: 0L, cf: 0L, of: 0L, R4: 0xF000000FL, R5: 0x00000F04L, R6: 0L, })


        # Test against qemu
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x1L}),
                         { nf: 0L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000001L, R3: 0x00000002L})
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x7FFFFFFFL}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 1L, R2: 0x00000001L, R3: 0x80000000L})
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0x80000000L, R3: 0x80000000L}),
                         { nf: 0L, zf: 1L, cf: 1L, of: 1L, R2: 0x80000000L, R3: 0x00000000L})
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0x7FFFFFFFL, R3:0x7FFFFFFFL}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 1L, R2: 0x7FFFFFFFL, R3:0xFFFFFFFEL})
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0L, R3:0}),
                         { nf: 0L, zf: 1L, cf: 0L, of: 0L, R2: 0L, R3:0})
        self.assertEqual(compute('ADDS               R3,    R2,   R3 ', {R2: 0xFFFFFFFFL, R3:0xFFFFFFFFL}),
                         { nf: 1L, zf: 0L, cf: 1L, of: 0L, R2: 0xFFFFFFFFL, R3:0xFFFFFFFEL})





    def test_ADR(self):
        # §A8.8.12:                ADR{<c>}{<q>} <Rd>, <label>    <==>    ADD{<c>}{<q>} <Rd>, PC, #<const>
        pass

    def test_AND(self):
        # §A8.8.13:                AND{S}{<c>}{<q>} {<Rd>,} <Rn>, #<const>
        self.assertRaises(
            ValueError, compute, 'AND          R4,   0x00000001 ')
        self.assertEqual(compute('AND                R4,    R4,   0x00000001 ',   {R4: 0xDEADBEEFL, }), {R4: 0x00000001L, })
        self.assertEqual(compute('AND                R4,    R4,   0x00000000 ',   {R4: 0x00000000L, }), {R4: 0x00000000L, })
        self.assertEqual(compute('AND                PC,    R4,   0x00000001 ',   {R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {R4: 0xFFFFFFFFL, PC: 0x00000001L, })
        self.assertEqual(compute('AND                PC,    R4,   0x00000000 ',   {R4: 0xFFFFFFFFL, PC: 0x55555555L, }), {R4: 0xFFFFFFFFL, PC: 0x00000000L, })

        # §A8.8.14:                AND{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm> {,<shift>}
        self.assertRaises(
            ValueError, compute, 'AND          R4,   R5          ')
        self.assertEqual(compute('AND                R4,    R4,   R5          ',  {R4: 0xFFFFFFFEL, R5: 0x00000001L, }), {R4: 0x00000000L, R5: 0x00000001L, })
        self.assertEqual(compute('AND                R4,    R4,   R5    LSL 1 ',  {R4: 0x00000011L, R5: 0x00000008L, }), {R4: 0x00000010L, R5: 0x00000008L, })
        self.assertEqual(compute('AND                R4,    R4,   R5    LSR 2 ',  {R4: 0xFFFFFFFFL, R5: 0x80000041L, }), {R4: 0x20000010L, R5: 0x80000041L, })
        self.assertEqual(compute('AND                R4,    R4,   R5    ASR 3 ',  {R4: 0xF00000FFL, R5: 0x80000081L, }), {R4: 0xF0000010L, R5: 0x80000081L, })
        self.assertEqual(compute('AND                R4,    R4,   R5    ROR 4 ',  {R4: 0xFFFFFFFFL, R5: 0x000000FFL, }), {R4: 0xF000000FL, R5: 0x000000FFL, })
        self.assertEqual(compute('AND                R4,    R4,   R5    RRX   ',  {R4: 0xFFFFFFFFL, R5: 0x00000101L, }), {R4: ExprCompose(ExprInt(0x80L, 31), cf_init), R5: 0x00000101L, })

        # §A8.8.15:                AND{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm>, <type> <Rs>
        self.assertEqual(compute('AND                R4,    R6,   R4    LSL R5',  {R4: 0x00000001L, R5: 0x00000004L, R6: -1, }), {R4: 0x00000010L, R5: 0x00000004L, R6: 0xFFFFFFFFL, })
        self.assertEqual(compute('AND                R4,    R6,   R4    LSR R5',  {R4: 0x00000110L, R5: 0x80000004L, R6: -1, }), {R4: 0x00000011L, R5: 0x80000004L, R6: 0xFFFFFFFFL, })
        self.assertEqual(compute('AND                R4,    R6,   R4    ASR R5',  {R4: 0x80000010L, R5: 0xF0000001L, R6: -1, }), {R4: 0xC0000008L, R5: 0xF0000001L, R6: 0xFFFFFFFFL, })
        self.assertEqual(compute('AND                R4,    R6,   R4    ROR R5',  {R4: 0x000000FFL, R5: 0x00000F04L, R6: -1, }), {R4: 0xF000000FL, R5: 0x00000F04L, R6: 0xFFFFFFFFL, })

    def test_ASR(self):
        # §A8.8.16:                ASR{S}{<c>}{<q>} {<Rd>,} <Rm>, #<imm>    <==>    MOV{S}{<c>}{<q>} {<Rd>,} <Rm>, ASR #<n>
        pass

        # §A8.8.17:                ASR{S}{<c>}{<q>} {<Rd>,} <Rn>, <Rm>      <==>    MOV{S}{<c>}{<q>} {<Rd>,} <Rn>, ASR <Rm>
        pass

    def test_SUBS(self):
        # Test against qemu
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x2L, R3: 0x1L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x00000002L, R3: 0x1L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x2L}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000001L, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x0L, R3: 0xFFFFFFFFL}),
                         { nf: 0L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000000L, R3: 0x1L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0xFFFFFFFFL, R3: 0x0L}),
                         { nf: 1L, zf: 0L, cf: 1L, of: 0L, R2: 0xFFFFFFFFL, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x7FFFFFFFL}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000001L, R3: 0x80000002L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x7FFFFFFFL, R3: 0x1L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x7FFFFFFFL, R3: 0x7FFFFFFEL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x80000000L, R3: 0x80000001L}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x80000000L, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x80000001L, R3: 0x80000000L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x80000001L, R3: 0x1L})

    def test_CMP(self):
        # Test against qemu
        self.assertEqual(compute('CMP                R0,    R1 ', {R0: 0x11223344L, R1: 0x88223344L}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 1L, R0: 0x11223344L, R1: 0x88223344L})

        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x2L, R3: 0x1L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x00000002L, R3: 0x1L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x2L}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000001L, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x0L, R3: 0xFFFFFFFFL}),
                         { nf: 0L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000000L, R3: 0x1L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0xFFFFFFFFL, R3: 0x0L}),
                         { nf: 1L, zf: 0L, cf: 1L, of: 0L, R2: 0xFFFFFFFFL, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x1L, R3: 0x7FFFFFFFL}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x00000001L, R3: 0x80000002L})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x7FFFFFFFL, R3: 0x1L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x7FFFFFFFL, R3: 0x7FFFFFFEL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x80000000L, R3: 0x80000001L}),
                         { nf: 1L, zf: 0L, cf: 0L, of: 0L, R2: 0x80000000L, R3: 0xFFFFFFFFL})
        self.assertEqual(compute('SUBS               R3,    R2,   R3 ', {R2: 0x80000001L, R3: 0x80000000L}),
                         { nf: 0L, zf: 0L, cf: 1L, of: 0L, R2: 0x80000001L, R3: 0x1L})



    def test_ADDS(self):
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {R2: 0x3L, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {R2: 0x3L, R3: 0x2L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {R2: 0xffffffffL, R3: 0xffffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {R2: 0xffffffffL, R3: 0x0L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {R2: 0x80000000L, R3: 0x7fffffffL, of: 0x1L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {R2: 0x80000000L, R3: 0x1L, of: 0x1L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {R2: 0x1L, R3: 0x80000001L, of: 0x1L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('ADDS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {R2: 0x1L, R3: 0x80000000L, of: 0x1L, zf: 0x0L, cf: 0x1L, nf: 0x0L})

    def test_ANDS(self):
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0xffffffffL})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x0L})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x1L, R3: 0x80000001L})
        self.assertEqual(compute('ANDS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x1L, R3: 0x80000000L})

    def test_BICS(self):
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x0L, R2: 0x2L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0xffffffffL})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0x0L})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7ffffffeL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x80000001L})
        self.assertEqual(compute('BICS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x80000000L})

    def test_CMN(self):
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x2L, R3: 0x1L}), {R2: 0x2L, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x1L, R3: 0x2L}), {R2: 0x1L, R3: 0x2L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {R2: 0x0L, R3: 0xffffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {R2: 0xffffffffL, R3: 0x0L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {R2: 0x1L, R3: 0x7fffffffL, of: 0x1L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {R2: 0x7fffffffL, R3: 0x1L, of: 0x1L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {R2: 0x80000000L, R3: 0x80000001L, of: 0x1L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('CMN   R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {R2: 0x80000001L, R3: 0x80000000L, of: 0x1L, zf: 0x0L, cf: 0x1L, nf: 0x0L})

    def test_CMP(self):
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x2L, R3: 0x1L}), {R2: 0x2L, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x1L, R3: 0x2L}), {R2: 0x1L, R3: 0x2L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {R2: 0x0L, R3: 0xffffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {R2: 0xffffffffL, R3: 0x0L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x1L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {R2: 0x1L, R3: 0x7fffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {R2: 0x7fffffffL, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {R2: 0x80000000L, R3: 0x80000001L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('CMP   R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {R2: 0x80000001L, R3: 0x80000000L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})

    def test_EORS(self):
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x0L, R2: 0x3L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x0L, R2: 0x3L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0xffffffffL})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0x0L})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x7ffffffeL, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7ffffffeL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x80000001L})
        self.assertEqual(compute('EORS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x80000000L})

    def test_MULS(self):
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x0L, R2: 0x2L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x0L, R2: 0x2L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0xffffffffL})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0x0L})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x1L, R3: 0x80000001L})
        self.assertEqual(compute('MULS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x1L, R3: 0x80000000L})

    def test_ORRS(self):
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x0L, R2: 0x3L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x0L, R2: 0x3L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0xffffffffL})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0x0L})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x80000001L, nf: 0x1L, R3: 0x80000001L})
        self.assertEqual(compute('ORRS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x80000001L, nf: 0x1L, R3: 0x80000000L})

    def test_RSBS(self):
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {R2: 0xffffffffL, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {R2: 0x1L, R3: 0x2L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {R2: 0xffffffffL, R3: 0xffffffffL, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x1L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {R2: 0x1L, R3: 0x0L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {R2: 0x7ffffffeL, R3: 0x7fffffffL, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {R2: 0x80000002L, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {R2: 0x1L, R3: 0x80000001L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('RSBS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {R2: 0xffffffffL, R3: 0x80000000L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})

    def test_SUBS(self):
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x2L, R3: 0x1L}), {R2: 0x1L, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x1L, R3: 0x2L}), {R2: 0xffffffffL, R3: 0x2L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {R2: 0x1L, R3: 0xffffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x0L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {R2: 0xffffffffL, R3: 0x0L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x1L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {R2: 0x80000002L, R3: 0x7fffffffL, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {R2: 0x7ffffffeL, R3: 0x1L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {R2: 0xffffffffL, R3: 0x80000001L, of: 0x0L, zf: 0x0L, cf: 0x0L, nf: 0x1L})
        self.assertEqual(compute('SUBS   R2, R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {R2: 0x1L, R3: 0x80000000L, of: 0x0L, zf: 0x0L, cf: 0x1L, nf: 0x0L})

    def test_TEQ(self):
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x0L, R2: 0x2L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x0L, R2: 0x0L, nf: 0x1L, R3: 0xffffffffL})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x0L, R2: 0xffffffffL, nf: 0x1L, R3: 0x0L})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x0L, R3: 0x80000001L})
        self.assertEqual(compute('TEQ   R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x80000001L, nf: 0x0L, R3: 0x80000000L})

    def test_TST(self):
        self.assertEqual(compute('TST   R2, R3', {R2: 0x2L, R3: 0x1L}), {zf: 0x1L, R2: 0x2L, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x1L, R3: 0x2L}), {zf: 0x1L, R2: 0x1L, nf: 0x0L, R3: 0x2L})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x0L, R3: 0xffffffffL}), {zf: 0x1L, R2: 0x0L, nf: 0x0L, R3: 0xffffffffL})
        self.assertEqual(compute('TST   R2, R3', {R2: 0xffffffffL, R3: 0x0L}), {zf: 0x1L, R2: 0xffffffffL, nf: 0x0L, R3: 0x0L})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x1L, R3: 0x7fffffffL}), {zf: 0x0L, R2: 0x1L, nf: 0x0L, R3: 0x7fffffffL})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x7fffffffL, R3: 0x1L}), {zf: 0x0L, R2: 0x7fffffffL, nf: 0x0L, R3: 0x1L})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x80000000L, R3: 0x80000001L}), {zf: 0x0L, R2: 0x80000000L, nf: 0x1L, R3: 0x80000001L})
        self.assertEqual(compute('TST   R2, R3', {R2: 0x80000001L, R3: 0x80000000L}), {zf: 0x0L, R2: 0x80000001L, nf: 0x1L, R3: 0x80000000L})

    def test_UMUL(self):
        self.assertEqual(compute('UMULL R1, R2, R4, R5', {R4: 0x0L, R5: 0x0L}), {R1: 0x0L, R2: 0x0L, R4: 0x0L, R5: 0x0L})
        self.assertEqual(compute('UMULL R0, R1, R2, R3', {R2: 0x1L, R3: 0x80808080L}), {R0: 0x80808080L, R1: 0x0L, R2: 0x1L, R3: 0x80808080L})
        self.assertEqual(compute('UMULL R2, R3, R4, R5', {R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d78L, R3: 0x09a0cd05L, R4: 0x12345678L, R5: 0x87654321L})
        self.assertEqual(compute('UMULL R2, R3, R4, R5', {R4: 0xffffffffL, R5: 0x00000002L}), {R2: 0xfffffffeL, R3: 0x00000001L, R4: 0xffffffffL, R5: 0x00000002L})

    def test_UMLAL(self):
        self.assertEqual(compute('UMLAL R1, R2, R4, R5', {R1: 0x0L, R2: 0x0L, R4: 0x1L, R5: 0x0L}), {R1: 0x0L, R2: 0x0L, R4: 0x1L, R5: 0x0L})
        self.assertEqual(compute('UMLAL R0, R1, R2, R3', {R0: 0x0L, R1: 0x0L, R2: 0x1L, R3: 0x80808080L}), {R0: 0x80808080L, R1: 0x0L, R2: 0x1L, R3: 0x80808080L})
        self.assertEqual(compute('UMLAL R2, R3, R4, R5', {R2: 0xffffffffL, R3: 0x0L, R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d77L, R3: 0x09a0cd06L, R4: 0x12345678L, R5: 0x87654321L})
        self.assertEqual(compute('UMLAL R2, R3, R4, R5', {R2: 0xffffffffL, R3: 0x2L, R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d77L, R3: 0x09a0cd08L, R4: 0x12345678L, R5: 0x87654321L})

    def test_SMUL(self):
        self.assertEqual(compute('SMULL R1, R2, R4, R5', {R4: 0x0L, R5: 0x0L}), {R1: 0x0L, R2: 0x0L, R4: 0x0L, R5: 0x0L})
        self.assertEqual(compute('SMULL R0, R1, R2, R3', {R2: 0x1L, R3: 0x80808080L}), {R0: 0x80808080L, R1: 0xffffffffL, R2: 0x1L, R3: 0x80808080L})
        self.assertEqual(compute('SMULL R0, R1, R2, R3', {R2: 0xffff0000L, R3: 0xffff0000L}), {R0: 0x0L, R1: 0x1L, R2: 0xffff0000L, R3: 0xffff0000L})
        self.assertEqual(compute('SMULL R2, R3, R4, R5', {R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d78L, R3: 0xf76c768dL, R4: 0x12345678L, R5: 0x87654321L})
        self.assertEqual(compute('SMULL R2, R3, R4, R5', {R4: 0xffffffffL, R5: 0x00000002L}), {R2: 0xfffffffeL, R3: 0xffffffffL, R4: 0xffffffffL, R5: 0x00000002L})

    def test_SMLAL(self):
        self.assertEqual(compute('SMLAL R1, R2, R4, R5', {R1: 0x0L, R2: 0x0L, R4: 0x1L, R5: 0x0L}), {R1: 0x0L, R2: 0x0L, R4: 0x1L, R5: 0x0L})
        self.assertEqual(compute('SMLAL R0, R1, R2, R3', {R0: 0x0L, R1: 0x0L, R2: 0x1L, R3: 0x80808080L}), {R0: 0x80808080L, R1: 0xffffffffL, R2: 0x1L, R3: 0x80808080L})
        self.assertEqual(compute('SMLAL R2, R3, R4, R5', {R2: 0xffffffffL, R3: 0x0L, R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d77L, R3: 0xf76c768eL, R4: 0x12345678L, R5: 0x87654321L})
        self.assertEqual(compute('SMLAL R2, R3, R4, R5', {R2: 0xffffffffL, R3: 0x00000002L, R4: 0x12345678L, R5: 0x87654321L}), {R2: 0x70b88d77L, R3: 0xf76c7690L, R4: 0x12345678L, R5: 0x87654321L})

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestARMSemantic)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
