#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.arch.ebc.arch import mn_ebc

for raw, asm in [
    ('65875080',             'MOVSNW R7, [R0-0x50]'),
    ('6507B0FF',             'MOVSNW R7, R0-0x50'),
    ('0c47',                 'ADD32 R7, R4'),
    ('4c47',                 'ADD64 R7, R4'),
    ('0006',                 'BREAK 6'),
    ('83109afdffff',         'CALL32 R0+0xFFFFFFFFFFFFFD9A'),
    ('0307',                 'CALL32A R7'),
    ('832f01000010',         'CALL32EXA [R7+0x4]'),
    ('4547',                 'CMP64EQ R7, R4'),
    ('0567',                 'CMP32EQ R7, R6'),
    ('2d072000',             'CMPI32WEQ R7, 0x20'),
    ('5c44',                 'EXTNDD64 R4, R4'),
    ('0203',                 'JMP8 0x3'),
    ('82e6',                 'JMP8CC 0xFFFFFFFFFFFFFFE6'),
    ('c250',                 'JMP8CS 0x50'),
    ('8110a2010000',         'JMP32 R0+0x1A2'),
    ('1dba',                 'MOVBW [R2], [R3]'),
    ('776838000100',         'MOVIDW [R0+0x38], 0x1'),
    ('b73700000100',         'MOVIQD R7, 0x10000'),
    ('f7370200000000000080', 'MOVIQQ R7, 0x8000000000000002'),
    ('77360000',             'MOVIQW R6, 0x0'),
    ('b2781000',             'MOVNW [R0+0x10], R7'),
    ('72871000',             'MOVNW R7, [R0+0x10]'),
    ('2472',                 'MOVQD R2, R7'),
    ('6400e0850080',         'MOVQD R0, R0-0x85E0'),
    ('60005080',             'MOVQW R0, R0-0x50'),
    ('b9374a020000',         'MOVRELD R7, 0x24A'),
    ('b904d00b0000',         'MOVRELD R4, 0xBD0'),
    ('65871000',             'MOVSNW R7, [R0+0x10]'),
    ('2544',                 'MOVSNW R4, R4'),
    ('1ff7',                 'MOVDW R7, [R7]'),
    ('1ec7',                 'MOVWW R7, [R4]'),
    ('7387f0850000',         'MOVND R7, [R0+0x85F0]'),
    ('ce670200',             'MUL64 R7, R6+0x2'),
    ('1547',                 'OR32 R7, R4'),
    ('0400',                 'RET'),
    ('97670400',             'SHL32 R7, R6+0x4'),
    ('1647',                 'XOR32 R7, R4'),
    ]:
    mode = 32
    d = mn_ebc.dis(raw.decode('hex'), mode)
    print raw.ljust(25), str(d).ljust(45),
    l = mn_ebc.fromstring(asm, mode)
    print str(l).ljust(45), [x.encode('hex') for x in mn_ebc.asm(l)]
    assert(str(d) == str(l))
    if  raw not in ['832f01000010']:
        assert(any(x.encode('hex').lower() == raw.lower() for x in mn_ebc.asm(l)))

