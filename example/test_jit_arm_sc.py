#!/usr/bin/env python
#-*- coding:utf-8 -*-
from miasm2.analysis import debugging, gdbserver

from miasm2.analysis.sandbox import Sandbox_Linux_armb_str
from miasm2.analysis.sandbox import Sandbox_Linux_arml_str
from miasm2.jitter.jitload import vm_load_elf, libimp, preload_elf
from miasm2.analysis.machine import Machine
from elfesteem.strpatchwork import StrPatchwork
import logging

from pdb import pm

parser = Sandbox_Linux_arml_str.parser(description="""Sandbox an elf binary with arm engine
(ex: test_jit_arm_sc.py example/demo_arm_l.bin)""")
parser.add_argument("filename", help="string Filename")
parser.add_argument("endianess", help="endianness [b/l]")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")

options = parser.parse_args()

if options.endianess == 'b':
    sandbox = Sandbox_Linux_armb_str
elif options.endianess == 'l':
    sandbox = Sandbox_Linux_arml_str
else:
    raise ValueError("Bad endianess!")

sb = sandbox(options.filename, options, globals())

if options.address is None:
    raise ValueError('invalid address')

sb.run()

# test correct de xor
start = sb.jitter.cpu.R0
stop = sb.jitter.cpu.R1
s = sb.jitter.vm.get_mem(start, stop-start)
s = StrPatchwork(s)
for i, c in enumerate(s):
    s[i] = chr(ord(c)^0x11)
s = str(s)
assert(s == "test string\x00")


