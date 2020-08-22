#! /usr/bin/env python2
#-*- coding:utf-8 -*-
from miasm.core.utils import int_to_byte
from miasm.analysis.sandbox import Sandbox_Linux_armb_str
from miasm.analysis.sandbox import Sandbox_Linux_arml_str
from miasm.loader.strpatchwork import StrPatchwork
from miasm.core.locationdb import LocationDB

from pdb import pm

parser = Sandbox_Linux_arml_str.parser(description="""Sandbox an elf binary with arm engine
(ex: jit_arm_sc.py example/demo_arm_l.bin)""")
parser.add_argument("filename", help="string Filename")
parser.add_argument("endianness", help="endianness [b/l]")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")

options = parser.parse_args()

if options.endianness == 'b':
    sandbox = Sandbox_Linux_armb_str
elif options.endianness == 'l':
    sandbox = Sandbox_Linux_arml_str
else:
    raise ValueError("Bad endianness!")

loc_db = LocationDB()
sb = sandbox(loc_db, options.filename, options, globals())

if options.address is None:
    raise ValueError('invalid address')

sb.run()

# test correct de xor
start = sb.jitter.cpu.R0
stop = sb.jitter.cpu.R1
s = sb.jitter.vm.get_mem(start, stop-start)
s = StrPatchwork(s)
for i, c in enumerate(s):
    s[i] = int_to_byte(ord(c)^0x11)
s = bytes(s)
assert(s == b"test string\x00")


