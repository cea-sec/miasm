#!/usr/bin/env python
#-*- coding:utf-8 -*-
from miasm2.analysis import debugging, gdbserver

from miasm2.analysis.sandbox import Sandbox_Linux_arml
from miasm2.jitter.jitload import vm_load_elf, libimp, preload_elf
from miasm2.analysis.machine import Machine
import logging

from pdb import pm

parser = Sandbox_Linux_arml.parser(description="""Sandbox an elf binary with arm engine
(ex: test_jit_arm.py example/md5_arm -a A684)""")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")

options = parser.parse_args()
sb = Sandbox_Linux_arml(options.filename, options, globals())


if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    sb.jitter.vm.dump_memory_page_pool()

if options.address is None:
    raise ValueError('invalid address')

sb.run()

