#! /usr/bin/env python2
#-*- coding:utf-8 -*-
from __future__ import print_function
import logging
from pdb import pm

from miasm2.analysis.sandbox import Sandbox_Linux_arml

# Get arguments
parser = Sandbox_Linux_arml.parser(description="""Sandbox an elf binary with arm
 engine (ex: jit_arm.py samples/md5_arm -a A684)""")
parser.add_argument("filename", help="ELF Filename")
parser.add_argument('-v', "--verbose", help="verbose mode", action="store_true")
options = parser.parse_args()

# Prepare the sandbox
sb = Sandbox_Linux_arml(options.filename, options, globals())

# Handle 'verbose' option
if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print(sb.jitter.vm)

# Run the code
sb.run()
