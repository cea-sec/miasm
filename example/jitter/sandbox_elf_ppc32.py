import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Linux_ppc32b
from miasm2.jitter.csts import *
from miasm2.jitter.jitload import log_func
import logging

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_ppc32b.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Linux_ppc32b(options.filename, options, globals())
log_func.setLevel(logging.ERROR)

sb.run()
