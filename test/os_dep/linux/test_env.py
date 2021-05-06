from __future__ import print_function
import os
import sys
from pdb import pm
from miasm.analysis.binary import Container
from miasm.analysis.sandbox import Sandbox_Linux_x86_32, Sandbox_Linux_x86_64,\
    Sandbox_Linux_arml, Sandbox_Linux_aarch64l
from miasm.core.locationdb import LocationDB

if len(sys.argv) < 2:
    print("Usage: %s <arch> ..." % sys.argv[0])
    exit(0)

arch = sys.argv[1]

if arch == "x86_32":
    sandbox = Sandbox_Linux_x86_32
elif arch == "x86_64":
    sandbox = Sandbox_Linux_x86_64
elif arch == "arml":
    sandbox = Sandbox_Linux_arml
elif arch == "aarch64l":
    sandbox = Sandbox_Linux_aarch64l
else:
    raise ValueError("Unsupported arch: %s" % arch)

# Parse arguments
parser = sandbox.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args(sys.argv[2:])

# Create sandbox
loc_db = LocationDB()
sb = sandbox(loc_db, options.filename, options, globals())

# Run
sb.run()

assert(sb.jitter.running is False)
