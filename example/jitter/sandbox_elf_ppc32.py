import os
from pdb import pm
from miasm.analysis.sandbox import Sandbox_Linux_ppc32b
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import *
from miasm.jitter.jitload import log_func
import logging

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_ppc32b.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Linux_ppc32b(loc_db, options.filename, options, globals())
log_func.setLevel(logging.ERROR)

sb.run()
