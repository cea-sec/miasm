import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Linux_aarch64l
from miasm2.jitter.jitload import log_func
import logging


# Python auto completion
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_aarch64l.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Linux_aarch64l(options.filename, options, globals())

log_func.setLevel(logging.ERROR)

# Run
sb.run()

assert(sb.jitter.run is False)
