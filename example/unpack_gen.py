import os
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Win_x86_32

# Python auto completion
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Win_x86_32.parser()
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Win_x86_32(options.filename, options, globals())

# Run
sb.run()
