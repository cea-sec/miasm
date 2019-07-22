from pdb import pm
from miasm.analysis.sandbox import Sandbox_Win_x86_32

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

# Create sandbox
sb = Sandbox_Win_x86_32(options.filename, options, globals())

# Run
sb.run()

assert(sb.jitter.run is False)
