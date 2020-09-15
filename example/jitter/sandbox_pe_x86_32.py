from pdb import pm
from miasm.analysis.sandbox import Sandbox_WinXP_x86_32
from miasm.core.locationdb import LocationDB
# Insert here user defined methods

# Parse arguments
parser = Sandbox_WinXP_x86_32.parser(description="PE sandboxer")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_WinXP_x86_32(loc_db, options, globals())

# Run
sb.run()

assert(sb.jitter.run is False)
