import logging
from pdb import pm
from miasm.analysis.sandbox import Sandbox_Linux_aarch64l
from miasm.core.locationdb import LocationDB
from miasm.jitter.jitload import log_func

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Linux_aarch64l.parser(description="ELF sandboxer")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Linux_aarch64l(loc_db, options, globals())

log_func.setLevel(logging.ERROR)

# Run
sb.run()

assert(sb.jitter.run is False)
