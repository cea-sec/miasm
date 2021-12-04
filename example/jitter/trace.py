"""
This example demonstrates two instrumentation possibility:
 - instrumentation executed at each instruction
 - instrumentation on jitter behavior (here, memory tracking)

Note: for better performance, one can also extend Codegen to produce
instrumentation at the C / LLVM level
"""
from __future__ import print_function

import os
import time
from pdb import pm
from miasm.analysis.sandbox import Sandbox_Linux_arml
from miasm.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm.jitter.jitcore_python import JitCore_Python
from miasm.core.locationdb import LocationDB

# Function called at each instruction
instr_count = 0
def instr_hook(jitter):
    global instr_count
    instr_count += 1
    return True

# Extension of the Python jitter to track memory accesses
class ESETrackMemory(EmulatedSymbExec):
    """Emulated symb exec with memory access tracking"""

    def mem_read(self, expr_mem):
        value = super(ESETrackMemory, self).mem_read(expr_mem)
        print("Read %s: %s" % (expr_mem, value))
        return value

    def mem_write(self, dest, data):
        print("Write %s: %s" % (dest, data))
        return super(ESETrackMemory, self).mem_write(dest, data)

# Parse arguments
parser = Sandbox_Linux_arml.parser(description="Tracer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Use our memory tracker
JitCore_Python.SymbExecClass = ESETrackMemory

# Create sandbox, forcing Python jitter
options.jitter = "python"
loc_db = LocationDB()
sb = Sandbox_Linux_arml(loc_db, options.filename, options, globals())

# Force jit one instr per call, and register our callback
sb.jitter.jit.set_options(jit_maxline=1, max_exec_per_call=1)
sb.jitter.exec_cb = instr_hook

# Run
start_time = time.time()
sb.run()
stop_time = time.time()

assert sb.jitter.running is False
print("Instr speed: %02.f / sec" % (instr_count / (stop_time - start_time)))
