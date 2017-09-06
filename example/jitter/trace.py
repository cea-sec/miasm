"""
This example demonstrates two instrumentation possibility:
 - instrumentation executed at each instruction
 - instrumentation on jitter behavior (here, memory tracking)

Note: for better performance, one can also extend Codegen to produce
instrumentation at the C / LLVM level
"""
import os
import time
from pdb import pm
from miasm2.analysis.sandbox import Sandbox_Linux_arml
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm2.jitter.jitcore_python import JitCore_Python

# Function called at each instruction
instr_count = 0
def instr_hook(jitter):
    global instr_count
    instr_count += 1
    return True

# Extension of the Python jitter to track memory accesses
class ESETrackMemory(EmulatedSymbExec):
    """Emulated symb exec with memory access tracking"""

    def _func_read(self, expr_mem):
        value = super(ESETrackMemory, self)._func_read(expr_mem)
        print "Read %s: %s" % (expr_mem, value)
        return value

    def _func_write(self, symb_exec, dest, data):
        print "Write %s: %s" % (dest, data)
        return super(ESETrackMemory, self)._func_write(symb_exec, dest, data)

# Parse arguments
parser = Sandbox_Linux_arml.parser(description="Tracer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

# Use our memory tracker
JitCore_Python.SymbExecClass = ESETrackMemory

# Create sandbox, forcing Python jitter
options.jitter = "python"
sb = Sandbox_Linux_arml(options.filename, options, globals())

# Force jit one instr per call, and register our callback
sb.jitter.jit.set_options(jit_maxline=1, max_exec_per_call=1)

# Run
start_time = time.time()

sb.init_run()
sb.jitter.continue_run(callback=instr_hook)
stop_time = time.time()

assert sb.jitter.run is False
print "Instr speed: %02.f / sec" % (instr_count / (stop_time - start_time))
