import sys
import os
from optparse import OptionParser
from miasm2.arch.x86.arch import mn_x86
from miasm2.jitter.jitload import jitter_x86_32
from miasm2.jitter.jitload import bin_stream_vm
from miasm2.jitter.csts import *

from pdb import pm


filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

parser = OptionParser(usage="usage: %prog rawfiley arch address [options]")
(options, args) = parser.parse_args(sys.argv[1:])

if len(args) < 1:
    parser.print_help()
    sys.exit(0)


def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True


myjit = jitter_x86_32()
myjit.init_stack()

fname = args[0]
data = open(fname).read()
run_addr = 0x40000000
myjit.vm.vm_add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

myjit.jit.log_regs = True
myjit.jit.log_mn = True
myjit.vm_push_uint32_t(0x1337beef)

myjit.add_breakpoint(0x1337beef, code_sentinelle)

myjit.init_run(run_addr)
myjit.continue_run()
