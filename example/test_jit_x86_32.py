import sys
import os
from argparse import ArgumentParser
from miasm2.jitter.jitload import bin_stream_vm
from miasm2.jitter.csts import *
from miasm2.analysis.machine import Machine

from pdb import pm


filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)

parser = ArgumentParser(description="x86 32 basic Jitter")
parser.add_argument("filename", help="x86 32 shellcode filename")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine. Possible values are : tcc (default), llvm",
                    default="tcc")
args = parser.parse_args()

def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True


myjit = Machine("x86_32").jitter(args.jitter)
myjit.init_stack()

data = open(args.filename).read()
run_addr = 0x40000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

myjit.jit.log_regs = True
myjit.jit.log_mn = True
myjit.push_uint32_t(0x1337beef)

myjit.add_breakpoint(0x1337beef, code_sentinelle)

myjit.init_run(run_addr)
myjit.continue_run()
del(myjit)
