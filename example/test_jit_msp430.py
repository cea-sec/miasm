#!/usr/bin/env python
#-*- coding:utf-8 -*-
from argparse import ArgumentParser
from miasm2.analysis import debugging, gdbserver
from miasm2.jitter.csts import *

from miasm2.jitter.jitload import vm_load_elf, libimp, preload_elf
from miasm2.analysis.machine import Machine

parser = ArgumentParser(
    description="""Sandbox raw binary with msp430 engine
(ex: test_jit_msp430.py example/msp430_sc.bin 0)""")
parser.add_argument("-r", "--log-regs",
                    help="Log registers value for each instruction",
                    action="store_true")
parser.add_argument("-m", "--log-mn",
                    help="Log desassembly conversion for each instruction",
                    action="store_true")
parser.add_argument("-n", "--log-newbloc",
                    help="Log basic blocks processed by the Jitter",
                    action="store_true")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine. Possible values are : tcc (default), llvm",
                    default="tcc")
parser.add_argument("-d", "--debugging",
                    help="Attach a CLI debugguer to the sandboxed programm",
                    action="store_true")
parser.add_argument("binary",
                    help="binary to run")
parser.add_argument("addr",
                    help="start exec on addr")

machine = Machine("msp430")

def jit_msp430_binary(args):
    filepath, entryp = args.binary, int(args.addr, 16)
    myjit = machine.jitter(jit_type = args.jitter)
    myjit.init_stack()

    # Log level (if available with jitter engine)
    myjit.jit.log_regs = args.log_regs
    myjit.jit.log_mn = args.log_mn
    myjit.jit.log_newbloc = args.log_newbloc

    myjit.vm.add_memory_page(0, PAGE_READ | PAGE_WRITE, open(filepath).read())
    myjit.add_breakpoint(0x1337, lambda _: exit(0))


    # for stack
    myjit.vm.add_memory_page(0xF000, PAGE_READ | PAGE_WRITE, "\x00"*0x1000)

    myjit.cpu.SP = 0xF800

    myjit.push_uint16_t(0x1337)
    myjit.init_run(entryp)



    # Handle debugging
    if args.debugging is True:
        dbg = debugging.Debugguer(myjit)
        cmd = debugging.DebugCmd(dbg)
        cmd.cmdloop()

    else:
        print(myjit.continue_run())

if __name__ == '__main__':
    from sys import stderr
    args = parser.parse_args()
    jit_msp430_binary(args)
