#! /usr/bin/env python2
#-*- coding:utf-8 -*-
from argparse import ArgumentParser
from miasm2.analysis import debugging
from miasm2.jitter.csts import *
from miasm2.analysis.machine import Machine

from pdb import pm

parser = ArgumentParser(
    description="""Sandbox raw binary with mips32 engine
(ex: jit_mips32.py example/mips32_sc_l.bin 0)""")
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
                    help="Jitter engine (default is 'gcc')",
                    default="gcc")
parser.add_argument("-d", "--debugging",
                    help="Attach a CLI debugguer to the sandboxed programm",
                    action="store_true")
parser.add_argument("binary",
                    help="binary to run")
parser.add_argument("addr",
                    help="start exec on addr")

machine = Machine("mips32l")

def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def jit_mips32_binary(args):
    filepath, entryp = args.binary, int(args.addr, 0)
    myjit = machine.jitter(jit_type = args.jitter)
    myjit.init_stack()

    # Log level (if available with jitter engine)
    myjit.jit.log_regs = args.log_regs
    myjit.jit.log_mn = args.log_mn
    myjit.jit.log_newbloc = args.log_newbloc

    myjit.vm.add_memory_page(0, PAGE_READ | PAGE_WRITE, open(filepath).read())
    myjit.add_breakpoint(0x1337BEEF, code_sentinelle)


    # for stack
    myjit.vm.add_memory_page(0xF000, PAGE_READ | PAGE_WRITE, "\x00"*0x1000)

    myjit.cpu.SP = 0xF800

    myjit.cpu.RA = 0x1337BEEF
    myjit.init_run(entryp)



    # Handle debugging
    if args.debugging is True:
        dbg = debugging.Debugguer(myjit)
        cmd = debugging.DebugCmd(dbg)
        cmd.cmdloop()

    else:
        print(myjit.continue_run())
    return myjit
if __name__ == '__main__':
    args = parser.parse_args()
    myjit = jit_mips32_binary(args)
