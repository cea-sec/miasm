#! /usr/bin/env python2
#-*- coding:utf-8 -*-
from __future__ import print_function
from argparse import ArgumentParser
from miasm.analysis import debugging
from miasm.jitter.csts import *
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB


parser = ArgumentParser(
    description="""Sandbox raw binary with mips32 engine
(ex: jit_mips32.py example/mips32_sc_l.bin 0)""")
parser.add_argument("-t", "--trace",
                    help="Log instructions/registers values",
                    action="store_true")
parser.add_argument("-n", "--log-newbloc",
                    help="Log basic blocks processed by the Jitter",
                    action="store_true")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine (default is 'gcc')",
                    default="gcc")
parser.add_argument("-d", "--debugging",
                    help="Attach a CLI debugguer to the sandboxed program",
                    action="store_true")
parser.add_argument("binary",
                    help="binary to run")
parser.add_argument("addr",
                    help="start exec on addr")

machine = Machine("mips32l")

def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

def jit_mips32_binary(args):
    loc_db = LocationDB()
    filepath, entryp = args.binary, int(args.addr, 0)
    myjit = machine.jitter(loc_db, jit_type = args.jitter)
    myjit.init_stack()

    # Log level (if available with jitter engine)
    myjit.set_trace_log(
        trace_instr=args.trace,
        trace_regs=args.trace,
        trace_new_blocks=args.log_newbloc
    )

    myjit.vm.add_memory_page(
        0,
        PAGE_READ | PAGE_WRITE,
        open(filepath, 'rb').read()
    )
    myjit.add_breakpoint(0x1337BEEF, code_sentinelle)


    # for stack
    myjit.vm.add_memory_page(0xF000, PAGE_READ | PAGE_WRITE, b"\x00"*0x1000)

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
