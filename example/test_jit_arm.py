#!/usr/bin/env python
#-*- coding:utf-8 -*-
from argparse import ArgumentParser
from miasm2.analysis import debugging, gdbserver

from miasm2.jitter.jitload import vm_load_elf, libimp, preload_elf
from miasm2.analysis.machine import Machine

from pdb import pm

parser = ArgumentParser(
    description="""Sandbox an elf binary with arm engine
(ex: test_jit_arm.py example/md5_arm A684)""")
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

machine = Machine("arm")

def jit_arm_binary(args):
    filepath, entryp = args.binary, int(args.addr, 16)
    myjit = machine.jitter(jit_type = args.jitter)
    myjit.init_stack()

    # Log level (if available with jitter engine)
    myjit.jit.log_regs = args.log_regs
    myjit.jit.log_mn = args.log_mn
    myjit.jit.log_newbloc = args.log_newbloc

    elf = vm_load_elf(myjit.vm, filepath)
    libs = libimp()
    preload_elf(myjit.vm, elf, libs)
    myjit.add_lib_handler(libs)
    myjit.add_breakpoint(0x1337BEEF, lambda _: exit(0))
    regs = myjit.cpu.get_gpreg()
    regs['LR'] = 0x1337BEEF
    myjit.cpu.set_gpreg(regs)
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
    jit_arm_binary(args)
