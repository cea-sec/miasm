# -*- coding: utf8 -*-

import os
import logging
from pdb import pm
from elfesteem import pe
from miasm2.analysis.sandbox import Sandbox_Win_x86_32


filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


# User defined methods

def kernel32_GetProcAddress(jitter):
    """Hook on GetProcAddress to note where UPX stores import pointers"""
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])

    # When the function is called, EBX is a pointer to the destination buffer
    dst_ad = jitter.cpu.EBX
    logging.info('EBX ' + hex(dst_ad))

    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else jitter.get_str_ansi(args.fname))
    logging.info(fname)

    # Get the generated address of the library, and store it in memory to
    # dst_ad
    ad = sb.libs.lib_get_add_func(args.libbase, fname, dst_ad)
    # Add a breakpoint in case of a call on the resolved function
    # NOTE: never happens in UPX, just for skeleton
    jitter.handle_function(ad)

    jitter.func_ret_stdcall(ret_ad, ad)

parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True
sb = Sandbox_Win_x86_32(options.filename, options, globals(),
                        parse_reloc=False)


if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print sb.jitter.vm

if options.graph is True:
    open("graph.dot", "w").write(ab.graph.dot())


if options.verbose is True:
    print sb.jitter.vm


#####################TAINT##########################

import miasm2.analysis.taint_analysis as taint

def add_some_taint(jitter):
    print "\n","_"*40,"Initializing Taint","_"*40,"\n"
    # jitter.cpu.taint_memory(0x401100,3)
    jitter.cpu.taint_register(0, jitter.jit.codegen.regs_index["RSP"])
    # taint.display_all_taint(jitter)
    # jitter.cpu.untaint_all(len(jitter.jit.codegen.regs_index))
    # jitter.cpu.untaint_all_registers(len(jitter.jit.codegen.regs_index))
    # jitter.cpu.untaint_all_memory()
    return True

def add_some_taint_2(jitter):
    print "_"*40,"Initializing Taint","_"*40
    jitter.cpu.taint_register(0, jitter.jit.codegen.regs_index["RSP"])
    jitter.cpu.taint_register(1, jitter.jit.codegen.regs_index["RAX"])
    jitter.jit.log_mn = True
    return True

def add_some_taint_3(jitter):
    print "_"*40,"Initializing Taint","_"*40
    jitter.cpu.taint_register(0, jitter.jit.codegen.regs_index["RSI"])
    jitter.jit.log_mn = True
    return True

def display_taint(jitter):
    taint.display_all_taint(jitter)
    return True

taint.enable_taint_analysis(sb.jitter, 2) # Taint analysis with 2 colors
# sb.jitter.add_breakpoint(0x407570, add_some_taint)
# sb.jitter.add_breakpoint(0x4076E0, add_some_taint)
# sb.jitter.add_breakpoint(0x407570, add_some_taint_2)
sb.jitter.add_breakpoint(0x407571, add_some_taint_3) # Taint should Vanish
# sb.jitter.add_breakpoint(0x407571, display_taint)

import miasm2.jitter.csts as csts

sb.jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_REG, taint.on_taint_register)
sb.jitter.cpu.do_taint_reg_cb(0)
sb.jitter.cpu.do_taint_reg_cb(1)
sb.jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_REG, taint.on_untaint_register)
sb.jitter.cpu.do_untaint_reg_cb(0)
sb.jitter.cpu.do_untaint_reg_cb(1)
sb.jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, taint.on_taint_memory)
sb.jitter.cpu.do_taint_mem_cb(0)
sb.jitter.cpu.do_taint_mem_cb(1)
sb.jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_MEM, taint.on_untaint_memory)
sb.jitter.cpu.do_untaint_mem_cb(0)
sb.jitter.cpu.do_untaint_mem_cb(1)

####################################################

sb.run()
