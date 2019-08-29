#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
import logging
from pdb import pm
from elfesteem import pe
from miasm.analysis.sandbox import Sandbox_Win_x86_32

# Used in custom version of lib_get_add_func()
from miasm.jitter.loader.utils import canon_libname_libfunc

# User defined methods

def kernel32_GetProcAddress(jitter):
    """Hook on GetProcAddress to note where the packer stores import pointers"""

    # Retrieve the return address of the current procedure and arguments (needed
    # to rebuild a clean import table)
    ret_ad, args = jitter.func_args_stdcall(["libbase", "fname"])

    # Handle ordinal imports
    fname = (args.fname if args.fname < 0x10000
             else jitter.get_str_ansi(args.fname))
    logging.info(fname)

    # Get the generated address of the library
    ad = lib_get_add_func_custom(sb.libs, args.libbase, fname)

    # Add a breakpoint in case of a call on the resolved function
    # NOTE: never happens in UPX, just for skeleton
    jitter.handle_function(ad)

    # When the function is called, EBX is a pointer to the destination buffer
    # dst_ad = jitter.cpu.EBX
    ##
    # We will find using taint analysis where the
    # return value will be saved.
    start_analysis(jitter, sb.libs, args.libbase, fname)

    # Return to caller using ABI standards
    jitter.func_ret_stdcall(ret_ad, ad)


def lib_get_add_func_custom(mylibimp, libad, imp_ord_or_name):
    """Custom version of lib_get_add_func() from class libimp in miasm.jitter.loader.utils

    In our case we do not want to add the destination address of the address of the function
    we are looking for. We only want to get the address of the function. The destination address
    is what we are looking for and we need the actual address of the function in order to find
    it.
    The destination address will be added after with lib_add_dst_ad(). if we don't do it we will
    get an error when we try to rebuild our PE since this information is needed.
    """
    if not libad in mylibimp.name2off.values():
        raise ValueError('unknown lib base !', hex(libad))

    if imp_ord_or_name in mylibimp.lib_imp2ad[libad]:
        return mylibimp.lib_imp2ad[libad][imp_ord_or_name]
    ad = mylibimp.libbase2lastad[libad]
    mylibimp.libbase2lastad[libad] += 0x11 # Arbitrary NOTE : Why is it working ?
    mylibimp.lib_imp2ad[libad][imp_ord_or_name] = ad

    # NOTE : What is it doing below ?
    name_inv = dict([(x[1], x[0]) for x in mylibimp.name2off.items()])
    c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
    mylibimp.fad2cname[ad] = c_name
    mylibimp.fad2info[ad] = libad, imp_ord_or_name

    return ad

def lib_add_dst_ad(mylibimp, libad, imp_ord_or_name, dst_ad):
    """Add the destination address of the address of the function in the libimp structure"""

    # NOTE : Can have multiple destination addresses
    if not imp_ord_or_name in mylibimp.lib_imp2dstad[libad]:
        mylibimp.lib_imp2dstad[libad][imp_ord_or_name] = set()
    mylibimp.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

jitter_global = None
libs_global = None
libbase_global = None
fname_global = None
def start_analysis(jitter, libs, libbase, fname):
    global jitter_global
    global libs_global
    global libbase_global
    global fname_global
    jitter_global = jitter
    libs_global = libs
    libbase_global = libbase
    fname_global = fname

    print "[+] Start Taint Analysis"

    # Add taint origin
    color_index = 0
    jitter.cpu.taint_register(color_index, jitter.jit.codegen.regs_index["RAX"])

    jitter.jit.log_mn = True

    return True

def on_memory_taint(jitter):
    taint.display_all_taint(jitter)
    last_mem = jitter.cpu.last_tainted_memory(0)
    addr, size = last_mem[0]
    print "\t[>] FOUND : %x->%s" % (addr, fname_global)
    lib_add_dst_ad(libs_global, libbase_global, fname_global, addr) # Add the import (use during PE rebuild)
    jitter.cpu.untaint_all()
    jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
    jitter.jit.log_mn = False
    return True

# Parsing arguments
parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--debug",
                    help="debug mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True
options.taint = True
sb = Sandbox_Win_x86_32(options.filename, options, globals(),
                        parse_reloc=False)

if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
elif options.debug is True:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print sb.jitter.vm

# Ensure there is one and only one leave (for OEP discovering)
mdis = sb.machine.dis_engine(sb.jitter.bs)
mdis.dont_dis_nulstart_bloc = True
asmcfg = mdis.dis_multiblock(sb.entry_point)

leaves = list(asmcfg.get_bad_blocks())
assert(len(leaves) == 1)
l = leaves.pop()
logging.info(l)

end_offset = mdis.loc_db.get_location_offset(l.loc_key)

logging.info('final offset')
logging.info(hex(end_offset))

# Export CFG graph (dot format)
if options.graph is True:
    open("graph.dot", "w").write(asmcfg.dot())

if options.verbose is True:
    print sb.jitter.vm

def update_binary(jitter):
    sb.pe.Opthdr.AddressOfEntryPoint = sb.pe.virt2rva(jitter.pc)
    logging.info('updating binary')
    for s in sb.pe.SHList:
        sdata = sb.jitter.vm.get_mem(sb.pe.rva2virt(s.addr), s.rawsize)
        sb.pe.rva.set(s.addr, sdata)

    # Stop execution
    jitter.run = False
    return False

# Set callbacks
sb.jitter.add_breakpoint(end_offset, update_binary)

#####################TAINT##########################
import miasm.analysis.taint_analysis as taint

taint.enable_taint_analysis(sb.jitter)
color_index = 0

import miasm.jitter.csts as csts
sb.jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_memory_taint)
sb.jitter.cpu.enable_taint_mem_cb(color_index)
####################################################

# Run
sb.run()

# Rebuild PE
# Alternative solution: miasm.jitter.loader.pe.vm2pe(sb.jitter, out_fname,
# libs=sb.libs, e_orig=sb.pe)
new_dll = []

sb.pe.SHList.align_sections(0x1000, 0x1000)
# logging.info(repr(sb.pe.SHList))

sb.pe.DirRes = pe.DirRes(sb.pe)
sb.pe.DirImport.impdesc = None
# logging.info(repr(sb.pe.DirImport.impdesc))
new_dll = sb.libs.gen_new_lib(sb.pe)
# logging.info(new_dll)
sb.pe.DirImport.impdesc = []
sb.pe.DirImport.add_dlldesc(new_dll)
s_myimp = sb.pe.SHList.add_section(name="myimp", rawsize=len(sb.pe.DirImport))
# logging.info(repr(sb.pe.SHList))
sb.pe.DirImport.set_rva(s_myimp.addr)

# XXXX TODO
sb.pe.NThdr.optentries[pe.DIRECTORY_ENTRY_DELAY_IMPORT].rva = 0

bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
open(fname + '_unupx.bin', 'w').write(str(sb.pe))
