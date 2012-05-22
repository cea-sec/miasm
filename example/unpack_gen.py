import os
from elfesteem import *
from miasm.tools.pe_helper import *
import inspect
from miasm.core import asmbloc
from miasm.core import parse_asm
from miasm.tools.to_c_helper import *
from elfesteem import pe
import cProfile
import code
from miasm.tools import emul_helper
import sys
from miasm.tools import win_api
from miasm.tools import seh_helper


def whoami():
    return inspect.stack()[1][3]

from optparse import OptionParser

parser = OptionParser(usage = "usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="force eop address", default=None)
parser.add_option('-s', "--segm", dest="usesegm", action="store_true",
                  help="use segments fs:", default=False)
parser.add_option('-d', "--hdr", dest="loadhdr", action="store_true",
                  help="load pe hdr", default=False)
parser.add_option('-l', "--loadbasedll", dest="loadbasedll", action="store_true",
                  help="load base dll", default=False)
parser.add_option('-x', "--dumpall", dest="dumpall", action="store_true",
                  help="load base dll", default=False)
parser.add_option('-e', "--loadmainpe", dest="loadmainpe", action="store_true",
                  help="load main pe", default=False)

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)

e_orig, in_str, runtime_dll, segm_to_do, symbol_pool = load_pe_in_vm(args[0], options)
ad_oep = None
if options.address:
    ad_oep = int(options.address, 16)
    print "stop at", ad_oep


vm_push_uint32_t(0)
vm_push_uint32_t(0)
vm_push_uint32_t(0x1337beef)

known_blocs = {}
code_blocs_mem_range = []


log_regs = False
log_mn = log_regs
def run_bin(my_eip, known_blocs, code_blocs_mem_range):
    global log_regs, log_mn
    may_end = None
    while my_eip != 0x1337beef:

        if my_eip == ad_oep:
            print 'reach ad_oep', hex(ad_oep)
            return
        #dyn dll funcs
        if my_eip in runtime_dll.fad2cname:
            my_eip = manage_runtime_func(my_eip, [globals(), win_api], runtime_dll)
            continue

        my_eip, py_exception = do_bloc_emul(known_blocs, in_str, my_eip,
                                            symbol_pool, code_blocs_mem_range,
                                            log_regs = log_regs, log_mn = log_mn,
                                            segm_to_do = segm_to_do,
                                            dump_blocs = True)

        if py_exception:
            if py_exception & EXCEPT_CODE_AUTOMOD:
                known_blocs, code_blocs_mem_range = updt_automod_code(known_blocs)
            else:
                raise ValueError("except at", hex(my_eip))



ep =  e_orig.rva2virt(e_orig.Opthdr.AddressOfEntryPoint)

print "start emulation", hex(ep)
run_bin(ep, known_blocs, code_blocs_mem_range)
emul_helper.vm2pe("oo.bin", runtime_dll, e_orig)
