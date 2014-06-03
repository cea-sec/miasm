import sys
import os
from elfesteem import *
from elfesteem.strpatchwork import StrPatchwork
import inspect
import logging
from pdb import pm
import struct
from optparse import OptionParser
from miasm2.expression.expression import *
from miasm2.core import asmbloc

from miasm2.arch.x86.arch import mn_x86
from miasm2.jitter.jitload import load_pe_in_vm, load_elf_in_vm, bin_stream_vm, get_import_address_elf
from miasm2.jitter.jitter import updt_bloc_emul
from miasm2.jitter.vm_mngr import *
from miasm2.jitter.arch import Jit_x86
from miasm2.jitter.arch import Jit_arm
from miasm2.ir.ir2C import init_arch_C


from miasm2.core.bin_stream import bin_stream
# from jitter import *
from miasm2.jitter.os_dep import win_api_x86_32

from miasm2.ir.symbexec import symbexec

from miasm2.ir.ir2C import bloc2IR

from miasm2.arch.x86.regs import *


def whoami():
    return inspect.stack()[1][3]


log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


parser = OptionParser(usage="usage: %prog [options] file")
parser.add_option('-a', "--address", dest="address", metavar="ADDRESS",
                  help="force eop address", default=None)
parser.add_option('-m', "--architecture", dest="machine", metavar="MACHINE",
                  help="architecture to use for disasm: arm, x86_32, x86_64, ppc, java")
parser.add_option('-s', "--segm", dest="usesegm", action="store_true",
                  help="use segments fs:", default=False)
parser.add_option('-d', "--hdr", dest="loadhdr", action="store_true",
                  help="load pe hdr", default=False)
parser.add_option(
    '-l', "--loadbasedll", dest="loadbasedll", action="store_true",
    help="load base dll", default=False)
parser.add_option('-x', "--dumpall", dest="dumpall", action="store_true",
                  help="load base dll", default=False)
parser.add_option('-e', "--loadmainpe", dest="loadmainpe", action="store_true",
                  help="load main pe", default=False)

parser.add_option('-b', "--dumpblocs", dest="dumpblocs", action="store_true",
                  help="log disasm blogs", default=False)

parser.add_option('-r', "--parse_resources", dest="parse_resources",
                  action="store_true", help="parse pe resources", default=False)

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)


log.info("import machine...")
mode = None
if options.machine == "arm":
    from miasm2.arch.arm.arch import mn_arm as mn
elif options.machine == "sh4":
    from miasm2.arch.sh4_arch import mn_sh4 as mn
elif options.machine == "x86_32":
    from miasm2.arch.x86.arch import mn_x86 as mn
elif options.machine == "x86_64":
    from miasm2.arch.x86.arch import mn_x86 as mn
else:
    raise ValueError('unknown machine')
log.info('ok')
machines = {'arm': (mn, 'arm'),
            'sh4': (mn, None),
            'x86_32': (mn, 32),
            'x86_64': (mn, 64),
            }

mn, attrib = machines[options.machine]

arch2jit = {'x86': Jit_x86,
            'arm': Jit_arm}

jitarch = arch2jit[mn.name]

e, in_str, runtime_dll, segm_to_do, symbol_pool, stack_ad = load_pe_in_vm(
    mn, args[0], options)
# e, in_str, runtime_dll, segm_to_do, symbol_pool, stack_ad =
# load_elf_in_vm(mn, args[0], options)
init_arch_C(mn)

win_api_x86_32.winobjs.runtime_dll = runtime_dll
"""
regs = jitarch.vm_get_gpreg()
regs['RSP'] = stack_ad
jitarch.vm_set_gpreg(regs)
"""

symbol_pool = asmbloc.asm_symbol_pool()
known_blocs = {}
code_blocs_mem_range = []


ad = 0x951DAF
ad = 0x9518C6
ad = 0x9519FE
symbols_init = {}
for i, r in enumerate(all_regs_ids):
    symbols_init[r] = all_regs_ids_init[i]


def se_bloc(ad, arch, attrib, sb):
    l = asmbloc.asm_label(ad)
    b = asmbloc.asm_bloc(l)
    job_done = set()
    asmbloc.dis_bloc(arch, in_str, b, ad, job_done, symbol_pool,
                     attrib=attrib)  # , lines_wd = 8)
    print b
    bloc_ir = bloc2IR(arch, attrib, in_str, b, [], symbol_pool)
    sb.emulbloc(arch, bloc_ir)
    sb.dump_mem()

sb = symbexec(mn, symbols_init)
se_bloc(ad, mn, attrib, sb)
