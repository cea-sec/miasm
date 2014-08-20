import sys
import os
import time

from miasm2.core.bin_stream import bin_stream_elf, bin_stream_pe, bin_stream_str
from elfesteem import *
from miasm2.core.asmbloc import *
from miasm2.expression.simplifications import expr_simp
from optparse import OptionParser
from miasm2.core.cpu import dum_arg
from miasm2.expression.expression import *
from miasm2.core.interval import interval
from miasm2.analysis.machine import Machine

log = logging.getLogger("dis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)


# log_asmbloc.setLevel(logging.DEBUG)
filename = os.environ.get('PYTHONSTARTUP')
if filename and os.path.isfile(filename):
    execfile(filename)


parser = OptionParser(usage="usage: %prog [options] file address")
parser.add_option('-m', "--architecture", dest="machine", metavar="MACHINE",
                  help="architecture: " + ",".join(Machine.available_machine()))
parser.add_option('-f', "--followcall", dest="followcall", action="store_true",
                  default=False,
                  help="follow call")

parser.add_option('-b', "--blocwatchdog", dest="bw",
                  default=None,
                  help="address to disasemble")

parser.add_option('-n', "--funcsnumwatchdog", dest="funcswd",
                  default=None,
                  help="max func to disasm")

parser.add_option(
    '-r', "--recurfunctions", dest="recurfunctions", action="store_true",
    default=False,
    help="disasm found functions")

parser.add_option('-v', "--verbose", dest="verbose", action="store_true",
                  default=False,
                  help="verbose")

parser.add_option('-g', "--gen_ir", dest="gen_ir", action="store_true",
                  default=False,
                  help="gen intermediate representation")

parser.add_option('-z', "--dis_nulstart_bloc", dest="dis_nulstart_bloc",
                  action="store_true", default=False,
                  help="dont_dis_nulstart_bloc")
parser.add_option('-l', "--dontdis_retcall", dest="dontdis_retcall",
                  action="store_true", default=False,
                  help="only disasm call dst")

parser.add_option('-s', "--simplify", dest="simplify", action="store_true",
                  default=False,
                  help="for test purpose")

parser.add_option('-o', "--shiftoffset", dest="shiftoffset",
                  default="0",
                  help="shift input str by offset")

parser.add_option(
    '-a', "--trydisasmall", dest="trydisasmall", action="store_true",
    default=False,
    help="try disasm all binary")

parser.add_option('-i', "--image", dest="image", action="store_true",
                  default=False,
                  help="display image representation of disasm")

(options, args) = parser.parse_args(sys.argv[1:])
if not args:
    parser.print_help()
    sys.exit(0)
fname = args[0]

if options.verbose:
    log_asmbloc.setLevel(logging.DEBUG)

log.info("import machine...")
machine = Machine(options.machine)
mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira
log.info('ok')

if options.bw != None:
    options.bw = int(options.bw)
if options.funcswd != None:
    options.funcswd = int(options.funcswd)

log.info('load binary')
b = open(fname).read()

default_addr = 0
bs = None
if b.startswith('MZ'):
    e = pe_init.PE(b)
    if e.isPE() and e.NTsig.signature_value == 0x4550:
        bs = bin_stream_pe(e.virt)
        default_addr = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
elif b.startswith('\x7fELF'):
    e = elf_init.ELF(b)
    bs = bin_stream_elf(e.virt)
    default_addr = e.Ehdr.entry

if bs is None:
    shift = int(options.shiftoffset, 16)
    log.warning('fallback to string input (offset=%s)' % hex(shift))
    bs = bin_stream_str(b, shift=shift)


log.info('ok')
mdis = dis_engine(bs)
# configure disasm engine
mdis.dontdis_retcall = options.dontdis_retcall
mdis.blocs_wd = options.bw
mdis.dont_dis_nulstart_bloc = not options.dis_nulstart_bloc

todo = []
addrs = [int(a, 16) for a in args[1:]]

if len(addrs) == 0 and default_addr is not None:
    addrs.append(default_addr)
for ad in addrs:
    todo = [(mdis, None, ad)]

done = set()
all_funcs = set()
all_funcs_blocs = {}


done_interval = interval()
finish = False

# Main disasm loop
while not finish and todo:
    while not finish and todo:
        mdis, caller, ad = todo.pop(0)
        if ad in done:
            continue
        done.add(ad)
        ab = mdis.dis_multibloc(ad)

        log.info('func ok %.16x (%d)' % (ad, len(all_funcs)))

        all_funcs.add(ad)
        all_funcs_blocs[ad] = ab
        for b in ab:
            for l in b.lines:
                done_interval += interval([(l.offset, l.offset + l.l)])

        if options.funcswd is not None:
            options.funcswd -= 1
        if options.recurfunctions:
            for b in ab:
                i = b.get_subcall_instr()
                if not i:
                    continue
                for d in i.getdstflow(mdis.symbol_pool):
                    if not (isinstance(d, ExprId) and isinstance(d.name, asm_label)):
                        continue
                    todo.append((mdis, i, d.name.offset))

        if options.funcswd is not None and options.funcswd <= 0:
            finish = True

    if options.trydisasmall:
        for a, b in done_interval.intervals:
            if b in done:
                continue
            log.debug('add func %s' % hex(b))
            todo.append((mdis, None, b))


# Generate dotty graph
all_blocs = []
for blocs in all_funcs_blocs.values():
    all_blocs += blocs
    # for b in blocs:
    #    print b

log.info('generate graph file')
g = bloc2graph(all_blocs, True)
open('graph_execflow.txt', 'w').write(g)

log.info('generate intervals')

all_lines = []
total_l = 0

print done_interval
if options.image:
    log.info('build img')
    done_interval.show()

for i, j in done_interval.intervals:
    log.debug((hex(i), "->", hex(j)))


all_lines.sort(key=lambda x: x.offset)
open('lines.txt', 'w').write('\n'.join([str(l) for l in all_lines]))
log.info('total lines %s' % total_l)


# Bonus, generate IR graph
if options.gen_ir:
    log.info("generating IR")

    my_ir = ira(mdis.symbol_pool)
    my_ir.blocs = {}
    for ad, all_bloc in all_funcs_blocs.items():
        log.info("generating IR... %x" % ad)
        for b in all_bloc:
            my_ir.add_bloc(b)

    log.info("Gen Graph... %x" % ad)

    my_ir.gen_graph()

    if options.simplify:
        my_ir.dead_simp()

    out = my_ir.graph()
    open('graph_irflow.txt', 'w').write(out)
