#! /usr/bin/env python
from argparse import ArgumentParser
from pdb import pm

from elfesteem import pe_init
from elfesteem.strpatchwork import StrPatchwork

from miasm2.core import parse_asm, asmbloc
from miasm2.analysis.machine import Machine
from miasm2.core.interval import interval

parser = ArgumentParser("Multi-arch (32 bits) assembler")
parser.add_argument('architecture', help="architecture: " +
                    ",".join(Machine.available_machine()))
parser.add_argument("source", help="Source file to assemble")
parser.add_argument("output", help="Output file")
parser.add_argument("--PE", help="Create a PE with a few imports",
                    action="store_true")
parser.add_argument("-e", "--encrypt",
                    help="Encrypt the code between <label_start> <label_stop>",
                    nargs=2)
args = parser.parse_args()

# Get architecture-dependent parameters
machine = Machine(args.architecture)
try:
    attrib = machine.dis_engine.attrib
    size = int(attrib)
except AttributeError:
    attrib = None
    size = 32
except ValueError:
    size = 32
reg_and_id = dict(machine.mn.regs.all_regs_ids_byname)
base_expr = machine.base_expr
dst_interval = None

# Output format
if args.PE:
    pe = pe_init.PE(wsize=size)
    s_text = pe.SHList.add_section(name="text", addr=0x1000, rawsize=0x1000)
    s_iat = pe.SHList.add_section(name="iat", rawsize=0x100)
    new_dll = [({"name": "USER32.dll",
                 "firstthunk": s_iat.addr}, ["MessageBoxA"])]
    pe.DirImport.add_dlldesc(new_dll)
    s_myimp = pe.SHList.add_section(name="myimp", rawsize=len(pe.DirImport))
    pe.DirImport.set_rva(s_myimp.addr)
    pe.Opthdr.AddressOfEntryPoint = s_text.addr

    addr_main = pe.rva2virt(s_text.addr)
    virt = pe.virt
    output = pe
    dst_interval = interval([(pe.rva2virt(s_text.addr),
                              pe.rva2virt(s_text.addr + s_text.size))])
else:
    st = StrPatchwork()

    addr_main = 0
    virt = st
    output = st


# Get and parse the source code
with open(args.source) as fstream:
    source = fstream.read()

blocs, symbol_pool = parse_asm.parse_txt(machine.mn, attrib, source)

# Fix shellcode addrs
symbol_pool.set_offset(symbol_pool.getby_name("main"), addr_main)

if args.PE:
    symbol_pool.set_offset(symbol_pool.getby_name_create("MessageBoxA"),
                           pe.DirImport.get_funcvirt('USER32.dll', 'MessageBoxA'))

# Print and graph firsts blocs before patching it
for bloc in blocs:
    print bloc
open("graph.dot", "w").write(blocs.dot())

# Apply patches
patches = asmbloc.asm_resolve_final(machine.mn,
                                    blocs,
                                    symbol_pool,
                                    dst_interval)
if args.encrypt:
    # Encrypt code
    ad_start = symbol_pool.getby_name_create(args.encrypt[0]).offset
    ad_stop = symbol_pool.getby_name_create(args.encrypt[1]).offset

    new_patches = dict(patches)
    for ad, val in patches.items():
        if ad_start <= ad < ad_stop:
            new_patches[ad] = "".join([chr(ord(x) ^ 0x42) for x in val])
    patches = new_patches

print patches
if isinstance(virt, StrPatchwork):
    for offset, raw in patches.items():
        virt[offset] = raw
else:
    for offset, raw in patches.items():
        virt.set(offset, raw)


# Produce output
open(args.output, 'wb').write(str(output))
