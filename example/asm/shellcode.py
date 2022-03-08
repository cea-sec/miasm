#! /usr/bin/env python2
from __future__ import print_function
from argparse import ArgumentParser
from pdb import pm

from future.utils import viewitems
from miasm.loader import pe_init
from miasm.loader.strpatchwork import StrPatchwork

from miasm.core import parse_asm, asmblock
from miasm.analysis.machine import Machine
from miasm.core.interval import interval
from miasm.core.locationdb import LocationDB
from miasm.core.utils import iterbytes, int_to_byte

parser = ArgumentParser(description="Multi-arch (32 bits) assembler")
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
    new_dll = [
        (
            {
                "name": "USER32.dll",
                "firstthunk": s_iat.addr
            },
            [
                "MessageBoxA"
            ]
        )
    ]
    pe.DirImport.add_dlldesc(new_dll)
    s_myimp = pe.SHList.add_section(name="myimp", rawsize=len(pe.DirImport))
    pe.DirImport.set_rva(s_myimp.addr)
    pe.Opthdr.AddressOfEntryPoint = s_text.addr

    addr_main = pe.rva2virt(s_text.addr)
    virt = pe.virt
    output = pe
    dst_interval = interval(
        [
            (pe.rva2virt(s_text.addr), pe.rva2virt(s_text.addr + s_text.size))
        ]
    )
else:
    st = StrPatchwork()

    addr_main = 0
    virt = st
    output = st


# Get and parse the source code
with open(args.source) as fstream:
    source = fstream.read()


loc_db = LocationDB()

asmcfg = parse_asm.parse_txt(machine.mn, attrib, source, loc_db)

# Fix shellcode addrs
loc_db.set_location_offset(loc_db.get_name_location("main"), addr_main)

if args.PE:
    loc_db.set_location_offset(
        loc_db.get_or_create_name_location("MessageBoxA"),
        pe.DirImport.get_funcvirt(
            'USER32.dll',
            'MessageBoxA'
        )
    )

# Print and graph firsts blocks before patching it
for block in asmcfg.blocks:
    print(block)
open("graph.dot", "w").write(asmcfg.dot())

# Apply patches
patches = asmblock.asm_resolve_final(
    machine.mn,
    asmcfg,
    dst_interval
)
if args.encrypt:
    # Encrypt code
    loc_start = loc_db.get_or_create_name_location(args.encrypt[0])
    loc_stop = loc_db.get_or_create_name_location(args.encrypt[1])
    ad_start = loc_db.get_location_offset(loc_start)
    ad_stop = loc_db.get_location_offset(loc_stop)

    for ad, val in list(viewitems(patches)):
        if ad_start <= ad < ad_stop:
            patches[ad] = b"".join(int_to_byte(ord(x) ^ 0x42) for x in iterbytes(val))

print(patches)
if isinstance(virt, StrPatchwork):
    for offset, raw in viewitems(patches):
        virt[offset] = raw
else:
    for offset, raw in viewitems(patches):
        virt.set(offset, raw)


# Produce output
open(args.output, 'wb').write(bytes(output))
