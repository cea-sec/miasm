#! /usr/bin/env python
"""Minidump to PE example"""

import sys

from future.utils import viewvalues

from miasm.loader.minidump_init import Minidump
from miasm.loader.pe_init import PE

minidump = Minidump(open(sys.argv[1], 'rb').read())

pe = PE()
for i, memory in enumerate(sorted(viewvalues(minidump.memory),
                                  key=lambda x:x.address)):
    # Get section name
    name = str(memory.name)
    if not name:
        name = "s_%02d" % i
    else:
        name = name.split('\\')[-1]

    # Get section protection
    protect = memory.pretty_protect
    protect_mask = 0x20
    if protect == "UNKNOWN":
        protect_mask |= 0xe0000000
    else:
        if "EXECUTE" in protect:
            protect_mask |= 1 << 29
        if "READ" in protect:
            protect_mask |= 1 << 30
        if "WRITE" in protect:
            protect_mask |= 1 << 31

    # Add the section
    pe.SHList.add_section(name=name, addr=memory.address, rawsize=memory.size,
                          data=memory.content, flags=protect_mask)

# Find entry point
try:
    entry_point = minidump.threads.Threads[0].ThreadContext.Eip[0]
except AttributeError:
    entry_point = minidump.threads.Threads[0].ThreadContext.Rip[0]

pe.Opthdr.AddressOfEntryPoint = entry_point

open("out_pe.bin", "wb").write(bytes(pe))
