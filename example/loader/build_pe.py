#! /usr/bin/env python

from miasm.loader.pe_init import PE

# Build an empty PE object
pe_object = PE()

# Add a section with a just a "RET"
payload = b"\xc3"
s_text = pe_object.SHList.add_section(
    name="text", addr=0x1000, rawsize=0x1000, data=payload
)

# Set the entry point on this instruction
pe_object.Opthdr.AddressOfEntryPoint = s_text.addr

# Add some imports
new_dll = [
    ({"name": "kernel32.dll",
      "firstthunk": s_text.addr + 0x100},
     ["CreateFileA", "SetFilePointer", "WriteFile", "CloseHandle"]
    ),
    ({"name": "USER32.dll",
      "firstthunk": None},
     ["SetDlgItemInt", "GetMenu", "HideCaret"]
    )
]
pe_object.DirImport.add_dlldesc(new_dll)
s_myimp = pe_object.SHList.add_section(name="myimp", rawsize=0x1000)
pe_object.DirImport.set_rva(s_myimp.addr)

# Rebuild the PE and dump it to a file
open('fresh_pe.exe', 'wb').write(bytes(pe_object))
