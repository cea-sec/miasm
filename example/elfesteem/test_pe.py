#! /usr/bin/env python

import miasm.elfesteem.pe as pe
from miasm.elfesteem.pe_init import PE
import rlcompleter
import readline
import pdb
import sys
from pprint import pprint as pp
readline.parse_and_bind("tab: complete")


e_ = PE()
mysh = b"\xc3"
s_text = e_.SHList.add_section(
    name="text", addr=0x1000, rawsize=0x1000, data=mysh)
e_.Opthdr.AddressOfEntryPoint = s_text.addr
new_dll = [({"name": "kernel32.dll",
             "firstthunk": s_text.addr + 0x100},
            ["CreateFileA", "SetFilePointer", "WriteFile", "CloseHandle"]
            ),
           ({"name": "USER32.dll",
             "firstthunk": None},
            ["SetDlgItemInt", "GetMenu", "HideCaret"]
            )
           ]
e_.DirImport.add_dlldesc(new_dll)

s_myimp = e_.SHList.add_section(name="myimp", rawsize=0x1000)
e_.DirImport.set_rva(s_myimp.addr)
open('uu.bin', 'wb').write(bytes(e_))
