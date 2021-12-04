from __future__ import print_function
import os
import struct
import logging
from sys import stdout
from pdb import pm

try:
    stdout = stdout.buffer
except AttributeError:
    pass

from miasm.analysis.sandbox import Sandbox_Linux_x86_32
from miasm.jitter.jitload import log_func
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB

# Utils
def parse_fmt(s):
    fmt = s[:]+"\x00"
    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i:i+1]
        if c != "%":
            i+=1
            continue
        if fmt[i+1:i+2] == "%":
            i+=2
            continue
        j = 0
        i+=1
        while fmt[i+j:i+j+1] in "0123456789$.-":
            j+=1
        if fmt[i+j:i+j+1] in ['l']:
            j +=1
        if fmt[i+j:i+j+1] == "h":
            x = fmt[i+j:i+j+2]
        else:
            x = fmt[i+j:i+j+1]
        i+=j
        out.append(x)
    return out

nb_tests = 1
def xxx___printf_chk(jitter):
    """Tiny implementation of printf_chk"""
    global nb_tests
    ret_ad, args = jitter.func_args_systemv(["out", "format"])
    if args.out != 1:
        raise RuntimeError("Not implemented")
    fmt = jitter.get_c_str(args.format)
    # Manage llx
    fmt = fmt.replace("llx", "lx")
    fmt = fmt.replace("%016lx", "%016z")

    fmt_a = parse_fmt(fmt)
    esp = jitter.cpu.ESP
    args = []
    i = 0
    for x in fmt_a:
        a = jitter.vm.get_u32(esp + 8 + 4*i)
        if x == "s":
            a = jitter.get_c_str(a)
        elif x in ("x", 'X', "d"):
            pass
        elif x.lower() in ("f", "l"):
            a2 = jitter.vm.get_u32(esp + 8 + 4*(i+1))
            a = struct.unpack("d", struct.pack("Q", a2 << 32 | a))[0]
            i += 1
        elif x.lower() == 'z':
            a2 = jitter.vm.get_u32(esp + 8 + 4*(i+1))
            a = a2 << 32 | a
            i += 1
        else:
            raise RuntimeError("Not implemented format")
        args.append(a)
        i += 1
    fmt = fmt.replace("%016z", "%016lx")
    output = fmt%(tuple(args))
    # NaN bad repr in Python
    output = output.replace("nan", "-nan")

    if "\n" not in output:
        raise RuntimeError("Format must end with a \\n")

    # Check with expected result
    line = next(expected)
    if output != line:
        print("Expected:", line)
        print("Obtained:", output)
        raise RuntimeError("Bad semantic")

    stdout.write(b"[%d] %s" % (nb_tests, output.encode('utf8')))
    nb_tests += 1
    jitter.func_ret_systemv(ret_ad, 0)

def xxx_puts(jitter):
    '''
    #include <stdio.h>
    int puts(const char *s);

    writes the string s and a trailing newline to stdout.
    '''
    ret_addr, args = jitter.func_args_systemv(['target'])
    output = jitter.get_c_str(args.target)
    # Check with expected result
    line = next(expected)
    if output != line.rstrip():
        print("Expected:", line)
        print("Obtained:", output)
        raise RuntimeError("Bad semantic")
    return jitter.func_ret_systemv(ret_addr, 1)

# Parse arguments
parser = Sandbox_Linux_x86_32.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
parser.add_argument("funcname", help="Targeted function's name")
parser.add_argument("expected", help="Expected output")
options = parser.parse_args()

# Expected output
expected = open(options.expected)

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Linux_x86_32(loc_db, options.filename, options, globals())
try:
    addr = sb.elf.getsectionbyname(".symtab")[options.funcname].value
except AttributeError:
    raise RuntimeError("The target binary must have a symtab section")

log_func.setLevel(logging.ERROR)

# Segmentation
sb.jitter.cpu.set_segm_base(8, 0x7fff0000)
sb.jitter.cpu.GS = 8
sb.jitter.vm.add_memory_page(0x7fff0000 + 0x14, PAGE_READ | PAGE_WRITE, b"AAAA")


# Run
sb.run(addr)

assert(sb.jitter.running is False)
