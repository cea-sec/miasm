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

from miasm.analysis.sandbox import Sandbox_Linux_x86_64
from miasm.jitter.jitload import log_func
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE

# Utils
def parse_fmt(s):
    fmt = s[:]+b"\x00"
    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i:i+1]
        if c != b"%":
            i+=1
            continue
        if fmt[i+1:i+2] == b"%":
            i+=2
            continue
        j = 0
        i+=1
        while fmt[i+j:i+j+1] in b"0123456789$.-":
            j+=1
        if fmt[i+j:i+j+1] in [b'l']:
            j +=1
        if fmt[i+j:i+j+1] == b"h":
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
    fmt = jitter.get_str_ansi(args.format)
    # Manage llx
    fmt = fmt.replace(b"llx", b"lx")
    fmt = fmt.replace(b"%016lx", b"%016z")

    fmt_a = parse_fmt(fmt)
    args = []
    i = 0

    for x in fmt_a:
        a = jitter.get_arg_n_systemv(2 + i)
        if x == b"s":
            a = jitter.get_str_ansi(a)
        elif x in (b"x", b'X', b'd', b'z', b'Z'):
            pass
        elif x.lower() in (b"f","l"):
            a = struct.unpack("d", struct.pack("Q", a))[0]
            i += 1
        else:
            raise RuntimeError("Not implemented format")
        args.append(a)
        i += 1

    fmt = fmt.replace(b"%016z", b"%016lx")
    output = fmt%(tuple(args))
    # NaN bad repr in Python
    output = output.replace(b"nan", b"-nan")

    if b"\n" not in output:
        raise RuntimeError("Format must end with a \\n")

    # Check with expected result
    line = next(expected)
    if output != line.encode():
        print("Expected:", line)
        print("Obtained:", output)
        raise RuntimeError("Bad semantic")

    stdout.write(b"[%d] %s" % (nb_tests, output))
    nb_tests += 1
    jitter.func_ret_systemv(ret_ad, 0)

def xxx_puts(jitter):
    '''
    #include <stdio.h>
    int puts(const char *s);

    writes the string s and a trailing newline to stdout.
    '''
    ret_addr, args = jitter.func_args_systemv(['target'])
    output = jitter.get_str_ansi(args.target)
    # Check with expected result
    line = next(expected)
    if output != line.rstrip():
        print("Expected:", line)
        print("Obtained:", output)
        raise RuntimeError("Bad semantic")
    return jitter.func_ret_systemv(ret_addr, 1)

# Parse arguments
parser = Sandbox_Linux_x86_64.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
parser.add_argument("funcname", help="Targeted function's name")
parser.add_argument("expected", help="Expected output")
options = parser.parse_args()

# Expected output
expected = open(options.expected)

# Create sandbox
sb = Sandbox_Linux_x86_64(options.filename, options, globals())
try:
    addr = sb.elf.getsectionbyname(".symtab")[options.funcname].value
except AttributeError:
    raise RuntimeError("The target binary must have a symtab section")

log_func.setLevel(logging.ERROR)

# Segmentation
sb.jitter.cpu.set_segm_base(8, 0x7fff0000)
sb.jitter.cpu.FS = 8
sb.jitter.vm.add_memory_page(0x7fff0000 + 0x28, PAGE_READ | PAGE_WRITE, b"AAAAAAAA")


# Run
sb.run(addr)

assert(sb.jitter.run is False)
