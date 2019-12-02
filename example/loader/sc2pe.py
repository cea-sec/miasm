import sys

from argparse import ArgumentParser
from miasm.loader import pe_init


parser = ArgumentParser(description="Create a PE from a shellcode")
parser.add_argument("filename",
                    help="x86 shellcode filename")
parser.add_argument("-p", "--pename",
                    help="new PE filename (default is 'sc_pe.exe')",
                    default="sc_pe.exe")
parser.add_argument("-w", "--word-size",
                    help="word size (default is 32 bits)",
                    choices=[32, 64],
                    type=int,
                    default=32)
args = parser.parse_args()


data = open(args.filename, 'rb').read()
pe = pe_init.PE(wsize=args.word_size)
s_text = pe.SHList.add_section(name="text", addr=0x1000, data=data)
pe.Opthdr.AddressOfEntryPoint = s_text.addr
open(args.pename, 'wb').write(bytes(pe))
