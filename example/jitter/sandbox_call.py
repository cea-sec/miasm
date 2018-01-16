"""This example illustrate the Sandbox.call API, for direct call of a given
function"""

from miasm2.analysis.sandbox import Sandbox_Linux_arml
from miasm2.analysis.binary import Container
from miasm2.os_dep.linux_stdlib import linobjs
from miasm2.core.utils import hexdump

# Parse arguments
parser = Sandbox_Linux_arml.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
options = parser.parse_args()

sb = Sandbox_Linux_arml(options.filename, options, globals())

with open(options.filename, "rb") as fdesc:
    cont = Container.from_stream(fdesc)
    addr_to_call = cont.symbol_pool.getby_name("md5_starts").offset

# Calling md5_starts(malloc(0x64))
addr = linobjs.heap.alloc(sb.jitter, 0x64)
sb.call(addr_to_call, addr)
hexdump(sb.jitter.vm.get_mem(addr, 0x64))
