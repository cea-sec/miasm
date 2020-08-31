from argparse import ArgumentParser
import logging
import re

from miasm.loader import elf as elf_csts

from miasm.os_dep.linux import environment, syscall
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB

parser = ArgumentParser("Run an ELF in a Linux-like environment")
parser.add_argument("target", help="Target ELF")
parser.add_argument("extra_args", help="Arguments for the target ELF",
                    nargs="*", default=[])
parser.add_argument("-j", "--jitter", help="Jitter engine", default="llvm")
parser.add_argument("-p", "--passthrough", help="Reg-exp for passthrough files",
                    default="^$")
parser.add_argument("-f", "--flags", help="Flags")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Activate verbose syscalls")
args = parser.parse_args()

if args.verbose:
    syscall.log.setLevel(logging.DEBUG)

loc_db = LocationDB()
# Get corresponding interpreter and reloc address
cont_target_tmp = Container.from_stream(open(args.target, 'rb'), loc_db)
ld_path = bytes(cont_target_tmp.executable.getsectionbyname(".interp").content).strip(b"\x00")
if cont_target_tmp.executable.Ehdr.type in [elf_csts.ET_REL, elf_csts.ET_DYN]:
    elf_base_addr = 0x40000000
elif cont_target_tmp.executable.Ehdr.type == elf_csts.ET_EXEC:
    elf_base_addr = 0 # Not relocatable
else:
    raise ValueError("Unsupported type %d" % cont_target_tmp.executable.Ehdr.type)

# Instantiate a jitter
machine = Machine(cont_target_tmp.arch)
jitter = machine.jitter(loc_db, args.jitter)
jitter.init_stack()

# Get elements for the target architecture
if cont_target_tmp.arch == "arml":
    LinuxEnvironment = environment.LinuxEnvironment_arml
    syscall_callbacks = syscall.syscall_callbacks_arml
    prepare_loader = environment.prepare_loader_arml
elif cont_target_tmp.arch == "x86_64":
    LinuxEnvironment = environment.LinuxEnvironment_x86_64
    syscall_callbacks = syscall.syscall_callbacks_x86_64
    prepare_loader = environment.prepare_loader_x86_64
else:
    raise ValueError("Unsupported architecture: %r", cont_target_tmp.arch)

# Load the interpreter in memory, applying relocation
linux_env = LinuxEnvironment()
linux_env.filesystem.passthrough.append(re.compile(args.passthrough.encode()))
ld_path = linux_env.filesystem.resolve_path(ld_path)
cont_ld = Container.from_stream(
    open(ld_path, "rb"),
    vm=jitter.vm,
    addr=0x80000000,
    apply_reloc=True
)
# Load the target ELF in memory, without applying reloc
loc_db = cont_ld.loc_db
cont_target = Container.from_stream(
    open(args.target, "rb"),
    vm=jitter.vm,
    loc_db=loc_db,
    addr=elf_base_addr,
    apply_reloc=False
)
# PHDR containing the PH header
elf_phdr_header = next(
    ph32.ph for ph32 in cont_target.executable.ph
    if ph32.ph.type == elf_csts.PT_PHDR
)

# Prepare the desired environment
argv = [args.target.encode()] + [arg.encode() for arg in args.extra_args]
if args.flags:
    argv += [("-%s" % args.flags).encode()]
envp = {b"PATH": b"/usr/local/bin", b"USER": linux_env.user_name}
auxv = environment.AuxVec(
    elf_base_addr + elf_phdr_header.vaddr,
    cont_target.entry_point, linux_env
)
prepare_loader(jitter, argv, envp, auxv, linux_env)
syscall.enable_syscall_handling(jitter, linux_env, syscall_callbacks)


# Run
jitter.init_run(cont_ld.entry_point)
jitter.continue_run()
