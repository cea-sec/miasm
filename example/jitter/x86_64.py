from argparse import ArgumentParser
from pdb import pm
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_SYSCALL
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB


# Some syscalls often used by shellcodes
# See https://filippo.io/linux-syscall-table/
SYSCALL = {
        0: "read",
        1: "write",
        2: "open",
        0x9: "mmap",
        0x27: "getpid",
        0x29: "socket",
        0x2a: "connect",
        0x2b: "accept",
        0x2c: "sendto",
        0x2d: "recvfrom",
        0x31: "bind",
        0x32: "listen",
        0x33: "getsockname",
        0x34: "getpeername",
        0x3b: "execve",
        0x3c: "exit",
        0x3d: "wait4",
        0x3e: "kill",
        0x57: "unlink",
        0x5a: "chmod",
        0x5b: "fchmod",
        0x5c: "chown"
}


def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True


def log_syscalls(jitter):
    # For parameters, see
    # https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux
    # Example of how to implement some syscalls
    if jitter.cpu.EAX == 1:
        # Write
        size_t = jitter.cpu.RDX
        print("write(fd: {}, buf: {}, size_t: {})".format(
            jitter.cpu.RDI,
            jitter.vm.get_mem(jitter.cpu.RSI, size_t),
            size_t
        ))
        # Return value is the size written
        jitter.cpu.EAX = size_t
    elif jitter.cpu.EAX == 0x3c:
        # exit
        print("Exit syscall - stopping the machine")
        return False
    else:
        # Most syscalls are not implemented, it may create issues
        if jitter.cpu.EAX in SYSCALL:
            print("syscall {} - {} : Not Implemented".format(jitter.cpu.EAX, SYSCALL[jitter.cpu.EAX]))
        else:
            print("Unknown syscall {} : NotImplemented".format(jitter.cpu.EAX))
    jitter.cpu.set_exception(0)
    jitter.cpu.EAX = 0
    return True


if __name__ == "__main__":
    parser = ArgumentParser(description="x86 64 basic Jitter")
    parser.add_argument("filename", help="x86 64 shellcode filename")
    parser.add_argument("-j", "--jitter",
                        help="Jitter engine (default is 'gcc')",
                        default="gcc")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose mode")
    args = parser.parse_args()
    loc_db = LocationDB()

    myjit = Machine("x86_64").jitter(loc_db, args.jitter)
    myjit.init_stack()

    with open(args.filename, 'rb') as f:
        data = f.read()
    run_addr = 0x40000000
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

    if args.verbose:
        myjit.set_trace_log()
    myjit.push_uint64_t(0x1337beef)
    myjit.add_breakpoint(0x1337beef, code_sentinelle)
    # Add routine catching syscalls
    myjit.add_exception_handler(EXCEPT_SYSCALL, log_syscalls)
    myjit.run(run_addr)
