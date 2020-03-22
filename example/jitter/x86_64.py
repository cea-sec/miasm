from argparse import ArgumentParser
from pdb import pm
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, EXCEPT_SYSCALL
from miasm.analysis.machine import Machine


SYSCALL = {
        0x9: "sys_mmap",
        0x29: "sys_socket",
        0x2a: "sys_connect",
        0x2b: "sys_accept",
        0x2c: "sys_sendto",
        0x2d: "sys_recvfrom",
        0x3b: "execve",
}


def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True


def log_syscalls(jitter):
    if jitter.cpu.EAX in SYSCALL:
        print("SYSCALL {} {}".format(jitter.cpu.EAX, SYSCALL[jitter.cpu.EAX]))
    else:
        print("SYSCALL {}".format(jitter.cpu.EAX))
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

    myjit = Machine("x86_64").jitter(args.jitter)
    myjit.init_stack()

    data = open(args.filename, 'rb').read()
    run_addr = 0x40000000
    myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

    if args.verbose:
        myjit.set_trace_log()
    myjit.push_uint64_t(0x1337beef)
    myjit.add_breakpoint(0x1337beef, code_sentinelle)
    myjit.add_exception_handler(EXCEPT_SYSCALL, log_syscalls)
    myjit.run(run_addr)
