#-*- coding:utf-8 -*-

from __future__ import print_function
import struct
from sys import stdout

try:
    # Python3 binary stdout
    stdout = stdout.buffer
except AttributeError:
    pass

from miasm.core.utils import int_to_byte, cmp_elts
from miasm.os_dep.common import heap
from miasm.os_dep.common import get_fmt_args as _get_fmt_args


class c_linobjs(object):

    base_addr = 0x20000000
    align_addr = 0x1000
    def __init__(self):
        self.alloc_ad = self.base_addr
        self.alloc_align = self.align_addr
        self.heap = heap()

linobjs = c_linobjs()

ABORT_ADDR = 0x1337beef

def xxx___libc_start_main(jitter):
    """Basic implementation of __libc_start_main

    int __libc_start_main(int *(main) (int, char * *, char * *), int argc,
                          char * * ubp_av, void (*init) (void),
                          void (*fini) (void), void (*rtld_fini) (void),
                          void (* stack_end));

    Note:
     - init, fini, rtld_fini are ignored
     - return address is forced to ABORT_ADDR, to avoid calling abort/hlt/...
     - in powerpc, signature is:

    int __libc_start_main (int argc, char **argv, char **ev, ElfW (auxv_t) *
                       auxvec, void (*rtld_fini) (void), struct startup_info
                       *stinfo, char **stack_on_entry)

    """
    global ABORT_ADDR
    if jitter.arch.name == "ppc32":
        ret_ad, args = jitter.func_args_systemv(
            ["argc", "argv", "ev", "aux_vec", "rtld_fini", "st_info",
             "stack_on_entry"]
        )

        # Mimic glibc implementation
        if args.stack_on_entry != 0:
            argc = struct.unpack(">I",
                                 jitter.vm.get_mem(args.stack_on_entry, 4))[0]
            argv = args.stack_on_entry + 4
            envp = argv + ((argc + 1) * 4)
        else:
            argc = args.argc
            argv = args.argv
            envp = args.ev
        # sda_base, main, init, fini
        _, main, _, _ = struct.unpack(">IIII",
                                      jitter.vm.get_mem(args.st_info, 4 * 4))

    else:
        ret_ad, args = jitter.func_args_systemv(
            ["main", "argc", "ubp_av", "init", "fini", "rtld_fini", "stack_end"]
        )

        main = args.main
        # done by __libc_init_first
        size = jitter.lifter.pc.size // 8
        argc = args.argc
        argv = args.ubp_av
        envp = argv + (args.argc + 1) * size


    # Call int main(int argc, char** argv, char** envp)
    jitter.func_ret_systemv(main)
    ret_ad = ABORT_ADDR
    jitter.func_prepare_systemv(ret_ad, argc, argv, envp)
    return True


def xxx_isprint(jitter):
    '''
    #include <ctype.h>
    int isprint(int c);

    checks for any printable character including space.
    '''
    ret_addr, args = jitter.func_args_systemv(['c'])
    ret = 1 if 0x20 <= args.c & 0xFF < 0x7f else 0
    return jitter.func_ret_systemv(ret_addr, ret)


def xxx_memcpy(jitter):
    '''
    #include <string.h>
    void *memcpy(void *dest, const void *src, size_t n);

    copies n bytes from memory area src to memory area dest.
    '''
    ret_addr, args = jitter.func_args_systemv(['dest', 'src', 'n'])
    jitter.vm.set_mem(args.dest, jitter.vm.get_mem(args.src, args.n))
    return jitter.func_ret_systemv(ret_addr, args.dest)


def xxx_memset(jitter):
    '''
    #include <string.h>
    void *memset(void *s, int c, size_t n);

    fills the first n bytes of the memory area pointed to by s with the constant
    byte c.'''

    ret_addr, args = jitter.func_args_systemv(['dest', 'c', 'n'])
    jitter.vm.set_mem(args.dest, int_to_byte(args.c & 0xFF) * args.n)
    return jitter.func_ret_systemv(ret_addr, args.dest)


def xxx_puts(jitter):
    '''
    #include <stdio.h>
    int puts(const char *s);

    writes the string s and a trailing newline to stdout.
    '''
    ret_addr, args = jitter.func_args_systemv(['s'])
    index = args.s
    char = jitter.vm.get_mem(index, 1)
    while char != b'\x00':
        stdout.write(char)
        index += 1
        char = jitter.vm.get_mem(index, 1)
    stdout.write(b'\n')
    return jitter.func_ret_systemv(ret_addr, 1)


def get_fmt_args(jitter, fmt, cur_arg):
    return _get_fmt_args(fmt, cur_arg, jitter.get_c_str, jitter.get_arg_n_systemv)


def xxx_snprintf(jitter):
    ret_addr, args = jitter.func_args_systemv(['string', 'size', 'fmt'])
    cur_arg, fmt = 3, args.fmt
    size = args.size if args.size else 1
    output = get_fmt_args(jitter, fmt, cur_arg)
    output = output[:size - 1]
    ret = len(output)
    jitter.set_c_str(args.string, output)
    return jitter.func_ret_systemv(ret_addr, ret)


def xxx_sprintf(jitter):
    ret_addr, args = jitter.func_args_systemv(['string', 'fmt'])
    cur_arg, fmt = 2, args.fmt
    output = get_fmt_args(jitter, fmt, cur_arg)
    ret = len(output)
    jitter.set_c_str(args.string, output)
    return jitter.func_ret_systemv(ret_addr, ret)


def xxx_printf(jitter):
    ret_addr, args = jitter.func_args_systemv(['fmt'])
    cur_arg, fmt = 1, args.fmt
    output = get_fmt_args(jitter, fmt, cur_arg)
    ret = len(output)
    stdout.write(output.encode('utf8'))
    return jitter.func_ret_systemv(ret_addr, ret)


def xxx_strcpy(jitter):
    ret_ad, args = jitter.func_args_systemv(["dst", "src"])
    str_src = jitter.get_c_str(args.src)
    jitter.set_c_str(args.dst, str_src)
    jitter.func_ret_systemv(ret_ad, args.dst)


def xxx_strlen(jitter):
    ret_ad, args = jitter.func_args_systemv(["src"])
    str_src = jitter.get_c_str(args.src)
    jitter.func_ret_systemv(ret_ad, len(str_src))


def xxx_malloc(jitter):
    ret_ad, args = jitter.func_args_systemv(["msize"])
    addr = linobjs.heap.alloc(jitter, args.msize)
    jitter.func_ret_systemv(ret_ad, addr)


def xxx_free(jitter):
    ret_ad, args = jitter.func_args_systemv(["ptr"])
    jitter.func_ret_systemv(ret_ad, 0)


def xxx_strcmp(jitter):
    ret_ad, args = jitter.func_args_systemv(["ptr_str1", "ptr_str2"])
    s1 = jitter.get_c_str(args.ptr_str1)
    s2 = jitter.get_c_str(args.ptr_str2)
    jitter.func_ret_systemv(ret_ad, cmp_elts(s1, s2))


def xxx_strncmp(jitter):
    ret_ad, args = jitter.func_args_systemv(["ptr_str1", "ptr_str2", "size"])
    s1 = jitter.get_c_str(args.ptr_str1, args.size)
    s2 = jitter.get_c_str(args.ptr_str2, args.size)
    jitter.func_ret_systemv(ret_ad, cmp_elts(s1, s2))
