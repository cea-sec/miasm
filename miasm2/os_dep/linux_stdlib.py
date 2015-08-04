#!/usr/bin/env python
#-*- coding:utf-8 -*-

from sys import stdout
from string import printable

from miasm2.os_dep.common import \
    heap, set_str_ansi, set_str_unic, get_str_ansi, get_str_unic


class c_linobjs(object):

    base_addr = 0x20000000
    align_addr = 0x1000
    def __init__(self):
        self.alloc_ad = self.base_addr
        self.alloc_align = self.align_addr
        self.heap = heap()

linobjs = c_linobjs()


def xxx_isprint(jitter):
    '''
    #include <ctype.h>
    int isprint(int c);

    checks for any printable character including space.
    '''
    ret_addr, args = jitter.func_args_stdcall(['c'])
    ret = 1 if chr(args.c & 0xFF) in printable else 0
    return jitter.func_ret_stdcall(ret_addr, ret)


def xxx_memcpy(jitter):
    '''
    #include <string.h>
    void *memcpy(void *dest, const void *src, size_t n);

    copies n bytes from memory area src to memory area dest.
    '''
    ret_addr, args = jitter.func_args_stdcall(['dest', 'src', 'n'])
    jitter.vm.set_mem(args.dest, jitter.vm.get_mem(args.src, args.n))
    return jitter.func_ret_stdcall(ret_addr, args.dest)


def xxx_memset(jitter):
    '''
    #include <string.h>
    void *memset(void *s, int c, size_t n);

    fills the first n bytes of the memory area pointed to by s with the constant
    byte c.'''

    ret_addr, args = jitter.func_args_stdcall(['dest', 'c', 'n'])
    jitter.vm.set_mem(args.dest, chr(args.c & 0xFF) * args.n)
    return jitter.func_ret_stdcall(ret_addr, args.dest)


def xxx_puts(jitter):
    '''
    #include <stdio.h>
    int puts(const char *s);

    writes the string s and a trailing newline to stdout.
    '''
    ret_addr, args = jitter.func_args_stdcall(['s'])
    index = args.s
    char = jitter.vm.get_mem(index, 1)
    while char != '\x00':
        stdout.write(char)
        index += 1
        char = jitter.vm.get_mem(index, 1)
    stdout.write('\n')
    return jitter.func_ret_stdcall(ret_addr, 1)


def get_fmt_args(jitter, fmt, cur_arg):
    output = ""
    while True:
        char = jitter.vm.get_mem(fmt, 1)
        fmt += 1
        if char == '\x00':
            break
        if char == '%':
            token = '%'
            while True:
                char = jitter.vm.get_mem(fmt, 1)
                fmt += 1
                token += char
                if char.lower() in '%cdfsux':
                    break
            if token.endswith('s'):
                arg = jitter.get_str_ansi(jitter.get_arg_n_stdcall(cur_arg))
            else:
                arg = jitter.get_arg_n_stdcall(cur_arg)
            char = token % arg
            cur_arg += 1
        output += char
    return output


def xxx_snprintf(jitter):
    ret_addr, args = jitter.func_args_stdcall(['string', 'size', 'fmt'])
    cur_arg, fmt = 3, args.fmt
    size = args.size if args.size else 1
    output = get_fmt_args(jitter, fmt, cur_arg)
    output = output[:size - 1]
    ret = len(output)
    jitter.vm.set_mem(args.string, output + '\x00')
    return jitter.func_ret_stdcall(ret_addr, ret)


def xxx_sprintf(jitter):
    ret_addr, args = jitter.func_args_stdcall(['string', 'fmt'])
    cur_arg, fmt = 2, args.fmt
    output = get_fmt_args(jitter, fmt, cur_arg)
    ret = len(output)
    jitter.vm.set_mem(args.string, output + '\x00')
    return jitter.func_ret_stdcall(ret_addr, ret)


def xxx_printf(jitter):
    ret_addr, args = jitter.func_args_stdcall(['fmt'])
    cur_arg, fmt = 1, args.fmt
    output = get_fmt_args(jitter, fmt, cur_arg)
    ret = len(output)
    print output,
    return jitter.func_ret_stdcall(ret_addr, ret)


def xxx_strcpy(jitter):
    ret_ad, args = jitter.func_args_stdcall(["dst", "src"])
    str_src = jitter.get_str_ansi(args.src) + '\x00'
    jitter.vm.set_mem(args.dst, str_src)
    jitter.func_ret_stdcall(ret_ad, args.dst)


def xxx_strlen(jitter):
    ret_ad, args = jitter.func_args_stdcall(["src"])
    str_src = jitter.get_str_ansi(args.src)
    jitter.func_ret_stdcall(ret_ad, len(str_src))


def xxx_malloc(jitter):
    ret_ad, args = jitter.func_args_stdcall(["msize"])
    addr = linobjs.heap.alloc(jitter, args.msize)
    jitter.func_ret_stdcall(ret_ad, addr)


def xxx_free(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ptr"])
    jitter.func_ret_stdcall(ret_ad, 0)


def xxx_strcmp(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2"])
    s1 = get_str_ansi(jitter, args.ptr_str1)
    s2 = get_str_ansi(jitter, args.ptr_str2)
    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))


def xxx_strncmp(jitter):
    ret_ad, args = jitter.func_args_stdcall(["ptr_str1", "ptr_str2", "size"])
    s1 = get_str_ansi(jitter, args.ptr_str1, args.size)
    s2 = get_str_ansi(jitter, args.ptr_str2, args.size)
    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))
