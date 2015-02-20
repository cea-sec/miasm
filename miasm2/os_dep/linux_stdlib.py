#!/usr/bin/env python
#-*- coding:utf-8 -*-

from sys import stdout
from string import printable


def xxx_isprint(jitter):
    '''
    #include <ctype.h>
    int isprint(int c);

    checks for any printable character including space.
    '''
    ret_addr, args  = jitter.func_args_stdcall(['c'])
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


def xxx_snprintf(jitter):
    '''
    #include <stdio.h>
    int snprintf(char *str, size_t size, const char *format, ...);

    writes to string str according to format format and at most size bytes.
    '''
    ret_addr, args = jitter.func_args_stdcall(['string', 'size', 'fmt'])
    curarg, output, fmt = 3, '', args.fmt
    size = args.size if args.size else 1
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
                if char in '%cdfsux':
                    break
            char = token % jitter.get_arg_n_stdcall(curarg)
            curarg += 1
        output += char
    output = output[:size - 1]
    ret = len(output)
    jitter.vm.set_mem(args.string, output + '\x00')
    return jitter.func_ret_stdcall(ret_addr, ret)
