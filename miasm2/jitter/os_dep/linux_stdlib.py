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
    c,  = jitter.func_args_fastcall(1)
    ret = chr(c & 0xFF) in printable and 1 or 0
    return jitter.func_ret_fastcall(ret)


def xxx_memcpy(jitter):
    '''
    #include <string.h>
    void *memcpy(void *dest, const void *src, size_t n);

    copies n bytes from memory area src to memory area dest.
    '''
    dest, src, n, = jitter.func_args_fastcall(3)
    jitter.vm.vm_set_mem(dest, jitter.vm.vm_get_mem(src, n))
    return jitter.func_ret_fastcall(dest)


def xxx_puts(jitter):
    '''
    #include <stdio.h>
    int puts(const char *s);

    writes the string s and a trailing newline to stdout.
    '''
    s, = jitter.func_args_fastcall(1)
    while True:
        c = jitter.vm.vm_get_mem(s, 1)
        s += 1
        if c == '\x00':
            break
        stdout.write(c)
    stdout.write('\n')
    return jitter.func_ret_fastcall(1)


def xxx_snprintf(jitter):
    '''
    #include <stdio.h>
    int snprintf(char *str, size_t size, const char *format, ...);

    writes to string str according to format format and at most size bytes.
    '''
    str, size, format, = jitter.func_args_fastcall(3)
    curarg, output = 4, ''
    while True:
        c = jitter.vm.vm_get_mem(format, 1)
        format += 1
        if c == '\x00':
            break
        if c == '%':
            token = '%'
            while True:
                c = jitter.vm.vm_get_mem(format, 1)
                format += 1
                token += c
                if c in '%cdfsux':
                    break
            c = token % jitter.func_args_fastcall(curarg)[-1]
            curarg += 1
        output += c
    output = output[:size - 1]
    ret = len(output)
    jitter.vm.vm_set_mem(str, output + '\x00')
    return jitter.func_ret_fastcall(ret)
