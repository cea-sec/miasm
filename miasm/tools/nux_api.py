#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
from to_c_helper import *
import struct
import inspect
import socket
import time
import random
import os
import sys
import string

ctime_str = None
def fd_generator():
    i = 0
    while True:
        yield i
        i+=1

fd_gen = fd_generator()
fd_stdin = fd_gen.next()
fd_stout = fd_gen.next()


socket_pool = {}
def get_str_ansi(ad_str, max_l = None):
    l = 0
    tmp = ad_str
    while vm_get_str(tmp, 1) != "\x00":
        tmp +=1
        l+=1
        if max_l and l > max_l:
            break
    return vm_get_str(ad_str, l)

def get_dw_stack(offset):
    esp = vm_get_gpreg()['esp']
    return updw(vm_get_str(esp+offset, 4))


def whoami():
    return inspect.stack()[1][3]


def xxx___libc_start_main():
    ret_ad = vm_pop_uint32_t()
    arg_1 = get_dw_stack(0)
    arg_2 = get_dw_stack(4)
    arg_3 = get_dw_stack(4)
    arg_4 = get_dw_stack(8)
    arg_5 = get_dw_stack(0xc)
    arg_6 = get_dw_stack(0x10)
    arg_7 = get_dw_stack(0x14)
    arg_8 = get_dw_stack(0x18)

    print whoami(), hex(ret_ad), hex(arg_1), hex(arg_2), hex(arg_3), hex(arg_4), hex(arg_5), hex(arg_6), hex(arg_7), hex(arg_8)
    regs = vm_get_gpreg()
    regs['eip'] = arg_1 # main
    # TODO XXX should push argc, argv here
    vm_set_gpreg(regs)

    vm_push_uint32_t(0x1337beef)



def xxx_memset():
    ret_ad = vm_pop_uint32_t()
    arg_addr = get_dw_stack(0)
    arg_c = get_dw_stack(4)
    arg_size = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(arg_addr), arg_c, arg_size, ')'
    vm_set_mem(arg_addr, chr(arg_c)*arg_size)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_addr
    vm_set_gpreg(regs)

def xxx_memcpy():
    ret_ad = vm_pop_uint32_t()
    dst = get_dw_stack(0)
    src = get_dw_stack(4)
    size = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(dst), hex(src), hex(size), ')'

    s = vm_get_str(src, size)
    vm_set_mem(dst, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = dst
    vm_set_gpreg(regs)

def xxx_memcmp():
    ret_ad = vm_pop_uint32_t()
    s1 = get_dw_stack(0)
    s2 = get_dw_stack(4)
    size = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(s1), hex(s2), hex(size), ')'

    s1s = vm_get_str(s1, size)
    s2s = vm_get_str(s2, size)
    print repr(s1s)
    print repr(s2s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = cmp(s1s, s2s)
    vm_set_gpreg(regs)


def xxx_printf():
    ret_ad = vm_pop_uint32_t()
    fmt_p = get_dw_stack(0)
    fmt_s = get_str_ansi(fmt_p)

    print whoami(), hex(ret_ad), '(', repr(fmt_s), ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_socket():
    ret_ad = vm_pop_uint32_t()
    arg_domain = get_dw_stack(0)
    arg_type = get_dw_stack(4)
    arg_proto = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_domain, arg_type, arg_proto,')'
    fd = fd_gen.next()
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    #regs['eax'] = fd
    # XXX DANGEROUS
    s = socket.socket(arg_domain, arg_type, arg_proto)
    socket_pool[s.fileno()] = s
    regs['eax'] = s.fileno()


    vm_set_gpreg(regs)


def xxx_htonl():
    ret_ad = vm_pop_uint32_t()
    arg_dw = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_dw,')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = socket.htonl(arg_dw)
    vm_set_gpreg(regs)

def xxx_htons():
    ret_ad = vm_pop_uint32_t()
    arg_dw = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_dw,')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = socket.htons(arg_dw)
    vm_set_gpreg(regs)

def xxx_bind():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_addr = get_dw_stack(4)
    arg_addrlen = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_sockfd, hex(arg_addr), arg_addrlen,')'

    addr_s = vm_get_str(arg_addr, arg_addrlen)
    print repr(addr_s)
    sin_f, sin_port, sin_addr = struct.unpack('>HHL', addr_s[:8])
    print repr(sin_f), repr(sin_port), repr(sin_addr)
    # XXX
    #sin_port = 2222
    socket_pool[arg_sockfd].bind(('', sin_port))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_listen():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_backlog = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', arg_sockfd, arg_backlog, ')'
    socket_pool[arg_sockfd].listen(arg_backlog)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_accept():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_addr = get_dw_stack(4)
    arg_addrlen = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_sockfd, hex(arg_addr), arg_addrlen, ')'
    conn, addr = socket_pool[arg_sockfd].accept()
    socket_pool[conn.fileno()] = conn

    print 'ACCEPT', conn, addr

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = conn.fileno()
    vm_set_gpreg(regs)


def xxx_puts():
    ret_ad = vm_pop_uint32_t()
    arg_s = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_s, ')'
    s = get_str_ansi(arg_s)
    print 'PUTS'
    print s

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_putchar():
    ret_ad = vm_pop_uint32_t()
    arg_c = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_c, ')'
    print chr(arg_c&0xff)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx__IO_putc():
    ret_ad = vm_pop_uint32_t()
    arg_c = get_dw_stack(0)
    arg_stream = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_stream), hex(arg_c), ')'
    socket_pool[arg_stream].write(chr(arg_c&0xFF))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_recv():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_buf = get_dw_stack(4)
    arg_len = get_dw_stack(8)
    arg_flags = get_dw_stack(12)

    print whoami(), hex(ret_ad), '(', arg_sockfd, arg_buf, arg_len, arg_sockfd, ')'
    buf = socket_pool[arg_sockfd].recv(arg_len)

    print 'RECV', repr(buf)
    vm_set_mem(arg_buf, buf)


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    if buf:
        regs['eax'] = len(buf)
    else:
        regs['eax'] = -1
    vm_set_gpreg(regs)


def xxx_send():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_buf = get_dw_stack(4)
    arg_len = get_dw_stack(8)
    arg_flags = get_dw_stack(12)

    print whoami(), hex(ret_ad), '(', arg_sockfd, arg_buf, arg_len, arg_sockfd, ')'
    buf = vm_get_str(arg_buf, arg_len)
    try:
        socket_pool[arg_sockfd].send(buf)
    except:
        print 'send fail'
        buf = ""

    print 'SEND', repr(buf)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(buf)
    vm_set_gpreg(regs)

def xxx_close():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_sockfd, ')'
    socket_pool[arg_sockfd].close()

    print 'close', repr(arg_sockfd)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_signal():
    ret_ad = vm_pop_uint32_t()
    arg_signum = get_dw_stack(0)
    arg_sigh = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', arg_signum, hex(arg_sigh), ')'
    # XXX todo
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_setsockopt():
    ret_ad = vm_pop_uint32_t()
    arg_sockfd = get_dw_stack(0)
    arg_level = get_dw_stack(4)
    arg_optname = get_dw_stack(8)
    arg_optval = get_dw_stack(12)
    arg_optlen = get_dw_stack(16)

    print whoami(), hex(ret_ad), '(', arg_sockfd, hex(arg_level), arg_optname, hex(arg_optval), arg_optlen, ')'
    opt_val = vm_get_str(arg_optval, arg_optlen)
    print repr(opt_val)

    # Translation between C and python values
    # #define SOL_SOCKET	0xffff
    dct_level = {0xffff:1, 1:1}
    dct_argname = {4:2, 2:2}
    arg_level = dct_level[arg_level]
    arg_optname = dct_argname[arg_optname]

    print repr(arg_level), repr(arg_optname), repr(opt_val)
    socket_pool[arg_sockfd].setsockopt(arg_level, arg_optname, opt_val)
    # XXX todo
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_getpwnam():
    ret_ad = vm_pop_uint32_t()
    arg_name = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_name), ')'
    s = get_str_ansi(arg_name)
    print repr(s)
    # create fake struct

    name = s
    password = "pwd_"+name
    rname = name
    udir = "/home/"+name
    ushell = "shell_"+name

    ad = vm_get_memory_page_max_address()

    vm_add_memory_page(ad, PAGE_READ|PAGE_WRITE, 0x1000*"\x00")
    ad = (ad+0xfff) & 0xfffff000
    s = struct.pack('IIIIIII',
                    ad+0x100,
                    ad+0x200,
                    1337,
                    1337,
                    ad+0x300,
                    ad+0x400,
                    ad+0x500)

    s = struct.pack('256s256s256s256s256s256s', s, name, password, rname, udir, ushell)
    print repr(s)
    vm_set_mem(ad, s)


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)

def xxx_getuid():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1337
    vm_set_gpreg(regs)

def xxx_getgid():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1337
    vm_set_gpreg(regs)

def xxx_initgroups():
    ret_ad = vm_pop_uint32_t()
    arg_name = get_dw_stack(0)
    arg_group = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_name), arg_group, ')'
    s = get_str_ansi(arg_name)
    print repr(s)
    # XXX todo
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_setresgid():
    ret_ad = vm_pop_uint32_t()
    arg_ruid = get_dw_stack(0)
    arg_euid = get_dw_stack(4)
    arg_suid = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_ruid, arg_euid, arg_suid, ')'
    # XXX todo
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_setresuid():
    ret_ad = vm_pop_uint32_t()
    arg_ruid = get_dw_stack(0)
    arg_euid = get_dw_stack(4)
    arg_suid = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_ruid, arg_euid, arg_suid, ')'
    # XXX todo
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_getegid():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1337
    vm_set_gpreg(regs)

def xxx_geteuid():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(', ')'
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 1337
    vm_set_gpreg(regs)

def xxx_chdir():
    ret_ad = vm_pop_uint32_t()
    arg_path = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_path), ')'
    if arg_path:
        s = get_str_ansi(arg_path)
    else:
        s = "default_path"
    print repr(s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_time():
    ret_ad = vm_pop_uint32_t()
    arg_time = get_dw_stack(0)
    print whoami(), hex(ret_ad), '(', hex(arg_time), ')'

    t = int(time.time())
    if arg_time:
        vm_set_mem(arg_time, pdw(t))
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = t
    vm_set_gpreg(regs)

def xxx_ctime():
    global ctime_str
    ret_ad = vm_pop_uint32_t()
    arg_time = get_dw_stack(0)
    print whoami(), hex(ret_ad), '(', hex(arg_time), ')'

    if not ctime_str:
        ad = vm_get_memory_page_max_address()
        vm_add_memory_page(ad, PAGE_READ|PAGE_WRITE, 0x1000*"\x00")
        ctime_str = ad

    t = vm_get_str(arg_time, 4)
    t = updw(t)
    print hex(t)
    s = time.ctime(t)
    vm_set_mem(ctime_str, s)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ctime_str
    vm_set_gpreg(regs)

def xxx_srand():
    ret_ad = vm_pop_uint32_t()
    arg_seed = get_dw_stack(0)
    print whoami(), hex(ret_ad), '(', hex(arg_seed), ')'

    random.seed(arg_seed)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_rand():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(',  ')'


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = random.randint(0, 0xffffffff)
    vm_set_gpreg(regs)

def xxx_fork():
    ret_ad = vm_pop_uint32_t()
    print whoami(), hex(ret_ad), '(',  ')'


    ret = os.fork()
    #ret= 0
    print 'FORK', ret
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)



def xxx_strncpy():
    ret_ad = vm_pop_uint32_t()
    arg_dst = get_dw_stack(0)
    arg_src = get_dw_stack(4)
    arg_n = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(arg_dst), hex(arg_src), arg_n,   ')'
    src = get_str_ansi(arg_src, arg_n)
    src = (src+'\x00'*arg_n)[:arg_n]

    vm_set_mem(arg_dst, src)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_dst
    vm_set_gpreg(regs)

def xxx_strlen():
    ret_ad = vm_pop_uint32_t()
    arg_src = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_src),   ')'
    src = get_str_ansi(arg_src)
    print repr(src)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(src)
    vm_set_gpreg(regs)


def xxx_read():
    ret_ad = vm_pop_uint32_t()
    arg_fd = get_dw_stack(0)
    arg_buf = get_dw_stack(4)
    arg_len = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', arg_fd, arg_buf, arg_len, ')'
    buf = os.read(arg_fd, arg_len)

    print 'RECV', repr(buf)
    vm_set_mem(arg_buf, buf)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(buf)
    vm_set_gpreg(regs)

def xxx_strcmp():
    ret_ad = vm_pop_uint32_t()
    arg_s1 = get_dw_stack(0)
    arg_s2 = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_s1), hex(arg_s2),    ')'
    s1 = get_str_ansi(arg_s1)
    s2 = get_str_ansi(arg_s2)
    print repr(s1), repr(s2)
    if s1 == s2:
        ret = 0
    elif s1 > s2:
        ret = 1
    else:
        ret = -1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)

def xxx_exit():
    ret_ad = vm_pop_uint32_t()
    arg_code = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_code),   ')'

    sys.exit(arg_code)

def xxx__exit():
    xxx_exit()


def xxx_fdopen():
    ret_ad = vm_pop_uint32_t()
    arg_fd = get_dw_stack(0)
    arg_mode = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', arg_fd, hex(arg_mode),    ')'
    m = get_str_ansi(arg_mode)
    print repr(m)

    s = os.fdopen(arg_fd, m, 0)
    socket_pool[id(s)] = s



    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = id(s)
    vm_set_gpreg(regs)

def xxx_fclose():
    ret_ad = vm_pop_uint32_t()
    arg_fd = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_fd,     ')'
    socket_pool[arg_fd].close()



    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def parse_fmt(s):
    fmt = s[:]+"\x00"
    out = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c != "%":
            i+=1
            continue
        if fmt[i+1] == "%":
            i+=2
            continue
        j = 0
        i+=1
        while fmt[i+j] in "0123456789$.":
            j+=1
        if fmt[i+j] in ['l']:
            j +=1
        if fmt[i+j] == "h":
            x = fmt[i+j:i+j+2]
        else:
            x = fmt[i+j]
        i+=j
        out.append(x)
    return out


def xxx_fprintf():
    ret_ad = vm_pop_uint32_t()
    arg_stream = get_dw_stack(0)
    arg_fmt = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', arg_stream, hex(arg_fmt),    ')'
    s = get_str_ansi(arg_fmt)
    print repr(s)

    fmt_a = parse_fmt(s)
    offset = 8
    args = []
    for i, x in enumerate(fmt_a):
        a = get_dw_stack(offset+4*i)
        if x == "s":
            a = get_str_ansi(a)
        args.append(a)
    print repr(s), repr(args)

    oo = s%(tuple(args))
    print repr(oo)
    socket_pool[arg_stream].write(oo)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(oo)
    vm_set_gpreg(regs)

def xxx_snprintf():
    ret_ad = vm_pop_uint32_t()
    dst = get_dw_stack(0)
    size = get_dw_stack(4)
    arg_fmt = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(dst), hex(size), hex(arg_fmt),    ')'
    s = get_str_ansi(arg_fmt)
    fmt_a = parse_fmt(s)
    offset = 0xc
    args = []
    for i, x in enumerate(fmt_a):
        a = get_dw_stack(offset+4*i)
        if x == "s":
            a = get_str_ansi(a)
        args.append(a)
    print repr(s), repr(args)

    oo = s%(tuple(args))
    print repr(oo)
    vm_set_mem(dst, oo)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(oo)
    vm_set_gpreg(regs)

def xxx_isprint():
    ret_ad = vm_pop_uint32_t()
    c = get_dw_stack(0)
    print whoami(), hex(ret_ad), '(', hex(c), ')'

    if chr(c&0xFF) in string.printable:
        ret = 1
    else:
        ret = 0

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)


def xxx_fgets():
    ret_ad = vm_pop_uint32_t()
    arg_buf = get_dw_stack(0)
    arg_size = get_dw_stack(4)
    arg_stream = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(arg_buf), arg_size, arg_stream,   ')'
    buf = ""
    while len(buf) < arg_size-1:
        buf += socket_pool[arg_stream].read(1)
        if not buf:
            break
        if "\n" in buf:
            break
        if "\x00" in buf:
            break
    if buf:
        buf += "\x00"
    print repr(buf)
    vm_set_mem(arg_buf, buf)

    if not buf:
        arg_buf = 0
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_buf
    vm_set_gpreg(regs)

def xxx_fwrite():
    ret_ad = vm_pop_uint32_t()
    arg_buf = get_dw_stack(0)
    arg_size = get_dw_stack(4)
    arg_nmemb = get_dw_stack(8)
    arg_stream = get_dw_stack(12)

    print whoami(), hex(ret_ad), '(', hex(arg_buf), arg_size, arg_nmemb, arg_stream,   ')'

    buf = vm_get_str(arg_buf, arg_size*arg_nmemb)
    print repr(buf)
    socket_pool[arg_stream].write(buf)
    """
    except:
        print "err in write"
        buf = ""
    """
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(buf)
    vm_set_gpreg(regs)

def xxx_fflush():
    ret_ad = vm_pop_uint32_t()
    arg_stream = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_stream,   ')'

    socket_pool[arg_stream].flush()
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_malloc():
    ret_ad = vm_pop_uint32_t()
    arg_size = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_size),   ')'


    ad = vm_get_memory_page_max_address()
    ad = (ad+0xfff) & 0xfffff000
    vm_add_memory_page(ad, PAGE_READ|PAGE_WRITE, arg_size*"\x00")

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ad
    vm_set_gpreg(regs)

def xxx_calloc():
    xxx_malloc()

def xxx_free():
    ret_ad = vm_pop_uint32_t()
    ptr = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(ptr),   ')'


    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)

def xxx_bzero():
    ret_ad = vm_pop_uint32_t()
    arg_addr = get_dw_stack(0)
    arg_size = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_addr), arg_size,   ')'

    vm_set_mem(arg_addr, "\x00"*arg_size)
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_fopen():
    ret_ad = vm_pop_uint32_t()
    arg_path = get_dw_stack(0)
    arg_mode = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', arg_path, hex(arg_mode),    ')'
    path = get_str_ansi(arg_path)
    m = get_str_ansi(arg_mode)
    print repr(path), repr(m)
    path = "/home/serpilliere/projet/pelogger/user.db"
    try:
        s = open(path, m, 0)
        socket_pool[id(s)] = s
        s= id(s)
    except:
        s = 0



    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = s
    vm_set_gpreg(regs)

def xxx_fread():
    ret_ad = vm_pop_uint32_t()
    arg_buf = get_dw_stack(0)
    arg_size = get_dw_stack(4)
    arg_nmemb = get_dw_stack(8)
    arg_stream = get_dw_stack(12)

    print whoami(), hex(ret_ad), '(', hex(arg_buf), hex(arg_size), hex(arg_nmemb), hex(arg_stream),   ')'

    buf = socket_pool[arg_stream].read(arg_size*arg_nmemb)
    print repr(buf)
    print "ret", arg_nmemb
    vm_set_mem(arg_buf, buf)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_nmemb
    vm_set_gpreg(regs)


def xxx_fseek():
    ret_ad = vm_pop_uint32_t()
    stream = get_dw_stack(0)
    offset = get_dw_stack(4)
    whence = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(stream), hex(offset), hex(whence),   ')'

    buf = socket_pool[stream].seek(offset, whence )
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_rewind():
    ret_ad = vm_pop_uint32_t()
    arg_stream = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', hex(arg_stream),   ')'

    socket_pool[arg_stream].seek(0)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = 0
    vm_set_gpreg(regs)


def xxx_atoi():
    ret_ad = vm_pop_uint32_t()
    arg_nptr = get_dw_stack(0)

    print whoami(), hex(ret_ad), '(', arg_nptr,   ')'
    buf = get_str_ansi(arg_nptr)
    print repr(buf)
    i = int(buf)
    print i



    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = i
    vm_set_gpreg(regs)


def xxx_strcpy():
    ret_ad = vm_pop_uint32_t()
    arg_dst = get_dw_stack(0)
    arg_src = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_dst), hex(arg_src),    ')'
    src = get_str_ansi(arg_src)
    vm_set_mem(arg_dst, src+"\x00")

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_dst
    vm_set_gpreg(regs)


def my_vprintf(arg_fmt, arg_ap):
    fmt = get_str_ansi(arg_fmt)
    #print repr(fmt)

    fmt_a = parse_fmt(fmt)

    args = []
    for i, x in enumerate(fmt_a):
        a = updw(vm_get_str(arg_ap+4*i, 4))
        if x == "s":
            a = get_str_ansi(a)
        args.append(a)


    s = fmt%(tuple(args))+"\x00"
    #print repr(s)
    return s

def xxx_vfprintf():
    ret_ad = vm_pop_uint32_t()
    arg_stream = get_dw_stack(0)
    size = get_dw_stack(4)
    arg_fmt = get_dw_stack(8)
    arg_ap = get_dw_stack(0xc)

    print whoami(), hex(ret_ad), '(', hex(arg_stream), hex(size), hex(arg_fmt), hex(arg_ap),   ')'
    s = my_vprintf(arg_fmt, arg_ap)
    ad = vm_get_memory_page_max_address()
    ad = (ad+0xfff) & 0xfffff000

    socket_pool[arg_stream].write(s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(s)
    vm_set_gpreg(regs)


def xxx_vasprintf():
    ret_ad = vm_pop_uint32_t()
    arg_strp = get_dw_stack(0)
    arg_fmt = get_dw_stack(4)
    arg_ap = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(arg_strp), hex(arg_fmt), hex(arg_ap),   ')'
    s = my_vprintf(arg_fmt, arg_ap)
    print repr(s)
    ad = vm_get_memory_page_max_address()
    ad = (ad+0xfff) & 0xfffff000
    vm_add_memory_page(ad, PAGE_READ|PAGE_WRITE, (len(s)+1)*"\x00")

    vm_set_mem(arg_strp, pdw(ad))
    vm_set_mem(ad, s)

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(fmt)
    vm_set_gpreg(regs)


def xxx_sprintf():
    ret_ad = vm_pop_uint32_t()
    arg_str = get_dw_stack(0)
    arg_fmt = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_str), hex(arg_fmt),    ')'
    s = get_str_ansi(arg_fmt)
    print repr(s)
    fmt_a = parse_fmt(s)
    offset = 8
    args = []
    for i, x in enumerate(fmt_a):
        a = get_dw_stack(offset+4*i)
        if x == "s":
            a = get_str_ansi(a)
        args.append(a)
    print repr(s), repr(args)

    oo = s%(tuple(args))
    print repr(oo)
    vm_set_mem(arg_str, oo+"\x00")
    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = len(oo)
    vm_set_gpreg(regs)


def xxx_strcat():
    ret_ad = vm_pop_uint32_t()
    arg_dst = get_dw_stack(0)
    arg_src = get_dw_stack(4)

    print whoami(), hex(ret_ad), '(', hex(arg_dst), hex(arg_src),    ')'
    src = get_str_ansi(arg_src)
    dst = get_str_ansi(arg_dst)
    print repr(dst), repr(src)
    vm_set_mem(arg_dst, dst+src+'\x00')

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = arg_dst
    vm_set_gpreg(regs)

def xxx_strncmp():
    ret_ad = vm_pop_uint32_t()
    arg_s1 = get_dw_stack(0)
    arg_s2 = get_dw_stack(4)
    arg_n = get_dw_stack(8)

    print whoami(), hex(ret_ad), '(', hex(arg_s1), hex(arg_s2), arg_n,   ')'

    s1 = get_str_ansi(arg_s1, arg_n)
    s2 = get_str_ansi(arg_s2, arg_n)
    print repr(s1), repr(s2)
    if s1 == s2:
        ret = 0
    elif s1 > s2:
        ret = 1
    else:
        ret = -1

    regs = vm_get_gpreg()
    regs['eip'] = ret_ad
    regs['eax'] = ret
    vm_set_gpreg(regs)
