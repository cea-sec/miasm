from builtins import range
import fcntl
import functools
import logging
import struct
import termios

from miasm.jitter.csts import EXCEPT_INT_XX, EXCEPT_SYSCALL
from miasm.core.utils import pck64

log = logging.getLogger('syscalls')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.WARNING)


def _dump_struct_stat_x86_64(info):
    data = struct.pack(
        "QQQIIIIQQQQQQQQQQQQQ",
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        0, # 32 bit padding
        info.st_rdev,
        info.st_size,
        info.st_blksize,
        info.st_blocks,
        info.st_atime,
        info.st_atimensec,
        info.st_mtime,
        info.st_mtimensec,
        info.st_ctime,
        info.st_ctimensec,
        0, # unused
        0, # unused
        0, # unused
    )
    return data


def _dump_struct_stat_arml(info):
    data = struct.pack(
        "QIIIIIIIIIIIIIIIIII",
        info.st_dev,
        0, # pad
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_rdev,
        info.st_size,
        info.st_blksize,
        info.st_blocks,
        info.st_atime,
        info.st_atimensec,
        info.st_mtime,
        info.st_mtimensec,
        info.st_ctime,
        info.st_ctimensec,
        0, # unused
        0, # unused
    )
    return data


def sys_x86_64_rt_sigaction(jitter, linux_env):
    # Parse arguments
    sig, act, oact, sigsetsize = jitter.syscall_args_systemv(4)
    log.debug("sys_rt_sigaction(%x, %x, %x, %x)", sig, act, oact, sigsetsize)

    # Stub
    if oact != 0:
        # Return an empty old action
        jitter.vm.set_mem(oact, b"\x00" * sigsetsize)
    jitter.syscall_ret_systemv(0)


def sys_generic_brk(jitter, linux_env):
    # Parse arguments
    addr, = jitter.syscall_args_systemv(1)
    log.debug("sys_brk(%d)", addr)

    # Stub
    jitter.syscall_ret_systemv(linux_env.brk(addr, jitter.vm))


def sys_x86_32_newuname(jitter, linux_env):
    # struct utsname {
    #     char sysname[];    /* Operating system name (e.g., "Linux") */
    #     char nodename[];   /* Name within "some implementation-defined
    #                            network" */
    #     char release[];    /* Operating system release (e.g., "2.6.28") */
    #     char version[];    /* Operating system version */
    #     char machine[];    /* Hardware identifier */
    # }

    # Parse arguments
    nameptr, = jitter.syscall_args_systemv(1)
    log.debug("sys_newuname(%x)", nameptr)

    # Stub
    info = [
        linux_env.sys_sysname,
        linux_env.sys_nodename,
        linux_env.sys_release,
        linux_env.sys_version,
        linux_env.sys_machine
    ]
    # TODO: Elements start at 0x41 multiples on my tests...
    output = b""
    for elem in info:
        output += elem
        output += b"\x00" * (0x41 - len(elem))
    jitter.vm.set_mem(nameptr, output)
    jitter.syscall_ret_systemv(0)


def sys_x86_64_newuname(jitter, linux_env):
    # struct utsname {
    #     char sysname[];    /* Operating system name (e.g., "Linux") */
    #     char nodename[];   /* Name within "some implementation-defined
    #                            network" */
    #     char release[];    /* Operating system release (e.g., "2.6.28") */
    #     char version[];    /* Operating system version */
    #     char machine[];    /* Hardware identifier */
    # }

    # Parse arguments
    nameptr, = jitter.syscall_args_systemv(1)
    log.debug("sys_newuname(%x)", nameptr)

    # Stub
    info = [
        linux_env.sys_sysname,
        linux_env.sys_nodename,
        linux_env.sys_release,
        linux_env.sys_version,
        linux_env.sys_machine
    ]
    # TODO: Elements start at 0x41 multiples on my tests...
    output = b""
    for elem in info:
        output += elem
        output += b"\x00" * (0x41 - len(elem))
    jitter.vm.set_mem(nameptr, output)
    jitter.syscall_ret_systemv(0)


def sys_arml_newuname(jitter, linux_env):
    # struct utsname {
    #     char sysname[];    /* Operating system name (e.g., "Linux") */
    #     char nodename[];   /* Name within "some implementation-defined
    #                            network" */
    #     char release[];    /* Operating system release (e.g., "2.6.28") */
    #     char version[];    /* Operating system version */
    #     char machine[];    /* Hardware identifier */
    # }

    # Parse arguments
    nameptr, = jitter.syscall_args_systemv(1)
    log.debug("sys_newuname(%x)", nameptr)

    # Stub
    info = [
        linux_env.sys_sysname,
        linux_env.sys_nodename,
        linux_env.sys_release,
        linux_env.sys_version,
        linux_env.sys_machine
    ]
    # TODO: Elements start at 0x41 multiples on my tests...
    output = b""
    for elem in info:
        output += elem
        output += b"\x00" * (0x41 - len(elem))
    jitter.vm.set_mem(nameptr, output)
    jitter.syscall_ret_systemv(0)


def sys_generic_access(jitter, linux_env):
    # Parse arguments
    pathname, mode = jitter.syscall_args_systemv(2)
    rpathname = jitter.get_c_str(pathname)
    rmode = mode
    if mode == 1:
        rmode = "F_OK"
    elif mode == 2:
        rmode = "R_OK"
    log.debug("sys_access(%s, %s)", rpathname, rmode)

    # Stub
    # Do not check the mode
    if linux_env.filesystem.exists(rpathname):
        jitter.syscall_ret_systemv(0)
    else:
        jitter.syscall_ret_systemv(-1)


def sys_x86_64_openat(jitter, linux_env):
    # Parse arguments
    dfd, filename, flags, mode = jitter.syscall_args_systemv(4)
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_openat(%x, %r, %x, %x)", dfd, rpathname, flags, mode)

    # Stub
    # flags, openat particularity over 'open' are ignored
    jitter.syscall_ret_systemv(linux_env.open_(rpathname, flags))


def sys_x86_64_newstat(jitter, linux_env):
    # Parse arguments
    filename, statbuf = jitter.syscall_args_systemv(2)
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_newstat(%r, %x)", rpathname, statbuf)

    # Stub
    if linux_env.filesystem.exists(rpathname):
        info = linux_env.stat(rpathname)
        data = _dump_struct_stat_x86_64(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.syscall_ret_systemv(0)
    else:
        # ENOENT (No such file or directory)
        jitter.syscall_ret_systemv(-1)


def sys_arml_stat64(jitter, linux_env):
    # Parse arguments
    filename, statbuf = jitter.syscall_args_systemv(2)
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_newstat(%r, %x)", rpathname, statbuf)

    # Stub
    if linux_env.filesystem.exists(rpathname):
        info = linux_env.stat(rpathname)
        data = _dump_struct_stat_arml(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.syscall_ret_systemv(0)
    else:
        # ENOENT (No such file or directory)
        jitter.syscall_ret_systemv(-1)


def sys_x86_64_writev(jitter, linux_env):
    # Parse arguments
    fd, vec, vlen = jitter.syscall_args_systemv(3)
    log.debug("sys_writev(%d, %d, %x)", fd, vec, vlen)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    for iovec_num in range(vlen):
        # struct iovec {
        #    void  *iov_base;    /* Starting address */
        #    size_t iov_len;     /* Number of bytes to transfer */
        # };
        iovec = jitter.vm.get_mem(vec + iovec_num * 8 * 2, 8*2)
        iov_base, iov_len = struct.unpack("QQ", iovec)
        fdesc.write(jitter.get_c_str(iov_base)[:iov_len])

    jitter.syscall_ret_systemv(vlen)


def sys_arml_writev(jitter, linux_env):
    # Parse arguments
    fd, vec, vlen = jitter.syscall_args_systemv(3)
    log.debug("sys_writev(%d, %d, %x)", fd, vec, vlen)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    for iovec_num in range(vlen):
        # struct iovec {
        #    void  *iov_base;    /* Starting address */
        #    size_t iov_len;     /* Number of bytes to transfer */
        # };
        iovec = jitter.vm.get_mem(vec + iovec_num * 4 * 2, 4*2)
        iov_base, iov_len = struct.unpack("II", iovec)
        fdesc.write(jitter.get_c_str(iov_base)[:iov_len])

    jitter.syscall_ret_systemv(vlen)


def sys_generic_exit_group(jitter, linux_env):
    # Parse arguments
    status, = jitter.syscall_args_systemv(1)
    log.debug("sys_exit_group(%d)", status)

    # Stub
    log.debug("Exit with status code %d", status)
    jitter.running = False


def sys_generic_read(jitter, linux_env):
    # Parse arguments
    fd, buf, count = jitter.syscall_args_systemv(3)
    log.debug("sys_read(%d, %x, %x)", fd, buf, count)

    # Stub
    data = linux_env.read(fd, count)
    jitter.vm.set_mem(buf, data)
    jitter.syscall_ret_systemv(len(data))


def sys_x86_64_fstat(jitter, linux_env):
    # Parse arguments
    fd, statbuf = jitter.syscall_args_systemv(2)
    log.debug("sys_fstat(%d, %x)", fd, statbuf)

    # Stub
    info = linux_env.fstat(fd)
    data = _dump_struct_stat_x86_64(info)
    jitter.vm.set_mem(statbuf, data)
    jitter.syscall_ret_systemv(0)


def sys_arml_fstat64(jitter, linux_env):
    # Parse arguments
    fd, statbuf = jitter.syscall_args_systemv(2)
    log.debug("sys_fstat(%d, %x)", fd, statbuf)

    # Stub
    info = linux_env.fstat(fd)
    data = _dump_struct_stat_arml(info)
    jitter.vm.set_mem(statbuf, data)
    jitter.syscall_ret_systemv(0)


def sys_generic_mmap(jitter, linux_env):
    # Parse arguments
    addr, len_, prot, flags, fd, off = jitter.syscall_args_systemv(6)
    log.debug("sys_mmap(%x, %x, %x, %x, %x, %x)", addr, len_, prot, flags, fd, off)

    # Stub
    addr = linux_env.mmap(addr, len_, prot & 0xFFFFFFFF, flags & 0xFFFFFFFF,
                          fd & 0xFFFFFFFF, off, jitter.vm)
    jitter.syscall_ret_systemv(addr)


def sys_generic_mmap2(jitter, linux_env):
    # Parse arguments
    addr, len_, prot, flags, fd, off = jitter.syscall_args_systemv(6)
    log.debug("sys_mmap2(%x, %x, %x, %x, %x, %x)", addr, len_, prot, flags, fd, off)
    off = off * 4096

    # Stub
    addr = linux_env.mmap(addr, len_, prot & 0xFFFFFFFF, flags & 0xFFFFFFFF,
                          fd & 0xFFFFFFFF, off, jitter.vm)
    jitter.syscall_ret_systemv(addr)


def sys_generic_mprotect(jitter, linux_env):
    # Parse arguments
    start, len_, prot = jitter.syscall_args_systemv(3)
    assert jitter.vm.is_mapped(start, len_)
    log.debug("sys_mprotect(%x, %x, %x)", start, len_, prot)

    # Do nothing
    jitter.syscall_ret_systemv(0)


def sys_generic_close(jitter, linux_env):
    # Parse arguments
    fd, = jitter.syscall_args_systemv(1)
    log.debug("sys_close(%x)", fd)

    # Stub
    linux_env.close(fd)
    jitter.syscall_ret_systemv(0)


def sys_x86_64_arch_prctl(jitter, linux_env):
    # Parse arguments
    code_name = {
        0x1001: "ARCH_SET_GS",
        0x1002: "ARCH_SET_FS",
        0x1003: "ARCH_GET_FS",
        0x1004: "ARCH_GET_GS",
        0x1011: "ARCH_GET_CPUID",
        0x1012: "ARCH_SET_CPUID",
        0x2001: "ARCH_MAP_VDSO_X32",
        0x2002: "ARCH_MAP_VDSO_32",
        0x2003: "ARCH_MAP_VDSO_64",
        0x3001: "ARCH_CET_STATUS",
        0x3002: "ARCH_CET_DISABLE",
        0x3003: "ARCH_CET_LOCK",
        0x3004: "ARCH_CET_EXEC",
        0x3005: "ARCH_CET_ALLOC_SHSTK",
        0x3006: "ARCH_CET_PUSH_SHSTK",
        0x3007: "ARCH_CET_LEGACY_BITMAP",
    }
    code = jitter.cpu.RDI
    rcode = code_name[code]
    addr = jitter.cpu.RSI
    log.debug("sys_arch_prctl(%s, %x)", rcode, addr)

    if code == 0x1002:
        jitter.cpu.set_segm_base(jitter.cpu.FS, addr)
    elif code == 0x3001:
        # CET status (disabled)
        jitter.vm.set_mem(addr, pck64(0))
    else:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_set_tid_address(jitter, linux_env):
    # Parse arguments
    tidptr = jitter.cpu.RDI
    # clear_child_tid = tidptr
    log.debug("sys_set_tid_address(%x)", tidptr)

    jitter.cpu.RAX = linux_env.process_tid


def sys_x86_64_set_robust_list(jitter, linux_env):
    # Parse arguments
    head = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    # robust_list = head
    log.debug("sys_set_robust_list(%x, %x)", head, len_)
    jitter.cpu.RAX = 0

def sys_x86_64_rt_sigprocmask(jitter, linux_env):
    # Parse arguments
    how = jitter.cpu.RDI
    nset = jitter.cpu.RSI
    oset = jitter.cpu.RDX
    sigsetsize = jitter.cpu.R10
    log.debug("sys_rt_sigprocmask(%x, %x, %x, %x)", how, nset, oset, sigsetsize)
    if oset != 0:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_prlimit64(jitter, linux_env):
    # Parse arguments
    pid = jitter.cpu.RDI
    resource = jitter.cpu.RSI
    new_rlim = jitter.cpu.RDX
    if new_rlim != 0:
        raise RuntimeError("Not implemented")
    old_rlim = jitter.cpu.R10
    log.debug("sys_prlimit64(%x, %x, %x, %x)", pid, resource, new_rlim,
              old_rlim)

    # Stub
    if resource == 3:
        # RLIMIT_STACK
        jitter.vm.set_mem(old_rlim,
                          struct.pack("QQ",
                                      0x100000,
                                      0x7fffffffffffffff, # RLIM64_INFINITY
                          ))
    else:
        raise RuntimeError("Not implemented")
    jitter.cpu.RAX = 0


def sys_x86_64_statfs(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    rpathname = jitter.get_c_str(pathname)
    log.debug("sys_statfs(%r, %x)", rpathname, buf)

    # Stub
    if not linux_env.filesystem.exists(rpathname):
        jitter.cpu.RAX = -1
    else:
        info = linux_env.filesystem.statfs()
        raise RuntimeError("Not implemented")


def sys_x86_64_ioctl(jitter, linux_env):
    # Parse arguments
    fd, cmd, arg = jitter.syscall_args_systemv(3)
    log.debug("sys_ioctl(%x, %x, %x)", fd, cmd, arg)

    info = linux_env.ioctl(fd, cmd, arg)
    if info is False:
        jitter.syscall_ret_systemv(-1)
    else:
        if cmd == termios.TCGETS:
            data = struct.pack("BBBB", *info)
            jitter.vm.set_mem(arg, data)
        elif cmd == termios.TIOCGWINSZ:
            data = struct.pack("HHHH", *info)
            jitter.vm.set_mem(arg, data)
        else:
            assert data is None
        jitter.syscall_ret_systemv(0)


def sys_arml_ioctl(jitter, linux_env):
    # Parse arguments
    fd, cmd, arg = jitter.syscall_args_systemv(3)
    log.debug("sys_ioctl(%x, %x, %x)", fd, cmd, arg)

    info = linux_env.ioctl(fd, cmd, arg)
    if info is False:
        jitter.syscall_ret_systemv(-1)
    else:
        if cmd == termios.TCGETS:
            data = struct.pack("BBBB", *info)
            jitter.vm.set_mem(arg, data)
        elif cmd == termios.TIOCGWINSZ:
            data = struct.pack("HHHH", *info)
            jitter.vm.set_mem(arg, data)
        else:
            assert data is None
        jitter.syscall_ret_systemv(0)

def sys_generic_open(jitter, linux_env):
    # Parse arguments
    filename, flags, mode = jitter.syscall_args_systemv(3)
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_open(%r, %x, %x)", rpathname, flags, mode)
    # Stub
    # 'mode' is ignored
    jitter.syscall_ret_systemv(linux_env.open_(rpathname, flags))


def sys_generic_write(jitter, linux_env):
    # Parse arguments
    fd, buf, count = jitter.syscall_args_systemv(3)
    log.debug("sys_write(%d, %x, %x)", fd, buf, count)

    # Stub
    data = jitter.vm.get_mem(buf, count)
    jitter.syscall_ret_systemv(linux_env.write(fd, data))


def sys_x86_64_getdents(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    dirent = jitter.cpu.RSI
    count = jitter.cpu.RDX
    log.debug("sys_getdents(%x, %x, %x)", fd, dirent, count)

    # Stub
    def packing_callback(cur_len, d_ino, d_type, name):
        # struct linux_dirent {
        #        unsigned long  d_ino;     /* Inode number */
        #        unsigned long  d_off;     /* Offset to next linux_dirent */
        #        unsigned short d_reclen;  /* Length of this linux_dirent */
        #        char           d_name[];  /* Filename (null-terminated) */
        #                          /* length is actually (d_reclen - 2 -
        #                             offsetof(struct linux_dirent, d_name)) */
        #        /*
        #        char           pad;       // Zero padding byte
        #        char           d_type;    // File type (only since Linux
        #                                  // 2.6.4); offset is (d_reclen - 1)
        #        */
        #    }
        d_reclen = 8 * 2 + 2 + 1 + len(name) + 1
        d_off = cur_len + d_reclen
        entry = struct.pack("QqH", d_ino, d_off, d_reclen) + \
                name.encode("utf8") + b"\x00" + struct.pack("B", d_type)
        assert len(entry) == d_reclen
        return entry

    out = linux_env.getdents(fd, count, packing_callback)
    jitter.vm.set_mem(dirent, out)
    jitter.cpu.RAX = len(out)


def sys_arml_getdents64(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.R0
    dirent = jitter.cpu.R1
    count = jitter.cpu.R2
    log.debug("sys_getdents64(%x, %x, %x)", fd, dirent, count)

    # Stub
    def packing_callback(cur_len, d_ino, d_type, name):
        # struct linux_dirent64 {
        #        ino64_t        d_ino;    /* 64-bit inode number */
        #        off64_t        d_off;    /* 64-bit offset to next structure */
        #        unsigned short d_reclen; /* Size of this dirent */
        #        unsigned char  d_type;   /* File type */
        #        char           d_name[]; /* Filename (null-terminated) */
        #    };
        d_reclen = 8 * 2 + 2 + 1 + len(name) + 1
        d_off = cur_len + d_reclen
        entry = struct.pack("QqHB", d_ino, d_off, d_reclen, d_type) + \
                name + b"\x00"
        assert len(entry) == d_reclen
        return entry

    out = linux_env.getdents(fd, count, packing_callback)
    jitter.vm.set_mem(dirent, out)
    jitter.cpu.R0 = len(out)


def sys_x86_64_newlstat(jitter, linux_env):
    # Parse arguments
    filename = jitter.cpu.RDI
    statbuf = jitter.cpu.RSI
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_newlstat(%s, %x)", rpathname, statbuf)

    # Stub
    if not linux_env.filesystem.exists(rpathname):
        # ENOENT (No such file or directory)
        jitter.cpu.RAX = -1
    else:
        info = linux_env.lstat(rpathname)
        data = _dump_struct_stat_x86_64(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.cpu.RAX = 0


def sys_arml_lstat64(jitter, linux_env):
    # Parse arguments
    filename = jitter.cpu.R0
    statbuf = jitter.cpu.R1
    rpathname = jitter.get_c_str(filename)
    log.debug("sys_newlstat(%s, %x)", rpathname, statbuf)

    # Stub
    if not linux_env.filesystem.exists(rpathname):
        # ENOENT (No such file or directory)
        jitter.cpu.R0 = -1
    else:
        info = linux_env.lstat(rpathname)
        data = _dump_struct_stat_arml(info)
        jitter.vm.set_mem(statbuf, data)
        jitter.cpu.R0 = 0


def sys_x86_64_lgetxattr(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    name = jitter.cpu.RSI
    value = jitter.cpu.RDX
    size = jitter.cpu.R10
    rpathname = jitter.get_c_str(pathname)
    rname = jitter.get_c_str(name)
    log.debug("sys_lgetxattr(%r, %r, %x, %x)", rpathname, rname, value, size)

    # Stub
    jitter.vm.set_mem(value, b"\x00" * size)
    jitter.cpu.RAX = 0


def sys_x86_64_getxattr(jitter, linux_env):
    # Parse arguments
    pathname = jitter.cpu.RDI
    name = jitter.cpu.RSI
    value = jitter.cpu.RDX
    size = jitter.cpu.R10
    rpathname = jitter.get_c_str(pathname)
    rname = jitter.get_c_str(name)
    log.debug("sys_getxattr(%r, %r, %x, %x)", rpathname, rname, value, size)

    # Stub
    jitter.vm.set_mem(value, b"\x00" * size)
    jitter.cpu.RAX = 0


def sys_x86_64_socket(jitter, linux_env):
    # Parse arguments
    family = jitter.cpu.RDI
    type_ = jitter.cpu.RSI
    protocol = jitter.cpu.RDX
    log.debug("sys_socket(%x, %x, %x)", family, type_, protocol)

    jitter.cpu.RAX = linux_env.socket(family, type_, protocol)


def sys_x86_64_connect(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    uservaddr = jitter.cpu.RSI
    addrlen = jitter.cpu.RDX
    raddr = jitter.get_c_str(uservaddr + 2)
    log.debug("sys_connect(%x, %r, %x)", fd, raddr, addrlen)

    # Stub
    # Always refuse the connection
    jitter.cpu.RAX = -1


def sys_x86_64_clock_gettime(jitter, linux_env):
    # Parse arguments
    which_clock = jitter.cpu.RDI
    tp = jitter.cpu.RSI
    log.debug("sys_clock_gettime(%x, %x)", which_clock, tp)

    # Stub
    value = linux_env.clock_gettime()
    jitter.vm.set_mem(tp, struct.pack("Q", value))
    jitter.cpu.RAX = 0


def sys_x86_64_lseek(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    offset = jitter.cpu.RSI
    whence = jitter.cpu.RDX
    log.debug("sys_lseek(%d, %x, %x)", fd, offset, whence)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    mask = (1 << 64) - 1
    if offset > (1 << 63):
        offset = - ((offset ^ mask) + 1)

    new_offset = fdesc.lseek(offset, whence)
    jitter.cpu.RAX = new_offset


def sys_x86_64_munmap(jitter, linux_env):
    # Parse arguments
    addr = jitter.cpu.RDI
    len_ = jitter.cpu.RSI
    log.debug("sys_munmap(%x, %x)", addr, len_)

    # Do nothing
    jitter.cpu.RAX = 0


def sys_x86_64_readlink(jitter, linux_env):
    # Parse arguments
    path = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    bufsize = jitter.cpu.RDX
    rpath = jitter.get_c_str(path)
    log.debug("sys_readlink(%r, %x, %x)", rpath, buf, bufsize)

    # Stub
    link = linux_env.filesystem.readlink(rpath)
    if link is None:
        # Not a link
        jitter.cpu.RAX = -1
    else:
        data = link[:bufsize - 1] + b"\x00"
        jitter.vm.set_mem(buf, data)
        jitter.cpu.RAX = len(data) - 1

def sys_x86_64_getpid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getpid()")

    # Stub
    jitter.cpu.RAX = linux_env.process_pid


def sys_x86_64_sysinfo(jitter, linux_env):
    # Parse arguments
    info = jitter.cpu.RDI
    log.debug("sys_sysinfo(%x)", info)

    # Stub
    data = struct.pack("QQQQQQQQQQHQQI",
                       0x1234, # uptime
                       0x2000, # loads (1 min)
                       0x2000, # loads (5 min)
                       0x2000, # loads (15 min)
                       0x10000000, # total ram
                       0x10000000, # free ram
                       0x10000000, # shared memory
                       0x0, # memory used by buffers
                       0x0, # total swap
                       0x0, # free swap
                       0x1, # nb current processes
                       0x0, # total high mem
                       0x0, # available high mem
                       0x1, # memory unit size
    )
    jitter.vm.set_mem(info, data)
    jitter.cpu.RAX = 0


def sys_generic_geteuid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_geteuid()")

    # Stub
    jitter.syscall_ret_systemv(linux_env.user_euid)


def sys_generic_getegid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getegid()")

    # Stub
    jitter.syscall_ret_systemv(linux_env.user_egid)


def sys_generic_getuid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getuid()")

    # Stub
    jitter.syscall_ret_systemv(linux_env.user_uid)


def sys_generic_getgid(jitter, linux_env):
    # Parse arguments
    log.debug("sys_getgid()")

    # Stub
    jitter.syscall_ret_systemv(linux_env.user_gid)


def sys_generic_setgid(jitter, linux_env):
    # Parse arguments
    gid, = jitter.syscall_args_systemv(1)
    log.debug("sys_setgid(%x)", gid)

    # Stub
    # Denied if different
    if gid != linux_env.user_gid:
        jitter.syscall_ret_systemv(-1)
    else:
        jitter.syscall_ret_systemv(0)


def sys_generic_setuid(jitter, linux_env):
    # Parse arguments
    uid, = jitter.syscall_args_systemv(1)
    log.debug("sys_setuid(%x)", uid)

    # Stub
    # Denied if different
    if uid != linux_env.user_uid:
        jitter.syscall_ret_systemv(-1)
    else:
        jitter.syscall_ret_systemv(0)


def sys_arml_set_tls(jitter, linux_env):
    # Parse arguments
    ptr = jitter.cpu.R0
    log.debug("sys_set_tls(%x)", ptr)

    # Stub
    linux_env.tls = ptr
    jitter.cpu.R0 = 0


def sys_generic_fcntl64(jitter, linux_env):
    # Parse arguments
    fd, cmd, arg = jitter.syscall_args_systemv(3)
    log.debug("sys_fcntl(%x, %x, %x)", fd, cmd, arg)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    if cmd == fcntl.F_GETFL:
        jitter.syscall_ret_systemv(fdesc.flags)
    elif cmd == fcntl.F_SETFL:
        # Ignore flag change
        jitter.syscall_ret_systemv(0)
    elif cmd == fcntl.F_GETFD:
        jitter.syscall_ret_systemv(fdesc.flags)
    elif cmd == fcntl.F_SETFD:
        # Ignore flag change
        jitter.syscall_ret_systemv(0)
    else:
        raise RuntimeError("Not implemented")


def sys_x86_64_pread64(jitter, linux_env):
    # Parse arguments
    fd = jitter.cpu.RDI
    buf = jitter.cpu.RSI
    count = jitter.cpu.RDX
    pos = jitter.cpu.R10
    log.debug("sys_pread64(%x, %x, %x, %x)", fd, buf, count, pos)

    # Stub
    fdesc = linux_env.file_descriptors[fd]
    cur_pos = fdesc.tell()
    fdesc.seek(pos)
    data = fdesc.read(count)
    jitter.vm.set_mem(buf, data)
    fdesc.seek(cur_pos)
    jitter.cpu.RAX = len(data)


def sys_arml_gettimeofday(jitter, linux_env):
    # Parse arguments
    tv = jitter.cpu.R0
    tz = jitter.cpu.R1
    log.debug("sys_gettimeofday(%x, %x)", tv, tz)

    # Stub
    value = linux_env.clock_gettime()
    if tv:
        jitter.vm.set_mem(tv, struct.pack("II", value, 0))
    if tz:
        jitter.vm.set_mem(tz, struct.pack("II", 0, 0))
    jitter.cpu.R0 = 0


def sys_mips32b_socket(jitter, linux_env):
    # Parse arguments
    family, type_, protocol = jitter.syscall_args_systemv(3)
    log.debug("sys_socket(%x, %x, %x)", family, type_, protocol)

    ret1 = linux_env.socket(family, type_, protocol)
    jitter.syscall_ret_systemv(ret1, 0, 0)


syscall_callbacks_x86_32 = {
    0x7A: sys_x86_32_newuname,
}


syscall_callbacks_x86_64 = {
    0x0: sys_generic_read,
    0x1: sys_generic_write,
    0x2: sys_generic_open,
    0x3: sys_generic_close,
    0x4: sys_x86_64_newstat,
    0x5: sys_x86_64_fstat,
    0x6: sys_x86_64_newlstat,
    0x8: sys_x86_64_lseek,
    0x9: sys_generic_mmap,
    0x10: sys_x86_64_ioctl,
    0xA: sys_generic_mprotect,
    0xB: sys_x86_64_munmap,
    0xC: sys_generic_brk,
    0xD: sys_x86_64_rt_sigaction,
    0xE: sys_x86_64_rt_sigprocmask,
    0x11: sys_x86_64_pread64,
    0x14: sys_x86_64_writev,
    0x15: sys_generic_access,
    0x27: sys_x86_64_getpid,
    0x29: sys_x86_64_socket,
    0x2A: sys_x86_64_connect,
    0x3F: sys_x86_64_newuname,
    0x48: sys_generic_fcntl64,
    0x4E: sys_x86_64_getdents,
    0x59: sys_x86_64_readlink,
    0x63: sys_x86_64_sysinfo,
    0x66: sys_generic_getuid,
    0x68: sys_generic_getgid,
    0x6B: sys_generic_geteuid,
    0x6C: sys_generic_getegid,
    0xE4: sys_x86_64_clock_gettime,
    0x89: sys_x86_64_statfs,
    0x9E: sys_x86_64_arch_prctl,
    0xBF: sys_x86_64_getxattr,
    0xC0: sys_x86_64_lgetxattr,
    0xDA: sys_x86_64_set_tid_address,
    0xE7: sys_generic_exit_group,
    0x101: sys_x86_64_openat,
    0x111: sys_x86_64_set_robust_list,
    0x12E: sys_x86_64_prlimit64,
}


syscall_callbacks_arml = {

    0x3: sys_generic_read,
    0x4: sys_generic_write,
    0x5: sys_generic_open,
    0x6: sys_generic_close,
    0x2d: sys_generic_brk,
    0x21: sys_generic_access,
    0x36: sys_arml_ioctl,
    0x7a: sys_arml_newuname,
    0x7d: sys_generic_mprotect,
    0x92: sys_arml_writev,
    0xc0: sys_generic_mmap2,
    0xc3: sys_arml_stat64,
    0xc4: sys_arml_lstat64,
    0xc5: sys_arml_fstat64,
    0xc7: sys_generic_getuid,
    0xc8: sys_generic_getgid,
    0xc9: sys_generic_geteuid,
    0xcA: sys_generic_getegid,
    0x4e: sys_arml_gettimeofday,
    0xd5: sys_generic_setuid,
    0xd6: sys_generic_setgid,
    0xd9: sys_arml_getdents64,
    0xdd: sys_generic_fcntl64,
    0xf8: sys_generic_exit_group,

    # ARM-specific ARM_NR_BASE == 0x0f0000
    0xf0005: sys_arml_set_tls,
}


syscall_callbacks_mips32b = {
    0x1057: sys_mips32b_socket,
}

def syscall_x86_64_exception_handler(linux_env, syscall_callbacks, jitter):
    """Call to actually handle an EXCEPT_SYSCALL exception
    In the case of an error raised by a SYSCALL, call the corresponding
    syscall_callbacks
    @linux_env: LinuxEnvironment_x86_64 instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)
    """

    # Dispatch to SYSCALL stub
    syscall_number = jitter.cpu.RAX
    callback = syscall_callbacks.get(syscall_number)
    if callback is None:
        raise KeyError(
            "No callback found for syscall number 0x%x" % syscall_number
        )
    callback(jitter, linux_env)
    log.debug("-> %x", jitter.cpu.RAX)

    # Clean exception and move pc to the next instruction, to let the jitter
    # continue
    jitter.cpu.set_exception(jitter.cpu.get_exception() ^ EXCEPT_SYSCALL)
    return True



def syscall_x86_32_exception_handler(linux_env, syscall_callbacks, jitter):
    """Call to actually handle an EXCEPT_INT_XX exception
    In the case of an error raised by a SYSCALL, call the corresponding
    syscall_callbacks
    @linux_env: LinuxEnvironment_x86_32 instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)
    """
    # Ensure the jitter has break on a SYSCALL
    if jitter.cpu.interrupt_num != 0x80:
        return True

    # Dispatch to SYSCALL stub
    syscall_number = jitter.cpu.EAX
    callback = syscall_callbacks.get(syscall_number)
    if callback is None:
        raise KeyError(
            "No callback found for syscall number 0x%x" % syscall_number
        )
    callback(jitter, linux_env)
    log.debug("-> %x", jitter.cpu.EAX)

    # Clean exception and move pc to the next instruction, to let the jitter
    # continue
    jitter.cpu.set_exception(jitter.cpu.get_exception() ^ EXCEPT_INT_XX)
    return True



def syscall_arml_exception_handler(linux_env, syscall_callbacks, jitter):
    """Call to actually handle an EXCEPT_PRIV_INSN exception
    In the case of an error raised by a SYSCALL, call the corresponding
    syscall_callbacks
    @linux_env: LinuxEnvironment_arml instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)
    """
    # Ensure the jitter has break on a SYSCALL
    if jitter.cpu.interrupt_num != 0x0:
        return True

    # Dispatch to SYSCALL stub
    syscall_number = jitter.cpu.R7
    callback = syscall_callbacks.get(syscall_number)
    if callback is None:
        raise KeyError(
            "No callback found for syscall number 0x%x" % syscall_number
        )
    callback(jitter, linux_env)
    log.debug("-> %x", jitter.cpu.R0)

    # Clean exception and move pc to the next instruction, to let the jitter
    # continue
    jitter.cpu.set_exception(jitter.cpu.get_exception() ^ EXCEPT_INT_XX)
    return True



def syscall_mips32b_exception_handler(linux_env, syscall_callbacks, jitter):
    """Call to actually handle an EXCEPT_SYSCALL exception
    In the case of an error raised by a SYSCALL, call the corresponding
    syscall_callbacks
    @linux_env: LinuxEnvironment_mips32b instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)
    """

    # Dispatch to SYSCALL stub
    syscall_number = jitter.cpu.V0
    callback = syscall_callbacks.get(syscall_number)
    if callback is None:
        raise KeyError(
            "No callback found for syscall number 0x%x" % syscall_number
        )
    callback(jitter, linux_env)
    log.debug("-> %x", jitter.cpu.V0)

    # Clean exception and move pc to the next instruction, to let the jitter
    # continue
    jitter.cpu.set_exception(jitter.cpu.get_exception() ^ EXCEPT_SYSCALL)
    return True



def enable_syscall_handling(jitter, linux_env, syscall_callbacks):
    """Activate handling of syscall for the current jitter instance.
    Syscall handlers are provided by @syscall_callbacks
    @linux_env: LinuxEnvironment instance
    @syscall_callbacks: syscall number -> func(jitter, linux_env)

    Example of use:
    >>> linux_env = LinuxEnvironment_x86_64()
    >>> enable_syscall_handling(jitter, linux_env, syscall_callbacks_x86_64)
    """
    arch_name = jitter.jit.arch_name
    if arch_name == "x8664":
        handler = syscall_x86_64_exception_handler
        handler = functools.partial(handler, linux_env, syscall_callbacks)
        jitter.add_exception_handler(EXCEPT_SYSCALL, handler)
    elif arch_name == "x8632":
        handler = syscall_x86_32_exception_handler
        handler = functools.partial(handler, linux_env, syscall_callbacks)
        jitter.add_exception_handler(EXCEPT_INT_XX, handler)
    elif arch_name == "arml":
        handler = syscall_arml_exception_handler
        handler = functools.partial(handler, linux_env, syscall_callbacks)
        jitter.add_exception_handler(EXCEPT_INT_XX, handler)
    elif arch_name == "mips32b":
        handler = syscall_mips32b_exception_handler
        handler = functools.partial(handler, linux_env, syscall_callbacks)
        jitter.add_exception_handler(EXCEPT_SYSCALL, handler)
    else:
        raise ValueError("No syscall handler implemented for %s" % arch_name)
