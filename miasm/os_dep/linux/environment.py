from __future__ import print_function
from collections import namedtuple
import functools
import logging
import os
import re
import struct
import termios

from future.utils import viewitems

from miasm.core.interval import interval
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE


REGEXP_T = type(re.compile(''))

StatInfo = namedtuple("StatInfo", [
    "st_dev", "st_ino", "st_nlink", "st_mode", "st_uid", "st_gid", "st_rdev",
    "st_size", "st_blksize", "st_blocks", "st_atime", "st_atimensec",
    "st_mtime", "st_mtimensec", "st_ctime", "st_ctimensec"
])
StatFSInfo = namedtuple("StatFSInfo", [
    "f_type", "f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files",
    "f_ffree", "f_fsid", "f_namelen", "f_frsize", "f_flags", "f_spare",
])

log = logging.getLogger("environment")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)

class FileDescriptor(object):
    """Stand for a file descriptor on a system

    According to inode(7), following types are possibles:
     - socket
     - symbolic link
     - regular file
     - block device
     - directory
     - character device
     - FIFO
    """

    # st_mode's file type
    file_type = None
    # st_mode's file mode (9 least bits are file permission bits)
    file_mode = 0o0777
    # st_dev / st_rdev
    cont_device_id = None
    device_id = 0
    # inode number (st_ino)
    inode = None
    # Number of hardlink (st_nlink)
    nlink = 0
    # Owner / group
    uid = None
    gid = None
    # Size (st_size / st_blksize / st_blocks)
    size = 0
    blksize = 0
    blocks = 0
    # Times
    atime = 0
    atimensec = 0
    mtime = 0
    mtimensec = 0
    ctime = 0
    ctimensec = 0

    def __init__(self, number):
        self.number = number
        self.is_closed = False

    def stat(self):
        mode = self.file_type | self.file_mode
        return StatInfo(
            st_dev=self.cont_device_id, st_ino=self.inode,
            st_nlink=self.nlink, st_mode=mode,
            st_uid=self.uid, st_gid=self.gid,
            st_rdev=self.device_id, st_size=self.size,
            st_blksize=self.blksize, st_blocks=self.blocks,
            st_atime=self.atime, st_atimensec=self.atimensec,
            st_mtime=self.mtime, st_mtimensec=self.mtimensec,
            st_ctime=self.ctime, st_ctimensec=self.ctimensec
        )

    def close(self):
        self.is_closed = True


class FileDescriptorCharDevice(FileDescriptor):
    file_type = 0o0020000 # S_IFCHR
    file_mode = 0o0620
    cont_device_id = 1
    device_id = 1


class FileDescriptorSTDIN(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDIN"""
    inode = 0

    def read(self, count):
        raise RuntimeError("Not implemented")


class FileDescriptorSTDOUT(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDOUT"""
    inode = 1

    def write(self, data):
        print("[STDOUT] %s" % data.rstrip())


class FileDescriptorSTDERR(FileDescriptorCharDevice):
    """Special file descriptor standinf for STDERR"""
    inode = 2

    def write(self, data):
        print("[STDERR] %s" % data.rstrip())


class FileDescriptorDirectory(FileDescriptor):
    """FileDescription designing a directory"""

    file_type = 0o0040000 # S_IFDIR

    def __init__(self, number, flags, filesystem, real_path):
        super(FileDescriptorDirectory, self).__init__(number)
        self.filesystem = filesystem
        self.real_path = real_path
        self.cur_listdir = None
        self.flags = flags

    def listdir(self):
        if self.cur_listdir is None:
            self.cur_listdir = os.listdir(self.real_path)
        while self.cur_listdir:
            yield self.cur_listdir.pop()


class FileDescriptorRegularFile(FileDescriptor):
    """FileDescriptor designing a regular file"""

    file_type = 0o0100000 # S_IFREG

    def __init__(self, number, flags, filesystem, real_fd):
        super(FileDescriptorRegularFile, self).__init__(number)
        self.flags = flags
        self.filesystem = filesystem
        self.real_fd = real_fd

    def write(self, data):
        raise RuntimeError("Not implemented")

    def read(self, count):
        return os.read(self.real_fd, count)

    def close(self):
        super(FileDescriptorRegularFile, self).close()
        return os.close(self.real_fd)

    def lseek(self, offset, whence):
        return os.lseek(self.real_fd, offset, whence) # SEEK_SET

    def tell(self):
        return self.lseek(0, 1) # SEEK_CUR

    def seek(self, offset):
        return self.lseek(offset, 0) # SEEK_SET


class FileDescriptorSocket(FileDescriptor):
    """FileDescription standing for a socket"""

    file_type = 0o0140000 # S_IFSOCK

    def __init__(self, number, family, type_, protocol):
        super(FileDescriptorSocket, self).__init__(number)
        self.family = family
        self.type_ = type_
        self.protocol = protocol


class FileSystem(object):
    """File system abstraction
    Provides standard operations on the filesystem, (a bit like FUSE)

    API using FileSystem only used sandbox-side path. FileSystem should be the
    only object able to interact with real path, outside the sandbox.

    Thus, if `resolve_path` is correctly implemented and used, it should not be
    possible to modify files outside the sandboxed path
    """

    device_id = 0x1234 # ID of device containing file (stat.st_dev)
    blocksize = 0x1000 # Size of block on this filesystem
    f_type = 0xef53 # (Type of filesystem) EXT4_SUPER_MAGIC
    nb_total_block = 0x1000
    nb_free_block = 0x100
    nb_avail_block = nb_free_block # Available to unprivileged user
    nb_total_fnode = 100 # Total file nodes in filesystem
    nb_free_fnode = 50
    max_filename_len = 256
    fragment_size = 0
    mount_flags = 0

    def __init__(self, base_path, linux_env):
        self.base_path = base_path
        self.linux_env = linux_env
        self.passthrough = []
        self.path_to_inode = {} # Real path (post-resolution) -> inode number

    def resolve_path(self, path, follow_link=True):
        """Resolve @path to the corresponding sandboxed path"""

        # path_bytes is used for Python 2 / Python 3 compatibility
        path_bytes = not isinstance(path, str)
        path_sep = os.path.sep.encode() if path_bytes else os.path.sep

        if path_bytes:
            def _convert(subpath):
                if not isinstance(subpath, str):
                    return subpath
                return subpath.encode()
            def _convert_re(expr):
                if isinstance(expr.pattern, str):
                    try:
                        return re.compile(
                            expr.pattern.encode(),
                            flags=expr.flags & ~re.UNICODE
                        )
                    except UnicodeEncodeError:
                        # Will never match
                        log.warning(
                            'Cannot convert regexp to bytes %r %r',
                            expr.pattern,
                            expr.flags,
                            exc_info=True,
                        )
                        return re.compile(b'$X')
                return expr
        else:
            def _convert(subpath):
                if not isinstance(subpath, str):
                    return subpath.decode()
                return subpath
            def _convert_re(expr):
                if not isinstance(expr.pattern, str):
                    try:
                        return re.compile(
                            expr.pattern.decode(),
                            flags=expr.flags & re.UNICODE
                        )
                    except UnicodeDecodeError:
                        # Will never match
                        log.warning(
                            'Cannot convert regexp to str %r %r',
                            expr.pattern,
                            expr.flags,
                            exc_info=True,
                        )
                        return re.compile('$X')
                return expr

        # Remove '../', etc.
        path = os.path.normpath(path)

        # Passthrough
        for passthrough in self.passthrough:
            if isinstance(passthrough, REGEXP_T):
                if _convert_re(passthrough).match(path):
                    return path
            elif _convert(passthrough) == path:
                return path

        # Remove leading '/' if any
        path = path.lstrip(path_sep)

        base_path = os.path.abspath(_convert(self.base_path))
        out_path = os.path.join(base_path, path)
        assert out_path.startswith(base_path + path_sep)
        if os.path.islink(out_path):
            link_target = os.readlink(out_path)
            # Link can be absolute or relative -> absolute
            link = os.path.normpath(os.path.join(os.path.dirname(path), link_target))
            if follow_link:
                out_path = self.resolve_path(link)
            else:
                out_path = link
        return out_path

    def get_path_inode(self, real_path):
        inode = self.path_to_inode.setdefault(real_path, len(self.path_to_inode))
        return inode

    def exists(self, path):
        sb_path = self.resolve_path(path)
        return os.path.exists(sb_path)

    def readlink(self, path):
        sb_path = self.resolve_path(path, follow_link=False)
        if not os.path.islink(sb_path):
            return None
        return os.readlink(sb_path)

    def statfs(self):
        return StatFSInfo(
            f_type=self.f_type, f_bsize=self.blocksize,
            f_blocks=self.nb_total_block, f_bfree=self.nb_free_block,
            f_bavail=self.nb_avail_block, f_files=self.nb_total_fnode,
            f_ffree=self.nb_free_fnode, f_fsid=self.device_id,
            f_namelen=self.max_filename_len,
            f_frsize=self.fragment_size, f_flags=self.mount_flags, f_spare=0)

    def getattr_(self, path, follow_link=True):
        sb_path = self.resolve_path(path, follow_link=follow_link)
        flags = self.linux_env.O_RDONLY
        if os.path.isdir(sb_path):
            flags |= self.linux_env.O_DIRECTORY

        fd = self.open_(path, flags, follow_link=follow_link)
        info = self.linux_env.fstat(fd)
        self.linux_env.close(fd)
        return info

    def open_(self, path, flags, follow_link=True):
        path = self.resolve_path(path, follow_link=follow_link)
        if not os.path.exists(path):
            # ENOENT (No such file or directory)
            return -1
        fd = self.linux_env.next_fd()
        acc_mode = flags & self.linux_env.O_ACCMODE

        if os.path.isdir(path):
            assert flags & self.linux_env.O_DIRECTORY == self.linux_env.O_DIRECTORY
            if acc_mode == self.linux_env.O_RDONLY:
                fdesc = FileDescriptorDirectory(fd, flags, self, path)
            else:
                raise RuntimeError("Not implemented")
        elif os.path.isfile(path):
            if acc_mode == os.O_RDONLY:
                # Read only
                real_fd = os.open(path, os.O_RDONLY)
            else:
                raise RuntimeError("Not implemented")
            fdesc = FileDescriptorRegularFile(fd, flags, self, real_fd)

        elif os.path.islink(path):
            raise RuntimeError("Not implemented")
        else:
            raise RuntimeError("Unknown file type for %r" % path)

        self.linux_env.file_descriptors[fd] = fdesc
        # Set stat info
        fdesc.cont_device_id = self.device_id
        fdesc.inode = self.get_path_inode(path)
        fdesc.uid = self.linux_env.user_uid
        fdesc.gid = self.linux_env.user_gid
        size = os.path.getsize(path)
        fdesc.size = size
        fdesc.blksize = self.blocksize
        fdesc.blocks = (size + ((512 - (size % 512)) % 512)) // 512
        return fd


class Networking(object):
    """Network abstraction"""

    def __init__(self, linux_env):
        self.linux_env = linux_env

    def socket(self, family, type_, protocol):
        fd = self.linux_env.next_fd()
        fdesc = FileDescriptorSocket(fd, family, type_, protocol)
        self.linux_env.file_descriptors[fd] = fdesc
        return fd


class LinuxEnvironment(object):
    """A LinuxEnvironment regroups information to simulate a Linux-like
    environment"""

    # To be overridden
    platform_arch = None

    # User information
    user_uid = 1000
    user_euid = 1000
    user_gid = 1000
    user_egid = 1000
    user_name = b"user"

    # Memory mapping information
    brk_current = 0x74000000
    mmap_current = 0x75000000

    # System information
    sys_sysname = b"Linux"
    sys_nodename = b"user-pc"
    sys_release = b"4.13.0-19-generic"
    sys_version = b"#22-Ubuntu"
    sys_machine = None

    # Filesystem
    filesystem_base = "file_sb"
    file_descriptors = None

    # Current process
    process_tid = 1000
    process_pid = 1000

    # Syscall restrictions
    ioctl_allowed = None # list of (fd, cmd), None value for wildcard
    ioctl_disallowed = None # list of (fd, cmd), None value for wildcard

    # Time
    base_time = 1531900000

    # Arch specific constant
    O_ACCMODE = None
    O_CLOEXEC = None
    O_DIRECTORY = None
    O_LARGEFILE = None
    O_NONBLOCK = None
    O_RDONLY = None

    def __init__(self):
        stdin = FileDescriptorSTDIN(0)
        stdout = FileDescriptorSTDOUT(1)
        stderr = FileDescriptorSTDERR(2)
        for std in [stdin, stdout, stderr]:
            std.uid = self.user_uid
            std.gid = self.user_gid
        self.file_descriptors = {
            0: stdin,
            1: stdout,
            2: stderr,
        }
        self.ioctl_allowed = [
            (0, termios.TCGETS),
            (0, termios.TIOCGWINSZ),
            (0, termios.TIOCSWINSZ),
            (1, termios.TCGETS),
            (1, termios.TIOCGWINSZ),
            (1, termios.TIOCSWINSZ),
        ]
        self.ioctl_disallowed = [
            (2, termios.TCGETS),
            (0, termios.TCSETSW),
        ]
        self.filesystem = FileSystem(self.filesystem_base, self)
        self.network = Networking(self)

    def next_fd(self):
        return len(self.file_descriptors)

    def clock_gettime(self):
        out = self.base_time
        self.base_time += 1
        return out

    def open_(self, path, flags, follow_link=True):
        """Stub for 'open' syscall"""
        return self.filesystem.open_(path, flags, follow_link=follow_link)

    def socket(self, family, type_, protocol):
        """Stub for 'socket' syscall"""
        return self.network.socket(family, type_, protocol)

    def fstat(self, fd):
        """Get file status through fd"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        return fdesc.stat()

    def stat(self, path):
        """Get file status through path"""
        return self.filesystem.getattr_(path)

    def lstat(self, path):
        """Get file status through path (not following links)"""
        return self.filesystem.getattr_(path, follow_link=False)

    def close(self, fd):
        """Stub for 'close' syscall"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        return fdesc.close()

    def write(self, fd, data):
        """Stub for 'write' syscall"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        fdesc.write(data)
        return len(data)

    def read(self, fd, count):
        """Stub for 'read' syscall"""
        fdesc = self.file_descriptors.get(fd)
        if fdesc is None:
            return None
        return fdesc.read(count)

    def getdents(self, fd, count, packing_callback):
        """Stub for 'getdents' syscall

        'getdents64' must be handled by caller (only the structure layout is
        modified)

        @fd: getdents' fd argument
        @count: getdents' count argument
        @packing_callback(cur_len, d_ino, d_type, name) -> entry
        """
        fdesc = self.file_descriptors[fd]
        if not isinstance(fdesc, FileDescriptorDirectory):
            raise RuntimeError("Not implemented")

        out = b""
        # fdesc.listdir continues from where it stopped
        for name in fdesc.listdir():
            d_ino = 1 # Not the real one
            d_type = 0 # DT_UNKNOWN (getdents(2) "All applications must properly
                       # handle a return of DT_UNKNOWN.")
            entry = packing_callback(len(out), d_ino, d_type, name)

            if len(out) + len(entry) > count:
                # Report to a further call
                fdesc.cur_listdir.append(name)
                break
            out = out + entry
        return out

    def ioctl(self, fd, cmd, arg):
        """Stub for 'ioctl' syscall
        Return the list of element to pack back depending on target ioctl
        If the ioctl is disallowed, return False
        """
        allowed = False
        disallowed = False
        for test in [(fd, cmd), (None, cmd), (fd, None)]:
            if test in self.ioctl_allowed:
                allowed = True
            if test in self.ioctl_disallowed:
                disallowed = True

        if allowed and disallowed:
            raise ValueError("fd: %x, cmd: %x is allowed and disallowed" % (fd, cmd))

        if allowed:
            if cmd == termios.TCGETS:
                return 0, 0, 0, 0
            elif cmd == termios.TIOCGWINSZ:
                # struct winsize
                # {
                #   unsigned short ws_row;	/* rows, in characters */
                #   unsigned short ws_col;	/* columns, in characters */
                #   unsigned short ws_xpixel;	/* horizontal size, pixels */
                #   unsigned short ws_ypixel;	/* vertical size, pixels */
                # };
                return 1000, 360, 1000, 1000
            elif cmd == termios.TIOCSWINSZ:
                # Ignore it
                return
            else:
                raise RuntimeError("Not implemented")

        elif disallowed:
            return False

        else:
            raise KeyError("Unknown ioctl fd:%x cmd:%x" % (fd, cmd))

    def mmap(self, addr, len_, prot, flags, fd, off, vmmngr):
        """Stub for 'mmap' syscall

        'mmap2' must be implemented by calling this function with off * 4096
        """
        if addr == 0:
            addr = self.mmap_current
            self.mmap_current += (len_ + 0x1000) & ~0xfff

        all_mem = vmmngr.get_all_memory()
        mapped = interval(
            [
                (start, start + info["size"] - 1)
                for start, info in viewitems(all_mem)
            ]
        )

        MAP_FIXED = 0x10
        if flags & MAP_FIXED:
            # Alloc missing and override
            missing = interval([(addr, addr + len_ - 1)]) - mapped
            for start, stop in missing:
                vmmngr.add_memory_page(
                    start,
                    PAGE_READ|PAGE_WRITE,
                    b"\x00" * (stop - start + 1),
                    "mmap allocated"
                )
        else:
            # Find first candidate segment nearby addr
            for start, stop in mapped:
                if stop < addr:
                    continue
                rounded = (stop + 1 + 0x1000) & ~0xfff
                if (interval([(rounded, rounded + len_)]) & mapped).empty:
                    addr = rounded
                    break
            else:
                assert (interval([(addr, addr + len_)]) & mapped).empty

            vmmngr.add_memory_page(
                addr,
                PAGE_READ|PAGE_WRITE,
                b"\x00" * len_,
                "mmap allocated"
            )

        if fd == 0xffffffff:
            MAP_ANONYMOUS = 0x20    # mman.h
            # fd and offset are ignored if MAP_ANONYMOUS flag is present
            if not(flags & MAP_ANONYMOUS) and off != 0:
                raise RuntimeError("Not implemented")
            data = b"\x00" * len_
        else:
            fdesc = self.file_descriptors[fd]
            cur_pos = fdesc.tell()
            fdesc.seek(off)
            data = fdesc.read(len_)
            fdesc.seek(cur_pos)

        vmmngr.set_mem(addr, data)
        return addr

    def brk(self, addr, vmmngr):
        """Stub for 'brk' syscall"""
        if addr == 0:
            addr = self.brk_current
        else:
            all_mem = vmmngr.get_all_memory()
            mapped = interval(
                [
                    (start, start + info["size"] - 1)
                    for start, info in viewitems(all_mem)
                ]
            )

            # Alloc missing and override
            missing = interval([(self.brk_current, addr)]) - mapped
            for start, stop in missing:
                vmmngr.add_memory_page(
                    start,
                    PAGE_READ|PAGE_WRITE,
                    b"\x00" * (stop - start + 1),
                    "BRK"
                )

            self.brk_current = addr
        return addr


class LinuxEnvironment_x86_32(LinuxEnvironment):
    platform_arch = b"x86_32"
    sys_machine = b"x86_32"

    # TODO FIXME
    ## O_ACCMODE = 0x3
    ## O_CLOEXEC = 0x80000
    ## O_DIRECTORY = 0x10000
    ## O_LARGEFILE = 0x8000
    ## O_NONBLOCK = 0x800
    ## O_RDONLY = 0


class LinuxEnvironment_x86_64(LinuxEnvironment):
    platform_arch = b"x86_64"
    sys_machine = b"x86_64"

    O_ACCMODE = 0x3
    O_CLOEXEC = 0x80000
    O_DIRECTORY = 0x10000
    O_LARGEFILE = 0x8000
    O_NONBLOCK = 0x800
    O_RDONLY = 0


class LinuxEnvironment_arml(LinuxEnvironment):
    platform_arch = b"arml"
    sys_machine = b"arml"

    O_ACCMODE = 0x3
    O_CLOEXEC = 0x80000
    O_DIRECTORY = 0x4000
    O_LARGEFILE = 0x20000
    O_NONBLOCK = 0x800
    O_RDONLY = 0

    # ARM specific
    tls = 0
    # get_tls: __kuser_helper_version >= 1
    # cmpxchg: __kuser_helper_version >= 2
    # memory_barrier: __kuser_helper_version >= 3
    kuser_helper_version = 3


class LinuxEnvironment_mips32b(LinuxEnvironment):
    platform_arch = b"mips32b"
    sys_machine = b"mips32b"


class AuxVec(object):
    """Auxiliary vector abstraction, filled with default values
    (mainly based on https://lwn.net/Articles/519085)

    # Standard usage
    >>> auxv = AuxVec(elf_base_addr, cont_target.entry_point, linux_env)

    # Enable AT_SECURE
    >>> auxv = AuxVec(..., AuxVec.AT_SECURE=1)
    # Modify AT_RANDOM
    >>> auxv = AuxVec(..., AuxVec.AT_RANDOM="\x00"*0x10)

    # Using AuxVec instance for stack preparation
    # First, fill memory with vectors data
    >>> for AT_number, data in auxv.data_to_map():
            dest_ptr = ...
            copy_to_dest(data, dest_ptr)
            auxv.ptrs[AT_number] = dest_ptr
    # Then, get the key: value (with value being sometime a pointer)
    >>> for auxid, auxval in auxv.iteritems():
            ...
    """

    AT_PHDR = 3
    AT_PHNUM = 5
    AT_PAGESZ = 6
    AT_ENTRY = 9
    AT_UID = 11
    AT_EUID = 12
    AT_GID = 13
    AT_EGID = 14
    AT_PLATFORM = 15
    AT_HWCAP = 16
    AT_SECURE = 23
    AT_RANDOM = 25
    AT_SYSINFO_EHDR = 33

    def __init__(self, elf_phdr_vaddr, entry_point, linux_env, **kwargs):
        """Instantiate an AuxVec, with required elements:
        - elf_phdr_vaddr: virtual address of the ELF's PHDR in memory
        - entry_point: virtual address of the ELF entry point
        - linux_env: LinuxEnvironment instance, used to provides some of the
          option values

        Others options can be overridden by named arguments

        """
        self.info = {
            self.AT_PHDR: elf_phdr_vaddr,
            self.AT_PHNUM: 9,
            self.AT_PAGESZ: 0x1000,
            self.AT_ENTRY: entry_point,
            self.AT_UID: linux_env.user_uid,
            self.AT_EUID: linux_env.user_euid,
            self.AT_GID: linux_env.user_gid,
            self.AT_EGID: linux_env.user_egid,
            self.AT_PLATFORM: linux_env.platform_arch,
            self.AT_HWCAP: 0,
            self.AT_SECURE: 0,
            self.AT_RANDOM: b"\x00" * 0x10,
            # vDSO is not mandatory
            self.AT_SYSINFO_EHDR: None,
        }
        self.info.update(kwargs)
        self.ptrs = {} # info key -> corresponding virtual address

    def data_to_map(self):
        """Iterator on (AT_number, data)
        Once the data has been mapped, the corresponding ptr must be set in
        'self.ptrs[AT_number]'
        """
        for AT_number in [self.AT_PLATFORM, self.AT_RANDOM]:
            yield (AT_number, self.info[AT_number])

    def iteritems(self):
        """Iterator on auxiliary vector id and values"""
        for AT_number, value in viewitems(self.info):
            if AT_number in self.ptrs:
                value = self.ptrs[AT_number]
            if value is None:
                # AT to ignore
                continue
            yield (AT_number, value)

    items = iteritems

def prepare_loader_x86_64(jitter, argv, envp, auxv, linux_env,
                          hlt_address=0x13371acc):
    """Fill the environment with enough information to run a linux loader

    @jitter: Jitter instance
    @argv: list of strings
    @envp: dict of environment variables names to their values
    @auxv: AuxVec instance
    @hlt_address (default to 0x13371acc): stopping address

    Example of use:
    >>> jitter = machine.jitter()
    >>> jitter.init_stack()
    >>> linux_env = LinuxEnvironment_x86_64()
    >>> argv = ["/bin/ls", "-lah"]
    >>> envp = {"PATH": "/usr/local/bin", "USER": linux_env.user_name}
    >>> auxv = AuxVec(elf_base_addr, entry_point, linux_env)
    >>> prepare_loader_x86_64(jitter, argv, envp, auxv, linux_env)
    # One may want to enable syscall handling here
    # The program can now run from the loader
    >>> jitter.init_run(ld_entry_point)
    >>> jitter.continue_run()
    """
    # Stack layout looks like
    # [data]
    #  - auxv values
    #  - envp name=value
    #  - argv arguments
    # [auxiliary vector]
    # [environment pointer]
    # [argument vector]

    for AT_number, data in auxv.data_to_map():
        data += b"\x00"
        jitter.cpu.RSP -= len(data)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, data)
        auxv.ptrs[AT_number] = ptr

    env_ptrs = []
    for name, value in viewitems(envp):
        env = b"%s=%s\x00" % (name, value)
        jitter.cpu.RSP -= len(env)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, env)
        env_ptrs.append(ptr)

    argv_ptrs = []
    for arg in argv:
        arg += b"\x00"
        jitter.cpu.RSP -= len(arg)
        ptr = jitter.cpu.RSP
        jitter.vm.set_mem(ptr, arg)
        argv_ptrs.append(ptr)

    jitter.push_uint64_t(hlt_address)
    jitter.push_uint64_t(0)
    jitter.push_uint64_t(0)
    for auxid, auxval in viewitems(auxv):
        jitter.push_uint64_t(auxval)
        jitter.push_uint64_t(auxid)
    jitter.push_uint64_t(0)
    for ptr in reversed(env_ptrs):
        jitter.push_uint64_t(ptr)
    jitter.push_uint64_t(0)
    for ptr in reversed(argv_ptrs):
        jitter.push_uint64_t(ptr)
    jitter.push_uint64_t(len(argv))



def _arml__kuser_get_tls(linux_env, jitter):
    # __kuser_get_tls
    jitter.pc = jitter.cpu.LR
    jitter.cpu.R0 = linux_env.tls
    return True

def _arml__kuser_cmpxchg(jitter):
    oldval = jitter.cpu.R0
    newval = jitter.cpu.R1
    ptr = jitter.cpu.R2

    value = struct.unpack("<I", jitter.vm.get_mem(ptr, 4))[0]
    if value == oldval:
        jitter.vm.set_mem(ptr, struct.pack("<I", newval))
        jitter.cpu.R0 = 0
        jitter.cpu.cf = 1
    else:
        jitter.cpu.R0 = -1
        jitter.cpu.cf = 0

    jitter.pc = jitter.cpu.LR
    return True

def _arml__kuser_memory_barrier(jitter):
    # __kuser_memory_barrier
    jitter.pc = jitter.cpu.LR
    return True

def _arml__kuser_helper_version(linux_env, jitter):
    jitter.pc = jitter.cpu.LR
    jitter.cpu.R0 = linux_env.kuser_helper_version
    return True


def prepare_loader_arml(jitter, argv, envp, auxv, linux_env,
                        hlt_address=0x13371acc):
    """Fill the environment with enough information to run a linux loader

    @jitter: Jitter instance
    @argv: list of strings
    @envp: dict of environment variables names to their values
    @auxv: AuxVec instance
    @hlt_address (default to 0x13371acc): stopping address

    Example of use:
    >>> jitter = machine.jitter()
    >>> jitter.init_stack()
    >>> linux_env = LinuxEnvironment_arml()
    >>> argv = ["/bin/ls", "-lah"]
    >>> envp = {"PATH": "/usr/local/bin", "USER": linux_env.user_name}
    >>> auxv = AuxVec(elf_base_addr, entry_point, linux_env)
    >>> prepare_loader_arml(jitter, argv, envp, auxv, linux_env)
    # One may want to enable syscall handling here
    # The program can now run from the loader
    >>> jitter.init_run(ld_entry_point)
    >>> jitter.continue_run()
    """
    # Stack layout looks like
    # [data]
    #  - auxv values
    #  - envp name=value
    #  - argv arguments
    # [auxiliary vector]
    # [environment pointer]
    # [argument vector]

    for AT_number, data in auxv.data_to_map():
        data += b"\x00"
        jitter.cpu.SP -= len(data)
        ptr = jitter.cpu.SP
        jitter.vm.set_mem(ptr, data)
        auxv.ptrs[AT_number] = ptr

    env_ptrs = []
    for name, value in viewitems(envp):
        env = b"%s=%s\x00" % (name, value)
        jitter.cpu.SP -= len(env)
        ptr = jitter.cpu.SP
        jitter.vm.set_mem(ptr, env)
        env_ptrs.append(ptr)

    argv_ptrs = []
    for arg in argv:
        arg += b"\x00"
        jitter.cpu.SP -= len(arg)
        ptr = jitter.cpu.SP
        jitter.vm.set_mem(ptr, arg)
        argv_ptrs.append(ptr)

    jitter.push_uint32_t(hlt_address)
    jitter.push_uint32_t(0)
    jitter.push_uint32_t(0)
    for auxid, auxval in viewitems(auxv):
        jitter.push_uint32_t(auxval)
        jitter.push_uint32_t(auxid)
    jitter.push_uint32_t(0)
    for ptr in reversed(env_ptrs):
        jitter.push_uint32_t(ptr)
    jitter.push_uint32_t(0)
    for ptr in reversed(argv_ptrs):
        jitter.push_uint32_t(ptr)
    jitter.push_uint32_t(len(argv))

    # Add kernel user helpers
    # from Documentation/arm/kernel_user_helpers.txt

    if linux_env.kuser_helper_version >= 1:
        jitter.add_breakpoint(
            0xFFFF0FE0,
            functools.partial(_arml__kuser_get_tls, linux_env)
        )

    if linux_env.kuser_helper_version >= 2:
        jitter.add_breakpoint(0XFFFF0FC0, _arml__kuser_cmpxchg)

    if linux_env.kuser_helper_version >= 3:
        jitter.add_breakpoint(0xFFFF0FA0, _arml__kuser_memory_barrier)

    jitter.add_breakpoint(0xffff0ffc, _arml__kuser_helper_version)
