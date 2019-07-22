import os

from future.utils import viewitems

from miasm.core.utils import force_bytes
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import get_caller_name
from miasm.core.utils import pck64, upck64

BASE_SB_PATH = "file_sb"


def get_str_ansi(jitter, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
           jitter.vm.get_mem(tmp, 1) != b"\x00"):
        tmp += 1
        l += 1
    return jitter.vm.get_mem(ad_str, l)


def get_str_unic(jitter, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
           jitter.vm.get_mem(tmp, 2) != b"\x00\x00"):
        tmp += 2
        l += 2
    s = jitter.vm.get_mem(ad_str, l)
    s = s.decode("utf-16le")
    return s


def set_str_ansi(value):
    value = force_bytes(value)
    return value + b"\x00"


def set_str_unic(value):
    try:
        value = value.decode()
    except AttributeError:
        pass
    return value.encode("utf-16le") + b'\x00' * 2


class heap(object):

    "Light heap simulation"

    addr = 0x20000000
    align = 0x1000
    size = 32
    mask = (1 << size) - 1

    def next_addr(self, size):
        """
        @size: the size to allocate
        return the future checnk address
        """
        ret = self.addr
        self.addr = (self.addr + size + self.align - 1)
        self.addr &= self.mask ^ (self.align - 1)
        return ret

    def alloc(self, jitter, size, perm=PAGE_READ | PAGE_WRITE):
        """
        @jitter: a jitter instance
        @size: the size to allocate
        @perm: permission flags (see vm_alloc doc)
        """
        return self.vm_alloc(jitter.vm, size, perm)

    def vm_alloc(self, vm, size, perm=PAGE_READ | PAGE_WRITE):
        """
        @vm: a VmMngr instance
        @size: the size to allocate
        @perm: permission flags (PAGE_READ, PAGE_WRITE, PAGE_EXEC or any `|`
            combination of them); default is PAGE_READ|PAGE_WRITE
        """
        addr = self.next_addr(size)
        vm.add_memory_page(
            addr,
            perm,
            b"\x00" * (size),
            "Heap alloc by %s" % get_caller_name(2)
        )
        return addr

    def get_size(self, vm, ptr):
        """
        @vm: a VmMngr instance
        @size: ptr to get the size of the associated allocation.

        `ptr` can be the base address of a previous allocation, or an address
        within the allocated range. The size of the whole allocation is always
        returned, regardless ptr is the base address or not.
        """
        assert vm.is_mapped(ptr, 1)
        data = vm.get_all_memory()
        ptr_page = data.get(ptr, None)
        if ptr_page is None:
            for address, page_info in viewitems(data):
                if address <= ptr < address + page_info["size"]:
                    ptr_page = page_info
                    break
            else:
                raise RuntimeError("Must never happen (unmapped but mark as mapped by API)")
        return ptr_page["size"]


def windows_to_sbpath(path):
    """Convert a Windows path to a valid filename within the sandbox
    base directory.

    """
    path = [elt for elt in path.lower().replace('/', '_').split('\\') if elt]
    return os.path.join(BASE_SB_PATH, *path)


def unix_to_sbpath(path):
    """Convert a POSIX path to a valid filename within the sandbox
    base directory.

    """
    path = [elt for elt in path.split('/') if elt]
    return os.path.join(BASE_SB_PATH, *path)

def get_fmt_args(fmt, cur_arg, get_str, get_arg_n):
    idx = 0
    fmt = get_str(fmt)
    if isinstance(fmt, bytes):
        chars_format = b'%cdfsuxX'
        char_percent = b'%'
        char_string = b's'
        output = b""
    else:
        chars_format = u'%cdfsuxX'
        char_percent = u'%'
        char_string = u's'
        output = u""

    while True:
        if idx == len(fmt):
            break
        char = fmt[idx:idx+1]
        idx += 1
        if char == char_percent:
            token = char_percent
            while True:
                char = fmt[idx:idx+1]
                idx += 1
                token += char
                if char in chars_format:
                    break
            if char == char_percent:
                output += char
                continue
            if token.endswith(char_string):
                addr = get_arg_n(cur_arg)
                arg = get_str(addr)
            else:
                arg = get_arg_n(cur_arg)
            char = token % arg
            cur_arg += 1
        output += char
    return output
