from miasm2.jitter.csts import *

def get_str_ansi(jitter, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
        jitter.vm.get_mem(tmp, 1) != "\x00"):
        tmp += 1
        l += 1
    return jitter.vm.get_mem(ad_str, l)


def get_str_unic(jitter, ad_str, max_char=None):
    l = 0
    tmp = ad_str
    while ((max_char is None or l < max_char) and
        jitter.vm.get_mem(tmp, 2) != "\x00\x00"):
        tmp += 2
        l += 2
    s = jitter.vm.get_mem(ad_str, l)
    # TODO: real unicode decoding
    s = s[::2]
    return s


def set_str_ansi(s):
    return s + "\x00"


def set_str_unic(s):
    # TODO: real unicode encoding
    return "\x00".join(list(s)) + '\x00' * 3



class heap(object):
    "Light heap simulation"

    addr = 0x20000000
    align = 0x1000
    size = 32
    mask = (1<< size) - 1

    def next_addr(self, size):
        """
        @size: the size to allocate
        return the future checnk address
        """
        ret = self.addr
        self.addr = (self.addr + size + self.align - 1)
        self.addr &= self.mask ^ (self.align - 1)
        return ret


    def alloc(self, jitter, size):
        """
        @jitter: a jitter instance
        @size: the size to allocate
        """

        addr = self.next_addr(size)
        jitter.vm.add_memory_page(addr, PAGE_READ | PAGE_WRITE, "\x00" * size)
        return addr

