#! /usr/bin/env python2
#-*- coding:utf-8 -*-

import unittest
import logging
from miasm.analysis.machine import Machine
import miasm.os_dep.linux_stdlib as stdlib
from miasm.core.utils import pck32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB

machine = Machine("x86_32")

loc_db = LocationDB()
jit = machine.jitter(loc_db)
jit.init_stack()

heap = stdlib.linobjs.heap

class TestLinuxStdlib(unittest.TestCase):

    def test_xxx_sprintf(self):
        def alloc_str(s):
            s += b"\x00"
            ptr = heap.alloc(jit, len(s))
            jit.vm.set_mem(ptr, s)
            return ptr
        fmt  = alloc_str(b"'%s' %d")
        str_ = alloc_str(b"coucou")
        buf = heap.alloc(jit,1024)

        jit.push_uint32_t(1111)
        jit.push_uint32_t(str_)
        jit.push_uint32_t(fmt)
        jit.push_uint32_t(buf)
        jit.push_uint32_t(0) # ret_ad
        stdlib.xxx_sprintf(jit)
        ret = jit.get_c_str(buf)
        self.assertEqual(ret, "'coucou' 1111")


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestLinuxStdlib)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
