#! /usr/bin/env python2
#-*- coding:utf-8 -*-

from builtins import range
import unittest
import logging
from miasm2.analysis.machine import Machine
import miasm2.os_dep.common as commonapi
from miasm2.core.utils import pck32
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE

machine = Machine("x86_32")

jit = machine.jitter()
jit.init_stack()

class TestCommonAPI(unittest.TestCase):

    def test_get_size(self):
        heap = commonapi.heap()
        with self.assertRaises(AssertionError):
            heap.get_size(jit.vm, 0)
        heap.alloc(jit, 20)
        heap.alloc(jit, 40)
        heap.alloc(jit, 50)
        heap.alloc(jit, 60)
        ptr = heap.alloc(jit, 10)
        heap.alloc(jit, 80)
        for i in range(10):
            self.assertEqual(heap.get_size(jit.vm, ptr+i), 10)

if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestCommonAPI)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))

