#! /usr/bin/env python2

#-*- coding:utf-8 -*-

from __future__ import print_function
from builtins import range
import unittest


class TestUtils(unittest.TestCase):

    def test_boundedDict(self):
        from miasm.core.utils import BoundedDict

        # Use a callback
        def logger(key):
            print("DELETE", key)

        # Create a 5/2 dictionary
        bd = BoundedDict(5, 2, initialdata={"element": "value"},
                         delete_cb=logger)
        bd["element2"] = "value2"
        assert("element" in bd)
        assert("element2" in bd)
        self.assertEqual(bd["element"], "value")
        self.assertEqual(bd["element2"], "value2")

        # Increase 'element2' use
        _ = bd["element2"]

        for i in range(6):
            bd[i] = i
            print("Insert %d -> %s" % (i, bd))

        assert(len(bd) == 2)

        assert("element2" in bd)
        self.assertEqual(bd["element2"], "value2")


if __name__ == '__main__':
    testsuite = unittest.TestLoader().loadTestsFromTestCase(TestUtils)
    report = unittest.TextTestRunner(verbosity=2).run(testsuite)
    exit(len(report.errors + report.failures))
