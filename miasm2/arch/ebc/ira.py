#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.arch.ebc.sem import ir_ebc_32
from miasm2.ir.analysis import ira

class ir_a_ebc(ir_ebc_32, ira):
    def __init__(self, symbol_pool=None):
        ir_ebc_32.__init__(self, symbol_pool)

