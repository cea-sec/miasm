#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.core.asmbloc  import disasmEngine
from miasm2.arch.ebc.arch import mn_ebc

class dis_ebc(disasmEngine):
    def __init__(self, bs=None, mode=32, **kwargs):
        super(dis_ebc, self).__init__(mn_ebc, mode, bs, **kwargs)

