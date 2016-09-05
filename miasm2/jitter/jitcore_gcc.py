#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
import tempfile
import ctypes
import _ctypes
from subprocess import check_call

from miasm2.jitter import Jitgcc
from miasm2.jitter.jitcore_cc_base import JitCore_Cc_Base, gen_core


class JitCore_Gcc(JitCore_Cc_Base):
    "JiT management, using a C compiler as backend"

    def __init__(self, ir_arch, bs=None):
        super(JitCore_Gcc, self).__init__(ir_arch, bs)
        self.exec_wrapper = Jitgcc.gcc_exec_bloc

    def deleteCB(self, offset):
        """Free the state associated to @offset and delete it
        @offset: gcc state offset
        """
        _ctypes.dlclose(self.states[offset]._handle)
        del self.states[offset]

    def load_code(self, label, fname_so):
        f_name = self.label2fname(label)
        lib = ctypes.cdll.LoadLibrary(fname_so)
        func = getattr(lib, f_name)
        addr = ctypes.cast(func, ctypes.c_void_p).value
        self.lbl2jitbloc[label.offset] = addr
        self.states[label.offset] = lib

    def add_bloc(self, block):
        """Add a bloc to JiT and JiT it.
        @block: block to jit
        """
        block_hash = self.hash_block(block)
        fname_out = os.path.join(self.tempdir, "%s.so" % block_hash)

        if not os.access(fname_out, os.R_OK | os.X_OK):
            func_code = self.gen_c_code(block.label, block)

            # Create unique C file
            fdesc, fname_in = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)

            # Create unique SO file
            fdesc, fname_tmp = tempfile.mkstemp(suffix=".so")
            os.close(fdesc)

            inc_dir = ["-I%s" % inc for inc in self.include_files]
            libs = ["%s" % lib for lib in self.libs]
            args = ["cc"] + ["-O3"] + [
                "-shared", "-fPIC", fname_in, '-o', fname_tmp] + inc_dir + libs
            check_call(args)
            # Move temporary file to final file
            os.rename(fname_tmp, fname_out)
            os.remove(fname_in)

        self.load_code(block.label, fname_out)

    @staticmethod
    def gen_C_source(ir_arch, func_code):
        c_source = ""
        c_source += "\n".join(func_code)

        c_source = gen_core(ir_arch.arch, ir_arch.attrib) + c_source
        c_source = "#include <Python.h>\n" + c_source

        return c_source
