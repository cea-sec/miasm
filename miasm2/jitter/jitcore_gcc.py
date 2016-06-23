#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
import tempfile
import ctypes
import _ctypes
from distutils.sysconfig import get_python_inc
from subprocess import check_call
from hashlib import md5

from miasm2.ir.ir2C import irblocs2C
from miasm2.jitter import jitcore, Jitgcc
from miasm2.core.utils import keydefaultdict


def gen_core(arch, attrib):
    lib_dir = os.path.dirname(os.path.realpath(__file__))

    txt = ""
    txt += '#include "%s/queue.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr_py.h"\n' % lib_dir
    txt += '#include "%s/JitCore.h"\n' % lib_dir
    txt += '#include "%s/arch/JitCore_%s.h"\n' % (lib_dir, arch.name)
    txt += r'''
#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
'''
    return txt


def gen_C_source(ir_arch, func_code):
    c_source = ""
    c_source += "\n".join(func_code)

    c_source = gen_core(ir_arch.arch, ir_arch.attrib) + c_source
    c_source = "#include <Python.h>\n" + c_source

    return c_source


class myresolver(object):

    def __init__(self, offset):
        self.offset = offset

    def ret(self):
        return "return PyLong_FromUnsignedLongLong(0x%X);" % self.offset


class resolver(object):

    def __init__(self):
        self.resolvers = keydefaultdict(myresolver)

    def get_resolver(self, offset):
        return self.resolvers[offset]


class JitCore_Gcc(jitcore.JitCore):

    "JiT management, using GCC as backend"

    def __init__(self, ir_arch, bs=None):
        self.jitted_block_delete_cb = self.deleteCB
        super(JitCore_Gcc, self).__init__(ir_arch, bs)
        self.resolver = resolver()
        self.gcc_states = {}
        self.ir_arch = ir_arch
        self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_gcc_cache")
        try:
            os.mkdir(self.tempdir, 0755)
        except OSError:
            pass
        if not os.access(self.tempdir, os.R_OK | os.W_OK):
            raise RuntimeError(
                'Cannot access gcc cache directory %s ' % self.tempdir)
        self.exec_wrapper = Jitgcc.gcc_exec_bloc
        self.libs = None
        self.include_files = None

    def deleteCB(self, offset):
        """Free the state associated to @offset and delete it
        @offset: gcc state offset
        """
        _ctypes.dlclose(self.gcc_states[offset]._handle)
        del self.gcc_states[offset]

    def load(self):
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        libs = [os.path.join(lib_dir, 'VmMngr.so'),
                os.path.join(lib_dir,
                             'arch/JitCore_%s.so' % (self.ir_arch.arch.name))]

        include_files = [os.path.dirname(__file__),
                         get_python_inc()]
        self.include_files = include_files
        self.libs = libs

    def label2fname(self, label):
        """
        Generate function name from @label
        @label: asm_label instance
        """
        return "block_%s" % label.name

    def load_code(self, label, fname_so):
        f_name = self.label2fname(label)
        lib = ctypes.cdll.LoadLibrary(fname_so)
        func = getattr(lib, f_name)
        addr = ctypes.cast(func, ctypes.c_void_p).value
        self.lbl2jitbloc[label.offset] = addr
        self.gcc_states[label.offset] = lib

    def gen_c_code(self, label, irblocks):
        """
        Return the C code corresponding to the @irblocks
        @label: asm_label of the block to jit
        @irblocks: list of irblocks
        """
        f_name = self.label2fname(label)
        f_declaration = 'int %s(block_id * BlockDst, JitCpu* jitcpu)' % f_name
        out = irblocs2C(self.ir_arch, self.resolver, label, irblocks,
                        gen_exception_code=True,
                        log_mn=self.log_mn,
                        log_regs=self.log_regs)
        out = [f_declaration + '{'] + out + ['}\n']
        c_code = out

        return gen_C_source(self.ir_arch, c_code)

    def add_bloc(self, block):
        """Add a bloc to JiT and JiT it.
        @block: block to jit
        """
        block_raw = "".join(line.b for line in block.lines)
        block_hash = md5("%X_%s_%s_%s" % (block.label.offset,
                                          self.log_mn,
                                          self.log_regs,
                                          block_raw)).hexdigest()
        fname_out = os.path.join(self.tempdir, "%s.so" % block_hash)

        if not os.access(fname_out, os.R_OK | os.X_OK):
            irblocks = self.ir_arch.add_bloc(block, gen_pc_updt=True)
            func_code = self.gen_c_code(block.label, irblocks)

            # Create unique C file
            fdesc, fname_in = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)

            # Create unique SO file
            fdesc, fname_tmp = tempfile.mkstemp(suffix=".so")
            os.close(fdesc)

            inc_dir = ["-I%s" % inc for inc in self.include_files]
            libs = ["%s" % lib for lib in self.libs]
            args = ["gcc"] + ["-O3"] + [
                "-shared", "-fPIC", fname_in, '-o', fname_tmp] + inc_dir + libs
            check_call(args)
            # Move temporary file to final file
            os.rename(fname_tmp, fname_out)
            os.remove(fname_in)

        self.load_code(block.label, fname_out)
