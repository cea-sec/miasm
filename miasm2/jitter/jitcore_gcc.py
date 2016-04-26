#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
import tempfile
import ctypes
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
        pass

    def load(self):
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        libs = [os.path.join(lib_dir, 'VmMngr.so'),
                os.path.join(lib_dir,
                             'arch/JitCore_%s.so' % (self.ir_arch.arch.name))]

        include_files = [os.path.dirname(__file__),
                         get_python_inc()]
        self.include_files = include_files
        self.libs = libs

    def jit_gcc_compil(self, f_name, func_code):
        func_hash = md5(func_code).hexdigest()
        fname_out = os.path.join(self.tempdir, "%s.so" % func_hash)
        if not os.access(fname_out, os.R_OK | os.X_OK):
            # Create unique C file
            fdesc, fname_in = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)

            # Create unique SO file
            _, fname_tmp = tempfile.mkstemp(suffix=".so")

            inc_dir = ["-I%s" % inc for inc in self.include_files]
            libs = ["%s" % lib for lib in self.libs]
            args = ["gcc"] + ["-O3"] + [
                "-shared", "-fPIC", fname_in, '-o', fname_tmp] + inc_dir + libs
            check_call(args)
            # Move temporary file to final file
            os.rename(fname_tmp, fname_out)

        lib = ctypes.cdll.LoadLibrary(fname_out)
        func = getattr(lib, f_name)
        addr = ctypes.cast(func, ctypes.c_void_p).value
        return None, addr

    def jitirblocs(self, label, irblocs):
        f_name = "bloc_%s" % label.name
        f_declaration = 'int %s(block_id * BlockDst, JitCpu* jitcpu)' % f_name
        out = irblocs2C(self.ir_arch, self.resolver, label, irblocs,
                        gen_exception_code=True,
                        log_mn=self.log_mn,
                        log_regs=self.log_regs)
        out = [f_declaration + '{'] + out + ['}\n']
        c_code = out

        func_code = gen_C_source(self.ir_arch, c_code)

        # open('tmp_%.4d.c'%self.jitcount, "w").write(func_code)
        self.jitcount += 1
        gcc_state, mcode = self.jit_gcc_compil(f_name, func_code)
        self.lbl2jitbloc[label.offset] = mcode
        self.gcc_states[label.offset] = gcc_state
