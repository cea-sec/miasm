#-*- coding:utf-8 -*-

import os
import tempfile
from distutils.sysconfig import get_python_inc

from miasm2.jitter.jitcore import JitCore
from miasm2.core.utils import keydefaultdict


def gen_core(arch, attrib):
    lib_dir = os.path.dirname(os.path.realpath(__file__))

    txt = ""
    txt += '#include "%s/queue.h"\n' % lib_dir
    txt += '#include "%s/op_semantics.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr.h"\n' % lib_dir
    txt += '#include "%s/vm_mngr_py.h"\n' % lib_dir
    txt += '#include "%s/JitCore.h"\n' % lib_dir
    txt += '#include "%s/arch/JitCore_%s.h"\n' % (lib_dir, arch.name)

    txt += r'''
#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
'''
    return txt


class myresolver:

    def __init__(self, offset):
        self.offset = offset

    def ret(self):
        return "return PyLong_FromUnsignedLongLong(0x%X);" % self.offset


class resolver:

    def __init__(self):
        self.resolvers = keydefaultdict(myresolver)

    def get_resolver(self, offset):
        return self.resolvers[offset]


class JitCore_Cc_Base(JitCore):
    "JiT management, abstract class using a C compiler as backend"

    def __init__(self, ir_arch, bs=None):
        self.jitted_block_delete_cb = self.deleteCB
        super(JitCore_Cc_Base, self).__init__(ir_arch, bs)
        self.resolver = resolver()
        self.ir_arch = ir_arch
        self.states = {}
        self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")
        try:
            os.mkdir(self.tempdir, 0755)
        except OSError:
            pass
        if not os.access(self.tempdir, os.R_OK | os.W_OK):
            raise RuntimeError(
                'Cannot access cache directory %s ' % self.tempdir)
        self.exec_wrapper = None
        self.libs = None
        self.include_files = None

    def deleteCB(self, offset):
        raise NotImplementedError()

    def load(self):
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        libs = [os.path.join(lib_dir, 'VmMngr.so'),
                os.path.join(lib_dir,
                             'arch/JitCore_%s.so' % (self.ir_arch.arch.name))]

        include_files = [os.path.dirname(__file__),
                         get_python_inc()]
        self.include_files = include_files
        self.libs = libs

    def init_codegen(self, codegen):
        """
        Get the code generator @codegen
        @codegen: an CGen instance
        """
        self.codegen = codegen

    def label2fname(self, label):
        """
        Generate function name from @label
        @label: AsmLabel instance
        """
        return "block_%s" % self.codegen.label_to_jitlabel(label)

    def gen_c_code(self, label, block):
        """
        Return the C code corresponding to the @irblocks
        @label: AsmLabel of the block to jit
        @irblocks: list of irblocks
        """
        f_name = self.label2fname(label)
        f_declaration = 'int %s(block_id * BlockDst, JitCpu* jitcpu)' % f_name
        out = self.codegen.gen_c(block, log_mn=self.log_mn, log_regs=self.log_regs)
        out = [f_declaration + '{'] + out + ['}\n']
        c_code = out

        return self.gen_C_source(self.ir_arch, c_code)

    @staticmethod
    def gen_C_source(ir_arch, func_code):
        raise NotImplementedError()
