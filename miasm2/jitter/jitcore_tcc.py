#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
from distutils.sysconfig import get_python_inc
from subprocess import Popen, PIPE
from hashlib import md5
import tempfile

from miasm2.ir.ir2C import irblocs2C
from miasm2.jitter import jitcore, Jittcc


def jit_tcc_compil(func_name, func_code):
    global Jittcc
    c = Jittcc.tcc_compil(func_name, func_code)
    return c


class jit_tcc_code():

    def __init__(self, c):
        self.c = c

    def __call__(self, cpu, vm):
        return Jittcc.tcc_exec_bloc(self.c, cpu, vm)


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

    c_source = """
 #ifdef __x86_64__
 #ifndef __LP64__
 /*
  for ubuntu ?!? XXX TODO
  /!\ force 64 bit system using 64 bits libc
  change this to __ILP32__ to do so.
 */
 #define __LP64__
 #endif
 #endif
 """ + "#include <Python.h>\n" + c_source

    return c_source


class objref:

    def __init__(self, obj):
        self.obj = obj


class myresolver:

    def __init__(self, offset):
        self.offset = offset

    def ret(self):
        return "return PyLong_FromUnsignedLongLong(0x%X);" % self.offset

from miasm2.core.utils import keydefaultdict


class resolver:

    def __init__(self):
        self.resolvers = keydefaultdict(myresolver)

    def get_resolver(self, offset):
        return self.resolvers[offset]


class JitCore_Tcc(jitcore.JitCore):

    "JiT management, using LibTCC as backend"

    def __init__(self, ir_arch, bs=None):
        self.jitted_block_delete_cb = self.deleteCB
        super(JitCore_Tcc, self).__init__(ir_arch, bs)
        self.resolver = resolver()
        self.exec_wrapper = Jittcc.tcc_exec_bloc
        self.tcc_states = {}
        self.ir_arch = ir_arch

        self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_gcc_cache")
        try:
            os.mkdir(self.tempdir, 0755)
        except OSError:
            pass

    def deleteCB(self, offset):
        "Free the TCCState corresponding to @offset"
        if offset in self.tcc_states:
            Jittcc.tcc_end(self.tcc_states[offset])
            del self.tcc_states[offset]

    def load(self):
        # os.path.join(os.path.dirname(os.path.realpath(__file__)), "jitter")
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        libs = []
        libs.append(os.path.join(lib_dir, 'VmMngr.so'))
        libs.append(
            os.path.join(lib_dir, 'arch/JitCore_%s.so' % (self.ir_arch.arch.name)))
        libs = ';'.join(libs)
        jittcc_path = Jittcc.__file__
        include_dir = os.path.dirname(jittcc_path)
        include_dir += ";" + os.path.join(include_dir, "arch")
        # print include_dir

        # XXX HACK
        # As debian/ubuntu have moved some include files using arch directory,
        # TCC doesn't know them, so we get the info from GCC
        # For example /usr/include/x86_64-linux-gnu which contains limits.h
        p = Popen(["cc", "-Wp,-v", "-E", "-"],
                  stdout=PIPE, stderr=PIPE, stdin=PIPE)
        p.stdin.close()
        include_files = p.stderr.read().split('\n')
        include_files = [x[1:]
                         for x in include_files if x.startswith(' /usr/include')]
        include_files += [include_dir, get_python_inc()]
        include_files = ";".join(include_files)
        Jittcc.tcc_set_emul_lib_path(include_files, libs)

    def __del__(self):
        for tcc_state in self.tcc_states.values():
            Jittcc.tcc_end(tcc_state)

    def label2fname(self, label):
        """
        Generate function name from @label
        @label: asm_label instance
        """
        return "block_%s" % label.name

    def compil_code(self, block, func_code):
        """
        Compil the C code of @func_code from @block
        @block: original asm_block
        @func_code: C code of the block
        """
        label = block.label
        self.jitcount += 1
        tcc_state, mcode = jit_tcc_compil(self.label2fname(label), func_code)
        self.lbl2jitbloc[label.offset] = mcode
        self.tcc_states[label.offset] = tcc_state

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
        fname_out = os.path.join(self.tempdir, "%s.c" % block_hash)
        if os.access(fname_out, os.R_OK):
            func_code = open(fname_out).read()
        else:
            irblocks = self.ir_arch.add_bloc(block, gen_pc_updt=True)
            block.irblocs = irblocks
            func_code = self.gen_c_code(block.label, irblocks)

            # Create unique C file
            fdesc, fname_tmp = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)
            os.rename(fname_tmp, fname_out)

        self.compil_code(block, func_code)
