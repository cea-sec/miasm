#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os
from miasm2.ir.ir2C import irblocs2C
from subprocess import Popen, PIPE
import jitcore
from distutils.sysconfig import get_python_inc
import Jittcc


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
    txt += '#include "%s/arch/JitCore_%s.h"\n' % (lib_dir, arch.name)

    txt += r'''
#define RAISE(errtype, msg) {PyObject* p; p = PyErr_Format( errtype, msg ); return p;}
'''
    return txt


def gen_C_source(my_ir, func_code):
    c_source = ""
    c_source += "\n".join(func_code)

    c_source = gen_core(my_ir.arch, my_ir.attrib) + c_source

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

    def __init__(self, my_ir, bs=None):
        super(JitCore_Tcc, self).__init__(my_ir, bs)
        self.resolver = resolver()
        self.exec_wrapper = Jittcc.tcc_exec_bloc
        self.tcc_states =[]

    def load(self, arch):
        # os.path.join(os.path.dirname(os.path.realpath(__file__)), "jitter")
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        libs = []
        libs.append(os.path.join(lib_dir, 'arch/JitCore_%s.so' % (arch.name)))
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
        for tcc_state in self.tcc_states:
            Jittcc.tcc_end(tcc_state)

    def jitirblocs(self, label, irblocs):
        # irbloc = self.lbl2irbloc[lbl]
        f_name = "bloc_%s" % label.name
        f_declaration = \
            'PyObject* %s(vm_cpu_t* vmcpu, vm_mngr_t* vm_mngr)' % f_name
        out = irblocs2C(self.my_ir, self.resolver, label, irblocs,
                        gen_exception_code=True,
                        log_mn=self.log_mn,
                        log_regs=self.log_regs)
        out = [f_declaration + '{'] + out + ['}\n']
        c_code = out

        func_code = gen_C_source(self.my_ir, c_code)
        # print func_code
        # open('tmp_%.4d.c'%self.jitcount, "w").write(func_code)
        self.jitcount += 1
        tcc_state, mcode = jit_tcc_compil(f_name, func_code)
        self.tcc_states.append(tcc_state)
        jcode = jit_tcc_code(mcode)
        self.lbl2jitbloc[label.offset] = mcode
        self.addr2obj[label.offset] = jcode
        self.addr2objref[label.offset] = objref(jcode)
        # print "ADDR2CODE", hex(b.label.offset), hex(id(jcode))
