#-*- coding:utf-8 -*-
import os
import tempfile
from subprocess import Popen, PIPE

from miasm2.jitter import Jittcc
from miasm2.jitter.jitcore_cc_base import JitCore_Cc_Base, gen_core


class JitCore_Tcc(JitCore_Cc_Base):

    "JiT management, using LibTCC as backend"

    def __init__(self, ir_arch, bs=None):
        super(JitCore_Tcc, self).__init__(ir_arch, bs)
        self.exec_wrapper = Jittcc.tcc_exec_bloc

    def deleteCB(self, offset):
        "Free the TCCState corresponding to @offset"
        if offset in self.states:
            Jittcc.tcc_end(self.states[offset])
            del self.states[offset]

    def load(self):
        super(JitCore_Tcc, self).load()
        libs = ';'.join(self.libs)
        jittcc_path = Jittcc.__file__
        include_dir = os.path.dirname(jittcc_path)
        include_dir += ";" + os.path.join(include_dir, "arch")

        # XXX HACK
        # As debian/ubuntu have moved some include files using arch directory,
        # TCC doesn't know them, so we get the info from CC
        # For example /usr/include/x86_64-linux-gnu which contains limits.h
        p = Popen(["cc", "-Wp,-v", "-E", "-"],
                  stdout=PIPE, stderr=PIPE, stdin=PIPE)
        p.stdin.close()
        include_files = p.stderr.read().split('\n')
        include_files = [x[1:]
                         for x in include_files if x.startswith(' /usr/include')]
        include_files += self.include_files
        include_files = ";".join(include_files)
        Jittcc.tcc_set_emul_lib_path(include_files, libs)

    def __del__(self):
        for tcc_state in self.states.values():
            Jittcc.tcc_end(tcc_state)

    def jit_tcc_compil(self, func_name, func_code):
        return Jittcc.tcc_compil(func_name, func_code)

    def compil_code(self, block, func_code):
        """
        Compil the C code of @func_code from @block
        @block: original asm_block
        @func_code: C code of the block
        """
        label = block.label
        self.jitcount += 1
        tcc_state, mcode = self.jit_tcc_compil(self.label2fname(label), func_code)
        self.lbl2jitbloc[label.offset] = mcode
        self.states[label.offset] = tcc_state

    def add_bloc(self, block):
        """Add a bloc to JiT and JiT it.
        @block: block to jit
        """
        block_hash = self.hash_block(block)
        fname_out = os.path.join(self.tempdir, "%s.c" % block_hash)

        if os.access(fname_out, os.R_OK):
            func_code = open(fname_out, "rb").read()
        else:
            func_code = self.gen_c_code(block.label, block)

            # Create unique C file
            fdesc, fname_tmp = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)
            os.rename(fname_tmp, fname_out)

        self.compil_code(block, func_code)

    @staticmethod
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
