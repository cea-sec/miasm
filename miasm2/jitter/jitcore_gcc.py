#-*- coding:utf-8 -*-

import os
import tempfile
import ctypes
import _ctypes
import platform
from subprocess import check_call
from distutils.sysconfig import get_python_inc

from miasm2.jitter import Jitgcc
from miasm2.jitter.jitcore_cc_base import JitCore_Cc_Base, gen_core

is_win = platform.system() == "Windows"

class JitCore_Gcc(JitCore_Cc_Base):
    "JiT management, using a C compiler as backend"

    def __init__(self, ir_arch, bin_stream):
        super(JitCore_Gcc, self).__init__(ir_arch, bin_stream)
        self.exec_wrapper = Jitgcc.gcc_exec_block

    def deleteCB(self, offset):
        """Free the state associated to @offset and delete it
        @offset: gcc state offset
        """
        flib = None
        if platform.system() == "Windows":
            flib = _ctypes.FreeLibrary
        else:
            flib = _ctypes.dlclose
        flib(self.states[offset]._handle)
        del self.states[offset]

    def load_code(self, label, fname_so):
        lib = ctypes.cdll.LoadLibrary(fname_so)
        func = getattr(lib, self.FUNCNAME)
        addr = ctypes.cast(func, ctypes.c_void_p).value
        offset = self.ir_arch.loc_db.get_location_offset(label)
        self.offset_to_jitted_func[offset] = addr
        self.states[offset] = lib

    def add_block(self, block):
        """Add a bloc to JiT and JiT it.
        @block: block to jit
        """
        block_hash = self.hash_block(block)
        ext = ".so" if not is_win else ".pyd"
        fname_out = os.path.join(self.tempdir, "%s%s" % (block_hash, ext))

        if not os.access(fname_out, os.R_OK | os.X_OK):
            func_code = self.gen_c_code(block)

            # Create unique C file
            fdesc, fname_in = tempfile.mkstemp(suffix=".c")
            os.write(fdesc, func_code)
            os.close(fdesc)

            # Create unique SO file
            fdesc, fname_tmp = tempfile.mkstemp(suffix=ext)
            os.close(fdesc)

            inc_dir = ["-I%s" % inc for inc in self.include_files]
            libs = ["%s" % lib for lib in self.libs]
            if is_win:
                libs.append(os.path.join(get_python_inc(), "..", "libs", "python27.lib"))
                cl = [
                    "cl", "/nologo", "/W3", "/MP",
                    "/Od", "/DNDEBUG", "/D_WINDOWS", "/Gm-", "/EHsc",
                    "/RTC1", "/MD", "/GS",
                    fname_in
                ] + inc_dir + libs
                cl += ["/link", "/DLL", "/OUT:" + fname_tmp]
                out_dir, _ = os.path.split(fname_tmp)
                check_call(cl, cwd = out_dir)
            else:
                args = []
                args.extend(inc_dir)
                args.extend(["cc", "-O3", "-shared", "-fPIC", fname_in, "-o", fname_tmp])
                args.extend(libs)
                check_call(args)

            # Move temporary file to final file
            os.rename(fname_tmp, fname_out)
            os.remove(fname_in)

        self.load_code(block.loc_key, fname_out)

    @staticmethod
    def gen_C_source(ir_arch, func_code):
        c_source = ""
        c_source += "\n".join(func_code)

        c_source = gen_core(ir_arch.arch, ir_arch.attrib) + c_source
        c_source = "#define PARITY_IMPORT\n#include <Python.h>\n" + c_source
        return c_source
