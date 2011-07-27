#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
import os
import sys
try:
    from Crypto.Hash import MD5
except ImportError:
    print "cannot find crypto MD5, skipping"
    
from  ctypes import *
from miasm.tools.to_c_helper import *
from miasm.tools.emul_lib import libcodenat_interface    

# interrupt with eip update after instr
EXCEPT_CODE_AUTOMOD = (1<<0)
EXCEPT_SOFT_BP = (1<<1)

# interrupt with eip at instr
EXCEPT_UNK_MEM_AD = (1<<2)
EXCEPT_THROW_SEH = (1<<3)
EXCEPT_UNK_EIP = (1<<4)
EXCEPT_ACCESS_VIOL = (1<<5)
EXCEPT_INT_DIV_BY_ZERO = (1<<6)
EXCEPT_PRIV_INSN = (1<<7)
EXCEPT_ILLEGAL_INSN = (1<<8)




EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_ACCESS_VIOLATION = 0xc0000005
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xc0000094
EXCEPTION_PRIV_INSTRUCTION = 0xc0000096
EXCEPTION_ILLEGAL_INSTRUCTION = 0xc000001d


PAGE_READ  = 1
PAGE_WRITE = 2
PAGE_EXEC  = 4



class bloc_nat:
    def __init__(self, offset = 0, b = None, module_c = None, log_mn = False, log_regs = False):
        self.b = b
        self.module_c = module_c

blocs_nat = {}

def gen_C_module(c_source):
    
    lib_name = 'emul_cache/out_'+MD5.new(c_source).hexdigest()
    lib_dir = os.path.dirname(os.path.realpath(__file__))
    lib_dir = os.path.join(lib_dir, 'emul_lib')

    a = None
    try:
        aa = os.stat(lib_name+'.so')
        a = cdll.LoadLibrary('./%s.so'%lib_name)
    except:
        a = None
    if a == None:    
        open(lib_name+'.c', 'w').write(c_source)

        gcc_opts =  " -pthread -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes "
        gcc_opts += " -fPIC -I/usr/include/python2.6  "
        os.system('gcc -c '+gcc_opts + ' -L%s -lcodenat -lpython2.6 %s.c -o %s.o'%(lib_dir, lib_name, lib_name))

        gcc_opts =  ' -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions '
        gcc_opts += ' -L%s -lcodenat '%lib_dir
        gcc_opts_end = ' -Wl,-rpath,%s '%lib_dir
        os.system('gcc ' + gcc_opts + '%s.o -o %s.so '%(lib_name, lib_name) + gcc_opts_end)
        
        a = cdll.LoadLibrary('%s.so'%lib_name)

    return a


def del_bloc_in_range(known_blocs, ad1, ad2):
    bloc_out = {}
    for ad in known_blocs:
        bn = known_blocs[ad]
        # XXX no lines in bloc?
        if not bn.b.lines:
            continue
        
        if bn.b.lines[0].offset>=ad2 or bn.b.lines[-1].offset + bn.b.lines[-1].l <= ad1:
            #bloc_out.append(b)
            bloc_out[ad] = bn
        else:
            #print 'inv bloc', bn.b.label
            pass
    
    return bloc_out




def vm_save_state(fname):
    vmem = vm_get_all_memory()
    return vmem
    #XXX




libcntcc = None
def codenat_tcc_load():
    global libcntcc
    from distutils.sysconfig import get_python_inc
    import emul_lib.libcodenat_tcc as libcntcc
    lib_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "emul_lib")
    lib_path = os.path.join(lib_dir, 'libcodenat_tcc.so')
    libpath = libcodenat_interface.__file__
    libdir = os.path.dirname(libpath)
    print libpath
    print libdir
    libcntcc.tcc_set_emul_lib_path(libdir, libpath, get_python_inc())
    
def codenat_tcc_init():
    global libcntcc
    if libcntcc == None:
        codenat_tcc_load()

def codenat_tcc_compil(func_name, func_code):
    global libcntcc
    c = libcntcc.tcc_compil(func_name, func_code)
    return c

def codenat_tcc_exec(a):
    global libcntcc
    oo = libcntcc.tcc_exec_bloc(a)
    return oo

def rr():
    pass

class tcc_code():
    def __init__(self, c):
        self.c = c
        self.func = lambda :libcntcc.tcc_exec_bloc(self.c)

def gen_C_module_tcc(f_name, c_source):
    mcode = codenat_tcc_compil(f_name, c_source)    
    return tcc_code(mcode)
