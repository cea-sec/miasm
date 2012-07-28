#!/usr/bin/env python
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
from x86_escape import opcode_factory, bin_stream, instr_dis
from asmbloc import *
from parse_asm import *
import shlex
from ia32_sem import *
from copy import copy
import pefile
import pprint


class imp_func:
    def __init__(self, address, name, name_dll, unstack=None):
        self.address = address
        self.name = name
        self.dllname = name_dll
        self.unstack = unstack
    def __str__(self):
        return hex(self.address)+' '+str(self.name)+' '+str(self.dllname)+' '+str(self.unstack)

x86mnemo = opcode_factory()

fname = "calc.exe"
f = open(fname, 'rb')
pe =  pefile.PE(fname)

pool_import_func = {}
print "read import"
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #print entry.dll
    for imp in entry.imports:
      #print '\t', hex(imp.address), imp.name
      pool_import_func[imp.address] = imp_func(imp.address, imp.name, entry.dll)

dll_pe_cache = {}
dll_rep = "dlls/"
def init_dll_cache(dllname):
    global dll_pe_cache
    print "read %s"%dllname
    pe =  pefile.PE(dll_rep+dllname)
    dll_pe_cache[dllname] = pe
    print 'read ok'


def read_dll_export(dll_name, func_name):
    global dll_pe_cache
    fname = dll_name.lower()
    print "read export", fname

    if not fname in dll_pe_cache:
        print 'not loaded dll'
        init_dll_cache(fname)

    pe = dll_pe_cache[fname]
    """
    pe =  pefile.PE(fname)
    """
    f_tmp = open(dll_rep+fname, 'rb')

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return None

    dict_export = dict([(exp.name, exp) for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols])
    if not func_name in dict_export:
        return None

    offset = pe.get_offset_from_rva(dict_export[func_name].address)
    print "offset", hex(offset)
    in_str_tmp = bin_stream(f_tmp, offset)
    symbol_pool_tmp = asm_symbol_pool()
    all_bloc_tmp = dis_bloc_all(x86mnemo, in_str_tmp, in_str_tmp.offset, [], symbol_pool_tmp, follow_call = False)
    ret = quick_ret_analyse(offset, all_bloc_tmp)

    return ret



print "disasm bin follow "
#0x366
#0x2F0
#0x3B0

#open file
start_dis = 0x9F09#0xB50
in_str = bin_stream(f, start_dis)

#disasm binary
job_done = []
symbol_pool = asm_symbol_pool()
all_bloc = dis_bloc_all(x86mnemo, in_str, in_str.offset, job_done, symbol_pool, follow_call = False)
print "symbols:"
print symbol_pool

g = bloc2graph(all_bloc)
open("graph.txt" , "w").write(g)

jcc = ['jz', 'je', 'jnz', 'jp', 'jnp', 'jg', 'jge', 'ja', 'jae', 'jb', 'jbe', 'jl', 'jle', 'js', 'jns', 'loop']

eax_i = ExprId('eax_i')
ebx_i = ExprId('ebx_i')
ecx_i = ExprId('ecx_i')
edx_i = ExprId('edx_i')
esi_i = ExprId('esi_i')
edi_i = ExprId('edi_i')
esp_i = ExprId('esp_i')
ebp_i = ExprId('ebp_i')

MEM_GLOB = ExprId('MEM_GLOB')

def dump_pool(p):
    print '/-------------\\'
    for x in p:
        print x, p[x]
    print '\\_____________/'


def hook_mem_read(evaluator, src):
    evaluator.log.warn('mem read %s'%str(src))
    src_address = evaluator.eval_expr(src.arg, {})
    src_address = evaluator.simp_full_exp(src_address)
    src_address = evaluator.simp_expr_arith_final(src_address)

    print 'test read',src_address, evaluator.simp_expr_arith_final(src_address)
    dump_pool(evaluator.pool[MEM_GLOB])


    if not str(src_address) in evaluator.pool[MEM_GLOB]:
        evaluator.log.warning('unkown read address:%s'%src_address)
        return ExprMem(src_address, size = src.size)
    return evaluator.pool[MEM_GLOB][str(src_address)]


def hook_mem_write(evaluator, dst, src, pool_out):
    evaluator.log.warn("mem write: %s %s"%(str(dst), str(src)))

    dst_address = evaluator.eval_expr(dst.arg, {})
    dst_address = evaluator.simp_full_exp(dst_address)
    dst_address = evaluator.simp_expr_arith_final(dst_address)
    print 'test write',dst_address, evaluator.simp_expr_arith_final(dst_address)

    evaluator.pool[MEM_GLOB][str(dst_address)] = src
    dump_pool(evaluator.pool[MEM_GLOB])




#set unkown stack for all blocks
for b in all_bloc:
    b.eval_start,b.eval_stop = None, None
    for l in b.lines:
        l.arg_lookup = None
        l.stack_h_after = None



#first bloc start at 0
#esp_init_arg= 0x1000
evaluator = eval_int({esp:esp_i, ebp:ebp_i, eax:eax_i, ebx:ebx_i, ecx:ecx_i, edx:edx_i, esi:esi_i, edi:edi_i,
                      cs:9,
                      zf : 0,
                      nf : 0,
                      pf : 0,
                      of : 0,
                      cf : 0,
                      tf : 0,
                      i_f: 0,
                      df : 0,
                      af : 0,
                      iopl: 3,
                      nt : 0,
                      rf : 0,
                      vm : 0,
                      ac : 0,
                      vif: 0,
                      vip: 0,
                      i_d: 0,
                      MEM_GLOB:{},
                      },
                     hook_mem_read,
                     hook_mem_write
                     )
args_func = []
#for i in xrange(3, 0, -1):
    #args_func.append(ExprId('arg_%d'%i))

    #evaluator.eval_instr(push(args_func[-1]))
evaluator.eval_instr(push('ret_addr'))
esp_init= evaluator.pool[esp]

all_bloc[0].eval_start = evaluator

def quick_ret_analyse(offset, all_bloc_arg):
    #first, try to find ret and look for unstack arg.
    for b in all_bloc_arg:
        l = b.lines[-1]
        if l.m.name == 'ret':
            args = [dict_to_Expr(x, l.m.modifs) for x in l.arg]
            if len(args) == 0:
                return 0
            else:
                #exprint
                return args[0].arg
    #no ret found means special func
    #try evaluation to ret and look at esp decal
    #hack stack decal
    return None

def is_func_wrapper(ad, pool_import_func = {}):
    x86mnemo = opcode_factory()
    in_str_tmp = bin_stream(f, ad.offset)
    instr = x86mnemo.dis(in_str_tmp)
    print 'i'*80
    print instr
    if instr.m.name in ['jmp'] and is_address(instr.arg[0]):
        return True

    return False

#is simply import call?
def is_import_call(offset, eval_arg, symbol_pool, pool_import_func = {}):
    evaluator_tmp = eval_int(dict([(x,copy(eval_arg.pool[x])) for x in eval_arg.pool]), hook_mem_read, hook_mem_write)
    in_str_tmp = bin_stream(f, offset)

    #eval only jmp/call until eip load
    ad_done = {}
    while True:
        if offset in ad_done:
            return False, None
        ad_done[offset] = True
        l = x86mnemo.dis(in_str_tmp)
        if not l.m.name in ['call', 'jmp']:
            return False, None

        args = [dict_to_Expr(x, l.m.modifs) for x in l.arg]
        if l.m.name in ['call']:
            if is_imm(l.arg[0]):
                e = mnemo_func[l.m.name](ExprInt(in_str_tmp.offset), ExprOp('+', in_str.offset, args[0]) )
            else:
                e = mnemo_func[l.m.name](ExprInt(in_str_tmp.offset), args[0])
        else:
            e = mnemo_func[l.m.name](*args)

        evaluator_tmp.eval_instr(e)
        if eip in evaluator_tmp.pool:
            n_eip = evaluator_tmp.pool[eip]
            if type(n_eip) in [int, long]:
                offset = n_eip
                continue
            if not isinstance(n_eip, ExprMem):
                return False, None
            ad = evaluator_tmp.eval_expr(n_eip.arg, {})

            if not type(ad) in [int, long]:
                return False, None
            if not ad in pool_import_func:
                return False, None

            unstack = None
            print "import func spotted:", str(pool_import_func[ad])
            #if pool_import_func[ad].name in known_func:

            print pool_import_func[ad].name
            dll_name = pool_import_func[ad].dllname
            func_name = pool_import_func[ad].name
            unstack = read_dll_export(dll_name, func_name)
            print "result:",unstack
            #unstack = known_func[pool_import_func[ad].name].unstack

            return True, unstack
        iiiopop
        #offset = in_str_tmp.offset



def stack_h(b, symbol_pool, pool_import_func = {}):
    evaluator_tmp = eval_int(dict([(x,copy(b.eval_start.pool[x])) for x in b.eval_start.pool]), hook_mem_read, hook_mem_write)
    #if b.lines[0].offset == 0x9FCE:
    #    fds
    for m in b.lines:
        #m.stack_h = evaluator_tmp.pool[esp]
        m.stack_h = evaluator.simp_expr_arith_final(evaluator_tmp.pool[esp])
        print hex(m.offset), m.stack_h, str(m)


        if m.m.name in ['call']:

            """
            #hack call next code
            if m.offset+m.l == s.offset:
                evaluator_tmp.pool[esp]-=4
                return evaluator_tmp
            """
            ret, unstack = is_import_call(m.offset, evaluator_tmp, symbol_pool, pool_import_func)
            if unstack!=None:
                evaluator_tmp.pool[esp]=evaluator_tmp.eval_expr(ExprOp('+', evaluator_tmp.pool[esp], unstack), {})
                return evaluator_tmp
            if ret:
                return None

            if not has_symb(m.arg[0]):
                return None
            dst = m.arg[0][x86_afs.symb].keys()
            if len(dst)!=1:
                return None
            s = symbol_pool.getby_name(dst[0])
            if not s:
                return None


            if is_func_wrapper(s):
                return evaluator_tmp


            in_str_tmp = bin_stream(f, s.offset)

            job_done_tmp = []
            symbol_pool_tmp = asm_symbol_pool()
            all_bloc_tmp = dis_bloc_all(x86mnemo, in_str_tmp, in_str_tmp.offset, job_done_tmp, symbol_pool_tmp, follow_call = False)
            ret = quick_ret_analyse(s.offset, all_bloc_tmp)
            #decal not found
            if ret == None:
                return ret
            #decal is expr
            if isinstance(ret, Expr):
                #print ret
                e = evaluator_tmp.eval_expr(ret, {})
                if type(e) in [int, long]:
                    print "eval esp oki!", e
                    ret = e
                else:
                    return None

            #decal found int
            if type(ret) in [int, long]:
                evaluator_tmp.pool[esp]=evaluator_tmp.eval_expr(ExprOp('+', evaluator_tmp.pool[esp], ret), {})
                return evaluator_tmp


        if m.m.name in jcc:
            continue

        args = [dict_to_Expr(x, m.m.modifs) for x in m.arg]

        e = mnemo_func[m.m.name](*args)

        print "exprs:"
        for x in e:
            print x
        evaluator_tmp.eval_instr(e)
        if eip in evaluator_tmp.pool:
            print evaluator_tmp.pool[eip]
            ret = evaluator_tmp.eval_expr(eip, {})
            if ret == 'ret_addr':
                m.stack_h_after = evaluator.simp_expr_arith_final(evaluator_tmp.pool[esp])


    return evaluator_tmp


def get_expr_diff(evaluator, a, b):
    if evaluator == None:
        return None
    a_e = evaluator.simp_expr_arith_final(evaluator.eval_expr(a, {esp_i:0}))
    b_e = evaluator.simp_expr_arith_final(evaluator.eval_expr(b, {esp_i:0}))
    if not type(a_e) in [int, long] or not type(b_e) in [int, long]:
        return None
    return b_e-a_e





def resolve_func(all_bloc_arg, symbol_pool, pool_import_func):
    all_bloc_dict = dict([(b.label,b) for b in all_bloc_arg])
    while True:
        fini = True
        for b in all_bloc_arg:
            force_stack_h = False
            #if one son is known, inform his brothers
            if b.eval_stop == None:
                for next in b.bto:
                    if next.label in all_bloc_dict and all_bloc_dict[next.label].eval_start!=None:
                        b.eval_stop = all_bloc_dict[next.label].eval_start
                        force_stack_h = True

                        for x in b.bto:
                            if x.label in all_bloc_dict and all_bloc_dict[x.label].eval_start==None:
                                all_bloc_dict[x.label].eval_start = all_bloc_dict[next.label].eval_start
                                fini = False

            if b.eval_start == None and b.eval_stop != None:
                #try to find stack decal and inform start
                print "tttt", hex(b.lines[0].offset)

                b.eval_start = b.eval_stop
                tmp = stack_h(b, symbol_pool, pool_import_func)
                print '_____',tmp

                decal = get_expr_diff(tmp, tmp.eval_expr(esp, {}),b.eval_stop.eval_expr(esp, {}))

                if decal == None:
                    b.eval_start = None
                    fdsfsd
                    for l in b.lines:
                        l.stack_h = None
                    continue
                tmp.pool[esp] = ExprOp('+', b.eval_stop.pool[esp] ,decal)
                b.eval_start = tmp
                print 'decal found ', b.label, decal
                fini = False

            if b.eval_start == None:
                continue

            if b.eval_stop != None and not force_stack_h:
                continue


            print '*****eval:', b.label, b.eval_start.eval_expr(esp, {})
            b.eval_stop = stack_h(b, symbol_pool, pool_import_func)
            if b.eval_stop == None:
                continue
            print 'propag:', b.label, b.eval_stop.eval_expr(esp, {})
            for next in b.bto:
                if next.label in all_bloc_dict:
                    print next
                    all_bloc_dict[next.label].eval_start = b.eval_stop
            fini = False

        if fini:
            break

    lines = reduce(lambda x,y:x+y.lines, all_bloc_arg, [])
    return None



print '_'*10
print resolve_func(all_bloc, symbol_pool, pool_import_func)
print 'result:'
for b in all_bloc:
    #print b
    if not b.eval_stop or not b.eval_start:
        print b.label, 'unresolved bloc'
        continue

    #print b.label, esp_init-b.eval_start.pool[esp]
    #if eip in b.eval_stop.pool:
    #    print 'end at:', b.eval_stop.pool[eip], esp_init-b.eval_stop.pool[esp]

lines = reduce(lambda x,y:x+y.lines, all_bloc, [])
lines = [(l.offset, l) for l in lines]
lines.sort()
for o, l in lines:
    if not 'stack_h' in l.__dict__:
        l.stack_h = None
    print "%-20s"%str(l.stack_h), "%-20s"%str(l.stack_h_after), l
    #print "%-5s"%str(l.stack_h)
    #print l.arg

"""
for b in all_bloc:
    for l in b.lines:
        if not 'stack_h' in l.__dict__:
            l.stack_h = None
        print l.stack_h, l
"""
