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
from elfesteem import *
from elfesteem import pe
from elfesteem import cstruct

from miasm.arch.ia32_arch import *
from miasm.tools.emul_helper import *
from miasm.arch.ia32_sem import *
import struct
import miasm.core.asmbloc
import miasm.core.bin_stream
import os
import re
from  miasm.tools import to_c_helper
from miasm.core import bin_stream
pe_cache = {}
def pe_from_name(n):
    global pe_cache
    
    my_path = 'win_dll/'
    all_pe = os.listdir(my_path)
    if not n in all_pe:
        print 'cannot find PE', n
        return None

    pe_name = my_path+n
    if pe_name in pe_cache:
        return pe_cache[pe_name]
    e = pe_init.PE(open(pe_name, 'rb').read())
    pe_cache[pe_name] = e
    return e


def func_from_import(pe_name, func):
    e = pe_from_name(pe_name)

    if not e or not e.DirExport:
        print 'no export dir found'
        return None, None


    found = None
    if type(func) is str:
        for i, n in enumerate(e.DirExport.f_names):
            if n.name.name == func:
                found = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
                break

    elif type(func) in [int, long]:
        for i, n in enumerate(e.DirExport.f_names):
            if e.DirExport.f_nameordinals[i].ordinal+e.DirExport.expdesc.base == func:
                found = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
                break
    else:
        raise ValueError('unknown fund type', func)

    #XXX todo: test if redirected export
    return e, found



def is_rva_in_code_section(e, rva):
    s = e.getsectionbyrva(rva)
    return s.flags&0x20!=0

def guess_func_destack_dis(e, ad):
    job_done = set()
    symbol_pool = asmbloc.asm_symbol_pool()
    in_str = bin_stream(e.virt)
    
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad, job_done, symbol_pool, follow_call = False, patch_instr_symb = False)
    return guess_func_destack(all_bloc)
    

def guess_imports_ret_unstack(e):
    unresolved = set()
    resolved = {}
    redirected = {}
    for i,s in enumerate(e.DirImport.impdesc):
        l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
        libname = s.dlldescname.name
    
    
        for ii, f in enumerate(s.impbynames):
            print '_'*20
            funcname = f.name
            
            
            my_e, ret = func_from_import(libname.lower(), funcname)
            if ret:
                func_addr = my_e.rva2virt(ret.rva)
                print funcname, hex(func_addr)
            else:
                print 'not found'
                continue
    
            #XXX python int obj len zarb bug
            imgb = my_e.NThdr.ImageBase
            if imgb>0x80000000:
                imgb-=0x40000000
                func_addr-=0x40000000
                my_e.NThdr.ImageBase = imgb
            
            if not is_rva_in_code_section(my_e, ret.rva):
                print "not in code section"
                continue


            ok, r = guess_func_destack_dis(my_e, func_addr)
            print funcname, 'ret', r
            if ok == True:
                resolved[(libname, funcname)] = r
            elif ok == None:
                unresolved.add((libname, funcname))
            else:
                resolved[(libname, funcname)] = r


    return resolved, unresolved, redirected


def get_import_address(e):
    import2addr = {}
    
    for i,s in enumerate(e.DirImport.impdesc):
        fthunk = e.rva2virt(s.firstthunk)
        l = "%2d %-25s %s"%(i, repr(s.dlldescname) ,repr(s))
        
        libname = s.dlldescname.name.lower()
        for ii, imp in enumerate(s.impbynames):
            if isinstance(imp, pe.ImportByName):
                funcname = imp.name
            else:
                funcname = imp
            l = "    %2d %-16s"%(ii, repr(funcname))
    
    
            import2addr[(libname, funcname)] = e.rva2virt(s.firstthunk+4*ii)
    return import2addr


def get_import_address_elf(e):
    import2addr = {}
    for sh in e.sh:
        if not hasattr(sh, 'rel'):
            continue
        for k, v in sh.rel.items():
            import2addr[('xxx', k)] = v.offset
    return import2addr


def get_symbols_elf(e):
    sym2addr = {}
    for k, v in e.sh.dynsym.symbols.items():
        sym2addr[k] = v
    return sym2addr


def get_java_constant_pool(e):
    constants = {}
    for i, c in enumerate(e.hdr.constants_pool):
        constants[i+1] = c
    return constants

def guess_redirected(e, resolved, unresolved, redirected, import2addr):

    import2addr_inv = [(x[1], x[0]) for x in import2addr.items()]
    

    to_del = []
    for imp in redirected:
        ad = redirected[imp]
        if ad in import2addr_inv:
            my_imp = import2addr[ad]
            if not my_imp in resolved:
                continue
            else:
                resolved[my_imp] = resolved[imp]
                to_del.append(my_imp)
                

    redirected = [x for x in redirected if not x in to_del]
    
    return resolved, unresolved, redirected
            

if __name__ == '__main__':
    e, ret = func_from_import('hal.dll', 'KfAcquireSpinLock')
    if ret:
        print dir(ret)
        print hex(e.rva2virt(ret.rva))

def get_imp_to_dict(e):
    imp2ad = get_import_address(e)
    imp_d = {}
    
    for libf, ad in imp2ad.items():
        libname, f = libf
        imp_d[ad] = libf
    return imp_d




def get_imp_bloc(all_bloc, new_lib, imp_d, symbol_pool):
    f_imps = []
    symb_equiv = {}
    for b in all_bloc:
        for l in b.lines:
            for a in l.arg:
                if not x86_afs.ad in a or not a[x86_afs.ad]:
                    continue
                print a
                if not x86_afs.imm in a:
                    continue
                ad = a[x86_afs.imm]
                if not ad in imp_d:
                    continue
                print 'spot', ad, l
                lab = symbol_pool.getby_offset_create(ad)
                print lab


                l = symbol_pool.getby_offset(ad)
                print "ioioio", l
                l.offset = None

                a[x86_afs.symb] = {lab.name:1}
                print a
                del a[x86_afs.imm]

                libname, func = imp_d[ad]
                print func
                new_lib.append(
                    ({"name":libname,
                      "firstthunk":None},
                     [func]),
                    )
                f_imps.append(func)
                symb_equiv[func] = l
    return f_imps, symb_equiv


def code_is_line(e, ad):
    job_done = set()
    in_str = bin_stream.bin_stream(e.virt)
    symbol_pool = asmbloc.asm_symbol_pool()
    all_bloc = asmbloc.dis_bloc_all(x86_mn, in_str, ad, job_done, symbol_pool, bloc_wd = 2)
    if len(all_bloc) !=1:
        return None
    if len(all_bloc[0].lines)!=1:
        return None
    return all_bloc

def is_jmp_imp(l, imp_d):
    if not l.m.name == 'jmp':
        return False
    if not is_address(l.arg[0]):
        return False
    ad = dict(l.arg[0])
    del ad[x86_afs.ad]
    if not is_imm(ad):
        return False
    print ad
    i = ad[x86_afs.imm]
    if not i in imp_d:
        return False
    print imp_d[i]
    return imp_d[i]


def code_is_jmp_imp(e, ad, imp_d):
    all_bloc = code_is_line(e, ad)
    if not all_bloc:
        return None
    l = all_bloc[0].lines[0]
    return is_jmp_imp(l, imp_d)


#giving e and address in function guess function start
def guess_func_start(e, middle_ad, max_offset = 0x200):
    ad = middle_ad+1
    ad_found = None
    while ad > middle_ad - max_offset:
        ad-=1

        ####### heuristic CC pad #######
        if e.virt[ad] == "\xCC":
            if e.virt[((ad+3)&~3)-1] == "\xCC":
                ad_found = ((ad+3)&~3)
                break
            else:
                continue
        
        
        l = x86_mn.dis(e.virt[ad:ad+15])
        if not l:
            continue
        if l.m.name in ["ret"]:
            ad_found = ad+l.l
            break
        
    if not ad_found:
        print 'cannot find func start'
        return None

    while e.virt[ad_found] == "\xCC":
        ad_found+=1

    if e.virt[ad_found:ad_found+3] == "\x8D\x40\x00":
        ad_found += 3
    

    return ad_found

def get_nul_term(e, ad):
    out = ""
    while True:
        c = e.virt[ad]
        if c == None:
            return None
        if c == "\x00":
            break
        out+=c
        ad+=1
    return out

#return None if is not str
def guess_is_string(out):
    if out == None or len(out) == 0:
        return None
    cpt = 0
    for c in out:
        if c.isalnum():
            cpt+=1
    if cpt * 100 / len(out) > 40:
        return out
    
    return None


def get_guess_string(e, ad):
    s = get_nul_term(e, ad)
    return guess_is_string(s)
    

            
    


def canon_libname_libfunc(libname, libfunc):
    dn = libname.split('.')[0]
    fn = "%s"%libfunc
    return "%s_%s"%(dn, fn)
    

class libimp:
    def __init__(self, lib_base_ad = 0x77700000):
        self.name2off = {}
        self.libbase2lastad = {}
        self.libbase_ad = lib_base_ad
        self.lib_imp2ad = {}
        self.lib_imp2dstad = {}
        self.fad2cname = {}
        
    def lib_get_add_base(self, name):
        name = name.lower()
        if name in self.name2off:
            ad = self.name2off[name]
        else:
            print 'new lib', name
            ad = self.libbase_ad
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad+0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000
        return ad
    
    def lib_get_add_func(self, libad, imp_ord_or_name, dst_ad = None):
        if not libad in self.name2off.values():
            raise ValueError('unknown lib base!', hex(libad))

        #test if not ordinatl
        #if imp_ord_or_name >0x10000:
        #    imp_ord_or_name = vm_get_str(imp_ord_or_name, 0x100)
        #    imp_ord_or_name = imp_ord_or_name[:imp_ord_or_name.find('\x00')]


        #/!\ can have multiple dst ad
        if not imp_ord_or_name in self.lib_imp2dstad[libad]:
            self.lib_imp2dstad[libad][imp_ord_or_name] = set()
        self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)


        if imp_ord_or_name in self.lib_imp2ad[libad]:
            return self.lib_imp2ad[libad][imp_ord_or_name]
        print 'new imp', imp_ord_or_name, dst_ad
        ad = self.libbase2lastad[libad]
        self.libbase2lastad[libad] += 0x1
        self.lib_imp2ad[libad][imp_ord_or_name] = ad

        name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
        c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
        self.fad2cname[ad] = c_name
        return ad

    def check_dst_ad(self):
        for ad in self.lib_imp2dstad:
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads.sort()
            for i, x in enumerate(all_ads[:-1]):
                if x == None or all_ads[i+1] == None:
                    return False
                if x+4 != all_ads[i+1]:
                    return False
        return True
    
    def add_export_lib(self, e, name):
        # will add real lib addresses to database
        if name in self.name2off:
            ad = self.name2off[name]
        else:
            print 'new lib', name
            ad = e.NThdr.ImageBase
            libad = ad
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad+0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000

            ads = get_export_name_addr_list(e)
            for imp_ord_or_name, ad in ads:
                #if not imp_ord_or_name in self.lib_imp2dstad[libad]:
                #    self.lib_imp2dstad[libad][imp_ord_or_name] = set()
                #self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

                print 'new imp', imp_ord_or_name, hex(ad)
                self.lib_imp2ad[libad][imp_ord_or_name] = ad

                name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
                c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
                self.fad2cname[ad] = c_name


    def gen_new_lib(self, e):
        new_lib = []
        for n, ad in self.name2off.items():
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads = reduce(lambda x,y:x+list(y), all_ads, [])
            all_ads.sort()
            #first, drop None
            for i,x in enumerate(all_ads):
                if not x in [0,  None]:
                    break
            all_ads = all_ads[i:]
            while all_ads:
                othunk = all_ads[0]
                i = 0
                while i+1 < len(all_ads) and all_ads[i]+4 == all_ads[i+1]:
                    i+=1
                out_ads = dict()
                for k, vs in self.lib_imp2dstad[ad].items():
                    for v in vs:
                        out_ads[v] = k
                funcs = [out_ads[x] for x in all_ads[:i+1]]
                new_lib.append(({"name":n,
                                 "firstthunk":e.virt2rva(othunk)},
                                funcs)
                               )
                all_ads = all_ads[i+1:]
        return new_lib
            
                

def vm_load_pe(e, align_s = True, load_hdr = True):
    aligned = True
    for s in e.SHList:
        if s.addr & 0xFFF:
            aligned = False
            break

    if aligned:
        if load_hdr:
            pe_hdr = e.content[:0x400]+"\x00"*0xc00
            to_c_helper.vm_add_memory_page(e.NThdr.ImageBase, to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, pe_hdr)
    
        if align_s:
            for i, s in enumerate(e.SHList[:-1]):
                s.size = e.SHList[i+1].addr - s.addr
                s.rawsize = s.size
                s.offset = s.addr
            s = e.SHList[-1]
            s.size = (s.size+0xfff)&0xfffff000
        
        for s in e.SHList:
            data = str(s.data)
            data += "\x00"*(s.size-len(data))
            to_c_helper.vm_add_memory_page(e.rva2virt(s.addr), to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, data)
            s.offset = s.addr
        return

    #not aligned
    print 'WARNING pe is not aligned, creating big section'
    min_addr = None
    max_addr = None
    data = ""

    if load_hdr:
        data = e.content[:0x400]
        data += (e.SHList[0].addr - len(data))*"\x00"
        min_addr = 0


    
    for i, s in enumerate(e.SHList):
        if i < len(e.SHList)-1:
            s.size = e.SHList[i+1].addr - s.addr
        s.rawsize = s.size
        s.offset = s.addr

        if min_addr == None or s.addr < min_addr:
            min_addr = s.addr
            
        if max_addr == None or s.addr + s.size > max_addr:
            max_addr = s.addr + s.size
    min_addr = e.rva2virt(min_addr)
    max_addr = e.rva2virt(max_addr)

    print hex(min_addr) , hex(max_addr), hex(max_addr - min_addr)
    for s in e.SHList:
        data += str(s.data)
        data += "\x00"*(s.size-len(str(s.data)))

    vm_add_memory_page(min_addr, PAGE_READ|PAGE_WRITE, data)
    
    

def vm_load_elf(e, align_s = True, load_hdr = True):
    for p in e.ph.phlist:
        if p.ph.type != 1:
            continue
        print hex(p.ph.vaddr), hex(p.ph.offset), hex(p.ph.filesz)
        data = e._content[p.ph.offset:p.ph.offset + p.ph.filesz]
        
        r_vaddr = p.ph.vaddr & ~0xFFF
        data = (p.ph.vaddr - r_vaddr) *"\x00" + data
        data += (((len(data) +0xFFF) & ~0xFFF)-len(data)) * "\x00"
        to_c_helper.vm_add_memory_page(r_vaddr, to_c_helper.PAGE_READ|to_c_helper.PAGE_WRITE, data)
        
def preload_lib(e, runtime_lib, patch_vm_imp = True):
    fa = get_import_address(e)

    dyn_funcs = {}
    
    print 'imported funcs:', fa
    for (libname, libfunc), ad in fa.items():
        ad_base_lib = runtime_lib.lib_get_add_base(libname)
        ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

        libname_s = canon_libname_libfunc(libname, libfunc)
        dyn_funcs[libname_s] = ad_libfunc
        if patch_vm_imp:
            to_c_helper.vm_set_mem(ad, struct.pack(cstruct.size2type[e._wsize], ad_libfunc))
        
    return dyn_funcs

def preload_elf(e, patch_vm_imp = True, lib_base_ad = 0x77700000):
    # XXX quick hack
    fa = get_import_address_elf(e)
    runtime_lib = libimp(lib_base_ad)

    dyn_funcs = {}
    
    print 'imported funcs:', fa
    for (libname, libfunc), ad in fa.items():
        ad_base_lib = runtime_lib.lib_get_add_base(libname)
        ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

        libname_s = canon_libname_libfunc(libname, libfunc)
        dyn_funcs[libname_s] = ad_libfunc
        if patch_vm_imp:
            to_c_helper.vm_set_mem(ad, struct.pack(cstruct.size2type[e.size], ad_libfunc))
        
    return runtime_lib, dyn_funcs


def get_export_name_addr_list(e):
    out = []
    for i, n in enumerate(e.DirExport.f_names):
        addr = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
        f_name = n.name.name
        out.append((f_name, e.rva2virt(addr.rva)))
    return out



class find_call_xref:
    def __init__(self, e, off):
        import re
        self.e = e
        self.off = off
        #create itertor to find simple CALL offsets
        p = re.escape("\xE8")
        self.my_iter = re.finditer(p, e.content)
    def next(self):
        while True:
            off_i = self.my_iter.next().start()
            off = off_i + 5 + struct.unpack('i', self.e.content[off_i+1:off_i+5])[0]
            if off == self.off:
                return off_i
        raise StopIteration
    def __iter__(self):
        return self
        
