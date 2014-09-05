#!/usr/bin/env python

import os
from miasm2.core import asmbloc
from collections import defaultdict
import struct
from elfesteem import pe
from elfesteem import cstruct
from elfesteem import *

from csts import *
from miasm2.core.utils import *
from jitcore_tcc import JitCore_Tcc
from jitcore_llvm import JitCore_LLVM
from jitcore_python import JitCore_Python
from miasm2.core.bin_stream import bin_stream

from miasm2.ir.ir2C import init_arch_C
from miasm2.core.interval import interval
import inspect

import logging

log = logging.getLogger('jitload.py')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)

def whoami():
    return inspect.stack()[2][3]


class bin_stream_vm(bin_stream):

    def __init__(self, vm, offset=0L, base_offset=0L):
        self.offset = offset
        self.base_offset = base_offset
        self.vm = vm

    def getlen(self):
        return 0xFFFFFFFFFFFFFFFF

    def getbytes(self, start, l=1):
        try:
            s = self.vm.vm_get_mem(start + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(start))
        return s

    def readbs(self, l=1):
        try:
            s = self.vm.vm_get_mem(self.offset + self.base_offset, l)
        except:
            raise IOError('cannot get mem ad', hex(self.offset))
        self.offset += l
        return s

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def setoffset(self, val):
        self.offset = val


def get_import_address(e):
    import2addr = defaultdict(set)
    if e.DirImport.impdesc is None:
        return import2addr
    for s in e.DirImport.impdesc:
        # fthunk = e.rva2virt(s.firstthunk)
        # l = "%2d %-25s %s" % (i, repr(s.dlldescname), repr(s))
        libname = s.dlldescname.name.lower()
        for ii, imp in enumerate(s.impbynames):
            if isinstance(imp, pe.ImportByName):
                funcname = imp.name
            else:
                funcname = imp
            # l = "    %2d %-16s" % (ii, repr(funcname))
            import2addr[(libname, funcname)].add(
                e.rva2virt(s.firstthunk + e._wsize * ii / 8))
    return import2addr


def preload_pe(vm, e, runtime_lib, patch_vm_imp=True):
    fa = get_import_address(e)
    dyn_funcs = {}
    # log.debug('imported funcs: %s' % fa)
    for (libname, libfunc), ads in fa.items():
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                vm.vm_set_mem(
                    ad, struct.pack(cstruct.size2type[e._wsize], ad_libfunc))
    return dyn_funcs


def get_import_address_elf(e):
    import2addr = defaultdict(set)
    for sh in e.sh:
        if not hasattr(sh, 'rel'):
            continue
        for k, v in sh.rel.items():
            import2addr[('xxx', k)].add(v.offset)
    return import2addr


def preload_elf(vm, e, runtime_lib, patch_vm_imp=True):
    # XXX quick hack
    fa = get_import_address_elf(e)
    dyn_funcs = {}
    # log.debug('imported funcs: %s' % fa)
    for (libname, libfunc), ads in fa.items():
        for ad in ads:
            ad_base_lib = runtime_lib.lib_get_add_base(libname)
            ad_libfunc = runtime_lib.lib_get_add_func(ad_base_lib, libfunc, ad)

            libname_s = canon_libname_libfunc(libname, libfunc)
            dyn_funcs[libname_s] = ad_libfunc
            if patch_vm_imp:
                log.debug('patch %s %s %s' %
                          (hex(ad), hex(ad_libfunc), libfunc))
                vm.vm_set_mem(
                    ad, struct.pack(cstruct.size2type[e.size], ad_libfunc))
    return runtime_lib, dyn_funcs


def is_redirected_export(e, ad):
    # test is ad points to code or dll name
    out = ''
    for i in xrange(0x200):
        c = e.virt(ad + i)
        if c == "\x00":
            break
        out += c
        if not (c.isalnum() or c in "_.-+*$@&#()[]={}"):
            return False
    if not "." in out:
        return False
    i = out.find('.')
    return out[:i], out[i + 1:]


def get_export_name_addr_list(e):
    out = []
    # add func name
    for i, n in enumerate(e.DirExport.f_names):
        addr = e.DirExport.f_address[e.DirExport.f_nameordinals[i].ordinal]
        f_name = n.name.name
        # log.debug('%s %s' % (f_name, hex(e.rva2virt(addr.rva))))
        out.append((f_name, e.rva2virt(addr.rva)))

    # add func ordinal
    for i, o in enumerate(e.DirExport.f_nameordinals):
        addr = e.DirExport.f_address[o.ordinal]
        # log.debug('%s %s %s' % (o.ordinal, e.DirExport.expdesc.base,
        # hex(e.rva2virt(addr.rva))))
        out.append(
            (o.ordinal + e.DirExport.expdesc.base, e.rva2virt(addr.rva)))
    return out


def canon_libname_libfunc(libname, libfunc):
    dn = libname.split('.')[0]
    if type(libfunc) == str:
        return "%s_%s" % (dn, libfunc)
    else:
        return str(dn), libfunc


class libimp:

    def __init__(self, lib_base_ad=0x71111000, **kargs):
        self.name2off = {}
        self.libbase2lastad = {}
        self.libbase_ad = lib_base_ad
        self.lib_imp2ad = {}
        self.lib_imp2dstad = {}
        self.fad2cname = {}
        self.fad2info = {}
        self.all_exported_lib = []

    def lib_get_add_base(self, name):
        name = name.lower().strip(' ')
        if not "." in name:
            log.debug('warning adding .dll to modulename')
            name += '.dll'
            log.debug('%s' % name)

        if name in self.name2off:
            ad = self.name2off[name]
        else:
            ad = self.libbase_ad
            log.debug('new lib %s %s' % (name, hex(ad)))
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad + 0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000
        return ad

    def lib_get_add_func(self, libad, imp_ord_or_name, dst_ad=None):
        if not libad in self.name2off.values():
            raise ValueError('unknown lib base!', hex(libad))

        # test if not ordinatl
        # if imp_ord_or_name >0x10000:
        #    imp_ord_or_name = vm_get_str(imp_ord_or_name, 0x100)
        #    imp_ord_or_name = imp_ord_or_name[:imp_ord_or_name.find('\x00')]

        #/!\ can have multiple dst ad
        if not imp_ord_or_name in self.lib_imp2dstad[libad]:
            self.lib_imp2dstad[libad][imp_ord_or_name] = set()
        self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

        if imp_ord_or_name in self.lib_imp2ad[libad]:
            return self.lib_imp2ad[libad][imp_ord_or_name]
        # log.debug('new imp %s %s' % (imp_ord_or_name, dst_ad))
        ad = self.libbase2lastad[libad]
        self.libbase2lastad[libad] += 0x11  # arbitrary
        self.lib_imp2ad[libad][imp_ord_or_name] = ad

        name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
        c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
        self.fad2cname[ad] = c_name
        self.fad2info[ad] = libad, imp_ord_or_name
        return ad

    def check_dst_ad(self):
        for ad in self.lib_imp2dstad:
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads.sort()
            for i, x in enumerate(all_ads[:-1]):
                if x is None or all_ads[i + 1] is None:
                    return False
                if x + 4 != all_ads[i + 1]:
                    return False
        return True

    def add_export_lib(self, e, name):
        self.all_exported_lib.append(e)
        # will add real lib addresses to database
        if name in self.name2off:
            ad = self.name2off[name]
        else:
            log.debug('new lib %s' % name)
            ad = e.NThdr.ImageBase
            libad = ad
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad + 0x1
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000

            ads = get_export_name_addr_list(e)
            todo = ads
            # done = []
            while todo:
                # for imp_ord_or_name, ad in ads:
                imp_ord_or_name, ad = todo.pop()

                # if export is a redirection, search redirected dll
                # and get function real addr
                ret = is_redirected_export(e, ad)
                if ret:
                    exp_dname, exp_fname = ret
                    # log.debug('export redirection %s' % imp_ord_or_name)
                    # log.debug('source %s %s' % (exp_dname, exp_fname))
                    exp_dname = exp_dname + '.dll'
                    exp_dname = exp_dname.lower()
                    # if dll auto refes in redirection
                    if exp_dname == name:
                        libad_tmp = self.name2off[exp_dname]
                        if not exp_fname in self.lib_imp2ad[libad_tmp]:
                            # schedule func
                            todo = [(imp_ord_or_name, ad)] + todo
                            continue
                    elif not exp_dname in self.name2off:
                        raise ValueError('load %r first' % exp_dname)
                    c_name = canon_libname_libfunc(exp_dname, exp_fname)
                    libad_tmp = self.name2off[exp_dname]
                    ad = self.lib_imp2ad[libad_tmp][exp_fname]
                    # log.debug('%s' % hex(ad))
                # if not imp_ord_or_name in self.lib_imp2dstad[libad]:
                #    self.lib_imp2dstad[libad][imp_ord_or_name] = set()
                # self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

                # log.debug('new imp %s %s' % (imp_ord_or_name, hex(ad)))
                self.lib_imp2ad[libad][imp_ord_or_name] = ad

                name_inv = dict([(x[1], x[0]) for x in self.name2off.items()])
                c_name = canon_libname_libfunc(
                    name_inv[libad], imp_ord_or_name)
                self.fad2cname[ad] = c_name
                self.fad2info[ad] = libad, imp_ord_or_name

    def gen_new_lib(self, e, filter=lambda x: True):
        new_lib = []
        for n, ad in self.name2off.items():
            out_ads = dict()
            for k, vs in self.lib_imp2dstad[ad].items():
                for v in vs:
                    out_ads[v] = k
            all_ads = self.lib_imp2dstad[ad].values()
            all_ads = reduce(lambda x, y: x + list(y), all_ads, [])
            all_ads = [x for x in all_ads if filter(x)]
            log.debug('ads: %s' % [hex(x) for x in all_ads])
            all_ads.sort()
            # first, drop None
            if not all_ads:
                continue
            for i, x in enumerate(all_ads):
                if not x in [0,  None]:
                    break
            all_ads = all_ads[i:]
            while all_ads:
                othunk = all_ads[0]
                i = 0
                while i + 1 < len(all_ads) and all_ads[i] + 4 == all_ads[i + 1]:
                    i += 1
                funcs = [out_ads[x] for x in all_ads[:i + 1]]
                try:
                    rva = e.virt2rva(othunk)
                except pe.InvalidOffset:
                    rva = None
                if rva is not None:  # e.is_in_virt_address(othunk):
                    new_lib.append(({"name": n,
                                     "firstthunk": rva},
                                    funcs)
                                   )
                all_ads = all_ads[i + 1:]
        return new_lib


def vm_load_pe(vm, fname, align_s=True, load_hdr=True,
               **kargs):
    e = pe_init.PE(open(fname, 'rb').read(), **kargs)

    aligned = True
    for s in e.SHList:
        if s.addr & 0xFFF:
            aligned = False
            break

    if aligned:
        if load_hdr:
            hdr_len = max(0x200, e.NThdr.sectionalignment)
            min_len = min(e.SHList[0].addr, hdr_len)
            pe_hdr = e.content[:hdr_len]
            pe_hdr = pe_hdr + min_len * "\x00"
            pe_hdr = pe_hdr[:min_len]
            vm.vm_add_memory_page(
                e.NThdr.ImageBase, PAGE_READ | PAGE_WRITE, pe_hdr)
        if align_s:
            for i, s in enumerate(e.SHList[:-1]):
                s.size = e.SHList[i + 1].addr - s.addr
                s.rawsize = s.size
                s.data = strpatchwork.StrPatchwork(s.data[:s.size])
                s.offset = s.addr
            s = e.SHList[-1]
            s.size = (s.size + 0xfff) & 0xfffff000
        for s in e.SHList:
            data = str(s.data)
            data += "\x00" * (s.size - len(data))
            # log.debug('SECTION %s %s' % (hex(s.addr),
            # hex(e.rva2virt(s.addr))))
            vm.vm_add_memory_page(
                e.rva2virt(s.addr), PAGE_READ | PAGE_WRITE, data)
            # s.offset = s.addr
        return e

    # not aligned
    log.warning('pe is not aligned, creating big section')
    min_addr = None
    max_addr = None
    data = ""

    if load_hdr:
        data = e.content[:0x400]
        data += (e.SHList[0].addr - len(data)) * "\x00"
        min_addr = 0

    for i, s in enumerate(e.SHList):
        if i < len(e.SHList) - 1:
            s.size = e.SHList[i + 1].addr - s.addr
        s.rawsize = s.size
        s.offset = s.addr

        if min_addr is None or s.addr < min_addr:
            min_addr = s.addr
        if max_addr is None or s.addr + s.size > max_addr:
            max_addr = s.addr + max(s.size, len(s.data))
    min_addr = e.rva2virt(min_addr)
    max_addr = e.rva2virt(max_addr)
    log.debug('%s %s %s' %
              (hex(min_addr), hex(max_addr), hex(max_addr - min_addr)))

    vm.vm_add_memory_page(min_addr,
                          PAGE_READ | PAGE_WRITE,
                          (max_addr - min_addr) * "\x00")
    for s in e.SHList:
        log.debug('%s %s' % (hex(e.rva2virt(s.addr)), len(s.data)))
        vm.vm_set_mem(e.rva2virt(s.addr), str(s.data))
    return e


def vm_load_elf(vm, fname, **kargs):
    """
    Very dirty elf loader
    TODO XXX: implement real loader
    """
    #log.setLevel(logging.DEBUG)
    e = elf_init.ELF(open(fname, 'rb').read(), **kargs)
    i = interval()
    all_data = {}
    for p in e.ph.phlist:
        if p.ph.type != 1:
            continue
        log.debug('%s %s %s %s' %
                  (hex(p.ph.vaddr), hex(p.ph.memsz), hex(p.ph.offset), hex(p.ph.filesz)))
        data_o = e._content[p.ph.offset:p.ph.offset + p.ph.filesz]
        addr_o = p.ph.vaddr
        a_addr = addr_o & ~0xFFF
        b_addr = addr_o + max(p.ph.memsz, p.ph.filesz)
        b_addr = (b_addr + 0xFFF) & ~0xFFF
        all_data[addr_o] = data_o
        # -2: Trick to avoid merging 2 consecutive pages
        i += [(a_addr, b_addr-2)]
    for a, b in i.intervals:
        #print hex(a), hex(b)
        vm.vm_add_memory_page(a, PAGE_READ | PAGE_WRITE, "\x00"*(b+2-a))

    #vm.vm_dump_memory_page_pool()

    for r_vaddr, data in all_data.items():
        vm.vm_set_mem(r_vaddr, data)
    return e

def vm_load_pe_lib(fname_in, libs, lib_path_base, patch_vm_imp, **kargs):
    fname = os.path.join(lib_path_base, fname_in)
    e = vm_load_pe(fname, **kargs)
    libs.add_export_lib(e, fname_in)
    # preload_pe(e, libs, patch_vm_imp)
    return e


def vm_load_pe_libs(libs_name, libs, lib_path_base="win_dll",
                    patch_vm_imp=True, **kargs):
    lib_imgs = {}
    for fname in libs_name:
        e = vm_load_pe_lib(fname, libs, lib_path_base, patch_vm_imp)
        lib_imgs[fname] = e
    return lib_imgs


def vm_fix_imports_pe_libs(lib_imgs, libs, lib_path_base="win_dll",
                           patch_vm_imp=True, **kargs):
    for e in lib_imgs.values():
        preload_pe(e, libs, patch_vm_imp)



class CallbackHandler(object):

    "Handle a list of callback"

    def __init__(self):
        self.callbacks = {}  # Key -> [callback list]

    def add_callback(self, name, callback):
        "Add a callback to the key 'name'"
        self.callbacks[name] = self.callbacks.get(name, []) + [callback]

    def set_callback(self, name, *args):
        "Set the list of callback for key 'name'"
        self.callbacks[name] = list(args)

    def get_callbacks(self, name):
        "Return the list of callbacks associated to key 'name'"
        return self.callbacks.get(name, [])

    def remove_callback(self, callback):
        """Remove the callback from the list.
        Return the list of empty keys (removed)"""

        to_check = set()
        for key, cb_list in self.callbacks.items():
            try:
                cb_list.remove(callback)
                to_check.add(key)
            except ValueError:
                pass

        empty_keys = []
        for key in to_check:
            if len(self.callbacks[key]) == 0:
                empty_keys.append(key)
                del(self.callbacks[key])

        return empty_keys

    def call_callbacks(self, name, *args):
        """Call callbacks associated to key 'name' with arguments args. While
        callbacks return True, continue with next callback.
        Iterator on other results."""

        res = True

        for c in self.get_callbacks(name):
            res = c(*args)
            if res is not True:
                yield res

    def __call__(self, name, *args):
        "Wrapper for call_callbacks"
        return self.call_callbacks(name, *args)


class CallbackHandlerBitflag(CallbackHandler):

    "Handle a list of callback with conditions on bitflag"

    def __call__(self, bitflag, *args):
        """Call each callbacks associated with bit set in bitflag. While
        callbacks return True, continue with next callback.
        Iterator on other results"""

        res = True
        for b in self.callbacks.keys():

            if b & bitflag != 0:
                # If the flag matched
                for res in self.call_callbacks(b, *args):
                    if res is not True:
                        yield res


class ExceptionHandle():

    "Return type for exception handler"

    def __init__(self, except_flag):
        self.except_flag = except_flag

    @classmethod
    def memoryBreakpoint(cls):
        return cls(EXCEPT_BREAKPOINT_INTERN)

    def __eq__(self, to_cmp):
        if not isinstance(to_cmp, ExceptionHandle):
            return False
        return (self.except_flag == to_cmp.except_flag)


class jitter:

    "Main class for JIT handling"

    def __init__(self, ir_arch, jit_type="tcc"):
        """Init an instance of jitter.
        @ir_arch: ir instance for this architecture
        @jit_type: JiT backend to use. Available options are:
            - "tcc"
            - "llvm"
            - "python"
        """

        self.arch = ir_arch.arch
        self.attrib = ir_arch.attrib
        arch_name = ir_arch.arch.name  # (ir_arch.arch.name, ir_arch.attrib)
        if arch_name == "x86":
            from arch import JitCore_x86 as jcore
        elif arch_name == "arm":
            from arch import JitCore_arm as jcore
        elif arch_name == "msp430":
            from arch import JitCore_msp430 as jcore
        elif arch_name == "mips32":
            from arch import JitCore_mips32 as jcore
        else:
            raise ValueError("unsupported jit arch!")

        self.cpu = jcore.JitCpu()
        self.vm = jcore.VmMngr()
        self.bs = bin_stream_vm(self.vm)
        self.ir_arch = ir_arch
        init_arch_C(self.arch)

        if jit_type == "tcc":
            self.jit = JitCore_Tcc(self.ir_arch, self.bs)
        elif jit_type == "llvm":
            self.jit = JitCore_LLVM(self.ir_arch, self.bs)
        elif jit_type == "python":
            self.jit = JitCore_Python(self.ir_arch, self.bs)
        else:
            raise Exception("Unkown JiT Backend")

        self.cpu.vm_init_regs()
        self.vm.vm_init_memory_page_pool()
        self.vm.vm_init_code_bloc_pool()
        self.vm.vm_init_memory_breakpoint()

        self.vm.vm_set_addr2obj(self.jit.addr2obj)

        self.jit.load()
        self.stack_size = 0x10000
        self.stack_base = 0x1230000

        # Init callback handler
        self.breakpoints_handler = CallbackHandler()
        self.exceptions_handler = CallbackHandlerBitflag()
        self.init_exceptions_handler()
        self.exec_cb = None

    def init_exceptions_handler(self):
        "Add common exceptions handlers"

        def exception_automod(jitter):
            "Tell the JiT backend to update blocs modified"
            addr = self.vm.vm_get_last_write_ad()
            size = self.vm.vm_get_last_write_size()

            self.jit.updt_automod_code(self.vm, addr, size)
            self.vm.vm_set_exception(0)

            return True

        def exception_memory_breakpoint(jitter):
            "Stop the execution and return an identifier"
            return ExceptionHandle.memoryBreakpoint()

        self.add_exception_handler(EXCEPT_CODE_AUTOMOD, exception_automod)
        self.add_exception_handler(EXCEPT_BREAKPOINT_INTERN,
                                   exception_memory_breakpoint)

    def add_breakpoint(self, addr, callback):
        """Add a callback associated with addr.
        @addr: breakpoint address
        @callback: function with definition (jitter instance)
        """
        self.breakpoints_handler.add_callback(addr, callback)
        self.jit.add_disassembly_splits(addr)

    def set_breakpoint(self, addr, *args):
        """Set callbacks associated with addr.
        @addr: breakpoint address
        @args: functions with definition (jitter instance)
        """
        self.breakpoints_handler.set_callback(addr, *args)
        self.jit.add_disassembly_splits(addr)

    def remove_breakpoints_by_callback(self, callback):
        """Remove callbacks associated with breakpoint.
        @callback: callback to remove
        """
        empty_keys = self.breakpoints_handler.remove_callback(callback)
        for key in empty_keys:
            self.jit.remove_disassembly_splits(key)

    def add_exception_handler(self, flag, callback):
        """Add a callback associated with an exception flag.
        @flag: bitflag
        @callback: function with definition (jitter instance)
        """
        self.exceptions_handler.add_callback(flag, callback)

    def runbloc(self, pc):
        """Wrapper on JiT backend. Run the code at PC and return the next PC.
        @pc: address of code to run"""

        return self.jit.runbloc(self.cpu, self.vm, pc)

    def runiter_once(self, pc):
        """Iterator on callbacks results on code running from PC.
        Check exceptions before breakpoints."""

        self.pc = pc

        # Callback called before exec
        if self.exec_cb is not None:
            res = self.exec_cb(self)
            if res is not True:
                yield res

        # Check breakpoints
        old_pc = self.pc
        for res in self.breakpoints_handler(self.pc, self):
            if res is not True:
                yield res

        # If a callback changed pc, re call every callback
        if old_pc != self.pc:
            return

        # Exceptions should never be activated before run
        assert(self.get_exception() == 0)

        # Run the bloc at PC
        self.pc = self.runbloc(self.pc)

        # Check exceptions
        exception_flag = self.get_exception()
        for res in self.exceptions_handler(exception_flag, self):
            if res is not True:
                yield res

    def init_run(self, pc):
        """Create an iterator on pc with runiter.
        @pc: address of code to run
        """
        self.run_iterator = self.runiter_once(pc)
        self.pc = pc
        self.run = True

    def continue_run(self, step=False):
        """PRE: init_run.
        Continue the run of the current session until iterator returns or run is
        set to False.
        If step is True, run only one time.
        Return the iterator value"""

        while self.run:
            try:
                return self.run_iterator.next()
            except StopIteration:
                pass

            self.run_iterator = self.runiter_once(self.pc)

            if step is True:
                return None

        return None

    def init_stack(self):
        self.vm.vm_add_memory_page(
            self.stack_base, PAGE_READ | PAGE_WRITE, "\x00" * self.stack_size)
        sp = self.arch.getsp(self.attrib)
        setattr(self.cpu, sp.name, self.stack_base + self.stack_size)
        # regs = self.cpu.vm_get_gpreg()
        # regs[sp.name] = self.stack_base+self.stack_size
        # self.cpu.vm_set_gpreg(regs)

    def get_exception(self):
        return self.cpu.vm_get_exception() | self.vm.vm_get_exception()

    # commun functions
    def get_str_ansi(self, addr, max_char=None):
        """Get ansi str from vm.
        @addr: address in memory
        @max_char: maximum len"""
        l = 0
        tmp = addr
        while ((max_char is None or l < max_char) and
            self.vm.vm_get_mem(tmp, 1) != "\x00"):
            tmp += 1
            l += 1
        return self.vm.vm_get_mem(addr, l)

    def get_str_unic(self, addr, max_char=None):
        """Get unicode str from vm.
        @addr: address in memory
        @max_char: maximum len"""
        l = 0
        tmp = addr
        while ((max_char is None or l < max_char) and
            self.vm.vm_get_mem(tmp, 2) != "\x00\x00"):
            tmp += 2
            l += 2
        s = self.vm.vm_get_mem(addr, l)
        s = s[::2]  # TODO: real unicode decoding
        return s

    def set_str_ansi(self, addr, s):
        """Set an ansi string in memory"""
        s = s + "\x00"
        self.vm.vm_set_mem(addr, s)

    def set_str_unic(self, addr, s):
        """Set an unicode string in memory"""
        s = "\x00".join(list(s)) + '\x00' * 3
        self.vm.vm_set_mem(addr, s)




def vm2pe(myjit, fname, libs=None, e_orig=None,
          max_addr=1 << 64, min_addr=0x401000,
          min_section_offset=0x1000, img_base=None,
          added_funcs=None):
    mye = pe_init.PE()

    if img_base is None:
        img_base = e_orig.NThdr.ImageBase

    mye.NThdr.ImageBase = img_base
    all_mem = myjit.vm.vm_get_all_memory()
    addrs = all_mem.keys()
    addrs.sort()
    mye.Opthdr.AddressOfEntryPoint = mye.virt2rva(myjit.cpu.EIP)
    first = True
    for ad in addrs:
        if not min_addr <= ad < max_addr:
            continue
        log.debug('%s' % hex(ad))
        if first:
            mye.SHList.add_section(
                "%.8X" % ad,
                addr=ad - mye.NThdr.ImageBase,
                data=all_mem[ad]['data'],
                offset=min_section_offset)
        else:
            mye.SHList.add_section(
                "%.8X" % ad,
                addr=ad - mye.NThdr.ImageBase,
                data=all_mem[ad]['data'])
        first = False
    if libs:
        if added_funcs is not None:
            # name_inv = dict([(x[1], x[0]) for x in libs.name2off.items()])

            for addr, funcaddr in added_func:
                libbase, dllname = libs.fad2info[funcaddr]
                libs.lib_get_add_func(libbase, dllname, addr)

        new_dll = libs.gen_new_lib(mye, lambda x: mye.virt.is_addr_in(x))
    else:
        new_dll = {}

    log.debug('%s' % new_dll)

    mye.DirImport.add_dlldesc(new_dll)
    s_imp = mye.SHList.add_section("import", rawsize=len(mye.DirImport))
    mye.DirImport.set_rva(s_imp.addr)
    log.debug('%s' % repr(mye.SHList))
    if e_orig:
        # resource
        xx = str(mye)
        mye.content = xx
        ad = e_orig.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].rva
        log.debug('dirres %s' % hex(ad))
        if ad != 0:
            mye.NThdr.optentries[pe.DIRECTORY_ENTRY_RESOURCE].rva = ad
            mye.DirRes = pe.DirRes.unpack(xx, ad, mye)
            # log.debug('%s' % repr(mye.DirRes))
            s_res = mye.SHList.add_section(
                name="myres", rawsize=len(mye.DirRes))
            mye.DirRes.set_rva(s_res.addr)
            log.debug('%s' % repr(mye.DirRes))
    # generation
    open(fname, 'w').write(str(mye))

