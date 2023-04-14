from builtins import int as int_types
import warnings
import logging

from future.utils import viewitems, viewvalues
from past.builtins import basestring

log = logging.getLogger('loader_common')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.INFO)


def canon_libname_libfunc(libname, libfunc):
    assert isinstance(libname, basestring)
    assert isinstance(libfunc, basestring) or isinstance(libfunc, int_types)
    dn = libname.split('.')[0]
    if isinstance(libfunc, int_types):
        return str(dn), libfunc
    else:
        return "%s_%s" % (dn, libfunc)


class Loader(object):

    def __init__(self, vm, lib_base_ad=0x71111000, **kargs):
        self.vm = vm

        self.module_name_to_base_address = {}
        self.module_base_address_to_name = {}

        self.function_address_to_canonical_name = {}
        self.function_canonical_name_to_address = {}

        self.module_base_address_to_last_address = {}
        self.last_module_address = lib_base_ad
        self.module_name_to_export = {}
        self.canonical_name_to_dst_addr = {}
        self.function_address_to_info = {}
        self.unresolved_modules_names = set()

    def get_name2off(self):
        warnings.warn("Deprecated API: use .module_name_to_base_address(name) instead of name2off")
        return self.module_name_to_base_address

    def get_fad2cname(self):
        warnings.warn("Deprecated API: use .module_address_to_name(addr) instead of fad2cname")
        return self.function_address_to_canonical_name


    name2off = property(get_name2off)
    fad2cname = property(get_fad2cname)

    def fake_library_entry(self, module_name):
        addr = self.last_module_address
        log.warning("Create dummy entry for %r", module_name)
        self.unresolved_modules_names.add(module_name)
        self.module_name_to_base_address[module_name] = addr
        self.module_base_address_to_name[addr] = module_name
        self.module_base_address_to_last_address[addr] = addr + 0x4
        self.module_name_to_export[module_name] = {}
        self.last_module_address += 0x1000
        return addr

    def lib_get_add_base(self, name):
        raise NotImplementedError("Implement in sub class")

    def lib_get_add_func(self, libad, imp_ord_or_name, dst_ad=None):
        raise DeprecationWarning("Use resolve_function instead of lib_get_add_func")

    def load_module(self, vm, libname):
        raise NotImplementedError("Implement in sub class")

    def add_function(self, module_name, imp_ord_or_name, addr, dst_ad=None):
        canonical_name = canon_libname_libfunc(
            module_name, imp_ord_or_name
        )
        self.function_address_to_info[addr] = module_name, imp_ord_or_name

        if dst_ad is not None:
            self.canonical_name_to_dst_addr.setdefault(canonical_name, set()).add(dst_ad)

        self.function_address_to_canonical_name[addr] = canonical_name
        self.function_canonical_name_to_address[canonical_name] = addr

        return canonical_name

    def fake_resolve_function(self, module_address, imp_ord_or_name, dst_ad=None):
        module_name = self.module_base_address_to_name.get(module_address, None)
        if module_name is None:
            raise ValueError('unknown lib base!', hex(module_address))

        # test if not ordinatl
        # if imp_ord_or_name >0x10000:
        #    imp_ord_or_name = vm_get_str(imp_ord_or_name, 0x100)
        #    imp_ord_or_name = imp_ord_or_name[:imp_ord_or_name.find('\x00')]

        if imp_ord_or_name in self.module_name_to_export[module_name]:
            return self.module_name_to_export[module_name][imp_ord_or_name]
        log.debug('new imp %s %s' % (imp_ord_or_name, dst_ad))
        addr = self.module_base_address_to_last_address[module_address]
        canonical_name = self.add_function(module_name, imp_ord_or_name, addr, dst_ad=dst_ad)


        self.module_base_address_to_last_address[module_address] += 0x10  # arbitrary
        self.module_name_to_export[module_name][imp_ord_or_name] = addr
        self.function_canonical_name_to_address[canonical_name] = addr
        self.function_address_to_info[addr] = module_name, imp_ord_or_name
        return addr

    def check_dst_ad(self):
        for ad in self.lib_imp2dstad:
            all_ads = sorted(viewvalues(self.lib_imp2dstad[ad]))
            for i, x in enumerate(all_ads[:-1]):
                if x is None or all_ads[i + 1] is None:
                    return False
                if x + 4 != all_ads[i + 1]:
                    return False
        return True


