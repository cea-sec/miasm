from builtins import int as int_types
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


class libimp(object):

    def __init__(self, lib_base_ad=0x71111000, **kargs):
        self.name2off = {}
        self.libbase2lastad = {}
        self.libbase_ad = lib_base_ad
        self.lib_imp2ad = {}
        self.lib_imp2dstad = {}
        self.fad2cname = {}
        self.cname2addr = {}
        self.fad2info = {}
        self.all_exported_lib = []
        self.fake_libs = set()

    def lib_get_add_base(self, name):
        assert isinstance(name, basestring)
        name = name.lower().strip(' ')
        if not "." in name:
            log.warning('warning adding .dll to modulename')
            name += '.dll'
            log.warning(name)

        if name in self.name2off:
            ad = self.name2off[name]
        else:
            ad = self.libbase_ad
            log.warning("Create dummy entry for %r", name)
            self.fake_libs.add(name)
            self.name2off[name] = ad
            self.libbase2lastad[ad] = ad + 0x4
            self.lib_imp2ad[ad] = {}
            self.lib_imp2dstad[ad] = {}
            self.libbase_ad += 0x1000
        return ad

    def lib_get_add_func(self, libad, imp_ord_or_name, dst_ad=None):
        if not libad in viewvalues(self.name2off):
            raise ValueError('unknown lib base!', hex(libad))

        # test if not ordinatl
        # if imp_ord_or_name >0x10000:
        #    imp_ord_or_name = vm_get_str(imp_ord_or_name, 0x100)
        #    imp_ord_or_name = imp_ord_or_name[:imp_ord_or_name.find('\x00')]

        #/!\ can have multiple dst ad
        if not imp_ord_or_name in self.lib_imp2dstad[libad]:
            self.lib_imp2dstad[libad][imp_ord_or_name] = set()
        if dst_ad is not None:
            self.lib_imp2dstad[libad][imp_ord_or_name].add(dst_ad)

        if imp_ord_or_name in self.lib_imp2ad[libad]:
            return self.lib_imp2ad[libad][imp_ord_or_name]
        log.debug('new imp %s %s' % (imp_ord_or_name, dst_ad))
        ad = self.libbase2lastad[libad]
        self.libbase2lastad[libad] += 0x10  # arbitrary
        self.lib_imp2ad[libad][imp_ord_or_name] = ad

        name_inv = dict(
            (value, key) for key, value in viewitems(self.name2off)
        )
        c_name = canon_libname_libfunc(name_inv[libad], imp_ord_or_name)
        self.fad2cname[ad] = c_name
        self.cname2addr[c_name] = ad
        self.fad2info[ad] = libad, imp_ord_or_name
        return ad

    def check_dst_ad(self):
        for ad in self.lib_imp2dstad:
            all_ads = sorted(viewvalues(self.lib_imp2dstad[ad]))
            for i, x in enumerate(all_ads[:-1]):
                if x is None or all_ads[i + 1] is None:
                    return False
                if x + 4 != all_ads[i + 1]:
                    return False
        return True


