import logging

log = logging.getLogger('loader_common')
hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log.addHandler(hnd)
log.setLevel(logging.CRITICAL)


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

    def gen_new_lib(self, target_pe, filter=lambda _: True):
        """Gen a new DirImport description
        @target_pe: PE instance
        @filter: (boolean f(address)) restrict addresses to keep
        """

        new_lib = []
        for lib_name, ad in self.name2off.items():
            # Build an IMAGE_IMPORT_DESCRIPTOR

            # Get fixed addresses
            out_ads = dict() # addr -> func_name
            for func_name, dst_addresses in self.lib_imp2dstad[ad].items():
                out_ads.update({addr:func_name for addr in dst_addresses})

            # Filter available addresses according to @filter
            all_ads = [addr for addr in out_ads.keys() if filter(addr)]
            log.debug('ads: %s' % map(hex, all_ads))
            if not all_ads:
                continue

            # Keep non-NULL elements
            all_ads.sort()
            for i, x in enumerate(all_ads):
                if x not in [0,  None]:
                    break
            all_ads = all_ads[i:]

            while all_ads:
                # Find libname's Import Address Table
                othunk = all_ads[0]
                i = 0
                while i + 1 < len(all_ads) and all_ads[i] + 4 == all_ads[i + 1]:
                    i += 1
                # 'i + 1' is IAT's length

                # Effectively build an IMAGE_IMPORT_DESCRIPTOR
                funcs = [out_ads[addr] for addr in all_ads[:i + 1]]
                try:
                    rva = target_pe.virt2rva(othunk)
                except pe.InvalidOffset:
                    pass
                else:
                    new_lib.append(({"name": lib_name,
                                     "firstthunk": rva},
                                    funcs)
                                   )

                # Update elements to handle
                all_ads = all_ads[i + 1:]

        return new_lib


