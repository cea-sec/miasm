#! /usr/bin/env python

from distutils.core import setup, Extension
from distutils.util import get_platform
import shutil
import os, sys

def buil_all():
    packages=['miasm2',
              'miasm2/arch',
              'miasm2/arch/x86',
              'miasm2/arch/arm',
              'miasm2/arch/aarch64',
              'miasm2/arch/msp430',
              'miasm2/arch/mep',
              'miasm2/arch/sh4',
              'miasm2/arch/mips32',
              'miasm2/arch/ppc',
              'miasm2/core',
              'miasm2/expression',
              'miasm2/ir',
              'miasm2/ir/translators',
              'miasm2/analysis',
              'miasm2/os_dep',
              'miasm2/os_dep/linux',
              'miasm2/jitter',
              'miasm2/jitter/arch',
              'miasm2/jitter/loader',
              ]
    ext_modules_all = [
        Extension("miasm2.jitter.VmMngr",
                  ["miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/vm_mngr_py.c",
                   "miasm2/jitter/bn.c",
                  ]),
        Extension("miasm2.jitter.arch.JitCore_x86",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_x86.c"]),
        Extension("miasm2.jitter.arch.JitCore_arm",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_arm.c"]),
        Extension("miasm2.jitter.arch.JitCore_aarch64",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_aarch64.c"]),
        Extension("miasm2.jitter.arch.JitCore_msp430",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_msp430.c"]),
        Extension("miasm2.jitter.arch.JitCore_mep",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_mep.c"]),
        Extension("miasm2.jitter.arch.JitCore_mips32",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_mips32.c"]),
        Extension("miasm2.jitter.arch.JitCore_ppc32",
                  ["miasm2/jitter/JitCore.c",
                   "miasm2/jitter/vm_mngr.c",
                   "miasm2/jitter/op_semantics.c",
                   "miasm2/jitter/bn.c",
                   "miasm2/jitter/arch/JitCore_ppc32.c"],
                  depends=["miasm2/jitter/arch/JitCore_ppc32.h",
                           "miasm2/jitter/arch/JitCore_ppc32_regs.h",
                           "miasm2/jitter/bn.h",
                  ]),
        Extension("miasm2.jitter.Jitllvm",
                  ["miasm2/jitter/Jitllvm.c",
                   "miasm2/jitter/bn.c",
                  ]),
        Extension("miasm2.jitter.Jitgcc",
                  ["miasm2/jitter/Jitgcc.c",
                   "miasm2/jitter/bn.c",
                  ]),
        ]

    print 'building'
    build_ok = False
    for name, ext_modules in [('all', ext_modules_all),
    ]:
        print 'build with', repr(name)
        try:
            s = setup(
                name = 'Miasm',
                version = '2.0',
                packages = packages,
                package_data = {'miasm2':['jitter/*.h',
                                          'jitter/arch/*.h',]},
                ext_modules = ext_modules,
                # Metadata
                author = 'Fabrice Desclaux',
                author_email = 'serpilliere@droid-corp.org',
                description = 'Machine code manipulation library',
                license = 'GPLv2',
                # keywords = '',
                # url = '',
            )
        except SystemExit, e:
            print repr(e)
            continue
        build_ok = True
        break
    if not build_ok:
        raise ValueError('Unable to build Miasm!')
    print 'build', name
    # we copy libraries from build dir to current miasm directory
    build_base = None
    if 'build' in s.command_options:
        if 'build_base' in s.command_options['build']:
            build_base = s.command_options['build']['build_base']
    if build_base is None:
        build_base = "build"
        plat_specifier = ".%s-%s" % (get_platform(), sys.version[0:3])
        build_base = os.path.join('build','lib' + plat_specifier)
        print build_base

buil_all()
