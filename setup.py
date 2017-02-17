#! /usr/bin/env python

from distutils.core import setup, Extension
from distutils.util import get_platform
import shutil
import os
import sys


def build_all():
    ext_modules_no_tcc = [
        Extension('miasm2.jitter.VmMngr',
                  ['miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/vm_mngr_py.c']),
        Extension('miasm2.jitter.arch.JitCore_x86',
                  ['miasm2/jitter/JitCore.c',
                   'miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/arch/JitCore_x86.c']),
        Extension('miasm2.jitter.arch.JitCore_arm',
                  ['miasm2/jitter/JitCore.c',
                   'miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/arch/JitCore_arm.c']),
        Extension('miasm2.jitter.arch.JitCore_aarch64',
                  ['miasm2/jitter/JitCore.c',
                   'miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/arch/JitCore_aarch64.c']),
        Extension('miasm2.jitter.arch.JitCore_msp430',
                  ['miasm2/jitter/JitCore.c',
                   'miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/arch/JitCore_msp430.c']),
        Extension('miasm2.jitter.arch.JitCore_mips32',
                  ['miasm2/jitter/JitCore.c',
                   'miasm2/jitter/vm_mngr.c',
                   'miasm2/jitter/arch/JitCore_mips32.c']),
        Extension('miasm2.jitter.Jitgcc',
                  ['miasm2/jitter/Jitgcc.c']),
        Extension('miasm2.jitter.Jitllvm',
                  ['miasm2/jitter/Jitllvm.c']),
    ]

    ext_modules_all = list(ext_modules_no_tcc)
    ext_modules_all.append(
        Extension('miasm2.jitter.Jittcc',
                  ['miasm2/jitter/Jittcc.c'],
                  libraries=['tcc'])
    )

    print 'building'
    build_ok = False
    if sys.platform == 'darwin':
        from distutils import sysconfig
        vars = sysconfig.get_config_vars()
        vars['LDSHARED'] = vars['LDSHARED'].replace('-bundle', '-dynamiclib')
    for name, ext_modules in [('all', ext_modules_all),
                              ('notcc', ext_modules_no_tcc)]:
        print 'build with', repr(name)
        try:
            s = setup(
                name='Miasm',
                version='2.0',
                packages=['miasm2',
                          'miasm2/arch',
                          'miasm2/arch/x86',
                          'miasm2/arch/arm',
                          'miasm2/arch/aarch64',
                          'miasm2/arch/msp430',
                          'miasm2/arch/sh4',
                          'miasm2/arch/mips32',
                          'miasm2/core',
                          'miasm2/expression',
                          'miasm2/ir',
                          'miasm2/ir/translators',
                          'miasm2/analysis',
                          'miasm2/os_dep',
                          'miasm2/jitter',
                          'miasm2/jitter/arch',
                          'miasm2/jitter/loader',
                          ],
                package_data={'miasm2': ['jitter/*.h',
                                         'jitter/arch/*.h', ]},
                ext_modules=ext_modules,
                # Metadata
                author='Fabrice Desclaux',
                author_email='serpilliere@droid-corp.org',
                description='Machine code manipulation library',
                license='GPLv2',
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
    if name == 'notcc':
        print
        print '*'*80
        print 'Warning: TCC is not properly installed,'
        print 'Miasm will be installed without TCC Jitter'
        print 'Etheir install TCC or use LLVM jitter'
        print '*'*80
        print
    # we copy libraries from build dir to current miasm directory
    build_base = None
    if 'build' in s.command_options:
        if 'build_base' in s.command_options['build']:
            build_base = s.command_options['build']['build_base']
    if build_base is None:
        build_base = 'build'
        plat_specifier = ".%s-%s" % (get_platform(), sys.version[0:3])
        build_base = os.path.join('build', 'lib' + plat_specifier)
        print build_base

build_all()

