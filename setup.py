#! /usr/bin/env python2

from distutils.core import setup, Extension
from distutils.util import get_platform
from distutils.sysconfig import get_python_lib, get_config_vars
from shutil import copy2
import platform
import os, sys

is_win = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"

def set_extension_compile_args(extension):
    rel_lib_path = extension.name.replace('.', '/')
    abs_lib_path = os.path.join(get_python_lib(), rel_lib_path)
    lib_name = abs_lib_path + '.so'
    extension.extra_link_args = [ '-Wl,-install_name,' + lib_name]

def buil_all():
    if is_darwin:
        vars = sysconfig.get_config_vars()
        vars['LDSHARED'] = vars['LDSHARED'].replace('-bundle', '-dynamiclib')

    packages=["miasm2",
              "miasm2/arch",
              "miasm2/arch/x86",
              "miasm2/arch/arm",
              "miasm2/arch/aarch64",
              "miasm2/arch/msp430",
              "miasm2/arch/mep",
              "miasm2/arch/sh4",
              "miasm2/arch/mips32",
              "miasm2/arch/ppc",
              "miasm2/core",
              "miasm2/expression",
              "miasm2/ir",
              "miasm2/ir/translators",
              "miasm2/analysis",
              "miasm2/os_dep",
              "miasm2/os_dep/linux",
              "miasm2/jitter",
              "miasm2/jitter/arch",
              "miasm2/jitter/loader",
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

    if is_win:
        # Force setuptools to use whatever msvc version installed
        os.environ['MSSdk'] = '1'
        os.environ['DISTUTILS_USE_SDK'] = '1'
    elif is_mac:
        for extension in ext_modules_all:
            set_extension_compile_args(extension)
        vars = get_config_vars()
        vars['LDSHARED'] = vars['LDSHARED'].replace('-bundle', '-dynamiclib')

    print "building"
    build_ok = False
    for name, ext_modules in [("all", ext_modules_all),
    ]:
        print "build with", repr(name)
        try:
            s = setup(
                name = "Miasm",
                version = "2.0",
                packages = packages,
                package_data = {"miasm2":["jitter/*.h",
                                          "jitter/arch/*.h",]},
                ext_modules = ext_modules,
                # Metadata
                author = "Fabrice Desclaux",
                author_email = "serpilliere@droid-corp.org",
                description = "Machine code manipulation library",
                license = "GPLv2",
                # keywords = "",
                # url = "",
            )
        except SystemExit, e:
            print repr(e)
            continue
        build_ok = True
        break
    if not build_ok:
        raise ValueError("Unable to build Miasm!")
    print "build", name
    if is_win:
       # we copy libraries from build dir to current miasm directory
       build_base = "build"
       if "build" in s.command_options:
           if "build_base" in s.command_options["build"]:
               build_base = s.command_options["build"]["build_base"]
        libs = []
        for root, _, files in os.walk(build_base):
            for filename in files:
                if not filename.endswith(".lib"):
                    continue
                f_path = os.path.join(root, filename)
                libs.append(f_path)

        lib_dirname = None
        for dirname in os.listdir(build_base):
            if not dirname.startswith("lib"):
                continue
            lib_dirname = dirname
            break

        jitters = []
        for lib in libs:
            filename = os.path.basename(lib)
            dst = os.path.join(build_base, lib_dirname, "miasm2", "jitter")
            if filename not in ["VmMngr.lib", "Jitgcc.lib", "Jitllvm.lib"]:
                dst = os.path.join(dst, "arch")
            dst = os.path.join(dst, filename)
            if not os.path.isfile(dst):
                print "Copying", lib, "to", dst
                copy2(lib, dst)

buil_all()

