#! /usr/bin/env python2

from __future__ import print_function
from distutils.core import setup, Extension
from distutils.util import get_platform
import io
import os
import platform
from shutil import copy2
import sys

is_win = platform.system() == "Windows"

def buil_all():
    packages=[
        "miasm2",
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
        Extension(
            "miasm2.jitter.VmMngr",
            [
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/vm_mngr_py.c",
                "miasm2/jitter/bn.c",
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_x86",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_x86.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_arm",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_arm.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_aarch64",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_aarch64.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_msp430",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_msp430.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_mep",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_mep.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_mips32",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_mips32.c"
            ]
        ),
        Extension(
            "miasm2.jitter.arch.JitCore_ppc32",
            [
                "miasm2/jitter/JitCore.c",
                "miasm2/jitter/vm_mngr.c",
                "miasm2/jitter/op_semantics.c",
                "miasm2/jitter/bn.c",
                "miasm2/jitter/arch/JitCore_ppc32.c"
            ],
            depends=[
                "miasm2/jitter/arch/JitCore_ppc32.h",
                "miasm2/jitter/arch/JitCore_ppc32_regs.h",
                "miasm2/jitter/bn.h",
            ]
        ),
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

    print("building")
    build_ok = False
    for name, ext_modules in [("all", ext_modules_all),
    ]:
        print("build with", repr(name))
        try:
            s = setup(
                name = "Miasm",
                version = "2.0",
                packages = packages,
                package_data = {
                    "miasm2":[
                        "jitter/*.h",
                        "jitter/arch/*.h",
                    ]
                },
                ext_modules = ext_modules,
                # Metadata
                author = "Fabrice Desclaux",
                author_email = "serpilliere@droid-corp.org",
                description = "Machine code manipulation library",
                license = "GPLv2",
                long_description=io.open('README.md', encoding='utf-8').read(),
                keywords = [
                    "reverse engineering",
                    "disassembler",
                    "emulator",
                    "symbolic execution",
                    "intermediate representation",
                    "assembler",
                ],
                url = "http://miasm.re",
            )
        except SystemExit as e:
            print(repr(e))
            continue
        build_ok = True
        break
    if not build_ok:
        raise ValueError("Unable to build Miasm!")
    print("build", name)
    # we copy libraries from build dir to current miasm directory
    build_base = "build"
    if "build" in s.command_options:
        if "build_base" in s.command_options["build"]:
            build_base = s.command_options["build"]["build_base"]

    print(build_base)
    if is_win:
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
                print("Copying", lib, "to", dst)
                copy2(lib, dst)

buil_all()

