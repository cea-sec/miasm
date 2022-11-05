#! /usr/bin/env python2

from __future__ import print_function
# Reference: https://stackoverflow.com/a/13468644/1806760
from setuptools import setup, Extension
from distutils.util import get_platform
from distutils.sysconfig import get_python_lib, get_config_vars
from distutils.dist import DistributionMetadata
from distutils.command.install_data import install_data
from distutils.spawn import find_executable
import subprocess
from tempfile import TemporaryFile
import fnmatch
import io
import os
import platform
from shutil import copy2, copyfile, rmtree
import sys
import tempfile
import atexit
import re

is_win = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"
is_64bit = platform.architecture()[0] == "64bit"
if is_win:
    import winreg

def set_extension_compile_args(extension):
    rel_lib_path = extension.name.replace(".", "/")
    abs_lib_path = os.path.join(get_python_lib(), rel_lib_path)
    lib_name = abs_lib_path + ".so"
    extension.extra_link_args = [ "-Wl,-install_name," + lib_name]

class smart_install_data(install_data):
    """Replacement for distutils.command.install_data to handle
    configuration files location.
    """
    def run(self):
        # install files to /etc when target was /usr(/local)/etc
        self.data_files = [
            (path, files) for path, files in self.data_files
            if path  # skip README.md or any file with an empty path
        ]
        return install_data.run(self)

def win_get_llvm_reg():
    REG_PATH = "SOFTWARE\\LLVM\\LLVM"
    try:
      return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
    except FileNotFoundError:
      pass
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)

def win_find_clang_path():
    try:
        with win_get_llvm_reg() as rkey:
            return winreg.QueryValueEx(rkey, None)[0]
    except FileNotFoundError:
        # Visual Studio ships with an optional Clang distribution, try to detect it
        clang_cl = find_executable("clang-cl")
        if clang_cl is None:
            return None
        return os.path.abspath(os.path.join(os.path.dirname(clang_cl), "..", ".."))

def win_get_clang_version(clang_path):
    try:
        clang_cl = os.path.join(clang_path, "bin", "clang.exe")
        stdout = subprocess.check_output("\"{}\" --version".format(clang_cl))
        version = stdout.splitlines(False)[0].decode()
        match = re.search(r"version (\d+\.\d+\.\d+)", version)
        if match is None:
            return None
        version = list(map(lambda s: int(s), match.group(1).split(".")))
        return version
    except FileNotFoundError:
        return None

def win_use_clang():
    # To force python to use clang we copy the binaries in a temporary directory that's added to the PATH.
    # We could use the build directory created by distutils for this, but it seems non-trivial to gather
    # (https://stackoverflow.com/questions/12896367/reliable-way-to-get-the-build-directory-from-within-setup-py).

    clang_path = win_find_clang_path()
    if clang_path is None:
        return False
    clang_version = win_get_clang_version(clang_path)
    if clang_version is None:
        return False
    tmpdir = tempfile.mkdtemp(prefix="llvm")

    copyfile(os.path.join(clang_path, "bin", "clang-cl.exe"), os.path.join(tmpdir, "cl.exe"))

    # If you run the installation from a Visual Studio command prompt link.exe will already exist
    # Fall back to LLVM's lld-link.exe which is compatible with link's command line
    if find_executable("link") is None:
        # LLVM >= 14.0.0 started supporting the /LTCG flag
        # Earlier versions will error during the linking phase so bail out now
        if clang_version[0] < 14:
            return False
        copyfile(os.path.join(clang_path, "bin", "lld-link.exe"), os.path.join(tmpdir, "link.exe"))

    # Add the temporary directory at the front of the PATH and clean up on exit
    os.environ["PATH"] = "%s;%s" % (tmpdir, os.environ["PATH"])
    atexit.register(lambda dir_: rmtree(dir_), tmpdir)
    print("Found Clang {}.{}.{}: {}".format(clang_version[0], clang_version[1], clang_version[2], clang_path))
    return True

build_extensions = True
build_warnings = []
win_force_clang = False
if is_win:
    if is_64bit or find_executable("cl") is None:
        # We do not change to clang if under 32 bits, because even with Clang we
        # do not use uint128_t with the 32 bits ABI. Regardless we can try to
        # find it when building in 32-bit mode if cl.exe was not found in the PATH.
        win_force_clang = win_use_clang()
        if is_64bit and not win_force_clang:
            build_warnings.append("Could not find a suitable Clang/LLVM installation. You can download LLVM from https://releases.llvm.org")
            build_warnings.append("Alternatively you can select the 'C++ Clang-cl build tools' in the Visual Studio Installer")
            build_extensions = False
    cl = find_executable("cl")
    link = find_executable("link")
    if cl is None or link is None:
        build_warnings.append("Could not find cl.exe and/or link.exe in the PATH, try building miasm from a Visual Studio command prompt")
        build_warnings.append("More information at: https://wiki.python.org/moin/WindowsCompilers")
        build_extensions = False
    else:
        print("Found cl.exe: {}".format(cl))
        print("Found link.exe: {}".format(link))

def build_all():
    packages=[
        "miasm",
        "miasm/arch",
        "miasm/arch/x86",
        "miasm/arch/arm",
        "miasm/arch/aarch64",
        "miasm/arch/msp430",
        "miasm/arch/mep",
        "miasm/arch/sh4",
        "miasm/arch/mips32",
        "miasm/arch/ppc",
        "miasm/core",
        "miasm/expression",
        "miasm/ir",
        "miasm/ir/translators",
        "miasm/analysis",
        "miasm/os_dep",
        "miasm/os_dep/linux",
        "miasm/loader",
        "miasm/jitter",
        "miasm/jitter/arch",
        "miasm/jitter/loader",
    ]
    ext_modules_all = [
        Extension(
            "miasm.jitter.VmMngr",
            [
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/bn.c",
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_x86",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_x86.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_arm",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_arm.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_aarch64",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_aarch64.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_msp430",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_msp430.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_mep",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_mep.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_mips32",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_mips32.c"
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_ppc32",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_ppc32.c"
            ],
            depends=[
                "miasm/jitter/arch/JitCore_ppc32.h",
                "miasm/jitter/arch/JitCore_ppc32_regs.h",
                "miasm/jitter/bn.h",
            ]
        ),
        Extension(
            "miasm.jitter.arch.JitCore_m68k",
            [
                "miasm/jitter/JitCore.c",
                "miasm/jitter/vm_mngr.c",
                "miasm/jitter/vm_mngr_py.c",
                "miasm/jitter/op_semantics.c",
                "miasm/jitter/bn.c",
                "miasm/jitter/arch/JitCore_m68k.c"
            ]
        ),
        Extension("miasm.jitter.Jitllvm",
                  ["miasm/jitter/Jitllvm.c",
                   "miasm/jitter/bn.c",
                   "miasm/runtime/udivmodti4.c",
                   "miasm/runtime/divti3.c",
                   "miasm/runtime/udivti3.c"
                  ]),
        Extension("miasm.jitter.Jitgcc",
                  ["miasm/jitter/Jitgcc.c",
                   "miasm/jitter/bn.c",
                  ]),
        ]

    if is_win:
        # Force setuptools to use whatever msvc version installed
        # https://docs.python.org/3/distutils/apiref.html#module-distutils.msvccompiler
        os.environ["MSSdk"] = "1"
        os.environ["DISTUTILS_USE_SDK"] = "1"
        extra_compile_args = ["-D_CRT_SECURE_NO_WARNINGS"]
        if win_force_clang:
            march = "-m64" if is_64bit else "-m32"
            extra_compile_args += [
                march,
                "-Wno-unused-command-line-argument",
                "-Wno-visibility",
                "-Wno-dll-attribute-on-redeclaration",
                "-Wno-tautological-compare",
                "-Wno-unused-but-set-variable",
            ]
        for extension in ext_modules_all:
            extension.extra_compile_args = extra_compile_args
    elif is_mac:
        for extension in ext_modules_all:
            set_extension_compile_args(extension)
        cfg_vars = get_config_vars()
        cfg_vars["LDSHARED"] = cfg_vars["LDSHARED"].replace("-bundle", "-dynamiclib")

    # Do not attempt to build the extensions when disabled
    if not build_extensions:
        ext_modules_all = []

    print("building")
    if not os.path.exists("build"):
        os.mkdir("build")
    build_ok = False
    for name, ext_modules in [("all", ext_modules_all)]:
        print("build with", repr(name))
        try:
            s = setup(
                name = "miasm",
                version = __import__("miasm").VERSION,
                packages = packages,
                data_files=[("", ["README.md"])],
                package_data = {
                    "miasm": [
                        "jitter/*.h",
                        "jitter/arch/*.h",
                        "VERSION"
                    ]
                },
                install_requires=["future", "pyparsing~=2.0"],
                cmdclass={"install_data": smart_install_data},
                ext_modules = ext_modules,
                # Metadata
                author = "Fabrice Desclaux",
                author_email = "serpilliere@droid-corp.org",
                description = "Machine code manipulation library",
                license = "GPLv2",
                long_description=long_description,
                long_description_content_type=long_description_content_type,
                keywords = [
                    "reverse engineering",
                    "disassembler",
                    "emulator",
                    "symbolic execution",
                    "intermediate representation",
                    "assembler",
                ],
                classifiers=[
                    "Programming Language :: Python :: 2",
                    "Programming Language :: Python :: 3",
                    "Programming Language :: Python :: 2.7",
                    "Programming Language :: Python :: 3.6",
                ],
                url = "http://miasm.re",
            )
        except SystemExit as e:
            print(repr(e))
            continue
        build_ok = True
        break
    if not build_ok:
        if len(build_warnings) > 0:
            print("ERROR: There was an issue setting up the build environment:")
            for warning in build_warnings:
                print("  " + warning)
        raise ValueError("Unable to build Miasm!")
    print("build", name)
    # we copy libraries from build dir to current miasm directory
    build_base = "build"
    if "build" in s.command_options:
        if "build_base" in s.command_options["build"]:
            build_base = s.command_options["build"]["build_base"]

    print(build_base)
    if is_win and build_extensions:
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
            dst = os.path.join(build_base, lib_dirname, "miasm", "jitter")
            # Windows built libraries may have a name like VmMngr.cp38-win_amd64.lib
            if not any([fnmatch.fnmatch(filename, pattern) for pattern in ["VmMngr.*lib", "Jitgcc.*lib", "Jitllvm.*lib"]]):
                dst = os.path.join(dst, "arch")
            dst = os.path.join(dst, filename)
            if not os.path.isfile(dst):
                print("Copying", lib, "to", dst)
                copy2(lib, dst)

    # Inform the user about the skipped build
    if not build_extensions:
        print("WARNING: miasm jit extensions were not compiled, details:")
        for warning in build_warnings:
            print("  " + warning)

with io.open(os.path.join(os.path.abspath(os.path.dirname("__file__")),
                       "README.md"), encoding="utf-8") as fdesc:
    long_description = fdesc.read()
long_description_content_type = "text/markdown"


# Monkey patching (distutils does not handle Description-Content-Type
# from long_description_content_type parameter in setup()).
_write_pkg_file_orig = DistributionMetadata.write_pkg_file


def _write_pkg_file(self, file):
    with TemporaryFile(mode="w+") as tmpfd:
        _write_pkg_file_orig(self, tmpfd)
        tmpfd.seek(0)
        for line in tmpfd:
            if line.startswith("Metadata-Version: "):
                file.write("Metadata-Version: 2.1\n")
            elif line.startswith("Description: "):
                file.write("Description-Content-Type: %s; charset=UTF-8\n" %
                           long_description_content_type)
                file.write(line)
            else:
                file.write(line)


DistributionMetadata.write_pkg_file = _write_pkg_file


build_all()

