#! /usr/bin/env python2

from __future__ import print_function
from distutils.core import setup, Extension
from distutils.util import get_platform
from distutils.sysconfig import get_python_lib, get_config_vars
from distutils.dist import DistributionMetadata
from distutils.command.install_data import install_data
from tempfile import TemporaryFile
import fnmatch
import io
import os
import platform
from shutil import copy2, copyfile, rmtree
import sys
import tempfile
import atexit

is_win = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"
is_64bit = platform.architecture()[0] == "64bit"
if is_win:
    import winreg

def set_extension_compile_args(extension):
    rel_lib_path = extension.name.replace('.', '/')
    abs_lib_path = os.path.join(get_python_lib(), rel_lib_path)
    lib_name = abs_lib_path + '.so'
    extension.extra_link_args = [ '-Wl,-install_name,' + lib_name]

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
        return None

def win_use_clang():
    # Recent (>= 8 ?) LLVM versions does not ship anymore a cl.exe binary in
    # the msbuild-bin directory. Thus, we need to
    # * copy-paste bin/clang-cl.exe into a temporary directory
    # * rename it to cl.exe
    # * add that path first in %Path%
    # * clean this mess on exit
    # We could use the build directory created by distutils for this, but it
    # seems non trivial to gather
    # (https://stackoverflow.com/questions/12896367/reliable-way-to-get-the-build-directory-from-within-setup-py).
    clang_path = win_find_clang_path()
    if clang_path is None:
        return False
    tmpdir = tempfile.mkdtemp(prefix="llvm")
    copyfile(os.path.join(clang_path, "bin", "clang-cl.exe"), os.path.join(tmpdir, "cl.exe"))
    os.environ['Path'] = "%s;%s" % (tmpdir, os.environ["Path"])
    atexit.register(lambda dir_: rmtree(dir_), tmpdir)

    return True

win_force_clang = False
if is_win and is_64bit:
    # We do not change to clang if under 32 bits, because even with Clang we
    # don't have uint128_t with the 32 bits ABI.
    win_force_clang = win_use_clang()
    if not win_force_clang:
        print("Warning: couldn't find a Clang/LLVM installation. Some runtime functions needed by the jitter won't be compiled.")

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
        os.environ['MSSdk'] = '1'
        os.environ['DISTUTILS_USE_SDK'] = '1'
        if win_force_clang:
            march = "-m64" if is_64bit else "-m32"
            for extension in ext_modules_all:
                extension.extra_compile_args = [march]
    elif is_mac:
        for extension in ext_modules_all:
            set_extension_compile_args(extension)
        cfg_vars = get_config_vars()
        cfg_vars['LDSHARED'] = cfg_vars['LDSHARED'].replace('-bundle', '-dynamiclib')

    print("building")
    build_ok = False
    for name, ext_modules in [("all", ext_modules_all),
    ]:
        print("build with", repr(name))
        try:
            s = setup(
                name = "miasm",
                version = __import__("miasm").VERSION,
                packages = packages,
                data_files=[('', ["README.md"])],
                package_data = {
                    "miasm": [
                        "jitter/*.h",
                        "jitter/arch/*.h",
                        "VERSION"
                    ]
                },
                install_requires=['future', 'pyparsing~=2.0'],
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
            dst = os.path.join(build_base, lib_dirname, "miasm", "jitter")
            # Windows built libraries may have a name like VmMngr.cp38-win_amd64.lib
            if not any([fnmatch.fnmatch(filename, pattern) for pattern in ["VmMngr.*lib", "Jitgcc.*lib", "Jitllvm.*lib"]]):
                dst = os.path.join(dst, "arch")
            dst = os.path.join(dst, filename)
            if not os.path.isfile(dst):
                print("Copying", lib, "to", dst)
                copy2(lib, dst)


with io.open(os.path.join(os.path.abspath(os.path.dirname('__file__')),
                       'README.md'), encoding='utf-8') as fdesc:
    long_description = fdesc.read()
long_description_content_type = 'text/markdown'


# Monkey patching (distutils does not handle Description-Content-Type
# from long_description_content_type parameter in setup()).
_write_pkg_file_orig = DistributionMetadata.write_pkg_file


def _write_pkg_file(self, file):
    with TemporaryFile(mode="w+") as tmpfd:
        _write_pkg_file_orig(self, tmpfd)
        tmpfd.seek(0)
        for line in tmpfd:
            if line.startswith('Metadata-Version: '):
                file.write('Metadata-Version: 2.1\n')
            elif line.startswith('Description: '):
                file.write('Description-Content-Type: %s; charset=UTF-8\n' %
                           long_description_content_type)
                file.write(line)
            else:
                file.write(line)


DistributionMetadata.write_pkg_file = _write_pkg_file


build_all()

