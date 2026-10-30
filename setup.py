from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

import atexit
import fnmatch
import os
import platform
import re
import subprocess
import sysconfig
import tempfile
import pathlib
from shutil import copy2, copyfile, rmtree, which


is_win = platform.system() == "Windows"
is_mac = platform.system() == "Darwin"
is_64bit = platform.architecture()[0] == "64bit"
require_jit = os.environ.get("MIASM_REQUIRE_JIT") == "1"
if is_win:
    import winreg

BUILD_WARNINGS = []


def set_extension_compile_args(extension):
    rel_lib_path = extension.name.replace(".", "/")
    abs_lib_path = os.path.join(sysconfig.get_path("platlib"), rel_lib_path)
    lib_name = abs_lib_path + ".so"
    extension.extra_link_args = ["-Wl,-install_name," + lib_name]


def win_get_llvm_reg():
    REG_PATH = "SOFTWARE\\LLVM\\LLVM"
    try:
        return winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            REG_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
        )
    except FileNotFoundError:
        pass
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)


def win_find_clang_path():
    try:
        with win_get_llvm_reg() as rkey:
            return winreg.QueryValueEx(rkey, None)[0]
    except FileNotFoundError:
        # Visual Studio ships with an optional Clang distribution; detect that
        # when the standalone LLVM registry key is not present.
        clang_cl = which("clang-cl")
        if clang_cl is None:
            return None
        return os.path.abspath(os.path.join(os.path.dirname(clang_cl), "..", ".."))


def win_get_clang_version(clang_path):
    try:
        clang = os.path.join(clang_path, "bin", "clang.exe")
        stdout = subprocess.check_output('"{}" --version'.format(clang))
        version = stdout.splitlines(False)[0].decode()
        match = re.search(r"version (\d+\.\d+\.\d+)", version)
        if match is None:
            return None
        return [int(part) for part in match.group(1).split(".")]
    except FileNotFoundError:
        return None


def win_use_clang():
    # To force setuptools to use clang-cl, copy the LLVM tools into a
    # temporary directory as cl.exe/link.exe and put that directory first in
    # PATH. Using the build directory would avoid a tempdir, but setuptools
    # does not expose a reliable build path before build_ext starts.
    clang_path = win_find_clang_path()
    if clang_path is None:
        return False
    clang_version = win_get_clang_version(clang_path)
    if clang_version is None:
        return False

    tmpdir = tempfile.mkdtemp(prefix="llvm")
    try:
        copyfile(os.path.join(clang_path, "bin", "clang-cl.exe"), os.path.join(tmpdir, "cl.exe"))
        # When forcing clang, put lld-link.exe first as link.exe so setuptools
        # uses the LLVM-compatible linker. LLVM >= 14.0.0 is required because
        # earlier versions do not support MSVC's /LTCG flag and fail during
        # linking.
        if clang_version[0] < 14:
            rmtree(tmpdir)
            return False
        copyfile(os.path.join(clang_path, "bin", "lld-link.exe"), os.path.join(tmpdir, "link.exe"))
    except FileNotFoundError:
        rmtree(tmpdir)
        return False

    # Add the temporary directory at the front of PATH and clean it up when the
    # build process exits.
    os.environ["PATH"] = "%s;%s" % (tmpdir, os.environ["PATH"])
    atexit.register(lambda dir_: rmtree(dir_), tmpdir)
    print(
        "Found Clang {}.{}.{}: {}".format(
            clang_version[0], clang_version[1], clang_version[2], clang_path
        )
    )
    return True


def make_ext_modules(optional):
    vm_common = [
        "miasm/jitter/vm_mngr.c",
        "miasm/jitter/vm_mngr_py.c",
        "miasm/jitter/bn.c",
    ]
    core_common = [
        "miasm/jitter/JitCore.c",
        *vm_common,
        "miasm/jitter/op_semantics.c",
    ]

    return [
        Extension("miasm.jitter.VmMngr", vm_common, optional=optional),
        Extension(
            "miasm.jitter.arch.JitCore_x86",
            [*core_common, "miasm/jitter/arch/JitCore_x86.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_arm",
            [*core_common, "miasm/jitter/arch/JitCore_arm.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_aarch64",
            [*core_common, "miasm/jitter/arch/JitCore_aarch64.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_msp430",
            [*core_common, "miasm/jitter/arch/JitCore_msp430.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_mep",
            [
                "miasm/jitter/JitCore.c",
                *vm_common,
                "miasm/jitter/arch/JitCore_mep.c",
            ],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_mips32",
            [*core_common, "miasm/jitter/arch/JitCore_mips32.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_ppc32",
            [*core_common, "miasm/jitter/arch/JitCore_ppc32.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.arch.JitCore_m68k",
            [*core_common, "miasm/jitter/arch/JitCore_m68k.c"],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.Jitllvm",
            [
                "miasm/jitter/Jitllvm.c",
                "miasm/jitter/bn.c",

                # This is needed for the LLVM jitter.
                # Some LLVM IR instructions lowers to compiler_rt library calls.
                # llvmlite does not include the runtime, so we ship (part of) it instead.
                *pathlib.Path("miasm/runtime").glob("*.c")
            ],
            optional=optional,
        ),
        Extension(
            "miasm.jitter.Jitgcc",
            ["miasm/jitter/Jitgcc.c", "miasm/jitter/bn.c"],
            optional=optional,
        ),
    ]


def configured_ext_modules():
    build_extensions = True
    win_force_clang = False

    if is_win:
        if is_64bit or which("cl") is None:
            # 64-bit builds require clang for uint128_t support. In 32-bit mode
            # the ABI does not use uint128_t, so MSVC is fine; still try clang
            # there if cl.exe is missing from PATH.
            win_force_clang = win_use_clang()
            if is_64bit and not win_force_clang:
                BUILD_WARNINGS.append(
                    "Could not find a suitable Clang/LLVM installation. "
                    "You can download LLVM from https://releases.llvm.org"
                )
                BUILD_WARNINGS.append(
                    "Alternatively you can select the 'C++ Clang-cl build tools' "
                    "in the Visual Studio Installer"
                )
                build_extensions = False

        cl = which("cl")
        link = which("link")
        if cl is None or link is None:
            BUILD_WARNINGS.append(
                "Could not find cl.exe and/or link.exe in the PATH, try building "
                "miasm from a Visual Studio command prompt"
            )
            BUILD_WARNINGS.append("More information at: https://wiki.python.org/moin/WindowsCompilers")
            build_extensions = False
        else:
            print("Found cl.exe: {}".format(cl))
            print("Found link.exe: {}".format(link))

    if not build_extensions:
        message = "miasm jit extensions will not be compiled, details:"
        if require_jit:
            print("ERROR: " + message)
        else:
            print("WARNING: " + message)
        for warning in BUILD_WARNINGS:
            print("  " + warning)
        if require_jit:
            raise RuntimeError("Unable to build miasm native extensions")
        return []

    ext_modules = make_ext_modules(optional=not require_jit)

    if is_win:
        # Force setuptools to use the compiler/linker already selected in PATH.
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
        for extension in ext_modules:
            extension.extra_compile_args = extra_compile_args
    elif is_mac:
        for extension in ext_modules:
            set_extension_compile_args(extension)
        cfg_vars = sysconfig.get_config_vars()
        ldshared = cfg_vars.get("LDSHARED")
        if ldshared:
            cfg_vars["LDSHARED"] = ldshared.replace("-bundle", "-dynamiclib")

    return ext_modules


def write_version_file(root, version):
    version_file = os.path.join(root, "miasm", "VERSION")
    os.makedirs(os.path.dirname(version_file), exist_ok=True)
    with open(version_file, "w", encoding="utf-8") as fdesc:
        fdesc.write(version)


class MiasmBuildPy(build_py):
    def run(self):
        super().run()
        write_version_file(self.build_lib, self.distribution.get_version())


class MiasmSdist(sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        write_version_file(base_dir, self.distribution.get_version())


class MiasmBuildExt(build_ext):
    def build_extensions(self):
        if is_mac:
            linker_so = getattr(self.compiler, "linker_so", None)
            if isinstance(linker_so, list):
                self.compiler.linker_so = [
                    "-dynamiclib" if arg == "-bundle" else arg
                    for arg in linker_so
                ]
        super().build_extensions()

    def run(self):
        super().run()
        if is_win and self.extensions:
            self.copy_windows_import_libs()

    def copy_windows_import_libs(self):
        build_roots = {
            os.path.abspath("build"),
            os.path.abspath(os.path.dirname(self.build_lib)),
            os.path.abspath(os.path.dirname(self.build_temp)),
        }
        libs = []
        for build_root in build_roots:
            if not os.path.isdir(build_root):
                continue
            for root, _, files in os.walk(build_root):
                for filename in files:
                    if filename.endswith(".lib"):
                        libs.append(os.path.join(root, filename))

        for lib in libs:
            filename = os.path.basename(lib)
            dst_dir = os.path.join(self.build_lib, "miasm", "jitter")
            # Windows import libraries are named after the built extension,
            # e.g. VmMngr.cp313-win_amd64.lib.
            if not any(
                fnmatch.fnmatch(filename, pattern)
                for pattern in ["VmMngr.*lib", "Jitgcc.*lib", "Jitllvm.*lib"]
            ):
                dst_dir = os.path.join(dst_dir, "arch")
            os.makedirs(dst_dir, exist_ok=True)
            dst = os.path.join(dst_dir, filename)
            if os.path.abspath(lib) == os.path.abspath(dst):
                continue
            if not os.path.isfile(dst):
                print("Copying", lib, "to", dst)
                copy2(lib, dst)


setup(
    ext_modules=configured_ext_modules(),
    cmdclass={
        "build_ext": MiasmBuildExt,
        "build_py": MiasmBuildPy,
        "sdist": MiasmSdist,
    },
)
