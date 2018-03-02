import os
import importlib
import tempfile

from miasm2.jitter.llvmconvert import *
import miasm2.jitter.jitcore as jitcore
import Jitllvm


class JitCore_LLVM(jitcore.JitCore):

    "JiT management, using LLVM as backend"

    # Architecture dependant libraries
    arch_dependent_libs = {"x86": "JitCore_x86.so",
                           "arm": "JitCore_arm.so",
                           "msp430": "JitCore_msp430.so",
                           "mips32": "JitCore_mips32.so",
                           "aarch64": "JitCore_aarch64.so",
                           "ppc32": "JitCore_ppc32.so",
    }

    def __init__(self, ir_arch, bs=None):
        super(JitCore_LLVM, self).__init__(ir_arch, bs)

        self.options.update({"safe_mode": True,   # Verify each function
                             "optimise": True,     # Optimise functions
                             "log_func": False,    # Print LLVM functions
                             "log_assembly": False,  # Print assembly executed
                             })

        self.exec_wrapper = Jitllvm.llvm_exec_bloc
        self.ir_arch = ir_arch

        # Cache temporary dir
        self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")
        try:
            os.mkdir(self.tempdir, 0755)
        except OSError:
            pass
        if not os.access(self.tempdir, os.R_OK | os.W_OK):
            raise RuntimeError(
                'Cannot access cache directory %s ' % self.tempdir)

    def load(self):

        # Library to load within Jit context
        libs_to_load = []

        # Get architecture dependant Jitcore library (if any)
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        lib_dir = os.path.join(lib_dir, 'arch')
        try:
            jit_lib = os.path.join(
                lib_dir, self.arch_dependent_libs[self.ir_arch.arch.name])
            libs_to_load.append(jit_lib)
        except KeyError:
            pass

        # Create a context
        self.context = LLVMContext_JIT(libs_to_load, self.ir_arch)

        # Set the optimisation level
        self.context.optimise_level()

        # Save the current architecture parameters
        self.arch = self.ir_arch.arch

        # Get the correspondance between registers and vmcpu struct
        mod_name = "miasm2.jitter.arch.JitCore_%s" % (self.ir_arch.arch.name)
        mod = importlib.import_module(mod_name)
        self.context.set_vmcpu(mod.get_gpreg_offset_all())

        # Enable caching
        self.context.enable_cache()

    def add_bloc(self, block):
        """Add a block to JiT and JiT it.
        @block: the block to add
        """
        block_hash = self.hash_block(block)
        fname_out = os.path.join(self.tempdir, "%s.bc" % block_hash)

        if not os.access(fname_out, os.R_OK):
            # Build a function in the context
            func = LLVMFunction(self.context, LLVMFunction.canonize_label_name(block.label))

            # Set log level
            func.log_regs = self.log_regs
            func.log_mn = self.log_mn

            # Import asm block
            func.from_asmblock(block)

            # Verify
            if self.options["safe_mode"] is True:
                func.verify()

            # Optimise
            if self.options["optimise"] is True:
                func.optimise()

            # Log
            if self.options["log_func"] is True:
                print func
            if self.options["log_assembly"] is True:
                print func.get_assembly()

            # Use propagate the cache filename
            self.context.set_cache_filename(func, fname_out)

            # Get a pointer on the function for JiT
            ptr = func.get_function_pointer()

        else:
            # The cache file exists: function can be loaded from cache
            ptr = self.context.get_ptr_from_cache(fname_out, LLVMFunction.canonize_label_name(block.label))

        # Store a pointer on the function jitted code
        self.lbl2jitbloc[block.label.offset] = ptr
