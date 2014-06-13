import os
import importlib
import hashlib
try:
    from llvmconvert import *
except ImportError:
    pass
import jitcore
import Jitllvm


class JitCore_LLVM(jitcore.JitCore):

    "JiT management, using LLVM as backend"

    # Architecture dependant libraries
    arch_dependent_libs = {"x86": "arch/JitCore_x86.so",
                           "arm": "arch/JitCore_arm.so"}

    def __init__(self, my_ir, bs=None):
        super(JitCore_LLVM, self).__init__(my_ir, bs)

        self.options.update({"safe_mode": False,   # Verify each function
                             "optimise": False,     # Optimise functions
                             "log_func": False,    # Print LLVM functions
                             "log_assembly": False,  # Print assembly executed
                             "cache_ir": None      # SaveDir for cached .ll
                             })

        self.exec_wrapper = Jitllvm.llvm_exec_bloc
        self.exec_engines = []

    def load(self, arch):

        # Library to load within Jit context
        libs_to_load = []

        # Get the vm_mngr librairy
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        vm_mngr_path = os.path.join(lib_dir, 'vm_mngr.so')
        libs_to_load.append(vm_mngr_path)

        # Get architecture dependant Jitcore library (if any)
        try:
            jit_lib = os.path.join(
                lib_dir, self.arch_dependent_libs[arch.name])
            libs_to_load.append(jit_lib)
        except KeyError:
            pass

        # Create a context
        self.context = LLVMContext_JIT(libs_to_load)

        # Set the optimisation level
        self.context.optimise_level()

        # Save the current architecture parameters
        self.arch = arch

        # Get the correspondance between registers and vmcpu struct
        mod_name = "miasm2.jitter.arch.JitCore_%s" % (arch.name)
        mod = importlib.import_module(mod_name)
        self.context.set_vmcpu(mod.get_gpreg_offset_all())

        # Save module base
        self.mod_base_str = str(self.context.mod)

        # Set IRs transformation to apply
        self.context.set_IR_transformation(self.my_ir.expr_fix_regs_for_mode)

    def add_bloc(self, bloc):

        # Search in IR cache
        if self.options["cache_ir"] is not None:

            # /!\ This part is under development
            # Use it at your own risk

            # Compute Hash : label + bloc binary
            func_name = bloc.label.name
            to_hash = func_name

            # Get binary from bloc
            for line in bloc.lines:
                b = line.b
                to_hash += b

            # Compute Hash
            md5 = hashlib.md5(to_hash).hexdigest()

            # Try to load the function from cache
            filename = self.options["cache_ir"] + md5 + ".ll"

            try:
                fcontent = open(filename)
                content = fcontent.read()
                fcontent.close()

            except IOError:
                content = None

            if content is None:
                # Compute the IR
                super(JitCore_LLVM, self).add_bloc(bloc)

                # Save it
                fdest = open(filename, "w")
                dump = str(self.context.mod.get_function_named(func_name))
                my = "declare i16 @llvm.bswap.i16(i16) nounwind readnone\n"

                fdest.write(self.mod_base_str + my + dump)
                fdest.close()

            else:
                import llvm.core as llvm_c
                import llvm.ee as llvm_e
                my_mod = llvm_c.Module.from_assembly(content)
                func = my_mod.get_function_named(func_name)
                exec_en = llvm_e.ExecutionEngine.new(my_mod)
                self.exec_engines.append(exec_en)

                # We can use the same exec_engine
                ptr = self.exec_engines[0].get_pointer_to_function(func)

                # Store a pointer on the function jitted code
                self.lbl2jitbloc[bloc.label.offset] = ptr

        else:
            super(JitCore_LLVM, self).add_bloc(bloc)

    def jitirblocs(self, label, irblocs):

        # Build a function in the context
        func = LLVMFunction(self.context, label.name)

        # Set log level
        func.log_regs = self.log_regs
        func.log_mn = self.log_mn

        # Import irblocs
        func.from_blocs(irblocs)

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

        # Store a pointer on the function jitted code
        self.lbl2jitbloc[label.offset] = func.get_function_pointer()
