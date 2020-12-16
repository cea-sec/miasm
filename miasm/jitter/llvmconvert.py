#
#
# Miasm2 Extension:                                                            #
# - Miasm2 IR to LLVM IR                                                       #
# - JiT                                                                        #
#
# Requires:                                                                    #
# - llvmlite (tested on v0.15)                                                 #
#
# Authors : Fabrice DESCLAUX (CEA/DAM), Camille MOUGEY (CEA/DAM)               #
#
#

from builtins import zip
from builtins import range
import os
from llvmlite import binding as llvm
from llvmlite import ir as llvm_ir
from builtins import int as int_types
import warnings

from future.utils import viewitems, viewvalues

from miasm.expression.expression import ExprId, ExprInt, ExprMem, ExprSlice, \
    ExprCond, ExprLoc, ExprOp, ExprCompose, LocKey, Expr, \
    TOK_EQUAL, \
    TOK_INF_SIGNED, TOK_INF_UNSIGNED, \
    TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED

import miasm.jitter.csts as m2_csts
import miasm.core.asmblock as m2_asmblock
from miasm.core.utils import size2mask
from miasm.jitter.codegen import CGen, Attributes
from miasm.expression.expression_helper import possible_values


class LLVMType(llvm_ir.Type):

    "Handle LLVM Type"

    int_cache = {}

    @classmethod
    def IntType(cls, size=32):
        try:
            return cls.int_cache[size]
        except KeyError:
            cls.int_cache[size] = llvm_ir.IntType(size)
            return cls.int_cache[size]

    @classmethod
    def pointer(cls, addr):
        "Generic pointer for execution"
        return llvm_e.GenericValue.pointer(addr)

    @classmethod
    def generic(cls, e):
        "Generic value for execution"
        if isinstance(e, ExprInt):
            return llvm_e.GenericValue.int(LLVMType.IntType(e.size), int(e.arg))
        elif isinstance(e, llvm_e.GenericValue):
            return e
        else:
            raise ValueError()

    @classmethod
    def fptype(cls, size):
        """Return the floating type corresponding to precision @size"""
        if size == 32:
            precision = llvm_ir.FloatType()
        elif size == 64:
            precision = llvm_ir.DoubleType()
        else:
            raise RuntimeError("Unsupported precision: %x", size)
        return precision


class LLVMContext(object):

    "Context for llvm binding. Stand for a LLVM Module"

    known_fc = {}

    def __init__(self, name="mod"):
        "Initialize a context with a module named 'name'"
        # Initialize llvm
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

        # Initialize target for compilation
        target = llvm.Target.from_default_triple()
        self.target_machine = target.create_target_machine()
        self.init_exec_engine()

    def canonize_label_name(self, label):
        """Canonize @label names to a common form.
        @label: str or asmlabel instance"""
        if isinstance(label, str):
            return label
        elif isinstance(label, LocKey):
            return str(label)
        else:
            raise ValueError("label must either be str or LocKey")

    def optimise_level(self, level=2):
        """Set the optimisation level to @level from 0 to 2
        0: non-optimized
        2: optimized
        """

        # Set up the optimiser pipeline
        pmb = llvm.create_pass_manager_builder()
        pmb.opt_level = level
        pm = llvm.create_module_pass_manager()
        pmb.populate(pm)
        self.pass_manager = pm

    def init_exec_engine(self):
        mod = llvm.parse_assembly("")
        engine = llvm.create_mcjit_compiler(mod,
                                            self.target_machine)
        self.exec_engine = engine

    def new_module(self, name="mod"):
        """Create a module, with needed functions"""
        self.mod = llvm_ir.Module(name=name)
        self.add_fc(self.known_fc)
        self.add_op()

    def get_execengine(self):
        "Return the Execution Engine associated with this context"
        return self.exec_engine

    def get_passmanager(self):
        "Return the Pass Manager associated with this context"
        return self.pass_manager

    def get_module(self):
        "Return the module associated with this context"
        return self.mod

    def add_shared_library(self, filename):
        "Load the shared library 'filename'"
        return llvm.load_library_permanently(filename)

    def add_fc(self, fc, readonly=False):
        "Add function into known_fc"

        for name, detail in viewitems(fc):
            fnty = llvm_ir.FunctionType(detail["ret"], detail["args"])
            fn = llvm_ir.Function(self.mod, fnty, name=name)
            if readonly:
                fn.attributes.add("readonly")

    def add_op(self):
        "Add operations functions"

        i8 = LLVMType.IntType(8)
        p8 = llvm_ir.PointerType(i8)
        itype = LLVMType.IntType(64)
        ftype = llvm_ir.FloatType()
        dtype = llvm_ir.DoubleType()
        fc = {"llvm.ctpop.i8": {"ret": i8,
                                "args": [i8]},
              "llvm.nearbyint.f32": {"ret": ftype,
                                     "args": [ftype]},
              "llvm.nearbyint.f64": {"ret": dtype,
                                     "args": [dtype]},
              "llvm.trunc.f32": {"ret": ftype,
                                 "args": [ftype]},
              "segm2addr": {"ret": itype,
                            "args": [p8,
                                     itype,
                                     itype]},
              "x86_cpuid": {"ret": itype,
                        "args": [itype,
                                 itype]},
              "fpu_fcom_c0": {"ret": itype,
                          "args": [dtype,
                                   dtype]},
              "fpu_fcom_c1": {"ret": itype,
                          "args": [dtype,
                                   dtype]},
              "fpu_fcom_c2": {"ret": itype,
                          "args": [dtype,
                                   dtype]},
              "fpu_fcom_c3": {"ret": itype,
                          "args": [dtype,
                                   dtype]},
              "llvm.sqrt.f32": {"ret": ftype,
                                "args": [ftype]},
              "llvm.sqrt.f64": {"ret": dtype,
                                "args": [dtype]},
              "llvm.fabs.f32": {"ret": ftype,
                                "args": [ftype]},
              "llvm.fabs.f64": {"ret": dtype,
                                "args": [dtype]},
        }

        for k in [8, 16]:
            fc["bcdadd_%s" % k] = {"ret": LLVMType.IntType(k),
                                   "args": [LLVMType.IntType(k),
                                            LLVMType.IntType(k)]}
            fc["bcdadd_cf_%s" % k] = {"ret": LLVMType.IntType(k),
                                      "args": [LLVMType.IntType(k),
                                               LLVMType.IntType(k)]}
        self.add_fc(fc, readonly=True)


    def memory_lookup(self, func, addr, size):
        """Perform a memory lookup at @addr of size @size (in bit)"""
        raise NotImplementedError("Abstract method")

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        raise NotImplementedError("Abstract method")


class LLVMContext_JIT(LLVMContext):

    """Extend LLVMContext_JIT in order to handle memory management and custom
    operations"""

    def __init__(self, library_filenames, lifter, name="mod"):
        "Init a LLVMContext object, and load the mem management shared library"
        self.library_filenames = library_filenames
        self.lifter = lifter
        self.arch_specific()
        self.load_libraries()
        LLVMContext.__init__(self, name)
        self.vmcpu = {}

    @property
    def ir_arch(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir_arch"')
        return self.lifter

    def load_libraries(self):
        # Get LLVM specific functions
        name = "libLLVM-%d.%d" % (llvm.llvm_version_info[0],
                                  llvm.llvm_version_info[1],
        )
        try:
            # On Windows, no need to add ".dll"
            self.add_shared_library(name)
        except RuntimeError:
            try:
                # On Linux, ".so" is needed
                self.add_shared_library("%s.so" % name)
            except RuntimeError:
                pass

        # Load additional libraries
        for lib_fname in self.library_filenames:
            self.add_shared_library(lib_fname)

    def new_module(self, name="mod"):
        LLVMContext.new_module(self, name)
        self.add_memlookups()
        self.add_get_exceptionflag()
        self.add_log_functions()

    def arch_specific(self):
        arch = self.lifter.arch
        if arch.name == "x86":
            self.PC = arch.regs.RIP
            self.logging_func = "dump_gpregs_%d" % self.lifter.attrib
        else:
            self.PC = self.lifter.pc
            self.logging_func = "dump_gpregs"
        if arch.name == "mips32":
            from miasm.arch.mips32.jit import mipsCGen
            self.cgen_class = mipsCGen
            self.has_delayslot = True
        elif arch.name == "arm":
            from miasm.arch.arm.jit import arm_CGen
            self.cgen_class = arm_CGen
            self.has_delayslot = False
        else:
            self.cgen_class = CGen
            self.has_delayslot = False

    def add_memlookups(self):
        "Add MEM_LOOKUP functions"

        fc = {}
        p8 = llvm_ir.PointerType(LLVMType.IntType(8))
        for i in [8, 16, 32, 64]:
            fc["MEM_LOOKUP_%02d" % i] = {"ret": LLVMType.IntType(i),
                                         "args": [p8,
                                                  LLVMType.IntType(64)]}

            fc["MEM_WRITE_%02d" % i] = {"ret": llvm_ir.VoidType(),
                                        "args": [p8,
                                                 LLVMType.IntType(64),
                                                 LLVMType.IntType(i)]}

        fc["MEM_LOOKUP_INT_BN_TO_PTR"] = {"ret": llvm_ir.VoidType(),
                                          "args": [
                                              p8,
                                              LLVMType.IntType(32),
                                              LLVMType.IntType(64),
                                              p8
                                          ]}
        fc["MEM_WRITE_INT_BN_FROM_PTR"] = {"ret": llvm_ir.VoidType(),
                                           "args": [
                                               p8,
                                               LLVMType.IntType(32),
                                               LLVMType.IntType(64),
                                               p8,
                                           ]}

        fc["reset_memory_access"] = {"ret": llvm_ir.VoidType(),
                                     "args": [p8,
                                     ]}
        fc["check_memory_breakpoint"] = {"ret": llvm_ir.VoidType(),
                                         "args": [p8,
                                         ]}
        fc["check_invalid_code_blocs"] = {"ret": llvm_ir.VoidType(),
                                          "args": [p8,
                                          ]}
        self.add_fc(fc)

    def add_get_exceptionflag(self):
        "Add 'get_exception_flag' function"
        p8 = llvm_ir.PointerType(LLVMType.IntType(8))
        self.add_fc({"get_exception_flag": {"ret": LLVMType.IntType(64),
                                            "args": [p8]}}, readonly=True)

    def add_log_functions(self):
        "Add functions for state logging"

        p8 = llvm_ir.PointerType(LLVMType.IntType(8))
        self.add_fc({self.logging_func: {"ret": llvm_ir.VoidType(),
                                         "args": [p8]}},
                    readonly=True)

    def set_vmcpu(self, lookup_table):
        "Set the correspondence between register name and vmcpu offset"

        self.vmcpu = lookup_table

    def memory_lookup(self, func, addr, size):
        """Perform a memory lookup at @addr of size @size (in bit)"""
        builder = func.builder
        if size <= 64:
            fc_name = "MEM_LOOKUP_%02d" % size
            fc_ptr = self.mod.get_global(fc_name)
            addr_casted = builder.zext(addr, LLVMType.IntType(64))
            ret = builder.call(
                fc_ptr, [func.local_vars["jitcpu"],addr_casted]
            )
        else:
            # Miasm uses a memory lookup function which returns a bn_t for its
            # result. We cannot simply translate this into IntType. The trick
            # here is to use the function MEM_LOOKUP_INT_BN_TO_PTR which has a
            # different interface: the resulting bn_t is passed through a char*
            # argument.
            #
            # WARNING: Here, we use the fact that the serialisation of LLVM
            # IntType is the *same* as the bn_t structure.

            fc_name = "MEM_LOOKUP_INT_BN_TO_PTR"
            fc_ptr = self.mod.get_global(fc_name)
            addr_casted = builder.zext(addr, LLVMType.IntType(64))
            size_cst = llvm_ir.Constant(LLVMType.IntType(32), size)

            value_ptr = builder.alloca(llvm_ir.IntType(size))
            value_ptr_u8 = builder.bitcast(
                value_ptr,
                LLVMType.IntType(8).as_pointer()
            )


            builder.call(
                fc_ptr,
                [
                    func.local_vars["jitcpu"],
                    size_cst,
                    addr_casted,
                    value_ptr_u8
                ]
            )
            ret = builder.load(value_ptr)

        return ret

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        # Function call
        builder = func.builder
        if size <= 64:
            fc_name = "MEM_WRITE_%02d" % size
            fc_ptr = self.mod.get_global(fc_name)
            dst_casted = builder.zext(addr, LLVMType.IntType(64))
            builder.call(
                fc_ptr,
                [
                    func.local_vars["jitcpu"],
                    dst_casted,
                    value
                ]
            )
        else:
            # The same trick as described in MEM_LOOKUP_INT_BN_TO_PTR is used
            # here.

            fc_name = "MEM_WRITE_INT_BN_FROM_PTR"
            fc_ptr = self.mod.get_global(fc_name)
            addr_casted = builder.zext(addr, LLVMType.IntType(64))
            size_cst = llvm_ir.Constant(LLVMType.IntType(32), size)

            ret = builder.alloca(value.type)
            builder.store(value, ret)
            value_ptr = builder.bitcast(ret, llvm_ir.IntType(8).as_pointer())

            builder.call(
                fc_ptr,
                [
                    func.local_vars["jitcpu"],
                    size_cst,
                    addr_casted,
                    value_ptr,
                ]
            )


    @staticmethod
    def cache_notify(module, buffer):
        """Called when @module has been compiled to @buffer"""
        if not hasattr(module, "fname_out"):
            return
        fname_out = module.fname_out

        if os.access(fname_out, os.R_OK):
            # No need to overwrite
            return

        open(fname_out, "wb").write(buffer)

    @staticmethod
    def cache_getbuffer(module):
        """Return a compiled buffer for @module if available"""
        if not hasattr(module, "fname_out"):
            return None

        fname_out = module.fname_out
        if os.access(fname_out, os.R_OK):
            return open(fname_out, "rb").read()
        return None

    def enable_cache(self):
        "Enable cache of compiled object"
        # Load shared libraries
        for lib_fname in self.library_filenames:
            self.add_shared_library(lib_fname)

        # Activate cache
        self.exec_engine.set_object_cache(
            self.cache_notify,
            self.cache_getbuffer
        )

    def set_cache_filename(self, func, fname_out):
        "Set the filename @fname_out to use for cache for @func"
        # Use a custom attribute to propagate the cache filename
        func.as_llvm_mod().fname_out = fname_out

    def get_ptr_from_cache(self, file_name, func_name):
        "Load @file_name and return a pointer on the jitter @func_name"
        # We use an empty module to avoid losing time on function building
        empty_module = llvm.parse_assembly("")
        empty_module.fname_out = file_name

        engine = self.exec_engine
        engine.add_module(empty_module)
        engine.finalize_object()
        return engine.get_function_address(func_name)


class LLVMContext_IRCompilation(LLVMContext):

    """Extend LLVMContext in order to handle memory management and custom
    operations for Miasm IR compilation"""

    def memory_lookup(self, func, addr, size):
        """Perform a memory lookup at @addr of size @size (in bit)"""
        builder = func.builder
        int_size = LLVMType.IntType(size)
        ptr_casted = builder.inttoptr(
            addr,
            llvm_ir.PointerType(int_size)
        )
        return builder.load(ptr_casted)

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        builder = func.builder
        int_size = LLVMType.IntType(size)
        ptr_casted = builder.inttoptr(
            addr,
            llvm_ir.PointerType(int_size)
        )
        return builder.store(value, ptr_casted)


class LLVMFunction(object):
    """Represent a LLVM function

    Implementation note:
    A new module is created each time to avoid cumulative lag (if @new_module)
    """

    # Default logging values
    log_mn = False
    log_regs = True

    # Operation translation
    ## Basics
    op_translate = {'x86_cpuid': 'x86_cpuid',
    }
    ## Add the size as first argument
    op_translate_with_size = {}
    ## Add the size as suffix
    op_translate_with_suffix_size = {
        'bcdadd': 'bcdadd',
        'bcdadd_cf': 'bcdadd_cf',
    }

    def __init__(self, llvm_context, name="fc", new_module=True):
        "Create a new function with name @name"
        self.llvm_context = llvm_context
        if new_module:
            self.llvm_context.new_module()
        self.mod = self.llvm_context.get_module()

        self.my_args = []  # (Expr, LLVMType, Name)
        self.ret_type = None
        self.builder = None
        self.entry_bbl = None

        self.branch_counter = 0
        self.name = name
        self._llvm_mod = None

    # Constructor utils

    def new_branch_name(self):
        "Return a new branch name"
        self.branch_counter += 1
        return str(self.branch_counter)

    def append_basic_block(self, label, overwrite=True):
        """Add a new basic block to the current function.
        @label: str or asmlabel
        @overwrite: if False, do nothing if a bbl with the same name already exists
        Return the corresponding LLVM Basic Block"""
        name = self.llvm_context.canonize_label_name(label)
        bbl = self.name2bbl.get(name, None)
        if not overwrite and bbl is not None:
            return bbl
        bbl = self.fc.append_basic_block(name)
        self.name2bbl[name] = bbl

        return bbl

    def CreateEntryBlockAlloca(self, var_type, default_value=None):
        """Create an alloca instruction at the beginning of the current fc
        @default_value: if set, store the default_value just after the allocation
        """
        builder = self.builder
        current_bbl = builder.basic_block
        builder.position_at_start(self.entry_bbl)

        ret = builder.alloca(var_type)
        if default_value is not None:
            builder.store(default_value, ret)
        builder.position_at_end(current_bbl)
        return ret

    def get_ptr_by_expr(self, expr):
        """"Return a pointer casted corresponding to ExprId expr. If it is not
        already computed, compute it at the end of entry_bloc"""

        name = expr.name

        ptr_casted = self.local_vars_pointers.get(name, None)
        if ptr_casted is not None:
            # If the pointer has already been computed
            return ptr_casted

        # Get current objects
        builder = self.builder
        current_bbl = builder.basic_block

        # Go at the right position
        entry_bloc_bbl = self.entry_bbl
        builder.position_at_end(entry_bloc_bbl)

        # Compute the pointer address
        offset = self.llvm_context.vmcpu[name]

        # Pointer cast
        ptr = builder.gep(
            self.local_vars["vmcpu"],
            [
                llvm_ir.Constant(
                    LLVMType.IntType(),
                    offset
                )
            ]
        )
        pointee_type = LLVMType.IntType(expr.size)
        ptr_casted = builder.bitcast(
            ptr,
            llvm_ir.PointerType(pointee_type)
        )
        # Store in cache
        self.local_vars_pointers[name] = ptr_casted

        # Reset builder
        builder.position_at_end(current_bbl)

        return ptr_casted

    def update_cache(self, name, value):
        "Add 'name' = 'value' to the cache iff main_stream = True"

        if self.main_stream is True:
            self.expr_cache[name] = value

    def set_ret(self, var):
        "Cast @var and return it at the end of current bbl"
        if var.type.width < 64:
            var_casted = self.builder.zext(var, LLVMType.IntType(64))
        else:
            var_casted = var
        self.builder.ret(var_casted)

    def get_basic_block_by_loc_key(self, loc_key):
        "Return the bbl corresponding to label, None otherwise"
        return self.name2bbl.get(
            self.llvm_context.canonize_label_name(loc_key),
            None
        )

    def global_constant(self, name, value):
        """
        Inspired from numba/cgutils.py

        Get or create a (LLVM module-)global constant with *name* or *value*.
        """
        if name in self.mod.globals:
            return self.mod.globals[name]
        data = llvm_ir.GlobalVariable(self.mod, value.type, name=name)
        data.global_constant = True
        data.initializer = value
        return data

    def make_bytearray(self, buf):
        """
        Inspired from numba/cgutils.py

        Make a byte array constant from *buf*.
        """
        b = bytearray(buf)
        n = len(b)
        return llvm_ir.Constant(llvm_ir.ArrayType(llvm_ir.IntType(8), n), b)

    def printf(self, format, *args):
        """
        Inspired from numba/cgutils.py

        Calls printf().
        Argument `format` is expected to be a Python string.
        Values to be printed are listed in `args`.

        Note: There is no checking to ensure there is correct number of values
        in `args` and there type matches the declaration in the format string.
        """
        assert isinstance(format, str)
        mod = self.mod
        # Make global constant for format string
        cstring = llvm_ir.IntType(8).as_pointer()
        fmt_bytes = self.make_bytearray((format + '\00').encode('ascii'))

        base_name = "printf_format"
        count = 0
        while "%s_%d" % (base_name, count) in self.mod.globals:
            count += 1
        global_fmt = self.global_constant(
            "%s_%d" % (base_name, count),
            fmt_bytes
        )
        fnty = llvm_ir.FunctionType(
            llvm_ir.IntType(32),
            [cstring],
            var_arg=True
        )
        # Insert printf()
        fn = mod.globals.get('printf', None)
        if fn is None:
            fn = llvm_ir.Function(mod, fnty, name="printf")
        # Call
        ptr_fmt = self.builder.bitcast(global_fmt, cstring)
        return self.builder.call(fn, [ptr_fmt] + list(args))

    # Effective constructors

    def assign(self, src, dst):
        "Assign from LLVM src to M2 dst"

        # Destination
        builder = self.builder

        if isinstance(dst, ExprId):
            ptr_casted = self.get_ptr_by_expr(dst)
            builder.store(src, ptr_casted)

        elif isinstance(dst, ExprMem):
            addr = self.add_ir(dst.ptr)
            self.llvm_context.memory_write(self, addr, dst.size, src)
        else:
            raise Exception("UnknownAssignmentType")

    def init_fc(self):
        "Init the function"

        # Build type for fc signature
        fc_type = llvm_ir.FunctionType(
            self.ret_type,
            [k[1] for k in self.my_args]
        )

        # Add fc in module
        try:
            fc = llvm_ir.Function(self.mod, fc_type, name=self.name)
        except llvm.LLVMException:
            # Overwrite the previous function
            previous_fc = self.mod.get_global(self.name)
            previous_fc.delete()
            fc = self.mod.add_function(fc_type, self.name)

        # Name args
        for i, a in enumerate(self.my_args):
            fc.args[i].name = a[2]

        # Initialize local variable pool
        self.local_vars = {}
        self.local_vars_pointers = {}
        for i, a in enumerate(self.my_args):
            self.local_vars[a[2]] = fc.args[i]

        # Init cache
        self.expr_cache = {}
        self.main_stream = True
        self.name2bbl = {}

        # Function link
        self.fc = fc

        # Add a first BasicBlock
        self.entry_bbl = self.append_basic_block("entry")

        # Instruction builder
        self.builder = llvm_ir.IRBuilder(self.entry_bbl)

    def add_ir(self, expr):
        "Add a Miasm2 IR to the last bbl. Return the var created"

        if self.main_stream is True and expr in self.expr_cache:
            return self.expr_cache[expr]

        builder = self.builder

        if isinstance(expr, ExprInt):
            ret = llvm_ir.Constant(LLVMType.IntType(expr.size), int(expr))
            self.update_cache(expr, ret)
            return ret

        if expr.is_loc():
            offset = self.llvm_context.lifter.loc_db.get_location_offset(
                expr.loc_key
            )
            ret = llvm_ir.Constant(LLVMType.IntType(expr.size), offset)
            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, ExprId):
            name = expr.name
            try:
                # If expr.name is already known (args)
                return self.local_vars[name]
            except KeyError:
                pass

            ptr_casted = self.get_ptr_by_expr(expr)

            var = builder.load(ptr_casted, name)
            self.update_cache(expr, var)
            return var

        if isinstance(expr, ExprOp):
            op = expr.op

            if (op in self.op_translate or
                op in self.op_translate_with_size or
                op in self.op_translate_with_suffix_size):
                args = [self.add_ir(arg) for arg in expr.args]
                arg_size = expr.args[0].size

                if op in self.op_translate_with_size:
                    fc_name = self.op_translate_with_size[op]
                    arg_size_cst = llvm_ir.Constant(LLVMType.IntType(64),
                                                    arg_size)
                    args = [arg_size_cst] + args
                elif op in self.op_translate:
                    fc_name = self.op_translate[op]
                elif op in self.op_translate_with_suffix_size:
                    fc_name = "%s_%s" % (self.op_translate[op], arg_size)

                fc_ptr = self.mod.get_global(fc_name)

                # Cast args if needed
                casted_args = []
                for i, arg in enumerate(args):
                    if arg.type.width < fc_ptr.args[i].type.width:
                        casted_args.append(
                            builder.zext(
                                arg,
                                fc_ptr.args[i].type
                            )
                        )
                    else:
                        casted_args.append(arg)
                ret = builder.call(fc_ptr, casted_args)

                # Cast ret if needed
                ret_size = fc_ptr.return_value.type.width
                if ret_size > expr.size:
                    ret = builder.trunc(ret, LLVMType.IntType(expr.size))

                self.update_cache(expr, ret)
                return ret

            if op == "-":
                # Unsupported op '-' with more than 1 arg
                assert len(expr.args) == 1
                zero = LLVMType.IntType(expr.size)(0)
                ret = builder.sub(zero, self.add_ir(expr.args[0]))
                self.update_cache(expr, ret)
                return ret

            if op == "parity":
                assert len(expr.args) == 1
                arg = self.add_ir(expr.args[0])
                truncated = builder.trunc(arg, LLVMType.IntType(8))
                bitcount = builder.call(
                    self.mod.get_global("llvm.ctpop.i8"),
                    [truncated]
                )
                ret = builder.not_(builder.trunc(bitcount, LLVMType.IntType(1)))
                self.update_cache(expr, ret)
                return ret

            if op in ["cntleadzeros", "cnttrailzeros"]:
                assert len(expr.args) == 1
                arg = self.add_ir(expr.args[0])
                func_name = {
                    "cntleadzeros": "ctlz",
                    "cnttrailzeros": "cttz",
                }[op]
                func_llvm_name = "llvm.%s.i%d" % (func_name, expr.size)
                func_sig = {
                    func_llvm_name: {
                        "ret": LLVMType.IntType(expr.size),
                        "args": [LLVMType.IntType(expr.args[0].size)]
                    }
                }
                try:
                    self.mod.get_global(func_llvm_name)
                except KeyError:
                    self.llvm_context.add_fc(func_sig, readonly=True)
                ret = builder.call(
                    self.mod.get_global(func_llvm_name),
                    [arg]
                )
                self.update_cache(expr, ret)
                return ret


            if op.startswith('zeroExt_'):
                arg = expr.args[0]
                if expr.size == arg.size:
                    return arg
                new_expr = ExprCompose(arg, ExprInt(0, expr.size - arg.size))
                return self.add_ir(new_expr)

            if op.startswith("signExt_"):
                arg = expr.args[0]
                add_size = expr.size - arg.size
                new_expr = ExprCompose(
                    arg,
                    ExprCond(
                        arg.msb(),
                        ExprInt(size2mask(add_size), add_size),
                        ExprInt(0, add_size)
                    )
                )
                return self.add_ir(new_expr)


            if op == "segm":
                fc_ptr = self.mod.get_global("segm2addr")

                # Cast args if needed
                args = [self.add_ir(arg) for arg in expr.args]
                casted_args = []
                for i, arg in enumerate(args, 1):
                    if arg.type.width < fc_ptr.args[i].type.width:
                        casted_args.append(
                            builder.zext(
                                arg,
                                fc_ptr.args[i].type
                            )
                        )
                    else:
                        casted_args.append(arg)

                ret = builder.call(
                    fc_ptr,
                    [self.local_vars["jitcpu"]] + casted_args
                )
                if ret.type.width > expr.size:
                    ret = builder.trunc(ret, LLVMType.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["smod", "sdiv", "umod", "udiv"]:
                assert len(expr.args) == 2

                arg_b = self.add_ir(expr.args[1])
                arg_a = self.add_ir(expr.args[0])

                if op == "smod":
                    callback = builder.srem
                elif op == "sdiv":
                    callback = builder.sdiv
                elif op == "umod":
                    callback = builder.urem
                elif op == "udiv":
                    callback = builder.udiv

                ret = callback(arg_a, arg_b)
                self.update_cache(expr, ret)
                return ret

            unsigned_cmps = {
                "==": "==",
                "<u": "<",
                "<=u": "<="
            }
            if op in unsigned_cmps:
                op = unsigned_cmps[op]
                args = [self.add_ir(arg) for arg in expr.args]
                ret = builder.select(
                    builder.icmp_unsigned(op,
                                          args[0],
                                          args[1]
                    ),
                    llvm_ir.IntType(expr.size)(1),
                    llvm_ir.IntType(expr.size)(0)
                )
                self.update_cache(expr, ret)
                return ret

            if op in [">>", "<<", "a>>"]:
                assert len(expr.args) == 2
                # Undefined behavior must be enforced to 0
                count = self.add_ir(expr.args[1])
                value = self.add_ir(expr.args[0])
                itype = LLVMType.IntType(expr.size)
                cond_ok = self.builder.icmp_unsigned(
                    "<",
                    count,
                    itype(expr.size)
                )
                zero = itype(0)
                if op == ">>":
                    callback = builder.lshr
                elif op == "<<":
                    callback = builder.shl
                elif op == "a>>":
                    callback = builder.ashr
                    # x a>> size is 0 or -1, depending on x sign
                    cond_neg = self.builder.icmp_signed("<", value, zero)
                    zero = self.builder.select(cond_neg, itype(-1), zero)

                ret = self.builder.select(
                    cond_ok,
                    callback(value, count),
                    zero
                )
                self.update_cache(expr, ret)
                return ret


            if op in ['<<<', '>>>']:
                assert len(expr.args) == 2
                # First compute rotation modulus size
                count = self.add_ir(expr.args[1])
                value = self.add_ir(expr.args[0])
                itype = LLVMType.IntType(expr.size)
                expr_size = itype(expr.size)

                # As shift of expr_size is undefined, we urem the shifters
                shift = builder.urem(count, expr_size)
                shift_inv = builder.urem(
                    builder.sub(expr_size, shift),
                    expr_size
                )

                if op == '<<<':
                    part_a = builder.shl(value, shift)
                    part_b = builder.lshr(value, shift_inv)
                else:
                    part_a = builder.lshr(value, shift)
                    part_b = builder.shl(value, shift_inv)
                ret = builder.or_(part_a, part_b)
                self.update_cache(expr, ret)
                return ret

            if op == "sint_to_fp":
                fptype = LLVMType.fptype(expr.size)
                arg = self.add_ir(expr.args[0])
                ret = builder.sitofp(arg, fptype)
                ret = builder.bitcast(ret, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op.startswith("fp_to_sint"):
                size_arg = expr.args[0].size
                fptype_orig = LLVMType.fptype(size_arg)
                arg = self.add_ir(expr.args[0])
                arg = builder.bitcast(arg, fptype_orig)
                # Enforce IEEE-754 behavior. This could be enhanced with
                # 'llvm.experimental.constrained.nearbyint'
                if size_arg == 32:
                    func = self.mod.get_global("llvm.nearbyint.f32")
                elif size_arg == 64:
                    func = self.mod.get_global("llvm.nearbyint.f64")
                else:
                    raise RuntimeError("Unsupported size")
                rounded = builder.call(func, [arg])
                ret = builder.fptoui(rounded, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op.startswith("fpconvert_fp"):
                assert len(expr.args) == 1
                size_arg = expr.args[0].size
                fptype = LLVMType.fptype(expr.size)
                fptype_orig = LLVMType.fptype(size_arg)
                arg = self.add_ir(expr.args[0])
                arg = builder.bitcast(arg, fptype_orig)
                if expr.size > size_arg:
                    fc = builder.fpext
                elif expr.size < size_arg:
                    fc = builder.fptrunc
                else:
                    raise RuntimeError("Not supported, same size")
                ret = fc(arg, fptype)
                ret = builder.bitcast(ret, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op.startswith("fpround_"):
                assert len(expr.args) == 1
                fptype = LLVMType.fptype(expr.size)
                arg = self.add_ir(expr.args[0])
                arg = builder.bitcast(arg, fptype)
                if op == "fpround_towardszero" and expr.size == 32:
                    fc = self.mod.get_global("llvm.trunc.f32")
                else:
                    raise RuntimeError("Not supported, same size")
                rounded = builder.call(fc, [arg])
                ret = builder.bitcast(rounded, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["fcom_c0", "fcom_c1", "fcom_c2", "fcom_c3"]:
                arg1 = self.add_ir(expr.args[0])
                arg2 = self.add_ir(expr.args[0])
                fc_name = "fpu_%s" % op
                fc_ptr = self.mod.get_global(fc_name)
                casted_args = [
                    builder.bitcast(arg1, llvm_ir.DoubleType()),
                    builder.bitcast(arg2, llvm_ir.DoubleType()),
                ]
                ret = builder.call(fc_ptr, casted_args)

                # Cast ret if needed
                ret_size = fc_ptr.return_value.type.width
                if ret_size > expr.size:
                    ret = builder.trunc(ret, LLVMType.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["fsqrt", "fabs"]:
                arg = self.add_ir(expr.args[0])
                if op == "fsqrt":
                    op = "sqrt"

                # Apply the correct func
                if expr.size == 32:
                    arg = builder.bitcast(arg, llvm_ir.FloatType())
                    ret = builder.call(
                        self.mod.get_global("llvm.%s.f32" % op),
                        [arg]
                    )
                elif expr.size == 64:
                    arg = builder.bitcast(arg, llvm_ir.DoubleType())
                    ret = builder.call(
                        self.mod.get_global("llvm.%s.f64" % op),
                        [arg]
                    )
                else:
                    raise RuntimeError("Unsupported precision: %x", expr.size)

                ret = builder.bitcast(ret, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["fadd", "fmul", "fsub", "fdiv"]:
                # More than 2 args not yet supported
                assert len(expr.args) == 2
                arg1 = self.add_ir(expr.args[0])
                arg2 = self.add_ir(expr.args[1])
                precision = LLVMType.fptype(expr.size)
                arg1 = builder.bitcast(arg1, precision)
                arg2 = builder.bitcast(arg2, precision)
                if op == "fadd":
                    ret = builder.fadd(arg1, arg2)
                elif op == "fmul":
                    ret = builder.fmul(arg1, arg2)
                elif op == "fsub":
                    ret = builder.fsub(arg1, arg2)
                elif op == "fdiv":
                    ret = builder.fdiv(arg1, arg2)
                ret = builder.bitcast(ret, llvm_ir.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in [
                    TOK_EQUAL,
                    TOK_INF_SIGNED,
                    TOK_INF_EQUAL_SIGNED,
                    TOK_INF_UNSIGNED,
                    TOK_INF_EQUAL_UNSIGNED,
            ]:
                if op == TOK_EQUAL:
                    opname = "=="
                    callback = builder.icmp_unsigned
                elif op == TOK_INF_SIGNED:
                    opname = "<"
                    callback = builder.icmp_signed
                elif op == TOK_INF_UNSIGNED:
                    opname = "<"
                    callback = builder.icmp_unsigned
                elif op == TOK_INF_EQUAL_SIGNED:
                    opname = "<="
                    callback = builder.icmp_signed
                elif op == TOK_INF_EQUAL_UNSIGNED:
                    opname = "<"
                    callback = builder.icmp_unsigned

                left = self.add_ir(expr.args[0])
                right = self.add_ir(expr.args[1])

                ret = callback(opname, left, right)
                self.update_cache(expr, ret)

                return ret

            if len(expr.args) > 1:

                if op == "*":
                    callback = builder.mul
                elif op == "+":
                    callback = builder.add
                elif op == "&":
                    callback = builder.and_
                elif op == "^":
                    callback = builder.xor
                elif op == "|":
                    callback = builder.or_
                elif op == "%":
                    callback = builder.urem
                elif op == "/":
                    callback = builder.udiv
                else:
                    raise NotImplementedError('Unknown op: %s' % op)

                last = self.add_ir(expr.args[0])

                for i in range(1, len(expr.args)):
                    last = callback(last,
                                    self.add_ir(expr.args[i]))

                self.update_cache(expr, last)

                return last

            raise NotImplementedError()

        if isinstance(expr, ExprMem):

            addr = self.add_ir(expr.ptr)
            ret = self.llvm_context.memory_lookup(self, addr, expr.size)
            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, ExprCond):
            # Compute cond
            cond = self.add_ir(expr.cond)
            zero_casted = LLVMType.IntType(expr.cond.size)(0)
            condition_bool = builder.icmp_unsigned("!=", cond,
                                                   zero_casted)
            then_value = self.add_ir(expr.src1)
            else_value = self.add_ir(expr.src2)
            ret = builder.select(condition_bool, then_value, else_value)

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, ExprSlice):

            src = self.add_ir(expr.arg)

            # Remove trailing bits
            if expr.start != 0:
                to_shr = llvm_ir.Constant(
                    LLVMType.IntType(expr.arg.size),
                    expr.start
                )
                shred = builder.lshr(src, to_shr)
            else:
                shred = src

            # Remove leading bits
            to_and = llvm_ir.Constant(
                LLVMType.IntType(expr.arg.size),
                (1 << (expr.stop - expr.start)) - 1
            )
            anded = builder.and_(shred,
                                 to_and)

            # Cast into e.size
            ret = builder.trunc(
                anded,
                LLVMType.IntType(expr.size)
            )

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, ExprCompose):

            args = []

            # Build each part
            for start, src in expr.iter_args():
                # src & size
                src = self.add_ir(src)
                src_casted = builder.zext(
                    src,
                    LLVMType.IntType(expr.size)
                )
                to_and = llvm_ir.Constant(
                    LLVMType.IntType(expr.size),
                    (1 << src.type.width) - 1
                )
                anded = builder.and_(src_casted,
                                     to_and)

                if (start != 0):
                    # result << start
                    to_shl = llvm_ir.Constant(
                        LLVMType.IntType(expr.size),
                        start
                    )
                    shled = builder.shl(anded, to_shl)
                    final = shled
                else:
                    # Optimisation
                    final = anded

                args.append(final)

            # result = part1 | part2 | ...
            last = args[0]
            for i in range(1, len(expr.args)):
                last = builder.or_(last, args[i])

            self.update_cache(expr, last)
            return last

        raise Exception("UnkownExpression", expr.__class__.__name__)

    # JiT specifics

    def check_memory_exception(self, offset, restricted_exception=False):
        """Add a check for memory errors.
        @offset: offset of the current exception (int or Instruction)
        If restricted_exception, check only for exception which do not
        require a pc update, and do not consider automod exception"""

        # VmMngr "get_exception_flag" return's size
        size = 64
        t_size = LLVMType.IntType(size)

        # Get exception flag value
        # TODO: avoid costly call using a structure deref
        builder = self.builder
        fc_ptr = self.mod.get_global("get_exception_flag")
        exceptionflag = builder.call(fc_ptr, [self.local_vars["vmmngr"]])

        if restricted_exception is True:
            flag = ~m2_csts.EXCEPT_CODE_AUTOMOD & m2_csts.EXCEPT_DO_NOT_UPDATE_PC
            m2_flag = llvm_ir.Constant(t_size, flag)
            exceptionflag = builder.and_(exceptionflag, m2_flag)

        # Compute cond
        zero_casted = llvm_ir.Constant(t_size, 0)
        condition_bool = builder.icmp_unsigned(
            "!=",
            exceptionflag,
            zero_casted
        )

        # Create bbls
        branch_id = self.new_branch_name()
        then_block = self.append_basic_block('then%s' % branch_id)
        merge_block = self.append_basic_block('ifcond%s' % branch_id)

        builder.cbranch(condition_bool, then_block, merge_block)

        # Deactivate object caching
        current_main_stream = self.main_stream
        self.main_stream = False

        # Then Block
        builder.position_at_end(then_block)
        PC = self.llvm_context.PC
        if isinstance(offset, int_types):
            offset = self.add_ir(ExprInt(offset, PC.size))
        self.assign(offset, PC)
        self.assign(self.add_ir(ExprInt(1, 8)), ExprId("status", 32))
        self.set_ret(offset)

        builder.position_at_end(merge_block)
        # Reactivate object caching
        self.main_stream = current_main_stream

    def check_cpu_exception(self, offset, restricted_exception=False):
        """Add a check for CPU errors.
        @offset: offset of the current exception (int or Instruction)
        If restricted_exception, check only for exception which do not
        require a pc update"""

        # Get exception flag value
        builder = self.builder
        m2_exception_flag = self.llvm_context.lifter.arch.regs.exception_flags
        t_size = LLVMType.IntType(m2_exception_flag.size)
        exceptionflag = self.add_ir(m2_exception_flag)

        # Compute cond
        if restricted_exception is True:
            flag = m2_csts.EXCEPT_NUM_UPDT_EIP
            condition_bool = builder.icmp_unsigned(
                ">",
                exceptionflag,
                llvm_ir.Constant(t_size, flag)
            )
        else:
            zero_casted = llvm_ir.Constant(t_size, 0)
            condition_bool = builder.icmp_unsigned(
                "!=",
                exceptionflag,
                zero_casted
            )

        # Create bbls
        branch_id = self.new_branch_name()
        then_block = self.append_basic_block('then%s' % branch_id)
        merge_block = self.append_basic_block('ifcond%s' % branch_id)

        builder.cbranch(condition_bool, then_block, merge_block)

        # Deactivate object caching
        current_main_stream = self.main_stream
        self.main_stream = False

        # Then Block
        builder.position_at_end(then_block)
        PC = self.llvm_context.PC
        if isinstance(offset, int_types):
            offset = self.add_ir(ExprInt(offset, PC.size))
        self.assign(offset, PC)
        self.assign(self.add_ir(ExprInt(1, 8)), ExprId("status", 32))
        self.set_ret(offset)

        builder.position_at_end(merge_block)
        # Reactivate object caching
        self.main_stream = current_main_stream

    def gen_pre_code(self, instr_attrib):
        if instr_attrib.log_mn:
            loc_db = self.llvm_context.lifter.loc_db
            self.printf(
                "%.8X %s\n" % (
                    instr_attrib.instr.offset,
                    instr_attrib.instr.to_string(loc_db)
                )
            )

    def gen_post_code(self, attributes, pc_value):
        if attributes.log_regs:
            # Update PC for dump_gpregs
            PC = self.llvm_context.PC
            t_size = LLVMType.IntType(PC.size)
            dst = self.builder.zext(t_size(pc_value), t_size)
            self.assign(dst, PC)

            fc_ptr = self.mod.get_global(self.llvm_context.logging_func)
            self.builder.call(fc_ptr, [self.local_vars["vmcpu"]])

    def gen_post_instr_checks(self, attrib, next_instr):
        if attrib.mem_read | attrib.mem_write:
            fc_ptr = self.mod.get_global("check_memory_breakpoint")
            self.builder.call(fc_ptr, [self.local_vars["vmmngr"]])
            fc_ptr = self.mod.get_global("check_invalid_code_blocs")
            self.builder.call(fc_ptr, [self.local_vars["vmmngr"]])
            self.check_memory_exception(next_instr, restricted_exception=False)

        if attrib.set_exception:
            self.check_cpu_exception(next_instr, restricted_exception=False)

        if attrib.mem_read | attrib.mem_write:
            fc_ptr = self.mod.get_global("reset_memory_access")
            self.builder.call(fc_ptr, [self.local_vars["vmmngr"]])

    def expr2cases(self, expr):
        """
        Evaluate @expr and return:
        - switch value -> dst
        - evaluation of the switch value (if any)
        """

        to_eval = expr
        dst2case = {}
        case2dst = {}
        for i, solution in enumerate(possible_values(expr)):
            value = solution.value
            index = dst2case.get(value, i)
            to_eval = to_eval.replace_expr({value: ExprInt(index, value.size)})
            dst2case[value] = index
            if value.is_int() or value.is_loc():
                case2dst[i] = value
            else:
                case2dst[i] = self.add_ir(value)


        evaluated = self.add_ir(to_eval)
        return case2dst, evaluated

    def gen_jump2dst(self, attrib, instr_offsets, dst):
        """Generate the code for a jump to @dst with final check for error

        Several cases have to be considered:
         - jump to an offset out of the current ASM BBL (JMP 0x11223344)
         - jump to an offset inside the current ASM BBL (Go to next instruction)
         - jump to an offset back in the current ASM BBL (For max_exec jit
           option on self loops)
         - jump to a generated IR label, which must be jitted in this same
           function (REP MOVSB)
         - jump to a computed offset (CALL @32[0x11223344])

        """
        PC = self.llvm_context.PC
        # We are no longer in the main stream, deactivate cache
        self.main_stream = False

        offset = None
        if isinstance(dst, ExprInt):
            offset = int(dst)
            loc_key = self.llvm_context.lifter.loc_db.get_or_create_offset_location(offset)
            dst = ExprLoc(loc_key, dst.size)

        if isinstance(dst, ExprLoc):
            loc_key = dst.loc_key
            bbl = self.get_basic_block_by_loc_key(loc_key)
            offset = self.llvm_context.lifter.loc_db.get_location_offset(loc_key)
            if bbl is not None:
                # "local" jump, inside this function
                if offset is None:
                    # Avoid checks on generated label
                    self.builder.branch(bbl)
                    return

                if (offset in instr_offsets and
                    offset > attrib.instr.offset):
                    # forward local jump (ie. next instruction)
                    self.gen_post_code(attrib, offset)
                    self.gen_post_instr_checks(attrib, offset)
                    self.builder.branch(bbl)
                    return

                # reaching this point means a backward local jump, promote it to
                # extern

            # "extern" jump on a defined offset, return to the caller
            dst = self.add_ir(ExprInt(offset, PC.size))

        # "extern" jump with a computed value, return to the caller
        assert isinstance(dst, (llvm_ir.Instruction, llvm_ir.Value))
        # Cast @dst, if needed
        # for instance, x86_32: IRDst is 32 bits, so is @dst; PC is 64 bits
        if dst.type.width != PC.size:
            dst = self.builder.zext(dst, LLVMType.IntType(PC.size))

        self.gen_post_code(attrib, offset)
        self.assign(dst, PC)
        self.gen_post_instr_checks(attrib, dst)
        self.assign(self.add_ir(ExprInt(0, 8)), ExprId("status", 32))
        self.set_ret(dst)


    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """
        Generate the code for an @irblock
        @instr_attrib: an Attributes instance or the instruction to translate
        @attributes: list of Attributes corresponding to irblock assignments
        @instr_offsets: offset of all asmblock's instructions
        @irblock: an irblock instance
        """

        case2dst = None
        case_value = None
        instr = instr_attrib.instr

        for index, assignblk in enumerate(irblock):
            # Enable cache
            self.main_stream = True
            self.expr_cache = {}

            # Prefetch memory
            for element in assignblk.get_r(mem_read=True):
                if isinstance(element, ExprMem):
                    self.add_ir(element)

            # Evaluate expressions
            values = {}
            for dst, src in viewitems(assignblk):
                if dst == self.llvm_context.lifter.IRDst:
                    case2dst, case_value = self.expr2cases(src)
                else:
                    values[dst] = self.add_ir(src)

            # Check memory access exception
            if attributes[index].mem_read:
                self.check_memory_exception(
                    instr.offset,
                    restricted_exception=True
                )

            # Update the memory
            for dst, src in viewitems(values):
                if isinstance(dst, ExprMem):
                    self.assign(src, dst)

            # Check memory write exception
            if attributes[index].mem_write:
                self.check_memory_exception(
                    instr.offset,
                    restricted_exception=True
                )

            # Update registers values
            for dst, src in viewitems(values):
                if not isinstance(dst, ExprMem):
                    self.assign(src, dst)

            # Check post assignblk exception flags
            if attributes[index].set_exception:
                self.check_cpu_exception(
                    instr.offset,
                    restricted_exception=True
                )

        # Destination
        assert case2dst is not None
        if len(case2dst) == 1:
            # Avoid switch in this common case
            self.gen_jump2dst(
                instr_attrib,
                instr_offsets,
                next(iter(viewvalues(case2dst)))
            )
        else:
            current_bbl = self.builder.basic_block

            # Gen the out cases
            branch_id = self.new_branch_name()
            case2bbl = {}
            for case, dst in list(viewitems(case2dst)):
                name = "switch_%s_%d" % (branch_id, case)
                bbl = self.append_basic_block(name)
                case2bbl[case] = bbl
                self.builder.position_at_start(bbl)
                self.gen_jump2dst(instr_attrib, instr_offsets, dst)

            # Jump on the correct output
            self.builder.position_at_end(current_bbl)
            switch = self.builder.switch(case_value, case2bbl[0])
            for i, bbl in viewitems(case2bbl):
                if i == 0:
                    # Default case is case 0, arbitrary
                    continue
                switch.add_case(i, bbl)

    def gen_bad_block(self, asmblock):
        """
        Translate an asm_bad_block into a CPU exception
        """
        builder = self.builder
        m2_exception_flag = self.llvm_context.lifter.arch.regs.exception_flags
        t_size = LLVMType.IntType(m2_exception_flag.size)
        self.assign(
            self.add_ir(ExprInt(1, 8)),
            ExprId("status", 32)
        )
        self.assign(
            t_size(m2_csts.EXCEPT_UNK_MNEMO),
            m2_exception_flag
        )
        offset = self.llvm_context.lifter.loc_db.get_location_offset(
            asmblock.loc_key
        )
        self.set_ret(LLVMType.IntType(64)(offset))

    def gen_finalize(self, asmblock, codegen):
        """
        In case of delayslot, generate a dummy BBL which return on the computed
        IRDst or on next_label
        """
        if self.llvm_context.has_delayslot:
            next_label = codegen.get_block_post_label(asmblock)
            builder = self.builder

            builder.position_at_end(self.get_basic_block_by_loc_key(next_label))

            # Common code
            self.assign(self.add_ir(ExprInt(0, 8)),
                        ExprId("status", 32))

            # Check if IRDst has been set
            zero_casted = LLVMType.IntType(codegen.delay_slot_set.size)(0)
            condition_bool = builder.icmp_unsigned(
                "!=",
                self.add_ir(codegen.delay_slot_set),
                zero_casted
            )

            # Create bbls
            branch_id = self.new_branch_name()
            then_block = self.append_basic_block('then%s' % branch_id)
            else_block = self.append_basic_block('else%s' % branch_id)

            builder.cbranch(condition_bool, then_block, else_block)

            # Deactivate object caching
            self.main_stream = False

            # Then Block
            builder.position_at_end(then_block)
            PC = self.llvm_context.PC
            to_ret = self.add_ir(codegen.delay_slot_dst)
            self.assign(to_ret, PC)
            self.assign(self.add_ir(ExprInt(0, 8)),
                        ExprId("status", 32))
            self.set_ret(to_ret)

            # Else Block
            builder.position_at_end(else_block)
            PC = self.llvm_context.PC
            next_label_offset = self.llvm_context.lifter.loc_db.get_location_offset(next_label)
            to_ret = LLVMType.IntType(PC.size)(next_label_offset)
            self.assign(to_ret, PC)
            self.set_ret(to_ret)

    def from_asmblock(self, asmblock):
        """Build the function from an asmblock (asm_block instance).
        Prototype : f(i8* jitcpu, i8* vmcpu, i8* vmmngr, i8* status)"""

        # Build function signature
        self.my_args.append((ExprId("jitcpu", 32),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "jitcpu"))
        self.my_args.append((ExprId("vmcpu", 32),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "vmcpu"))
        self.my_args.append((ExprId("vmmngr", 32),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "vmmngr"))
        self.my_args.append((ExprId("status", 32),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "status"))
        ret_size = 64

        self.ret_type = LLVMType.IntType(ret_size)

        # Initialise the function
        self.init_fc()
        self.local_vars_pointers["status"] = self.local_vars["status"]

        if isinstance(asmblock, m2_asmblock.AsmBlockBad):
            self.gen_bad_block(asmblock)
            return

        # Create basic blocks (for label branches)
        entry_bbl, builder = self.entry_bbl, self.builder
        for instr in asmblock.lines:
            lbl = self.llvm_context.lifter.loc_db.get_or_create_offset_location(instr.offset)
            self.append_basic_block(lbl)

        # TODO: merge duplicate code with CGen
        codegen = self.llvm_context.cgen_class(self.llvm_context.lifter)
        irblocks_list = codegen.block2assignblks(asmblock)
        instr_offsets = [line.offset for line in asmblock.lines]

        # Prepare for delayslot
        if self.llvm_context.has_delayslot:
            for element in (codegen.delay_slot_dst, codegen.delay_slot_set):
                eltype = LLVMType.IntType(element.size)
                ptr = self.CreateEntryBlockAlloca(
                    eltype,
                    default_value=eltype(0)
                )
                self.local_vars_pointers[element.name] = ptr
            loc_key = codegen.get_block_post_label(asmblock)
            offset = self.llvm_context.lifter.loc_db.get_location_offset(loc_key)
            instr_offsets.append(offset)
            self.append_basic_block(loc_key)

        # Add content
        builder.position_at_end(entry_bbl)


        for instr, irblocks in zip(asmblock.lines, irblocks_list):
            instr_attrib, irblocks_attributes = codegen.get_attributes(
                instr,
                irblocks,
                self.log_mn,
                self.log_regs
            )

            # Pre-create basic blocks
            for irblock in irblocks:
                self.append_basic_block(irblock.loc_key, overwrite=False)

            # Generate the corresponding code
            for index, irblock in enumerate(irblocks):
                new_irblock = self.llvm_context.lifter.irbloc_fix_regs_for_mode(
                    irblock, self.llvm_context.lifter.attrib)

                # Set the builder at the beginning of the correct bbl
                self.builder.position_at_end(self.get_basic_block_by_loc_key(new_irblock.loc_key))

                if index == 0:
                    self.gen_pre_code(instr_attrib)
                self.gen_irblock(instr_attrib, irblocks_attributes[index], instr_offsets, new_irblock)

        # Gen finalize (see codegen::CGen) is unrecheable, except with delayslot
        self.gen_finalize(asmblock, codegen)

        # Branch entry_bbl on first label
        builder.position_at_end(entry_bbl)
        first_label_bbl = self.get_basic_block_by_loc_key(asmblock.loc_key)
        builder.branch(first_label_bbl)


    # LLVMFunction manipulation

    def __str__(self):
        "Print the llvm IR corresponding to the current module"
        return str(self.mod)

    def dot(self):
        "Return the CFG of the current function"
        return llvm.get_function_cfg(self.fc)

    def as_llvm_mod(self):
        """Return a ModuleRef standing for the current function"""
        if self._llvm_mod is None:
            self._llvm_mod = llvm.parse_assembly(str(self.mod))
        return self._llvm_mod

    def verify(self):
        "Verify the module syntax"
        return self.as_llvm_mod().verify()

    def get_bytecode(self):
        "Return LLVM bitcode corresponding to the current module"
        return self.as_llvm_mod().as_bitcode()

    def get_assembly(self):
        "Return native assembly corresponding to the current module"
        return self.llvm_context.target_machine.emit_assembly(self.as_llvm_mod())

    def optimise(self):
        "Optimise the function in place"
        return self.llvm_context.pass_manager.run(self.as_llvm_mod())

    def __call__(self, *args):
        "Eval the function with arguments args"

        e = self.llvm_context.get_execengine()

        genargs = [LLVMType.generic(a) for a in args]
        ret = e.run_function(self.fc, genargs)

        return ret.as_int()

    def get_function_pointer(self):
        "Return a pointer on the Jitted function"
        engine = self.llvm_context.get_execengine()

        # Add the module and make sure it is ready for execution
        engine.add_module(self.as_llvm_mod())
        engine.finalize_object()

        return engine.get_function_address(self.fc.name)


class LLVMFunction_IRCompilation(LLVMFunction):
    """LLVMFunction made for IR export, in conjunction with
    LLVMContext_IRCompilation.

    This class offers only the basics, and decision must be made by the class
    user on how actual registers, ABI, etc. are reflected


    Example of use:
    >>> context = LLVMContext_IRCompilation()
    >>> context.lifter = lifter
    >>>
    >>> func = LLVMFunction_IRCompilation(context, name="test")
    >>> func.ret_type = llvm_ir.VoidType()
    >>> func.init_fc()
    >>>
    >>> # Insert here function additional inits
    >>> XX = func.builder.alloca(...)
    >>> func.local_vars_pointers["EAX"] = XX
    >>> #
    >>>
    >>> func.from_ircfg(ircfg)
    """

    def init_fc(self):
        super(LLVMFunction_IRCompilation, self).init_fc()

        # Create a global IRDst if not any
        IRDst = self.llvm_context.lifter.IRDst
        if str(IRDst) not in self.mod.globals:
            llvm_ir.GlobalVariable(self.mod, LLVMType.IntType(IRDst.size),
                                   name=str(IRDst))

        # Create an 'exit' basic block, the final leave
        self.exit_bbl = self.append_basic_block("exit")

    def gen_jump2dst(self, _attrib, _instr_offsets, dst):
        self.main_stream = False

        if isinstance(dst, Expr):
            if dst.is_int():
                loc = self.llvm_context.lifter.loc_db.getby_offset_create(int(dst))
                dst = ExprLoc(loc, dst.size)
            assert dst.is_loc()
            bbl = self.get_basic_block_by_loc_key(dst.loc_key)
            if bbl is not None:
                # "local" jump, inside this function
                self.builder.branch(bbl)
                return

            # extern jump
            dst = self.add_ir(dst)

        # Emulate indirect jump with:
        #   @IRDst = dst
        #   goto exit
        self.builder.store(dst, self.mod.get_global("IRDst"))
        self.builder.branch(self.exit_bbl)

    def gen_irblock(self, irblock):
        instr_attrib = Attributes()
        attributes = [Attributes() for _ in range(len(irblock.assignblks))]
        instr_offsets = None
        return super(LLVMFunction_IRCompilation, self).gen_irblock(
            instr_attrib, attributes, instr_offsets, irblock
        )

    def from_ircfg(self, ircfg, append_ret=True):
        # Create basic blocks
        for loc_key, irblock in viewitems(ircfg.blocks):
            self.append_basic_block(loc_key)

        # Add IRBlocks
        for label, irblock in viewitems(ircfg.blocks):
            self.builder.position_at_end(self.get_basic_block_by_loc_key(label))
            self.gen_irblock(irblock)

        # Branch the entry BBL on the IRCFG head
        self.builder.position_at_end(self.entry_bbl)
        heads = ircfg.heads()
        assert len(heads) == 1
        starting_label = list(heads).pop()
        self.builder.branch(self.get_basic_block_by_loc_key(starting_label))

        # Returns with the builder on the exit block
        self.builder.position_at_end(self.exit_bbl)

        if append_ret:
            self.builder.ret_void()
