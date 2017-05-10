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

import os
from llvmlite import binding as llvm
from llvmlite import ir as llvm_ir
import miasm2.expression.expression as m2_expr
import miasm2.jitter.csts as m2_csts
import miasm2.core.asmblock as m2_asmblock
from miasm2.jitter.codegen import CGen
from miasm2.expression.expression_helper import possible_values


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
        if isinstance(e, m2_expr.ExprInt):
            return llvm_e.GenericValue.int(LLVMType.IntType(e.size), int(e.arg))
        elif isinstance(e, llvm_e.GenericValue):
            return e
        else:
            raise ValueError()


class LLVMContext():

    "Context for llvm binding. Stand for a LLVM Module"

    known_fc = {}

    def __init__(self, name="mod"):
        "Initialize a context with a module named 'name'"
        # Initialize llvm
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

        # Initilize target for compilation
        target = llvm.Target.from_default_triple()
        self.target_machine = target.create_target_machine()
        self.init_exec_engine()

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

    def add_fc(self, fc):
        "Add function into known_fc"

        for name, detail in fc.iteritems():
            fnty = llvm_ir.FunctionType(detail["ret"], detail["args"])
            llvm_ir.Function(self.mod, fnty, name=name)

    def memory_lookup(self, func, addr, size):
        """Perform a memory lookup at @addr of size @size (in bit)"""
        raise NotImplementedError("Abstract method")

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        raise NotImplementedError("Abstract method")


class LLVMContext_JIT(LLVMContext):

    """Extend LLVMContext_JIT in order to handle memory management and custom
    operations"""

    def __init__(self, library_filenames, ir_arch, name="mod"):
        "Init a LLVMContext object, and load the mem management shared library"
        self.library_filenames = library_filenames
        self.ir_arch = ir_arch
        self.arch_specific()
        LLVMContext.__init__(self, name)
        self.vmcpu = {}

    def new_module(self, name="mod"):
        LLVMContext.new_module(self, name)
        for lib_fname in self.library_filenames:
            self.add_shared_library(lib_fname)
        self.add_memlookups()
        self.add_get_exceptionflag()
        self.add_op()
        self.add_log_functions()

    def arch_specific(self):
        arch = self.ir_arch.arch
        if arch.name == "x86":
            self.PC = arch.regs.RIP
            self.logging_func = "dump_gpregs_%d" % self.ir_arch.attrib
        else:
            self.PC = self.ir_arch.pc
            self.logging_func = "dump_gpregs"
        if arch.name == "mips32":
            from miasm2.arch.mips32.jit import mipsCGen
            self.cgen_class = mipsCGen
            self.has_delayslot = True
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
                                            "args": [p8]}})

    def add_op(self):
        "Add operations functions"

        i8 = LLVMType.IntType(8)
        p8 = llvm_ir.PointerType(i8)
        itype = LLVMType.IntType(64)
        self.add_fc({"llvm.ctpop.i8": {"ret": i8,
                                       "args": [i8]}})
        self.add_fc({"rot_left": {"ret": itype,
                                  "args": [itype,
                                           itype,
                                           itype]}})
        self.add_fc({"rot_right": {"ret": itype,
                                   "args": [itype,
                                            itype,
                                            itype]}})
        self.add_fc({"rcr_rez_op": {"ret": itype,
                                    "args": [itype,
                                             itype,
                                             itype,
                                             itype]}})
        self.add_fc({"rcl_rez_op": {"ret": itype,
                                    "args": [itype,
                                             itype,
                                             itype,
                                             itype]}})
        self.add_fc({"x86_bsr": {"ret": itype,
                                 "args": [itype,
                                          itype]}})
        self.add_fc({"x86_bsf": {"ret": itype,
                                 "args": [itype,
                                          itype]}})
        self.add_fc({"segm2addr": {"ret": itype,
                                   "args": [p8,
                                            itype,
                                            itype]}})
        self.add_fc({"cpuid": {"ret": itype,
                               "args": [itype,
                                        itype]}})

        for k in [8, 16]:
            self.add_fc({"bcdadd_%s" % k: {"ret": LLVMType.IntType(k),
                                           "args": [LLVMType.IntType(k),
                                                    LLVMType.IntType(k)]}})
            self.add_fc({"bcdadd_cf_%s" % k: {"ret": LLVMType.IntType(k),
                                              "args": [LLVMType.IntType(k),
                                                       LLVMType.IntType(k)]}})

        for k in [16, 32, 64]:
            self.add_fc({"imod%s" % k: {"ret": LLVMType.IntType(k),
                                        "args": [p8,
                                                 LLVMType.IntType(k),
                                                 LLVMType.IntType(k)]}})
            self.add_fc({"idiv%s" % k: {"ret": LLVMType.IntType(k),
                                        "args": [p8,
                                                 LLVMType.IntType(k),
                                                 LLVMType.IntType(k)]}})
            self.add_fc({"umod%s" % k: {"ret": LLVMType.IntType(k),
                                        "args": [p8,
                                                 LLVMType.IntType(k),
                                                 LLVMType.IntType(k)]}})
            self.add_fc({"udiv%s" % k: {"ret": LLVMType.IntType(k),
                                        "args": [p8,
                                                 LLVMType.IntType(k),
                                                 LLVMType.IntType(k)]}})

    def add_log_functions(self):
        "Add functions for state logging"

        p8 = llvm_ir.PointerType(LLVMType.IntType(8))
        self.add_fc({self.logging_func: {"ret": llvm_ir.VoidType(),
                                         "args": [p8]}})

    def set_vmcpu(self, lookup_table):
        "Set the correspondance between register name and vmcpu offset"

        self.vmcpu = lookup_table

    def memory_lookup(self, func, addr, size):
        """Perform a memory lookup at @addr of size @size (in bit)"""
        builder = func.builder
        fc_name = "MEM_LOOKUP_%02d" % size
        fc_ptr = self.mod.get_global(fc_name)
        addr_casted = builder.zext(addr,
                                   LLVMType.IntType(64))

        ret = builder.call(fc_ptr, [func.local_vars["jitcpu"],
                                    addr_casted])
        return ret

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        # Function call
        builder = func.builder
        fc_name = "MEM_WRITE_%02d" % size
        fc_ptr = self.mod.get_global(fc_name)
        dst_casted = builder.zext(addr, LLVMType.IntType(64))
        builder.call(fc_ptr, [func.local_vars["jitcpu"],
                              dst_casted,
                              value])


    @staticmethod
    def cache_notify(module, buffer):
        """Called when @module has been compiled to @buffer"""
        if not hasattr(module, "fname_out"):
            return
        fname_out = module.fname_out

        if os.access(fname_out, os.R_OK):
            # No need to overwrite
            return

        open(fname_out, "w").write(buffer)

    @staticmethod
    def cache_getbuffer(module):
        """Return a compiled buffer for @module if available"""
        if not hasattr(module, "fname_out"):
            return None

        fname_out = module.fname_out
        if os.access(fname_out, os.R_OK):
            return open(fname_out).read()
        return None

    def enable_cache(self):
        "Enable cache of compiled object"
        # Load shared libraries
        for lib_fname in self.library_filenames:
            self.add_shared_library(lib_fname)

        # Activate cache
        self.exec_engine.set_object_cache(self.cache_notify,
                                          self.cache_getbuffer)

    def set_cache_filename(self, func, fname_out):
        "Set the filename @fname_out to use for cache for @func"
        # Use a custom attribute to propagate the cache filename
        func.as_llvm_mod().fname_out = fname_out

    def get_ptr_from_cache(self, file_name, func_name):
        "Load @file_name and return a pointer on the jitter @func_name"
        # We use an empty module to avoid loosing time on function building
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
        ptr_casted = builder.inttoptr(addr,
                                      llvm_ir.PointerType(int_size))
        return builder.load(ptr_casted)

    def memory_write(self, func, addr, size, value):
        """Perform a memory write at @addr of size @size (in bit) with LLVM IR @value"""
        builder = func.builder
        int_size = LLVMType.IntType(size)
        ptr_casted = builder.inttoptr(addr,
                                      llvm_ir.PointerType(int_size))
        return builder.store(value, ptr_casted)


class LLVMFunction():
    """Represent a LLVM function

    Implementation note:
    A new module is created each time to avoid cumulative lag (if @new_module)
    """

    # Default logging values
    log_mn = False
    log_regs = True

    # Operation translation
    ## Basics
    op_translate = {'cpuid': 'cpuid',
    }
    ## Add the size as first argument
    op_translate_with_size = {'<<<': 'rot_left',
                              '>>>': 'rot_right',
                              '<<<c_rez': 'rcl_rez_op',
                              '>>>c_rez': 'rcr_rez_op',
                              'bsr': 'x86_bsr',
                              'bsf': 'x86_bsf',
    }
    ## Add the size as suffix
    op_translate_with_suffix_size = {'bcdadd': 'bcdadd',
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
        name = self.canonize_label_name(label)
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
        ptr = builder.gep(self.local_vars["vmcpu"],
                          [llvm_ir.Constant(LLVMType.IntType(),
                                            offset)])
        regs = self.llvm_context.ir_arch.arch.regs
        if hasattr(regs, "float_list") and expr in regs.float_list:
            pointee_type = llvm_ir.DoubleType()
        else:
            pointee_type = LLVMType.IntType(expr.size)
        ptr_casted = builder.bitcast(ptr,
                                     llvm_ir.PointerType(pointee_type))
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

    @staticmethod
    def canonize_label_name(label):
        """Canonize @label names to a common form.
        @label: str or asmlabel instance"""
        if isinstance(label, str):
            return label
        if m2_asmblock.expr_is_label(label):
            label = label.name
        if isinstance(label, m2_asmblock.AsmLabel):
            if label.offset is None:
                return "label_%s" % label.name
            else:
                return "label_%X" % label.offset
        else:
            raise ValueError("label must either be str or asmlabel")

    def get_basic_bloc_by_label(self, label):
        "Return the bbl corresponding to label, None otherwise"
        return self.name2bbl.get(self.canonize_label_name(label), None)

    def global_constant(self, name, value):
        """
        Inspired from numba/cgutils.py

        Get or create a (LLVM module-)global constant with *name* or *value*.
        """
        module = self.mod
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
        while self.mod.get_global("%s_%d" % (base_name, count)):
            count += 1
        global_fmt = self.global_constant("%s_%d" % (base_name, count),
                                          fmt_bytes)
        fnty = llvm_ir.FunctionType(llvm_ir.IntType(32), [cstring],
                                    var_arg=True)
        # Insert printf()
        fn = mod.get_global('printf')
        if fn is None:
            fn = llvm_ir.Function(mod, fnty, name="printf")
        # Call
        ptr_fmt = self.builder.bitcast(global_fmt, cstring)
        return self.builder.call(fn, [ptr_fmt] + list(args))

    # Effective constructors

    def affect(self, src, dst):
        "Affect from LLVM src to M2 dst"

        # Destination
        builder = self.builder

        if isinstance(dst, m2_expr.ExprId):
            ptr_casted = self.get_ptr_by_expr(dst)
            builder.store(src, ptr_casted)

        elif isinstance(dst, m2_expr.ExprMem):
            addr = self.add_ir(dst.arg)
            self.llvm_context.memory_write(self, addr, dst.size, src)
        else:
            raise Exception("UnknownAffectationType")

    def init_fc(self):
        "Init the function"

        # Build type for fc signature
        fc_type = llvm_ir.FunctionType(self.ret_type, [k[1] for k in self.my_args])

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

        if isinstance(expr, m2_expr.ExprInt):
            ret = llvm_ir.Constant(LLVMType.IntType(expr.size), int(expr.arg))
            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprId):
            name = expr.name
            if not isinstance(name, str):
                # Resolve label
                offset = name.offset
                ret = llvm_ir.Constant(LLVMType.IntType(expr.size), offset)
                self.update_cache(expr, ret)
                return ret

            try:
                # If expr.name is already known (args)
                return self.local_vars[name]
            except KeyError:
                pass

            ptr_casted = self.get_ptr_by_expr(expr)

            var = builder.load(ptr_casted, name)
            self.update_cache(expr, var)
            return var

        if isinstance(expr, m2_expr.ExprOp):
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
                        casted_args.append(builder.zext(arg, fc_ptr.args[i].type))
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
                bitcount = builder.call(self.mod.get_global("llvm.ctpop.i8"),
                                        [truncated])
                ret = builder.not_(builder.trunc(bitcount, LLVMType.IntType(1)))
                self.update_cache(expr, ret)
                return ret

            if op == "segm":
                fc_ptr = self.mod.get_global("segm2addr")

                # Cast args if needed
                args = [self.add_ir(arg) for arg in expr.args]
                casted_args = []
                for i, arg in enumerate(args, 1):
                    if arg.type.width < fc_ptr.args[i].type.width:
                        casted_args.append(builder.zext(arg, fc_ptr.args[i].type))
                    else:
                        casted_args.append(arg)

                ret = builder.call(fc_ptr,
                                   [self.local_vars["jitcpu"]] + casted_args)
                if ret.type.width > expr.size:
                    ret = builder.trunc(ret, LLVMType.IntType(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["imod", "idiv", "umod", "udiv"]:
                fc_ptr = self.mod.get_global(
                    "%s%s" % (op, expr.args[0].size))
                args_casted = [self.add_ir(arg) for arg in expr.args]
                args = [self.local_vars["vmcpu"]] + args_casted
                ret = builder.call(fc_ptr, args)
                self.update_cache(expr, ret)
                return ret

            if op in [">>", "<<", "a>>"]:
                assert len(expr.args) == 2
                # Undefined behavior must be enforced to 0
                count = self.add_ir(expr.args[1])
                value = self.add_ir(expr.args[0])
                itype = LLVMType.IntType(expr.size)
                cond_ok = self.builder.icmp_unsigned("<", count,
                                                     itype(expr.size))
                if op == ">>":
                    callback = builder.lshr
                elif op == "<<":
                    callback = builder.shl
                elif op == "a>>":
                    callback = builder.ashr

                ret = self.builder.select(cond_ok, callback(value, count),
                                          itype(0))
                self.update_cache(expr, ret)
                return ret

            if op in ["int_16_to_double", "int_32_to_double", "int_64_to_double",
                      "mem_16_to_double", "mem_32_to_double", "mem_64_to_double"]:
                arg = self.add_ir(expr.args[0])
                ret = builder.uitofp(arg, llvm_ir.DoubleType())
                self.update_cache(expr, ret)
                return ret

            if op in ["double_to_int_16", "double_to_int_32", "double_to_int_64",
                      "double_to_mem_16", "double_to_mem_32", "double_to_mem_64"]:
                arg = self.add_ir(expr.args[0])
                ret = builder.fptoui(arg, llvm_ir.IntType(expr.size))
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
                elif op == "fadd":
                    callback = builder.fadd
                elif op == "fdiv":
                    callback = builder.fdiv
                else:
                    raise NotImplementedError('Unknown op: %s' % op)

                last = self.add_ir(expr.args[0])

                for i in range(1, len(expr.args)):
                    last = callback(last,
                                    self.add_ir(expr.args[i]))

                self.update_cache(expr, last)

                return last

            raise NotImplementedError()

        if isinstance(expr, m2_expr.ExprMem):

            addr = self.add_ir(expr.arg)
            return self.llvm_context.memory_lookup(self, addr, expr.size)

        if isinstance(expr, m2_expr.ExprCond):
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

        if isinstance(expr, m2_expr.ExprSlice):

            src = self.add_ir(expr.arg)

            # Remove trailing bits
            if expr.start != 0:
                to_shr = llvm_ir.Constant(LLVMType.IntType(expr.arg.size),
                                          expr.start)
                shred = builder.lshr(src,
                                     to_shr)
            else:
                shred = src

            # Remove leading bits
            to_and = llvm_ir.Constant(LLVMType.IntType(expr.arg.size),
                                      (1 << (expr.stop - expr.start)) - 1)
            anded = builder.and_(shred,
                                 to_and)

            # Cast into e.size
            ret = builder.trunc(anded,
                                LLVMType.IntType(expr.size))

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprCompose):

            args = []

            # Build each part
            for start, src in expr.iter_args():
                # src & size
                src = self.add_ir(src)
                src_casted = builder.zext(src,
                                          LLVMType.IntType(expr.size))
                to_and = llvm_ir.Constant(LLVMType.IntType(expr.size),
                                          (1 << src.type.width) - 1)
                anded = builder.and_(src_casted,
                                     to_and)

                if (start != 0):
                    # result << start
                    to_shl = llvm_ir.Constant(LLVMType.IntType(expr.size),
                                              start)
                    shled = builder.shl(anded, to_shl)
                    final = shled
                else:
                    # Optimisation
                    final = anded

                args.append(final)

            # result = part1 | part2 | ...
            last = args[0]
            for i in xrange(1, len(expr.args)):
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
        condition_bool = builder.icmp_unsigned("!=",
                                               exceptionflag,
                                               zero_casted)

        # Create bbls
        branch_id = self.new_branch_name()
        then_block = self.append_basic_block('then%s' % branch_id)
        merge_block = self.append_basic_block('ifcond%s' % branch_id)

        builder.cbranch(condition_bool, then_block, merge_block)

        # Deactivate object caching
        current_main_stream = self.main_stream
        self.main_stream = False

        # Then Bloc
        builder.position_at_end(then_block)
        PC = self.llvm_context.PC
        if isinstance(offset, (int, long)):
            offset = self.add_ir(m2_expr.ExprInt(offset, PC.size))
        self.affect(offset, PC)
        self.affect(self.add_ir(m2_expr.ExprInt(1, 8)), m2_expr.ExprId("status"))
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
        m2_exception_flag = self.llvm_context.ir_arch.arch.regs.exception_flags
        t_size = LLVMType.IntType(m2_exception_flag.size)
        exceptionflag = self.add_ir(m2_exception_flag)

        # Compute cond
        if restricted_exception is True:
            flag = m2_csts.EXCEPT_NUM_UPDT_EIP
            condition_bool = builder.icmp_unsigned(">", exceptionflag,
                                                   llvm_ir.Constant(t_size, flag))
        else:
            zero_casted = llvm_ir.Constant(t_size, 0)
            condition_bool = builder.icmp_unsigned("!=",
                                                   exceptionflag,
                                                   zero_casted)

        # Create bbls
        branch_id = self.new_branch_name()
        then_block = self.append_basic_block('then%s' % branch_id)
        merge_block = self.append_basic_block('ifcond%s' % branch_id)

        builder.cbranch(condition_bool, then_block, merge_block)

        # Deactivate object caching
        current_main_stream = self.main_stream
        self.main_stream = False

        # Then Bloc
        builder.position_at_end(then_block)
        PC = self.llvm_context.PC
        if isinstance(offset, (int, long)):
            offset = self.add_ir(m2_expr.ExprInt(offset, PC.size))
        self.affect(offset, PC)
        self.affect(self.add_ir(m2_expr.ExprInt(1, 8)), m2_expr.ExprId("status"))
        self.set_ret(offset)

        builder.position_at_end(merge_block)
        # Reactivate object caching
        self.main_stream = current_main_stream

    def gen_pre_code(self, instr_attrib):
        if instr_attrib.log_mn:
            self.printf("%.8X %s\n" % (instr_attrib.instr.offset,
                                       instr_attrib.instr))

    def gen_post_code(self, attributes):
        if attributes.log_regs:
            fc_ptr = self.mod.get_global(self.llvm_context.logging_func)
            self.builder.call(fc_ptr, [self.local_vars["vmcpu"]])

    def gen_post_instr_checks(self, attrib, next_instr):
        if attrib.mem_read | attrib.mem_write:
            fc_ptr = self.mod.get_global("check_memory_breakpoint")
            self.builder.call(fc_ptr, [self.local_vars["vmmngr"]])
            fc_ptr = self.mod.get_global("check_invalid_code_blocs")
            self.builder.call(fc_ptr, [self.local_vars["vmmngr"]])
            self.check_memory_exception(next_instr, restricted_exception=False)
        if attrib.set_exception or attrib.op_set_exception:
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
            to_eval = to_eval.replace_expr({value: m2_expr.ExprInt(index, value.size)})
            dst2case[value] = index
            if m2_asmblock.expr_is_int_or_label(value):
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

        if isinstance(dst, m2_expr.ExprInt):
            dst = m2_expr.ExprId(self.llvm_context.ir_arch.symbol_pool.getby_offset_create(int(dst)),
                                 dst.size)

        if m2_asmblock.expr_is_label(dst):
            bbl = self.get_basic_bloc_by_label(dst)
            offset = dst.name.offset
            if bbl is not None:
                # "local" jump, inside this function
                if offset is None:
                    # Avoid checks on generated label
                    self.builder.branch(bbl)
                    return

                if (offset in instr_offsets and
                    offset > attrib.instr.offset):
                    # forward local jump (ie. next instruction)
                    self.gen_post_code(attrib)
                    self.gen_post_instr_checks(attrib, offset)
                    self.builder.branch(bbl)
                    return

                # reaching this point means a backward local jump, promote it to
                # extern

            # "extern" jump on a defined offset, return to the caller
            dst = self.add_ir(m2_expr.ExprInt(offset, PC.size))

        # "extern" jump with a computed value, return to the caller
        assert isinstance(dst, (llvm_ir.Instruction, llvm_ir.Value))
        # Cast @dst, if needed
        # for instance, x86_32: IRDst is 32 bits, so is @dst; PC is 64 bits
        if dst.type.width != PC.size:
            dst = self.builder.zext(dst, LLVMType.IntType(PC.size))

        self.gen_post_code(attrib)
        self.affect(dst, PC)
        self.gen_post_instr_checks(attrib, dst)
        self.affect(self.add_ir(m2_expr.ExprInt(0, 8)), m2_expr.ExprId("status"))
        self.set_ret(dst)


    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """
        Generate the code for an @irblock
        @instr_attrib: an Attributs instance or the instruction to translate
        @attributes: list of Attributs corresponding to irblock assignments
        @instr_offsets: offset of all asmblock's instructions
        @irblock: an irblock instance
        """

        case2dst = None
        case_value = None
        instr = instr_attrib.instr

        for index, assignblk in enumerate(irblock.irs):
            # Enable cache
            self.main_stream = True
            self.expr_cache = {}

            # Prefetch memory
            for element in assignblk.get_r(mem_read=True):
                if isinstance(element, m2_expr.ExprMem):
                    self.add_ir(element)

            # Evaluate expressions
            values = {}
            for dst, src in assignblk.iteritems():
                if dst == self.llvm_context.ir_arch.IRDst:
                    case2dst, case_value = self.expr2cases(src)
                else:
                    values[dst] = self.add_ir(src)

            # Check memory access exception
            if attributes[index].mem_read:
                self.check_memory_exception(instr.offset,
                                            restricted_exception=True)

            # Check operation exception
            if attributes[index].op_set_exception:
                self.check_cpu_exception(instr.offset, restricted_exception=True)

            # Update the memory
            for dst, src in values.iteritems():
                if isinstance(dst, m2_expr.ExprMem):
                    self.affect(src, dst)

            # Check memory write exception
            if attributes[index].mem_write:
                self.check_memory_exception(instr.offset,
                                            restricted_exception=True)

            # Update registers values
            for dst, src in values.iteritems():
                if not isinstance(dst, m2_expr.ExprMem):
                    self.affect(src, dst)

            # Check post assignblk exception flags
            if attributes[index].set_exception:
                self.check_cpu_exception(instr.offset, restricted_exception=True)

        # Destination
        assert case2dst is not None
        if len(case2dst) == 1:
            # Avoid switch in this common case
            self.gen_jump2dst(instr_attrib, instr_offsets, case2dst.values()[0])
        else:
            current_bbl = self.builder.basic_block

            # Gen the out cases
            branch_id = self.new_branch_name()
            case2bbl = {}
            for case, dst in case2dst.iteritems():
                name = "switch_%s_%d" % (branch_id, case)
                bbl = self.append_basic_block(name)
                case2bbl[case] = bbl
                self.builder.position_at_start(bbl)
                self.gen_jump2dst(instr_attrib, instr_offsets, dst)

            # Jump on the correct output
            self.builder.position_at_end(current_bbl)
            switch = self.builder.switch(case_value, case2bbl[0])
            for i, bbl in case2bbl.iteritems():
                if i == 0:
                    # Default case is case 0, arbitrary
                    continue
                switch.add_case(i, bbl)

    def gen_bad_block(self, asmblock):
        """
        Translate an asm_bad_block into a CPU exception
        """
        builder = self.builder
        m2_exception_flag = self.llvm_context.ir_arch.arch.regs.exception_flags
        t_size = LLVMType.IntType(m2_exception_flag.size)
        self.affect(self.add_ir(m2_expr.ExprInt(1, 8)),
                    m2_expr.ExprId("status"))
        self.affect(t_size(m2_csts.EXCEPT_UNK_MNEMO),
                    m2_exception_flag)
        self.set_ret(LLVMType.IntType(64)(asmblock.label.offset))

    def gen_finalize(self, asmblock, codegen):
        """
        In case of delayslot, generate a dummy BBL which return on the computed IRDst
        or on next_label
        """
        if self.llvm_context.has_delayslot:
            next_label = codegen.get_block_post_label(asmblock)
            builder = self.builder

            builder.position_at_end(self.get_basic_bloc_by_label(next_label))

            # Common code
            self.affect(self.add_ir(m2_expr.ExprInt(0, 8)),
                        m2_expr.ExprId("status"))

            # Check if IRDst has been set
            zero_casted = LLVMType.IntType(codegen.delay_slot_set.size)(0)
            condition_bool = builder.icmp_unsigned("!=",
                                                   self.add_ir(codegen.delay_slot_set),
                                                   zero_casted)

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
            self.affect(to_ret, PC)
            self.affect(self.add_ir(m2_expr.ExprInt(0, 8)),
                        m2_expr.ExprId("status"))
            self.set_ret(to_ret)

            # Else Block
            builder.position_at_end(else_block)
            PC = self.llvm_context.PC
            to_ret = LLVMType.IntType(PC.size)(next_label.offset)
            self.affect(to_ret, PC)
            self.set_ret(to_ret)

    def from_asmblock(self, asmblock):
        """Build the function from an asmblock (asm_block instance).
        Prototype : f(i8* jitcpu, i8* vmcpu, i8* vmmngr, i8* status)"""

        # Build function signature
        self.my_args.append((m2_expr.ExprId("jitcpu"),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "jitcpu"))
        self.my_args.append((m2_expr.ExprId("vmcpu"),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "vmcpu"))
        self.my_args.append((m2_expr.ExprId("vmmngr"),
                             llvm_ir.PointerType(LLVMType.IntType(8)),
                             "vmmngr"))
        self.my_args.append((m2_expr.ExprId("status"),
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

        # Create basic blocks (for label branchs)
        entry_bbl, builder = self.entry_bbl, self.builder
        for instr in asmblock.lines:
            lbl = self.llvm_context.ir_arch.symbol_pool.getby_offset_create(instr.offset)
            self.append_basic_block(lbl)

        # TODO: merge duplicate code with CGen
        codegen = self.llvm_context.cgen_class(self.llvm_context.ir_arch)
        irblocks_list = codegen.block2assignblks(asmblock)
        instr_offsets = [line.offset for line in asmblock.lines]

        # Prepare for delayslot
        if self.llvm_context.has_delayslot:
            for element in (codegen.delay_slot_dst, codegen.delay_slot_set):
                eltype = LLVMType.IntType(element.size)
                ptr = self.CreateEntryBlockAlloca(eltype,
                                                  default_value=eltype(0))
                self.local_vars_pointers[element.name] = ptr
            lbl = codegen.get_block_post_label(asmblock)
            instr_offsets.append(lbl.offset)
            self.append_basic_block(lbl)

        # Add content
        builder.position_at_end(entry_bbl)


        for instr, irblocks in zip(asmblock.lines, irblocks_list):
            instr_attrib, irblocks_attributes = codegen.get_attributes(instr, irblocks, self.log_mn,
                                                                       self.log_regs)

            # Pre-create basic blocks
            for irblock in irblocks:
                self.append_basic_block(irblock.label, overwrite=False)

            # Generate the corresponding code
            for index, irblock in enumerate(irblocks):
                self.llvm_context.ir_arch.irbloc_fix_regs_for_mode(
                    irblock, self.llvm_context.ir_arch.attrib)

                # Set the builder at the begining of the correct bbl
                name = self.canonize_label_name(irblock.label)
                self.builder.position_at_end(self.get_basic_bloc_by_label(name))

                if index == 0:
                    self.gen_pre_code(instr_attrib)
                self.gen_irblock(instr_attrib, irblocks_attributes[index], instr_offsets, irblock)

        # Gen finalize (see codegen::CGen) is unrecheable, except with delayslot
        self.gen_finalize(asmblock, codegen)

        # Branch entry_bbl on first label
        builder.position_at_end(entry_bbl)
        first_label_bbl = self.get_basic_bloc_by_label(asmblock.label)
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
