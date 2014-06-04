#
#
# Miasm2 Extension:                                                            #
# - Miasm2 IR to LLVM IR                                                       #
# - JiT                                                                        #
#
# Requires:                                                                    #
# - llvmpy (tested on v0.11.2)                                                 #
#
# Authors : Fabrice DESCLAUX (CEA/DAM), Camille MOUGEY (CEA/DAM)               #
#
#

import llvm
import llvm.core as llvm_c
import llvm.ee as llvm_e
import llvm.passes as llvm_p
import miasm2.expression.expression as m2_expr
import miasm2.jitter.csts as m2_csts
import miasm2.core.asmbloc as m2_asmbloc


class LLVMType(llvm_c.Type):

    "Handle LLVM Type"

    int_cache = {}

    @classmethod
    def int(cls, size=32):
        try:
            return cls.int_cache[size]
        except KeyError:
            cls.int_cache[size] = llvm_c.Type.int(size)
            return cls.int_cache[size]

    @classmethod
    def pointer(cls, addr):
        "Generic pointer for execution"
        return llvm_e.GenericValue.pointer(addr)

    @classmethod
    def generic(cls, e):
        "Generic value for execution"
        if isinstance(e, m2_expr.ExprInt):
            return llvm_e.GenericValue.int(LLVMType.int(e.size), int(e.arg))
        elif isinstance(e, llvm_e.GenericValue):
            return e
        else:
            raise ValueError()


class LLVMContext():

    "Context for llvm binding. Stand for a LLVM Module"

    known_fc = {}

    def __init__(self, name="mod"):
        "Initialize a context with a module named 'name'"
        self.mod = llvm_c.Module.new(name)
        self.pass_manager = llvm_p.FunctionPassManager.new(self.mod)
        self.exec_engine = llvm_e.ExecutionEngine.new(self.mod)
        self.add_fc(self.known_fc)

    def optimise_level(self, classic_passes=True, dead_passes=True):
        """Set the optimisation level :
        classic_passes :
         - combine instruction
         - reassociate
         - global value numbering
         - simplify cfg

        dead_passes :
         - dead code
         - dead store
         - dead instructions
        """

        # Set up the optimiser pipeline

        if classic_passes is True:
            # self.pass_manager.add(llvm_p.PASS_INSTCOMBINE)
            self.pass_manager.add(llvm_p.PASS_REASSOCIATE)
            self.pass_manager.add(llvm_p.PASS_GVN)
            self.pass_manager.add(llvm_p.PASS_SIMPLIFYCFG)

        if dead_passes is True:
            self.pass_manager.add(llvm_p.PASS_DCE)
            self.pass_manager.add(llvm_p.PASS_DSE)
            self.pass_manager.add(llvm_p.PASS_DIE)

        self.pass_manager.initialize()

    def get_execengine(self):
        "Return the Execution Engine associated with this context"
        return self.exec_engine

    def get_passmanager(self):
        "Return the Pass Manager associated with this context"
        return self.exec_engine

    def get_module(self):
        "Return the module associated with this context"
        return self.mod

    def add_shared_library(self, filename):
        "Load the shared library 'filename'"
        return llvm_c.load_library_permanently(filename)

    def add_fc(self, fc):
        "Add function into known_fc"

        for name, detail in fc.items():
            self.mod.add_function(LLVMType.function(detail["ret"],
                                                    detail["args"]),
                                  name)


class LLVMContext_JIT(LLVMContext):

    "Extend LLVMContext_JIT in order to handle memory management"

    def __init__(self, library_filenames, name="mod"):
        "Init a LLVMContext object, and load the mem management shared library"
        LLVMContext.__init__(self, name)
        for lib_fname in library_filenames:
            self.add_shared_library(lib_fname)
        self.add_memlookups()
        self.add_get_exceptionflag()
        self.add_op()
        self.add_log_functions()
        self.vmcpu = {}

    def add_memlookups(self):
        "Add MEM_LOOKUP functions"

        fc = {}
        p8 = llvm_c.PointerType.pointer(LLVMType.int(8))
        for i in [8, 16, 32, 64]:
            fc["MEM_LOOKUP_%02d" % i] = {"ret": LLVMType.int(i),
                                         "args": [p8,
                                                  LLVMType.int(64)]}

            fc["MEM_WRITE_%02d" % i] = {"ret": LLVMType.void(),
                                        "args": [p8,
                                                 LLVMType.int(64),
                                                 LLVMType.int(i)]}

        self.add_fc(fc)

    def add_get_exceptionflag(self):
        "Add 'get_exception_flag' function"
        p8 = llvm_c.PointerType.pointer(LLVMType.int(8))
        self.add_fc({"get_exception_flag": {"ret": LLVMType.int(64),
                                            "args": [p8]}})

    def add_op(self):
        "Add operations functions"

        p8 = llvm_c.PointerType.pointer(LLVMType.int(8))
        self.add_fc({"parity": {"ret": LLVMType.int(),
                                "args": [LLVMType.int()]}})
        self.add_fc({"rot_left": {"ret": LLVMType.int(),
                                  "args": [LLVMType.int(),
                                           LLVMType.int(),
                                           LLVMType.int()]}})
        self.add_fc({"rot_right": {"ret": LLVMType.int(),
                                   "args": [LLVMType.int(),
                                            LLVMType.int(),
                                            LLVMType.int()]}})

        self.add_fc({"segm2addr": {"ret": LLVMType.int(64),
                                   "args": [p8,
                                            LLVMType.int(64),
                                            LLVMType.int(64)]}})

        for k in [8, 16]:
            self.add_fc({"bcdadd_%s" % k: {"ret": LLVMType.int(k),
                                           "args": [LLVMType.int(k),
                                                    LLVMType.int(k)]}})
            self.add_fc({"bcdadd_cf_%s" % k: {"ret": LLVMType.int(k),
                                              "args": [LLVMType.int(k),
                                                       LLVMType.int(k)]}})

        for k in [16, 32, 64]:
            self.add_fc({"imod%s" % k: {"ret": LLVMType.int(k),
                                        "args": [p8,
                                                 LLVMType.int(k),
                                                 LLVMType.int(k)]}})
            self.add_fc({"idiv%s" % k: {"ret": LLVMType.int(k),
                                        "args": [p8,
                                                 LLVMType.int(k),
                                                 LLVMType.int(k)]}})

    def add_log_functions(self):
        "Add functions for state logging"

        p8 = llvm_c.PointerType.pointer(LLVMType.int(8))
        self.add_fc({"dump_gpregs": {"ret": LLVMType.void(),
                                     "args": [p8]}})

    def set_vmcpu(self, lookup_table):
        "Set the correspondance between register name and vmcpu offset"

        self.vmcpu = lookup_table

    def set_IR_transformation(self, *args):
        """Set a list of transformation to apply on expression before their
        treatments.
        args: function Expr(Expr)"""
        self.IR_transformation_functions = args


class LLVMFunction():

    "Represent a llvm function"

    # Default logging values
    log_mn = False
    log_regs = False

    def __init__(self, llvm_context, name="fc"):
        "Create a new function with name fc"
        self.llvm_context = llvm_context
        self.mod = self.llvm_context.get_module()

        self.my_args = []  # (Expr, LLVMType, Name)
        self.ret_type = None
        self.builder = None
        self.entry_bbl = None

        self.branch_counter = 0
        self.name = name

    def new_branch_name(self):
        "Return a new branch name"

        self.branch_counter += 1
        return "%s" % self.branch_counter

    def viewCFG(self):
        "Show the CFG of the current function"
        self.fc.viewCFG()

    def append_basic_block(self, label):
        """Add a new basic block to the current function.
        @label: str or asmlabel
        Return the corresponding LLVM Basic Block"""
        name = self.canonize_label_name(label)
        bbl = self.fc.append_basic_block(name)
        self.name2bbl[label] = bbl

        return bbl

    def init_fc(self):
        "Init the function"

        # Build type for fc signature
        fc_type = LLVMType.function(
            self.ret_type, [k[1] for k in self.my_args])

        # Add fc in module
        try:
            fc = self.mod.add_function(fc_type, self.name)
        except llvm.LLVMException:
            # Overwrite the previous function
            previous_fc = self.mod.get_function_named(self.name)
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
        self.offsets_jitted = set()

        # Function link
        self.fc = fc

        # Add a first BasicBlock
        self.entry_bbl = self.append_basic_block("entry")

        # Instruction builder
        self.builder = llvm_c.Builder.new(self.entry_bbl)

    def CreateEntryBlockAlloca(self, var_type):
        "Create an alloca instruction at the beginning of the current fc"
        builder = self.builder
        current_bbl = builder.basic_block
        builder.position_at_end(self.entry_bbl)

        ret = builder.alloca(var_type)
        builder.position_at_end(current_bbl)
        return ret

    def get_ptr_by_expr(self, expr):
        """"Return a pointer casted corresponding to ExprId expr. If it is not
        already computed, compute it at the end of entry_bloc"""

        name = expr.name

        try:
            # If the pointer has already been computed
            ptr_casted = self.local_vars_pointers[name]

        except KeyError:
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
                              [llvm_c.Constant.int(LLVMType.int(),
                                                   offset)])
            int_size = LLVMType.int(expr.size)
            ptr_casted = builder.bitcast(ptr,
                                         llvm_c.PointerType.pointer(int_size))
            # Store in cache
            self.local_vars_pointers[name] = ptr_casted

            # Reset builder
            builder.position_at_end(current_bbl)

        return ptr_casted

    def clear_cache(self, regs_updated):
        "Remove from the cache values which depends on regs_updated"

        regs_updated_set = set(regs_updated)

        for expr in self.expr_cache.keys():
            if expr.get_r(True).isdisjoint(regs_updated_set) is not True:
                self.expr_cache.pop(expr)

    def update_cache(self, name, value):
        "Add 'name' = 'value' to the cache iff main_stream = True"

        if self.main_stream is True:
            self.expr_cache[name] = value

    def add_ir(self, expr):
        "Add a Miasm2 IR to the last bbl. Return the var created"

        if self.main_stream is True and expr in self.expr_cache:
            return self.expr_cache[expr]

        builder = self.builder

        if isinstance(expr, m2_expr.ExprInt):
            ret = llvm_c.Constant.int(LLVMType.int(expr.size), int(expr.arg))
            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprId):
            name = expr.name
            if not isinstance(name, str):
                # Resolve label
                offset = name.offset
                ret = llvm_c.Constant.int(LLVMType.int(expr.size), offset)
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

            if op == "parity":
                fc_ptr = self.mod.get_function_named("parity")
                arg = builder.zext(self.add_ir(expr.args[0]),
                                   LLVMType.int())
                ret = builder.call(fc_ptr, [arg])
                ret = builder.trunc(ret, LLVMType.int(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["<<<", ">>>"]:
                fc_name = "rot_left" if op == "<<<" else "rot_right"
                fc_ptr = self.mod.get_function_named(fc_name)
                args = [self.add_ir(arg) for arg in expr.args]
                arg_size = expr.args[0].size
                if arg_size < 32:
                    # Cast args
                    args = [builder.zext(arg, LLVMType.int(32))
                            for arg in args]
                arg_size_cst = llvm_c.Constant.int(LLVMType.int(),
                                                   arg_size)
                ret = builder.call(fc_ptr, [arg_size_cst] + args)
                if arg_size < 32:
                    # Cast ret
                    ret = builder.trunc(ret, LLVMType.int(arg_size))
                self.update_cache(expr, ret)
                return ret

            if op == "bcdadd":
                size = expr.args[0].size
                fc_ptr = self.mod.get_function_named("bcdadd_%s" % size)
                args = [self.add_ir(arg) for arg in expr.args]
                ret = builder.call(fc_ptr, args)
                self.update_cache(expr, ret)
                return ret

            if op == "bcdadd_cf":
                size = expr.args[0].size
                fc_ptr = self.mod.get_function_named("bcdadd_cf_%s" % size)
                args = [self.add_ir(arg) for arg in expr.args]
                ret = builder.call(fc_ptr, args)
                ret = builder.trunc(ret, LLVMType.int(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op == "-":
                zero = llvm_c.Constant.int(LLVMType.int(expr.size),
                                           0)
                ret = builder.sub(zero, self.add_ir(expr.args[0]))
                self.update_cache(expr, ret)
                return ret

            if op == "segm":
                fc_ptr = self.mod.get_function_named("segm2addr")
                args_casted = [builder.zext(self.add_ir(arg), LLVMType.int(64))
                               for arg in expr.args]
                args = [self.local_vars["vmcpu"]] + args_casted
                ret = builder.call(fc_ptr, args)
                ret = builder.trunc(ret, LLVMType.int(expr.size))
                self.update_cache(expr, ret)
                return ret

            if op in ["imod", "idiv"]:
                fc_ptr = self.mod.get_function_named(
                    "%s%s" % (op, expr.args[0].size))
                args_casted = [self.add_ir(arg) for arg in expr.args]
                args = [self.local_vars["vmcpu"]] + args_casted
                ret = builder.call(fc_ptr, args)
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
                elif op == ">>":
                    callback = builder.lshr
                elif op == "<<":
                    callback = builder.shl
                elif op == "a>>":
                    callback = builder.ashr
                elif op == "udiv":
                    callback = builder.udiv
                elif op == "umod":
                    callback = builder.urem
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

            fc_name = "MEM_LOOKUP_%02d" % expr.size
            fc_ptr = self.mod.get_function_named(fc_name)
            addr_casted = builder.zext(self.add_ir(expr.arg),
                                       LLVMType.int(64))

            ret = builder.call(fc_ptr, [self.local_vars["vmmngr"],
                                        addr_casted])

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprCond):
            # Compute cond
            cond = self.add_ir(expr.cond)
            zero_casted = llvm_c.Constant.int(LLVMType.int(expr.cond.size),
                                              0)
            condition_bool = builder.icmp(llvm_c.ICMP_NE, cond,
                                          zero_casted)

            # Alloc return var
            alloca = self.CreateEntryBlockAlloca(LLVMType.int(expr.size))

            # Create bbls
            branch_id = self.new_branch_name()
            then_block = self.append_basic_block('then%s' % branch_id)
            else_block = self.append_basic_block('else%s' % branch_id)
            merge_block = self.append_basic_block('ifcond%s' % branch_id)

            builder.cbranch(condition_bool, then_block, else_block)

            # Deactivate object caching
            current_main_stream = self.main_stream
            self.main_stream = False

            # Then Bloc
            builder.position_at_end(then_block)
            then_value = self.add_ir(expr.src1)
            builder.store(then_value, alloca)
            builder.branch(merge_block)

            # Else Bloc
            builder.position_at_end(else_block)
            else_value = self.add_ir(expr.src2)
            builder.store(else_value, alloca)
            builder.branch(merge_block)

            # Merge bloc
            builder.position_at_end(merge_block)
            ret = builder.load(alloca)

            # Reactivate object caching
            self.main_stream = current_main_stream

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprSlice):

            src = self.add_ir(expr.arg)

            # Remove trailing bits
            if expr.start != 0:
                to_shr = llvm_c.Constant.int(LLVMType.int(expr.arg.size),
                                             expr.start)
                shred = builder.lshr(src,
                                     to_shr)
            else:
                shred = src

            # Remove leading bits
            to_and = llvm_c.Constant.int(LLVMType.int(expr.arg.size),
                                         (1 << (expr.stop - expr.start)) - 1)
            anded = builder.and_(shred,
                                 to_and)

            # Cast into e.size
            ret = builder.trunc(anded,
                                LLVMType.int(expr.size))

            self.update_cache(expr, ret)
            return ret

        if isinstance(expr, m2_expr.ExprCompose):

            args = []

            # Build each part
            for arg in expr.args:
                src, start, stop = arg

                # src & (stop - start)
                src = self.add_ir(src)
                src_casted = builder.zext(src,
                                          LLVMType.int(expr.size))
                to_and = llvm_c.Constant.int(LLVMType.int(expr.size),
                                             (1 << (stop - start)) - 1)
                anded = builder.and_(src_casted,
                                     to_and)

                if (start != 0):
                    # result << start
                    to_shl = llvm_c.Constant.int(LLVMType.int(expr.size),
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

    def set_ret(self, var):
        "Cast @var and return it at the end of current bbl"
        if var.type.width < 64:
            var_casted = self.builder.zext(var, LLVMType.int(64))
        else:
            var_casted = var
        self.builder.ret(var_casted)

    def from_expr(self, expr):
        "Build the function from an expression"

        # Build function signature
        args = expr.get_r(True)
        for a in args:
            if not isinstance(a, m2_expr.ExprMem):
                self.my_args.append((a, LLVMType.int(a.size), a.name))

        self.ret_type = LLVMType.int(expr.size)

        # Initialise the function
        self.init_fc()

        ret = self.add_ir(expr)

        self.set_ret(ret)

    def affect(self, src, dst, add_new=True):
        "Affect from M2 src to M2 dst. If add_new, add a suffix '_new' to dest"

        # Source
        src = self.add_ir(src)

        # Destination
        builder = self.builder
        self.add_ir(m2_expr.ExprId("vmcpu"))

        if isinstance(dst, m2_expr.ExprId):
            dst_name = dst.name + "_new" if add_new else dst.name

            ptr_casted = self.get_ptr_by_expr(
                m2_expr.ExprId(dst_name, dst.size))
            builder.store(src, ptr_casted)

        elif isinstance(dst, m2_expr.ExprMem):
            self.add_ir(dst.arg)

            # Function call
            fc_name = "MEM_WRITE_%02d" % dst.size
            fc_ptr = self.mod.get_function_named(fc_name)
            dst = self.add_ir(dst.arg)
            dst_casted = builder.zext(dst, LLVMType.int(64))
            builder.call(fc_ptr, [self.local_vars["vmmngr"],
                                  dst_casted,
                                  src])

        else:
            raise Exception("UnknownAffectationType")

    def check_error(self, line, except_do_not_update_pc=False):
        """Add a check for memory errors.
        @line: Irbloc line corresponding to the current instruction
        If except_do_not_update_pc, check only for exception which do not
        require a pc update"""

        # VmMngr "get_exception_flag" return's size
        size = 64
        t_size = LLVMType.int(size)

        # Current address
        pc_to_return = line.offset

        # Get exception flag value
        builder = self.builder
        fc_ptr = self.mod.get_function_named("get_exception_flag")
        exceptionflag = builder.call(fc_ptr, [self.local_vars["vmmngr"]])

        if except_do_not_update_pc is True:
            auto_mod_flag = m2_csts.EXCEPT_DO_NOT_UPDATE_PC
            m2_flag = llvm_c.Constant.int(t_size, auto_mod_flag)
            exceptionflag = builder.and_(exceptionflag, m2_flag)

        # Compute cond
        zero_casted = llvm_c.Constant.int(t_size, 0)
        condition_bool = builder.icmp(llvm_c.ICMP_NE,
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
        self.set_ret(llvm_c.Constant.int(self.ret_type, pc_to_return))

        builder.position_at_end(merge_block)

        # Reactivate object caching
        self.main_stream = current_main_stream

    def log_instruction(self, instruction, line):
        "Print current instruction and registers if options are set"

        # Get builder
        builder = self.builder

        if self.log_mn is True:
            print instruction # TODO

        if self.log_regs is True:
            # Call dump general purpose registers
            fc_ptr = self.mod.get_function_named("dump_gpregs")
            builder.call(fc_ptr, [self.local_vars["vmcpu"]])

    def add_bloc(self, bloc, lines):
        "Add a bloc of instruction in the current function"

        for instruction, line in zip(bloc, lines):
            new_reg = set()

            # Check general errors only at the beggining of instruction
            if line.offset not in self.offsets_jitted:
                self.offsets_jitted.add(line.offset)
                self.check_error(line)

                # Log mn and registers if options is set
                self.log_instruction(instruction, line)


            # Pass on empty instruction
            if len(instruction) == 0:
                continue

            for expression in instruction:
                # Apply preinit transformation
                for func in self.llvm_context.IR_transformation_functions:
                    expression = func(expression)

                # Treat current expression
                self.affect(expression.src, expression.dst)

                # Save registers updated
                new_reg.update(expression.dst.get_w())

            # Check for errors (without updating PC)
            self.check_error(line, except_do_not_update_pc=True)

            # new -> normal
            reg_written = []
            for r in new_reg:
                if isinstance(r, m2_expr.ExprId):
                    r_new = m2_expr.ExprId(r.name + "_new", r.size)
                    reg_written += [r, r_new]
                    self.affect(r_new, r, add_new=False)

            # Clear cache
            self.clear_cache(reg_written)
            self.main_stream = True

    def from_bloc(self, bloc, final_expr):
        """Build the function from a bloc, with the dst equation.
        Prototype : f(i8* vmcpu, i8* vmmngr)"""

        # Build function signature
        self.my_args.append((m2_expr.ExprId("vmcpu"),
                             llvm_c.PointerType.pointer(LLVMType.int(8)),
                             "vmcpu"))
        self.my_args.append((m2_expr.ExprId("vmmngr"),
                             llvm_c.PointerType.pointer(LLVMType.int(8)),
                             "vmmngr"))
        self.ret_type = LLVMType.int(final_expr.size)

        # Initialise the function
        self.init_fc()

        # Add content
        self.add_bloc(bloc, [])

        # Finalise the function
        self.set_ret(self.add_ir(final_expr))

        raise NotImplementedError("Not tested")

    def canonize_label_name(self, label):
        """Canonize @label names to a common form.
        @label: str or asmlabel instance"""
        if isinstance(label, str):
            return label
        elif isinstance(label, m2_asmbloc.asm_label):
            return "label_%s" % label.name
        else:
            raise ValueError("label must either be str or asmlabel")

    def get_basic_bloc_by_label(self, label):
        "Return the bbl corresponding to label, None otherwise"
        return self.name2bbl.get(self.canonize_label_name(label), None)

    def gen_ret_or_branch(self, dest):
        """Manage the dest ExprId. If label, branch on it if it is known.
        Otherwise, return the ExprId or the offset value"""

        builder = self.builder

        if isinstance(dest, m2_expr.ExprId):
            dest_name = dest.name
        elif isinstance(dest, m2_expr.ExprSlice) and \
                isinstance(dest.arg, m2_expr.ExprId):
            # Manage ExprId mask case
            dest_name = dest.arg.name
        else:
            raise ValueError()

        if not isinstance(dest_name, str):
            label = dest_name
            target_bbl = self.get_basic_bloc_by_label(label)
            if target_bbl is None:
                self.set_ret(self.add_ir(dest))
            else:
                builder.branch(target_bbl)
        else:
            self.set_ret(self.add_ir(dest))

    def add_irbloc(self, irbloc):
        "Add the content of irbloc at the corresponding labeled block"
        builder = self.builder

        bloc = irbloc.irs
        dest = irbloc.dst
        label = irbloc.label
        lines = irbloc.lines

        # Get labeled basic bloc
        label_block = self.get_basic_bloc_by_label(label)
        builder.position_at_end(label_block)

        # Erase cache
        self.expr_cache = {}

        # Add the content of the bloc with corresponding lines
        self.add_bloc(bloc, lines)

        # Erase cache
        self.expr_cache = {}

        # Manage ret
        for func in self.llvm_context.IR_transformation_functions:
            dest = func(dest)

        if isinstance(dest, m2_expr.ExprCond):
            # Compute cond
            cond = self.add_ir(dest.cond)
            zero_casted = llvm_c.Constant.int(LLVMType.int(dest.cond.size),
                                              0)
            condition_bool = builder.icmp(llvm_c.ICMP_NE, cond,
                                          zero_casted)

            # Create bbls
            branch_id = self.new_branch_name()
            then_block = self.append_basic_block('then%s' % branch_id)
            else_block = self.append_basic_block('else%s' % branch_id)

            builder.cbranch(condition_bool, then_block, else_block)

            # Then Bloc
            builder.position_at_end(then_block)
            self.gen_ret_or_branch(dest.src1)

            # Else Bloc
            builder.position_at_end(else_block)
            self.gen_ret_or_branch(dest.src2)

        elif isinstance(dest, m2_expr.ExprId):
            self.gen_ret_or_branch(dest)

        elif isinstance(dest, m2_expr.ExprSlice):
            self.gen_ret_or_branch(dest)

        else:
            raise Exception("Bloc dst has to be an ExprId or an ExprCond")

    def from_blocs(self, blocs):
        """Build the function from a list of bloc (irbloc instances).
        Prototype : f(i8* vmcpu, i8* vmmngr)"""

        # Build function signature
        self.my_args.append((m2_expr.ExprId("vmcpu"),
                             llvm_c.PointerType.pointer(LLVMType.int(8)),
                             "vmcpu"))
        self.my_args.append((m2_expr.ExprId("vmmngr"),
                             llvm_c.PointerType.pointer(LLVMType.int(8)),
                             "vmmngr"))
        ret_size = blocs[0].dst.size

        self.ret_type = LLVMType.int(ret_size)

        # Initialise the function
        self.init_fc()

        # Create basic blocks (for label branchs)
        entry_bbl, builder = self.entry_bbl, self.builder

        for irbloc in blocs:
            name = self.canonize_label_name(irbloc.label)
            self.append_basic_block(name)

        # Add content
        builder.position_at_end(entry_bbl)

        for irbloc in blocs:
            self.add_irbloc(irbloc)

        # Branch entry_bbl on first label
        builder.position_at_end(entry_bbl)
        first_label_bbl = self.get_basic_bloc_by_label(blocs[0].label)
        builder.branch(first_label_bbl)

    def __str__(self):
        "Print the llvm IR corresponding to the current module"

        return str(self.fc)

    def verify(self):
        "Verify the module syntax"

        return self.mod.verify()

    def get_assembly(self):
        "Return native assembly corresponding to the current module"

        return self.mod.to_native_assembly()

    def optimise(self):
        "Optimise the function in place"
        while self.llvm_context.pass_manager.run(self.fc):
            continue

    def __call__(self, *args):
        "Eval the function with arguments args"

        e = self.llvm_context.get_execengine()

        genargs = [LLVMType.generic(a) for a in args]
        ret = e.run_function(self.fc, genargs)

        return ret.as_int()

    def get_function_pointer(self):
        "Return a pointer on the Jitted function"
        e = self.llvm_context.get_execengine()

        return e.get_pointer_to_function(self.fc)

# TODO:
# - Add more expressions
