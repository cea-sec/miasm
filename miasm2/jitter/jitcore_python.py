import miasm2.jitter.jitcore as jitcore
import miasm2.expression.expression as m2_expr
import miasm2.jitter.csts as csts
from miasm2.expression.simplifications import ExpressionSimplifier, expr_simp_explicit
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec

################################################################################
#                              Python jitter Core                              #
################################################################################


class JitCore_Python(jitcore.JitCore):
    "JiT management, using Miasm2 Symbol Execution engine as backend"

    SymbExecClass = EmulatedSymbExec

    def __init__(self, ir_arch, bin_stream):
        super(JitCore_Python, self).__init__(ir_arch, bin_stream)
        self.ir_arch = ir_arch
        self.ircfg = self.ir_arch.new_ircfg()

        # CPU & VM (None for now) will be set later

        self.symbexec = self.SymbExecClass(
            None, None,
            self.ir_arch, {},
            sb_expr_simp=expr_simp_explicit
        )
        self.symbexec.enable_emulated_simplifications()

    def set_cpu_vm(self, cpu, vm):
        self.symbexec.cpu = cpu
        self.symbexec.vm = vm

    def load(self):
        "Preload symbols according to current architecture"
        self.symbexec.reset_regs()

    def jit_irblocks(self, loc_key, irblocks):
        """Create a python function corresponding to an irblocks' group.
        @loc_key: the loc_key of the irblocks
        @irblocks: a group of irblocks
        """

        def myfunc(cpu):
            """Execute the function according to cpu and vmmngr states
            @cpu: JitCpu instance
            """
            # Get virtual memory handler
            vmmngr = cpu.vmmngr

            # Keep current location in irblocks
            cur_loc_key = loc_key

            # Required to detect new instructions
            offsets_jitted = set()

            # Get exec engine
            exec_engine = self.symbexec
            expr_simp = exec_engine.expr_simp

            known_loc_keys = set(irb.loc_key for irb in irblocks)
            # For each irbloc inside irblocks
            while True:
                # Get the current bloc
                for irb in irblocks:
                    if irb.loc_key == cur_loc_key:
                        break

                else:
                    raise RuntimeError("Irblocks must end with returning an "
                                       "ExprInt instance")

                # Refresh CPU values according to @cpu instance
                exec_engine.update_engine_from_cpu()

                # Execute current ir bloc
                for assignblk in irb:
                    instr = assignblk.instr
                    # For each new instruction (in assembly)
                    if instr is not None and instr.offset not in offsets_jitted:
                        # Test exceptions
                        vmmngr.check_invalid_code_blocs()
                        vmmngr.check_memory_breakpoint()
                        if vmmngr.get_exception():
                            exec_engine.update_cpu_from_engine()
                            return instr.offset

                        offsets_jitted.add(instr.offset)

                        # Log registers values
                        if self.log_regs:
                            exec_engine.update_cpu_from_engine()
                            exec_engine.cpu.dump_gpregs()

                        # Log instruction
                        if self.log_mn:
                            print "%08x %s" % (instr.offset, instr)

                        # Check for exception
                        if (vmmngr.get_exception() != 0 or
                            cpu.get_exception() != 0):
                            exec_engine.update_cpu_from_engine()
                            return instr.offset

                    # Eval current instruction (in IR)
                    exec_engine.eval_updt_assignblk(assignblk)
                    # Check for exceptions which do not update PC
                    exec_engine.update_cpu_from_engine()
                    if (vmmngr.get_exception() & csts.EXCEPT_DO_NOT_UPDATE_PC != 0 or
                        cpu.get_exception() > csts.EXCEPT_NUM_UPDT_EIP):
                        return instr.offset

                vmmngr.check_invalid_code_blocs()
                vmmngr.check_memory_breakpoint()

                # Get next bloc address
                ad = expr_simp(exec_engine.eval_expr(self.ir_arch.IRDst))

                # Updates @cpu instance according to new CPU values
                exec_engine.update_cpu_from_engine()

                # Manage resulting address
                if isinstance(ad, m2_expr.ExprInt):
                    return ad.arg.arg
                elif isinstance(ad, m2_expr.ExprLoc):
                    cur_loc_key = ad.loc_key
                else:
                    raise NotImplementedError("Type not handled: %s" % ad)

        # Associate myfunc with current loc_key
        offset = self.ir_arch.loc_db.get_location_offset(loc_key)
        assert offset is not None
        self.offset_to_jitted_func[offset] = myfunc

    def exec_wrapper(self, loc_key, cpu, _offset_to_jitted_func, _stop_offsets,
                     _max_exec_per_call):
        """Call the function @loc_key with @cpu
        @loc_key: function's loc_key
        @cpu: JitCpu instance
        """

        # Get Python function corresponding to @loc_key
        fc_ptr = self.offset_to_jitted_func[loc_key]

        # Execute the function
        return fc_ptr(cpu)
