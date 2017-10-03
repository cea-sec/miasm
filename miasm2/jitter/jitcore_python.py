import miasm2.jitter.jitcore as jitcore
import miasm2.expression.expression as m2_expr
import miasm2.jitter.csts as csts
from miasm2.expression.simplifications import ExpressionSimplifier
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec


################################################################################
#                              Python jitter Core                              #
################################################################################


class JitCore_Python(jitcore.JitCore):
    "JiT management, using Miasm2 Symbol Execution engine as backend"

    SymbExecClass = EmulatedSymbExec

    def __init__(self, ir_arch, bs=None):
        super(JitCore_Python, self).__init__(ir_arch, bs)
        self.ir_arch = ir_arch

        # CPU & VM (None for now) will be set later
        expr_simp = ExpressionSimplifier()
        expr_simp.enable_passes(ExpressionSimplifier.PASS_COMMONS)
        self.symbexec = self.SymbExecClass(None, None, self.ir_arch, {},
                                           sb_expr_simp=expr_simp)
        self.symbexec.enable_emulated_simplifications()

    def set_cpu_vm(self, cpu, vm):
        self.symbexec.cpu = cpu
        self.symbexec.vm = vm

    def load(self):
        "Preload symbols according to current architecture"
        self.symbexec.reset_regs()

    def jitirblocs(self, label, irblocks):
        """Create a python function corresponding to an irblocks' group.
        @label: the label of the irblocks
        @irblocks: a gorup of irblocks
        """

        def myfunc(cpu):
            """Execute the function according to cpu and vmmngr states
            @cpu: JitCpu instance
            """
            # Get virtual memory handler
            vmmngr = cpu.vmmngr

            # Keep current location in irblocks
            cur_label = label

            # Required to detect new instructions
            offsets_jitted = set()

            # Get exec engine
            exec_engine = self.symbexec
            expr_simp = exec_engine.expr_simp

            # For each irbloc inside irblocks
            while True:

                # Get the current bloc
                for irb in irblocks:
                    if irb.label == cur_label:
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
                    if instr.offset not in offsets_jitted:
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
                elif isinstance(ad, m2_expr.ExprId):
                    cur_label = ad.name
                else:
                    raise NotImplementedError("Type not handled: %s" % ad)

        # Associate myfunc with current label
        self.lbl2jitbloc[label.offset] = myfunc

    def exec_wrapper(self, label, cpu, _lbl2jitbloc, _breakpoints,
                     _max_exec_per_call):
        """Call the function @label with @cpu
        @label: function's label
        @cpu: JitCpu instance
        """

        # Get Python function corresponding to @label
        fc_ptr = self.lbl2jitbloc[label]

        # Execute the function
        return fc_ptr(cpu)
