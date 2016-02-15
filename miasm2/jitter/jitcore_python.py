import miasm2.jitter.jitcore as jitcore
import miasm2.expression.expression as m2_expr
import miasm2.jitter.csts as csts
from miasm2.expression.simplifications import expr_simp
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec


################################################################################
#                              Python jitter Core                              #
################################################################################


class JitCore_Python(jitcore.JitCore):
    "JiT management, using Miasm2 Symbol Execution engine as backend"

    def __init__(self, ir_arch, bs=None):
        super(JitCore_Python, self).__init__(ir_arch, bs)
        self.ir_arch = ir_arch

        # CPU (None for now) will be set by the "jitted" Python function
        self.symbexec = EmulatedSymbExec(None, self.ir_arch, {})

    def load(self):
        "Preload symbols according to current architecture"
        self.symbexec.reset_regs()

    def jitirblocs(self, label, irblocs):
        """Create a python function corresponding to an irblocs' group.
        @label: the label of the irblocs
        @irblocs: a gorup of irblocs
        """

        def myfunc(cpu, vmmngr):
            """Execute the function according to cpu and vmmngr states
            @cpu: JitCpu instance
            @vm: VmMngr instance
            """

            # Keep current location in irblocs
            cur_label = label

            # Required to detect new instructions
            offsets_jitted = set()

            # Get exec engine
            exec_engine = self.symbexec
            exec_engine.cpu = cpu

            # For each irbloc inside irblocs
            while True:

                # Get the current bloc
                for irb in irblocs:
                    if irb.label == cur_label:
                        break
                else:
                    raise RuntimeError("Irblocs must end with returning an "
                                       "ExprInt instance")

                # Refresh CPU values according to @cpu instance
                exec_engine.update_engine_from_cpu()

                # Execute current ir bloc
                for ir, line in zip(irb.irs, irb.lines):

                    # For each new instruction (in assembly)
                    if line.offset not in offsets_jitted:
                        offsets_jitted.add(line.offset)

                        # Log registers values
                        if self.log_regs:
                            exec_engine.update_cpu_from_engine()
                            cpu.dump_gpregs()

                        # Log instruction
                        if self.log_mn:
                            print "%08x %s" % (line.offset, line)

                        # Check for memory exception
                        if (vmmngr.get_exception() != 0):
                            exec_engine.update_cpu_from_engine()
                            return line.offset

                    # Eval current instruction (in IR)
                    exec_engine.eval_ir(ir)

                    # Check for memory exception which do not update PC
                    if (vmmngr.get_exception() & csts.EXCEPT_DO_NOT_UPDATE_PC != 0):
                        exec_engine.update_cpu_from_engine()
                        return line.offset

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

    def jit_call(self, label, cpu, vmmngr, _breakpoints):
        """Call the function label with cpu and vmmngr states
        @label: function's label
        @cpu: JitCpu instance
        @vm: VmMngr instance
        """

        # Get Python function corresponding to @label
        fc_ptr = self.lbl2jitbloc[label]

        # Execute the function
        return fc_ptr(cpu, vmmngr)
