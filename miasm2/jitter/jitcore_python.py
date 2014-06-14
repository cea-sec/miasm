import miasm2.jitter.jitcore as jitcore
import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.ir.symbexec import symbexec


class JitCore_Python(jitcore.JitCore):
    "JiT management, using Miasm2 Symbol Execution engine as backend"

    def __init__(self, my_ir, bs=None):
        super(JitCore_Python, self).__init__(my_ir, bs)
        self.symbexec = None

    def load(self, arch):
        "Preload symbols according to current architecture"

        symbols_init =  {}
        for i, r in enumerate(arch.regs.all_regs_ids):
            symbols_init[r] = arch.regs.all_regs_ids_init[i]

        self.symbexec = symbexec(arch, symbols_init, func_read = self.func_read)

    def func_read(self, expr_mem):
        """Memory read wrapper for symbolic execution
        @expr_mem: ExprMem"""

        addr = expr_mem.arg.arg.arg
        size = expr_mem.size / 8
        value = self.vmmngr.vm_get_mem(addr, size)
        return m2_expr.ExprInt_fromsize(expr_mem.size,
                                        int(value[::-1].encode("hex"), 16))

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
            loop = True

            # Get exec engine
            exec_engine = self.symbexec

            # For each irbloc inside irblocs
            while loop is True:

                # Get the current bloc
                loop = False
                for irb in irblocs:
                    if irb.label == cur_label:
                        loop = True
                        break
                if loop is False:
                    break

                # Refresh CPU values according to @cpu instance
                for symbol in exec_engine.symbols:
                    if isinstance(symbol, m2_expr.ExprId):
                        if hasattr(cpu, symbol.name):
                            value = m2_expr.ExprInt_fromsize(symbol.size,
                                                             getattr(cpu, symbol.name))
                            exec_engine.symbols.symbols_id[symbol] = value
                    else:
                        raise NotImplementedError("Type not handled: %s" % symbol)

                # Execute current ir bloc
                ad = expr_simp(exec_engine.emulbloc(irb))

                # Manage resulting address
                if isinstance(ad, m2_expr.ExprInt):
                    return ad.arg.arg
                else:
                    raise NotImplementedError("Type not handled: %s" % ad)

        # Associate myfunc with current label
        self.lbl2jitbloc[label.offset] = myfunc

    def jit_call(self, label, cpu, vmmngr):
        """Call the function label with cpu and vmmngr states
        @label: function's label
        @cpu: JitCpu instance
        @vm: VmMngr instance
        """

        # Get Python function corresponding to @label
        fc_ptr = self.lbl2jitbloc[label]

        # Update memory state
        self.vmmngr = vmmngr

        # Execute the function
        return fc_ptr(cpu, vmmngr)
