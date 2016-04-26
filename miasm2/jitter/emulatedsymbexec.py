import miasm2.expression.expression as m2_expr
from miasm2.ir.symbexec import symbexec


class EmulatedSymbExec(symbexec):
    """Symbolic exec instance linked with a jitter"""

    def __init__(self, cpu, *args, **kwargs):
        """Instanciate an EmulatedSymbExec, associated to CPU @cpu and bind
        memory accesses.
        @cpu: JitCpu instance
        """
        super(EmulatedSymbExec, self).__init__(*args, **kwargs)
        self.cpu = cpu
        self.func_read = self._func_read
        self.func_write = self._func_write

    def reset_regs(self):
        """Set registers value to 0. Ignore register aliases"""
        for reg in self.ir_arch.arch.regs.all_regs_ids_no_alias:
            self.symbols.symbols_id[reg] = m2_expr.ExprInt(0, size=reg.size)

    # Memory management
    def _func_read(self, expr_mem):
        """Memory read wrapper for symbolic execution
        @expr_mem: ExprMem"""

        addr = expr_mem.arg.arg.arg
        size = expr_mem.size / 8
        value = self.cpu.get_mem(addr, size)

        return m2_expr.ExprInt(int(value[::-1].encode("hex"), 16),
                               expr_mem.size)

    def _func_write(self, symb_exec, dest, data):
        """Memory read wrapper for symbolic execution
        @symb_exec: symbexec instance
        @dest: ExprMem instance
        @data: Expr instance"""

        # Get the content to write
        data = self.expr_simp(data)
        if not isinstance(data, m2_expr.ExprInt):
            raise RuntimeError("A simplification is missing: %s" % data)
        to_write = data.arg.arg

        # Format information
        addr = dest.arg.arg.arg
        size = data.size / 8
        content = hex(to_write).replace("0x", "").replace("L", "")
        content = "0" * (size * 2 - len(content)) + content
        content = content.decode("hex")[::-1]

        # Write in VmMngr context
        self.cpu.set_mem(addr, content)

    # Interaction symbexec <-> jitter
    def update_cpu_from_engine(self):
        """Updates @cpu instance according to new CPU values"""

        for symbol in self.symbols:
            if isinstance(symbol, m2_expr.ExprId):
                if hasattr(self.cpu, symbol.name):
                    value = self.symbols.symbols_id[symbol]
                    if not isinstance(value, m2_expr.ExprInt):
                        raise ValueError("A simplification is missing: %s" % value)

                    setattr(self.cpu, symbol.name, value.arg.arg)
            else:
                raise NotImplementedError("Type not handled: %s" % symbol)


    def update_engine_from_cpu(self):
        """Updates CPU values according to @cpu instance"""

        for symbol in self.symbols:
            if isinstance(symbol, m2_expr.ExprId):
                if hasattr(self.cpu, symbol.name):
                    value = m2_expr.ExprInt(getattr(self.cpu, symbol.name),
                                            symbol.size)
                    self.symbols.symbols_id[symbol] = value
            else:
                raise NotImplementedError("Type not handled: %s" % symbol)

    # CPU specific simplifications
    def _simp_handle_segm(self, e_s, expr):
        """Handle 'segm' operation"""
        if expr.op != "segm":
            return expr
        segm_nb = int(expr.args[0].arg)
        segmaddr = self.cpu.get_segm_base(segm_nb)
        return e_s(m2_expr.ExprOp("+",
                                  m2_expr.ExprInt(segmaddr, expr.size),
                                  expr.args[1]))

    def enable_emulated_simplifications(self):
        """Enable simplifications needing a CPU instance on associated
        ExpressionSimplifier
        """
        self.expr_simp.enable_passes({
            m2_expr.ExprOp: [self._simp_handle_segm]
        })
