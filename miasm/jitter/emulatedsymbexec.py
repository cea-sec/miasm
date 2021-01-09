from miasm.core.utils import decode_hex, encode_hex
import miasm.expression.expression as m2_expr
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.arch.x86.arch import is_op_segm


class EmulatedSymbExec(SymbolicExecutionEngine):
    """Symbolic exec instance linked with a jitter"""

    x86_cpuid = {
        0: {
            0: 0xa,
            1: 0x756E6547,
            2: 0x6C65746E,
            3: 0x49656E69,
        },
        1: {
            0: 0x00020652,
            1: 0x00000800,
            2: 0x00000209,
            3: 0x078bf9ff
        },
        2: {
            0: 0,
            1: 0,
            2: 0,
            3: 0
        },
        4: {
            0: 0,
            1: 0,
            2: 0,
            3: 0
        },
        7: {
            0: 0,
            1: (1 << 0) | (1 << 3),
            2: 0,
            3: 0
        },
        0x80000000: {
            0: 0x80000008,
            1: 0,
            2: 0,
            3: 0
        },
        0x80000001: {
            0: 0,
            1: 0,
            2: (1 << 0) | (1 << 8),
            3: (1 << 11) | (1 << 29),
        },
    }

    def __init__(self, cpu, vm, *args, **kwargs):
        """Instantiate an EmulatedSymbExec, associated to CPU @cpu and bind
        memory accesses.
        @cpu: JitCpu instance
        """
        super(EmulatedSymbExec, self).__init__(*args, **kwargs)
        self.cpu = cpu
        self.vm = vm

    def reset_regs(self):
        """Set registers value to 0. Ignore register aliases"""
        for reg in self.lifter.arch.regs.all_regs_ids_no_alias:
            self.symbols.symbols_id[reg] = m2_expr.ExprInt(0, size=reg.size)

    # Memory management
    def mem_read(self, expr_mem):
        """Memory read wrapper for symbolic execution
        @expr_mem: ExprMem"""

        addr = expr_mem.ptr
        if not addr.is_int():
            return super(EmulatedSymbExec, self).mem_read(expr_mem)
        addr = int(addr)
        size = expr_mem.size // 8
        value = self.vm.get_mem(addr, size)
        if self.vm.is_little_endian():
            value = value[::-1]
        self.vm.add_mem_read(addr, size)

        return m2_expr.ExprInt(
            int(encode_hex(value), 16),
            expr_mem.size
        )

    def mem_write(self, dest, data):
        """Memory read wrapper for symbolic execution
        @dest: ExprMem instance
        @data: Expr instance"""

        # Get the content to write
        data = self.expr_simp(data)
        if not isinstance(data, m2_expr.ExprInt):
            raise RuntimeError("A simplification is missing: %s" % data)
        to_write = int(data)

        # Format information
        addr = int(dest.ptr)
        size = data.size // 8
        content = hex(to_write).replace("0x", "").replace("L", "")
        content = "0" * (size * 2 - len(content)) + content
        content = decode_hex(content)

        if self.vm.is_little_endian():
            content = content[::-1]

        # Write in VmMngr context
        self.vm.set_mem(addr, content)

    # Interaction symbexec <-> jitter
    def update_cpu_from_engine(self):
        """Updates @cpu instance according to new CPU values"""

        for symbol in self.symbols:
            if isinstance(symbol, m2_expr.ExprId):
                if hasattr(self.cpu, symbol.name):
                    value = self.symbols.symbols_id[symbol]
                    if not isinstance(value, m2_expr.ExprInt):
                        raise ValueError("A simplification is missing: %s" % value)

                    setattr(self.cpu, symbol.name, int(value))
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
        if not is_op_segm(expr):
            return expr
        if not expr.args[0].is_int():
            return expr
        segm_nb = int(expr.args[0])
        segmaddr = self.cpu.get_segm_base(segm_nb)
        return e_s(m2_expr.ExprInt(segmaddr, expr.size) + expr.args[1])

    def _simp_handle_x86_cpuid(self, e_s, expr):
        """From miasm/jitter/op_semantics.h: x86_cpuid"""
        if expr.op != "x86_cpuid":
            return expr

        if any(not arg.is_int() for arg in expr.args):
            return expr
        a, reg_num = (int(arg) for arg in expr.args)

        # Not found error is keeped on purpose
        return m2_expr.ExprInt(self.x86_cpuid[a][reg_num], expr.size)

    def enable_emulated_simplifications(self):
        """Enable simplifications needing a CPU instance on associated
        ExpressionSimplifier
        """
        self.expr_simp.enable_passes({
            m2_expr.ExprOp: [self._simp_handle_segm, self._simp_handle_x86_cpuid],
        })
