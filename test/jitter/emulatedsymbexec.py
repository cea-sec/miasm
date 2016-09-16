import miasm2.expression.expression as m2_expr

from miasm2.analysis.machine import Machine
machine = Machine("x86_32")
jit = machine.jitter()

# Set the segment base that we will be using
jit.cpu.set_segm_base(4, 0x7FF70000)

# Create a EmulatdSymbExec instance with the minimum settings needed for tests
from miasm2.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm2.arch.x86.ira import ir_a_x86_32
emulatedsymbexec = EmulatedSymbExec(jit.cpu, None, ir_a_x86_32({}), {})
emulatedsymbexec.enable_emulated_simplifications()
emulatedsymbexec.symbols[m2_expr.ExprId('FS', 16)] = m2_expr.ExprInt16(0x4)
expr_segm = m2_expr.ExprOp('segm', m2_expr.ExprId('FS', 16), m2_expr.ExprId('RAX', 64))

# offset.size < arch_size
emulatedsymbexec.symbols[m2_expr.ExprId('RAX', 64)] = m2_expr.ExprInt16(0xAAAA)
evaled_expr = emulatedsymbexec.eval_expr(expr_segm, dict(emulatedsymbexec.symbols.items()))
assert emulatedsymbexec.expr_simp(evaled_expr) == m2_expr.ExprInt32(0x7FF7AAAA)

# offset.size == arch_size
emulatedsymbexec.symbols[m2_expr.ExprId('RAX', 64)] = m2_expr.ExprInt32(0xAAAABBBB)
evaled_expr = emulatedsymbexec.eval_expr(expr_segm, dict(emulatedsymbexec.symbols.items()))
assert emulatedsymbexec.expr_simp(evaled_expr) == m2_expr.ExprInt32(0x2AA1BBBB)

# offset.size > arch_size
emulatedsymbexec.symbols[m2_expr.ExprId('RAX', 64)] = m2_expr.ExprInt64(0xAAAABBBBCCCCDDDD)
evaled_expr = emulatedsymbexec.eval_expr(expr_segm, dict(emulatedsymbexec.symbols.items()))
assert emulatedsymbexec.expr_simp(evaled_expr) == m2_expr.ExprInt32(0x4cc3dddd)
