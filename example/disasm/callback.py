from miasm2.core.bin_stream import bin_stream_str
from miasm2.core.asmbloc import asm_constraint, asm_label
from miasm2.expression.expression import ExprId
from miasm2.arch.x86.disasm import dis_x86_32, cb_x86_funcs


def cb_x86_callpop(cur_bloc, symbol_pool, *args, **kwargs):
    """
    1000: call 1005
    1005: pop

    Will give:

    1000: push 1005
    1005: pop

    """
    if len(cur_bloc.lines) < 1:
        return
    l = cur_bloc.lines[-1]
    if l.name != 'CALL':
        return
    dst = l.args[0]
    if not (isinstance(dst, ExprId) and isinstance(dst.name, asm_label)):
        return
    if dst.name.offset != l.offset + l.l:
        return
    l.name = 'PUSH'
    cur_bloc.bto.clear()
    cur_bloc.add_cst(dst.name.offset, asm_constraint.c_next, symbol_pool)


# Prepare a tiny shellcode
shellcode = ''.join(["\xe8\x00\x00\x00\x00", # CALL $
                     "X",                    # POP EAX
                     "\xc3",                 # RET
                     ])
bin_stream = bin_stream_str(shellcode)
mdis = dis_x86_32(bin_stream)

print "Without callback:\n"
blocks = mdis.dis_multibloc(0)
print "\n".join(str(block) for block in blocks)

# Enable callback
cb_x86_funcs.append(cb_x86_callpop)
## Other method:
## mdis.dis_bloc_callback = cb_x86_callpop

# Clean disassembly cache
mdis.job_done.clear()

print "=" * 40
print "With callback:\n"
blocks_after = mdis.dis_multibloc(0)
print "\n".join(str(block) for block in blocks_after)

# Ensure the callback has been called
assert blocks[0].lines[0].name == "CALL"
assert blocks_after[0].lines[0].name == "PUSH"
