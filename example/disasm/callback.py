from miasm2.core.bin_stream import bin_stream_str
from miasm2.core.asmblock import AsmConstraint
from miasm2.arch.x86.disasm import dis_x86_32, cb_x86_funcs


def cb_x86_callpop(cur_bloc, symbol_pool, *args, **kwargs):
    """
    1000: call 1005
    1005: pop

    Will give:

    1000: push 1005
    1005: pop

    """
    # Pattern matching
    if len(cur_bloc.lines) < 1:
        return
    ## We want to match a CALL, always the last line of a basic block
    last_instr = cur_bloc.lines[-1]
    if last_instr.name != 'CALL':
        return
    ## The destination must be a location
    dst = last_instr.args[0]
    if not dst.is_loc():
        return

    loc_key = dst.loc_key
    offset = symbol_pool.loc_key_to_offset(loc_key)
    ## The destination must be the next instruction
    if offset != last_instr.offset + last_instr.l:
        return

    # Update instruction instance
    last_instr.name = 'PUSH'

    # Update next blocks to process in the disassembly engine
    cur_bloc.bto.clear()
    cur_bloc.add_cst(loc_key, AsmConstraint.c_next)


# Prepare a tiny shellcode
shellcode = ''.join(["\xe8\x00\x00\x00\x00", # CALL $
                     "X",                    # POP EAX
                     "\xc3",                 # RET
                     ])
bin_stream = bin_stream_str(shellcode)
mdis = dis_x86_32(bin_stream)

print "Without callback:\n"
asmcfg = mdis.dis_multiblock(0)
print "\n".join(str(block) for block in asmcfg.blocks)

# Enable callback
cb_x86_funcs.append(cb_x86_callpop)
## Other method:
## mdis.dis_block_callback = cb_x86_callpop

print "=" * 40
print "With callback:\n"
asmcfg_after = mdis.dis_multiblock(0)
print "\n".join(str(block) for block in asmcfg_after.blocks)

# Ensure the callback has been called
assert asmcfg.loc_key_to_block(asmcfg.heads()[0]).lines[0].name == "CALL"
assert asmcfg_after.loc_key_to_block(asmcfg_after.heads()[0]).lines[0].name == "PUSH"
