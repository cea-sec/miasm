from __future__ import print_function
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.asmblock import AsmConstraint
from miasm.core.locationdb import LocationDB


def cb_x86_callpop(mdis, cur_bloc, offset_to_dis):
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
    offset = mdis.loc_db.get_location_offset(loc_key)
    ## The destination must be the next instruction
    if offset != last_instr.offset + last_instr.l:
        return

    # Update instruction instance
    last_instr.name = 'PUSH'

    # Update next blocks to process in the disassembly engine
    cur_bloc.bto.clear()
    cur_bloc.add_cst(loc_key, AsmConstraint.c_next)


# Prepare a tiny shellcode
shellcode = (
    b"\xe8\x00\x00\x00\x00" # CALL $
    b"X"                    # POP EAX
    b"\xc3"                 # RET
)

# Instantiate a x86 32 bit architecture
machine = Machine("x86_32")
loc_db = LocationDB()
cont = Container.from_string(shellcode, loc_db)
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

print("Without callback:\n")
asmcfg = mdis.dis_multiblock(0)
print("\n".join(str(block) for block in asmcfg.blocks))

# Enable callback
mdis.dis_block_callback = cb_x86_callpop

print("=" * 40)
print("With callback:\n")
asmcfg_after = mdis.dis_multiblock(0)
print("\n".join(str(block) for block in asmcfg_after.blocks))

# Ensure the callback has been called
assert asmcfg.loc_key_to_block(asmcfg.heads()[0]).lines[0].name == "CALL"
assert asmcfg_after.loc_key_to_block(asmcfg_after.heads()[0]).lines[0].name == "PUSH"
