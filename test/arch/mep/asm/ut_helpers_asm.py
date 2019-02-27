# Toshiba MeP-c4 - unit tests helpers
# Guillaume Valadon <guillaume@valadon.net>

from __future__ import print_function

from builtins import range

from miasm.core.utils import decode_hex, encode_hex
from miasm.arch.mep.arch import mn_mep
from miasm.core.cpu import Disasm_Exception
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprLoc

import re


def dis(mn_hex):
    """Disassembly helper"""
    mn_bin = decode_hex(mn_hex)
    try:
        return mn_mep.dis(mn_bin, "b")
    except Disasm_Exception:
        assert(False)  # miasm don't know what to do


def check_instruction(mn_str, mn_hex, multi=None, offset=0):
    """Try to disassemble and assemble this instruction"""

    # Rename objdump registers names
    mn_str = re.sub("\$([0-9]+)", lambda m: "R"+m.group(1), mn_str)
    mn_str = mn_str.replace("$", "")

    # Disassemble
    mn = dis(mn_hex)
    mn.offset = offset
    if mn.dstflow():

        # Remember ExprInt arguments sizes
        args_size = list()
        for i in range(len(mn.args)):
            if isinstance(mn.args[i], ExprInt):
                args_size.append(mn.args[i].size)
            else:
                args_size.append(None)

        # Adjust arguments values using the instruction offset
        loc_db = LocationDB()
        mn.dstflow2label(loc_db)

        # Convert ExprLoc to ExprInt
        for i in range(len(mn.args)):
            if args_size[i] is None:
                continue
            if isinstance(mn.args[i], ExprLoc):
                addr = loc_db.get_location_offset(mn.args[i].loc_key)
                mn.args[i] = ExprInt(addr, args_size[i])

    print("dis: %s -> %s" % (mn_hex.rjust(20), str(mn).rjust(20)))
    assert(str(mn) == mn_str)  # disassemble assertion

    # Assemble and return all possible candidates
    instr = mn_mep.fromstring(mn_str, "b")
    instr.offset = offset
    instr.mode = "b"
    if instr.offset:
        instr.fixDstOffset()
    asm_list = [encode_hex(i).decode() for i in mn_mep.asm(instr)]

    # Check instructions variants
    if multi:
        print("Instructions count:", len(asm_list))
        assert(len(asm_list) == multi)

        # Ensure that variants correspond to the same disassembled instruction
        for mn_hex_tmp in asm_list:
            mn = dis(mn_hex_tmp)
            print("dis: %s -> %s" % (mn_hex_tmp.rjust(20), str(mn).rjust(20)))

    # Check the assembly result
    print(
        "asm: %s -> %s" % (
            mn_str.rjust(20),
            ", ".join(asm_list).rjust(20)
        )
    )
    assert(mn_hex in asm_list)  # assemble assertion


def launch_tests(obj):
    """Call test methods by name"""

    test_methods = [name for name in dir(obj) if name.startswith("test")]

    for method in test_methods:
        print(method)
        try:
            getattr(obj, method)()
        except AttributeError as e:
            print("Method not found: %s" % method)
            assert(False)
        print('-' * 42)
