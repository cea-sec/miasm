# Toshiba MeP-c4 - unit tests helpers
# Guillaume Valadon <guillaume@valadon.net>

from __future__ import print_function

from miasm.analysis.machine import Machine
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.locationdb import LocationDB


def jit_instructions(mn_str):
    """JIT instructions and return the jitter object."""

    # Get the miasm Machine
    machine = Machine("mepb")
    mn_mep = machine.mn()
    loc_db = LocationDB()

    # Assemble the instructions
    asm = b""
    for instr_str in mn_str.split("\n"):
        instr = mn_mep.fromstring(instr_str, "b")
        instr.mode = "b"
        asm += mn_mep.asm(instr)[0]

    # Init the jitter and add the assembled instructions to memory
    jitter = machine.jitter(loc_db, jit_type="gcc")
    jitter.vm.add_memory_page(0, PAGE_READ | PAGE_WRITE, asm)

    # Set the breakpoint
    jitter.add_breakpoint(len(asm), lambda x: False)

    # Jit the instructions
    #jitter.init_stack()
    jitter.init_run(0)
    jitter.continue_run()

    return jitter


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
