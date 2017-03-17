# -*- coding: utf8 -*-

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm, asmblock
from miasm2.analysis.machine import Machine
import miasm2.jitter.csts as csts
import miasm2.analysis.taint_analysis as taint

# TODO: tester d'autres jitter
# TODO: tester d'autres arch

nb_colors = 2
# Color's index:
red = 0
blue = 1

data_addr = 0x80000000
code_addr = 0x40000000

machine = Machine('x86_32')

def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def create_jitter():
    jitter = machine.jitter(jit_type='gcc')
    jitter.init_stack()
    jitter.vm.add_memory_page(data_addr, csts.PAGE_READ | csts.PAGE_WRITE, '0'*200)
    jitter.add_breakpoint(0x1337beef, code_sentinelle)
    jitter.push_uint32_t(0x1337beef)
    taint.enable_taint_analysis(jitter, nb_colors)
    return jitter

# Commons
def taint_RAX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
    return True

def taint_RBX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RBX"])
    return True

def taint_RCX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RCX"])
    return True

def taint_RCX_blue(jitter):
    jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RCX"])
    return True

def taint_RDX_blue(jitter):
    jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RDX"])
    return True

def taint_mem_0x123FFE8(jitter):
    jitter.cpu.taint_memory(0x123FFe8,4,red)
    return True

def taint_mem_RAX(jitter):
    jitter.cpu.taint_memory(jitter.cpu.RAX,4,red)
    return True


def test_taint_propagation():
    """Test taint propagation
    Enumerate all taint propagation scenarios (at least basics and especially
    tricky ones) and test them.
    """

    print "[+] Test taint propagation"

    jitter = create_jitter()
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, propagation_code())

    def check_no_more_taint(jitter):
        for color in range(jitter.nb_colors):
            regs, mems = jitter.cpu.get_all_taint(color)
            assert not regs
            assert not mems
        return True

    def test_reg_taint_reg(jitter):
        """Test if tainted reg can taint reg
        - EAX is tainted
        - MOV EBX, EAX
        - EBX should be tainted
        """
        print "\t[+] Test reg -> reg"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not mems
        assert len(regs) == 2
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RBX"]
        jitter.cpu.untaint_all()
        return True

    def test_reg_taint_mem(jitter):
        """
        - EAX is tainted
        - MOV DWORD PTR [EBX], EAX
        - [EBX] should be tainted
        """
        print "\t[+] Test reg -> mem"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert len(mems) == 1
        assert mems[0] == (0x80000000, 4)
        jitter.cpu.untaint_all()
        return True

    def test_mem_taint_reg(jitter):
        """
        - [EAX] is tainted
        - MOV EBX, DWORD PTR [EAX]
        - EBX should be tainted
        """
        print "\t[+] Test mem -> reg"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RBX"]
        assert len(mems) == 1
        assert mems[0] == (0x80000000, 4)
        jitter.cpu.untaint_all()
        return True

    def test_mem_taint_mem(jitter):
        """
        - [EAX] is tainted
        - PUSH   DWORD PTR [EAX]
        - [RSP] should be tainted
        """
        print "\t[+] Test mem -> mem"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 2
        assert mems[0] == (0x123FFF8, 4)
        assert mems[1] == (0x80000000, 4)
        jitter.cpu.untaint_all()
        return True

    def test_addr_taint_reg(jitter):
        """
        - EAX is tainted
        - MOV EBX, DWORD PTR [EAX]
        - EBX should be tainted
        """
        print "\t[+] Test addr -> reg"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not mems
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RBX"]
        jitter.cpu.untaint_all()
        return True

    def test_addr_taint_mem(jitter):
        """
        - EAX is tainted
        - MOV DWORD PTR [EAX], 0x1
        - [EAX] should be tainted
        """
        print "\t[+] Test addr -> mem"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert len(mems) == 1
        assert mems[0] == (0x80000000, 4)
        jitter.cpu.untaint_all()
        return True

    def test_pushad(jitter):
        """
        - EAX and ECX are tainted
        - The stack where EBX will be written is tainted
            -> this mem area is going to be untainted
        - PUSHAD
        - 2x4 bytes should be tainted
        """
        print "\t[+] Test multiple propagations (PUSHAD)"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 2
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RCX"]
        assert len(mems) == 1
        assert mems[0] == (0x123fff0, 8)
        jitter.cpu.untaint_all()
        return True

    def test_colors(jitter):
        """
        - Red: RAX, RBX, RCX
        - Blue:  RDX, RCX
        - PUSHAD
        -
        """
        print "\t[+] Test color conflicts (PUSHAD)"
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 3
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[2] == jitter.jit.codegen.regs_index["RCX"]
        assert len(mems) == 2
        assert mems[0] == (0x123ffc8, 4)
        assert mems[1] == (0x123ffd0, 8)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        assert regs[0] == jitter.jit.codegen.regs_index["RDX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RCX"]
        assert len(mems) == 1
        assert mems[0] == (0x123ffcc, 8)
        jitter.cpu.untaint_all()
        return True

    # REG -> REG
    jitter.add_breakpoint(0x40000005, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x40000007, test_reg_taint_reg)# Check that RBX is tainted
    # REG -> MEM
    jitter.add_breakpoint(0x40000007, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x40000009, test_reg_taint_mem)# Check that [RBX] is tainted
    # MEM -> REG
    jitter.add_breakpoint(0x40000009, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x4000000B, test_mem_taint_reg)# Check that RBX is tainted
    # MEM -> MEM
    jitter.add_breakpoint(0x4000000B, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x4000000D, test_mem_taint_mem)# Check that [RSP] is tainted
    # ADDR -> REG
    jitter.add_breakpoint(0x4000000D, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x4000000F, test_addr_taint_reg)# Check that RBX is tainted
    # ADDR -> MEM
    jitter.add_breakpoint(0x4000000F, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x40000015, test_addr_taint_mem)# Check that [RAX] is tainted
    # UNTAINT REG
    jitter.add_breakpoint(0x40000015, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x4000001A, check_no_more_taint)# Check that RAX is untainted
    # Multiple taint and untaint
    jitter.add_breakpoint(0x4000001A, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x40000020, check_no_more_taint)# Check that [RAX] is untainted
    jitter.add_breakpoint(0x40000020, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x40000020, taint_mem_0x123FFE8) # Taint [0x123FFE8]
    jitter.add_breakpoint(0x40000020, taint_RCX) # Taint RCX
    jitter.add_breakpoint(0x40000021, test_pushad) # Check PUSHAD
    # Colors
    jitter.add_breakpoint(0x40000021, taint_RAX) # Taint RAX in red
    jitter.add_breakpoint(0x40000021, taint_RBX) # Taint RBX in red
    jitter.add_breakpoint(0x40000021, taint_RCX) # Taint RCX in red
    jitter.add_breakpoint(0x40000021, taint_RCX_blue) # Taint RCX in blue
    jitter.add_breakpoint(0x40000021, taint_RDX_blue) # Taint RDX in blue
    jitter.add_breakpoint(0x40000022, test_colors) # Test colors

    jitter.init_run(code_addr)
    jitter.continue_run()

    jitter.breakpoints_handler.callbacks = {} # Clear breakpoints
    jitter.cpu.untaint_all()

def test_api():
    """Test API
    Test all functions made avalable by the taint analysis engine
    """

    print "[+] Test API"

    jitter = create_jitter()

    def test_api_taint_register(jitter):
        """ Test jitter.cpu.taint_register """

        print "\t[+] Test jitter.cpu.taint_register"

        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RBX"]
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_register(jitter):
        """ Test jitter.cpu.untaint_register """

        print "\t[+] Test jitter.cpu.untaint_register"

        jitter.cpu.untaint_register(blue, jitter.jit.codegen.regs_index["RCX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[1] == jitter.jit.codegen.regs_index["RBX"]
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        jitter.cpu.untaint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_all_registers_of_color(jitter):
        """ Test jitter.cpu.untaint_all_registers_of_color """

        print "\t[+] Test jitter.cpu.untaint_all_registers_of_color"

        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all_registers_of_color(blue)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RAX"]
        assert not mems
        jitter.cpu.untaint_all_registers_of_color(red)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems


    def test_api_untaint_all_registers(jitter):
        """ Test jitter.cpu.untaint_all_registers """

        print "\t[+] Test jitter.cpu.untaint_all_registers"

        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all_registers()
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_taint_memory(jitter):
        """ Test jitter.cpu.taint_memory """

        print "\t[+] Test jitter.cpu.taint_memory"

        jitter.cpu.taint_memory(0x80000000,4,red)
        jitter.cpu.taint_memory(0x80000006,7,red)
        jitter.cpu.taint_memory(0x80000006,7,blue)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        assert mems[0] == (0x80000006,7)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 2
        assert mems[0] == (0x80000000,4)
        assert mems[1] == (0x80000006,7)

    def test_api_untaint_memory(jitter):
        """ Test jitter.cpu.untaint_memory """

        print "\t[+] Test jitter.cpu.untaint_memory"

        jitter.cpu.untaint_memory(0x80000007,3,red)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        assert mems[0] == (0x80000006,7)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 3
        assert mems[0] == (0x80000000,4)
        assert mems[1] == (0x80000006,1)
        assert mems[2] == (0x8000000a,3)

    def test_api_untaint_all_memory_of_color(jitter):
        """ Test jitter.cpu.untaint_all_memory_of_color """

        print "\t[+] Test jitter.cpu.untaint_all_memory_of_color"

        jitter.cpu.untaint_all_memory_of_color(red)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        assert mems[0] == (0x80000006,7)
        jitter.cpu.untaint_all_memory_of_color(blue)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems

    def test_api_untaint_all_memory(jitter):
        """ Test jitter.cpu.untaint_all_memory """

        print "\t[+] Test jitter.cpu.untaint_all_memory"

        jitter.cpu.taint_memory(0x80000000,4,red)
        jitter.cpu.taint_memory(0x80000006,7,red)
        jitter.cpu.taint_memory(0x80000006,7,blue)
        jitter.cpu.untaint_all_memory()
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems

    def test_api_untaint_all_of_color(jitter):
        """ Test jitter.cpu.untaint_all_of_color """

        print "\t[+] Test jitter.cpu.untaint_all_of_color"

        jitter.cpu.taint_memory(0x80000000,4,red)
        jitter.cpu.taint_memory(0x80000006,7,blue)
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.untaint_all_of_color(red)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 1
        assert regs[0] == jitter.jit.codegen.regs_index["RBX"]
        assert len(mems) == 1
        assert mems[0] == (0x80000006,7)
        jitter.cpu.untaint_all_of_color(blue)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems

    def test_api_untaint_all(jitter):
        """ Test jitter.cpu.untaint_all """

        print "\t[+] Test jitter.cpu.untaint_all"

        jitter.cpu.taint_memory(0x80000000,4,red)
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all()
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems

    test_api_taint_register(jitter)
    test_api_untaint_register(jitter)
    test_api_untaint_all_registers_of_color(jitter)
    test_api_untaint_all_registers(jitter)
    test_api_taint_memory(jitter)
    test_api_untaint_memory(jitter)
    test_api_untaint_all_memory_of_color(jitter)
    test_api_untaint_all_memory(jitter)
    test_api_untaint_all_of_color(jitter)
    test_api_untaint_all(jitter)

def test_callback():
    """Test callback managment
    Test the callback managment done by the taint analysis engine
    """

    print "[+] Test callbacks"

    jitter = create_jitter()
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, callback_code())

    def on_taint_register_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on taint register callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 1
        assert last_regs[0] == jitter.jit.codegen.regs_index["RBX"]
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_taint_reg_cb(red)
        jitter.cpu.do_taint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
        return True

    def on_taint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix reg callback (taint/untaint)"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        assert last_regs[0] == jitter.jit.codegen.regs_index["zf"]
        assert last_regs[1] == jitter.jit.codegen.regs_index["pf"]
        assert last_regs[2] == jitter.jit.codegen.regs_index["nf"]
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 2
        assert last_regs[0] == jitter.jit.codegen.regs_index["of"]
        assert last_regs[1] == jitter.jit.codegen.regs_index["cf"]
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_taint_reg_cb(red)
        jitter.cpu.do_taint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
        return True

    def on_untaint_register_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on untaint register callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 1
        assert last_regs[0] == jitter.jit.codegen.regs_index["RBX"]
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_untaint_reg_cb(red)
        jitter.cpu.do_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
        return True

    def on_untaint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix reg callback (taint/untaint) - Part. 2"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        assert last_regs[0] == jitter.jit.codegen.regs_index["zf"]
        assert last_regs[1] == jitter.jit.codegen.regs_index["pf"]
        assert last_regs[2] == jitter.jit.codegen.regs_index["nf"]
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 2
        assert last_regs[0] == jitter.jit.codegen.regs_index["of"]
        assert last_regs[1] == jitter.jit.codegen.regs_index["cf"]
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_untaint_reg_cb(red)
        jitter.cpu.do_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
        return True


    def on_taint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on taint memory callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x80000000,4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_taint_mem_cb(red)
        jitter.cpu.do_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_taint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix mem callback (taint/untaint) - Part. 2"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFF8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFEC, 4)
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_taint_mem_cb(red)
        jitter.cpu.do_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_taint_memory_handler_3(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix colors callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFD8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFCC, 4)
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_taint_mem_cb(red)
        jitter.cpu.do_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_untaint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on untaint memory callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x80000000, 4)
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_untaint_mem_cb(red)
        jitter.cpu.do_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
        return True

    def on_untaint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix mem callback (taint/untaint)"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFF8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFEC, 4)
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(blue)
        assert not last_regs
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.do_untaint_mem_cb(red)
        jitter.cpu.do_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
        return True

    def second_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_memory_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_MEM, on_untaint_memory_handler_2)
        jitter.cpu.do_taint_mem_cb(red)
        jitter.cpu.do_taint_mem_cb(blue)
        jitter.cpu.do_untaint_mem_cb(red)
        jitter.cpu.do_untaint_mem_cb(blue)
        return True

    def third_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_register_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_register_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_REG, on_taint_register_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_REG, on_untaint_register_handler_2)
        jitter.cpu.do_taint_reg_cb(red)
        jitter.cpu.do_taint_reg_cb(blue)
        jitter.cpu.do_untaint_reg_cb(red)
        jitter.cpu.do_untaint_reg_cb(blue)
        return True

    def fourth_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler_3)
        jitter.cpu.do_taint_mem_cb(red)
        jitter.cpu.do_taint_mem_cb(blue)
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        return True

    global check_callback_occured
    check_callback_occured = 0

    jitter.add_breakpoint(0x40000005, taint_RAX) # Taint RAX
    jitter.add_breakpoint(0x40000019, second_handlers)
    jitter.add_breakpoint(0x4000001C, third_handlers)
    jitter.add_breakpoint(0x4000001E, fourth_handlers)

    jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_REG, on_taint_register_handler)
    jitter.cpu.do_taint_reg_cb(red)
    jitter.cpu.do_taint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_REG, on_untaint_register_handler)
    jitter.cpu.do_untaint_reg_cb(red)
    jitter.cpu.do_untaint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler)
    jitter.cpu.do_taint_mem_cb(red)
    jitter.cpu.do_taint_mem_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_MEM, on_untaint_memory_handler)
    jitter.cpu.do_untaint_mem_cb(red)
    jitter.cpu.do_untaint_mem_cb(blue)

    jitter.init_run(code_addr)
    jitter.continue_run()
    assert check_callback_occured == 9

def propagation_code():
    # Assemble code to test
    blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
    main:
       MOV    EAX, 0x80000000
       MOV    EBX, EAX                              ; reg -> reg
       MOV    DWORD PTR [EBX], EAX                  ; reg -> mem
       MOV    EBX, DWORD PTR [EAX]                  ; mem -> reg
       PUSH   DWORD PTR [EAX]                       ; mem -> mem
       MOV    EBX, DWORD PTR [EAX]                  ; addr -> reg
       MOV    DWORD PTR [EAX], 0x1                  ; addr -> mem
       MOV    EAX, 0x80000000                       ; untaint reg
       MOV    DWORD PTR [EAX], 0x1                  ; untaint mem
       PUSHAD                                       ; multiple taint and untaint
       PUSHAD                                       ; multiple colors
       PUSH   0x1337BEEF                            ; clean exit value
       RET
    ''')

    # Set 'main' label's offset
    symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

    # Spread information and resolve instructions offset
    asm = asmblock.asm_resolve_final(mn_x86, blocs, symbol_pool)

    compiled = ''
    for key in sorted(asm):
        compiled += asm[key]
    return compiled

def callback_code():
    # Assemble code to test
    blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
    main:
       MOV    EAX, 0x80000000
       MOV    EBX, EAX                              ; taint_reg_cb
       MOV    EBX, 0x80000000                       ; untaint_reg_cb
       MOV    DWORD PTR [EBX], EAX                  ; taint_mem_cb
       MOV    DWORD PTR [EBX], 0x0                  ; untaint_mem_cb
       MOV    DWORD PTR [0x123FFEC], EAX            ; preparation: taint EBX PUSHAD spot
       PUSHAD                                       ; taint_mem_cb + untaint_mem_cb
       ADD    EAX, EBX                              ; preparation
       TEST   EAX, EAX                              ; taint_reg_cb + untaint_reg_cb
       PUSHAD                                       ; multiple colors
       PUSH   0x1337BEEF                            ; clean exit value
       RET
    ''')

    # Set 'main' label's offset
    symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

    # Spread information and resolve instructions offset
    asm = asmblock.asm_resolve_final(mn_x86, blocs, symbol_pool)

    compiled = ''
    for key in sorted(asm):
        compiled += asm[key]
    return compiled

def conflicts_code():
    # TODO use this function to test SEH compatibility
    # Assemble code to test
    blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, '''
    main:
       PUSH   seh_handler                           ; push our exception handler
       MOV    EAX, DWORD PTR FS:[0]                 ; store old exception handler
       PUSH   EAX                                   ; and push it
       MOV    DWORD PTR FS:[0], ESP                 ; make our stack the new SEH
       MOV    DWORD PTR [0x10000000], 0x0           ; trigger SEH
    seh_handler:
       MOV EAX, 0x12345
       PUSH   0x1337BEEF                            ; clean exit value
       RET
    ''')

    # Set 'main' label's offset
    symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

    # Spread information and resolve instructions offset
    asm = asmblock.asm_resolve_final(mn_x86, blocs, symbol_pool)

    compiled = ''
    for key in sorted(asm):
        compiled += asm[key]
    return compiled

test_api()
test_taint_propagation()
test_callback()
