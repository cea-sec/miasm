# -*- coding: utf8 -*-

from miasm2.arch.x86.arch import mn_x86
from miasm2.core import parse_asm, asmblock
from miasm2.analysis.machine import Machine
import miasm2.jitter.csts as csts
import miasm2.analysis.taint_analysis as taint

# TODO: tests others jitter/arch

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

def assemble_code(code_str):
    # Assemble code to test
    blocs, symbol_pool = parse_asm.parse_txt(mn_x86, 32, code_str)

    # Set 'main' label's offset
    symbol_pool.set_offset(symbol_pool.getby_name("main"), 0x0)

    # Spread information and resolve instructions offset
    asm = asmblock.asm_resolve_final(mn_x86, blocs, symbol_pool)

    # TODO cleaner way to do this
    compiled = ''
    for key in sorted(asm):
        compiled += asm[key]
    return compiled

def taint_EAX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"], 0, 4)
    return True

def taint_AX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"], 0, 2)
    return True

def taint_EBX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RBX"], 0, 4)
    return True

def taint_ECX(jitter):
    jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RCX"], 0, 4)
    return True

def taint_ECX_blue(jitter):
    jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RCX"], 0, 4)
    return True

def taint_EDX_blue(jitter):
    jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RDX"], 0, 4)
    return True

def taint_mem_0x123FFE8(jitter):
    jitter.cpu.taint_memory(0x123FFe8,4,red)
    return True

def taint_mem_RAX(jitter):
    jitter.cpu.taint_memory(jitter.cpu.RAX,4,red)
    return True

def taint_mem_RBX(jitter):
    jitter.cpu.taint_memory(jitter.cpu.RBX,4,red)
    return True



def test_taint_propagation():
    """Test taint propagation
    Enumerate all taint propagation scenarios (at least basics and especially
    tricky ones) and test them.
    """

    print "[+] Test taint propagation"

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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RCX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 3
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 3
        assert regs[2][0] == jitter.jit.codegen.regs_index["RCX"]
        assert regs[2][1] == 0
        assert regs[2][2] == 3
        assert len(mems) == 2
        assert mems[0] == (0x123ffc8, 4)
        assert mems[1] == (0x123ffd0, 8)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        assert regs[0][0] == jitter.jit.codegen.regs_index["RDX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RCX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 3
        assert len(mems) == 1
        assert mems[0] == (0x123ffcc, 8)
        jitter.cpu.untaint_all()
        return True

    code_str = '''
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
    '''
    jitter = create_jitter()
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, assemble_code(code_str))

    # REG -> REG
    jitter.add_breakpoint(0x40000005, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x40000007, test_reg_taint_reg)# Check that RBX is tainted
    # REG -> MEM
    jitter.add_breakpoint(0x40000007, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x40000009, test_reg_taint_mem)# Check that [RBX] is tainted
    # MEM -> REG
    jitter.add_breakpoint(0x40000009, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x4000000B, test_mem_taint_reg)# Check that RBX is tainted
    # MEM -> MEM
    jitter.add_breakpoint(0x4000000B, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x4000000D, test_mem_taint_mem)# Check that [RSP] is tainted
    # ADDR -> REG
    jitter.add_breakpoint(0x4000000D, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x4000000F, test_addr_taint_reg)# Check that RBX is tainted
    # ADDR -> MEM
    jitter.add_breakpoint(0x4000000F, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x40000015, test_addr_taint_mem)# Check that [RAX] is tainted
    # UNTAINT REG
    jitter.add_breakpoint(0x40000015, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x4000001A, check_no_more_taint)# Check that RAX is untainted
    # Multiple taint and untaint
    jitter.add_breakpoint(0x4000001A, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(0x40000020, check_no_more_taint)# Check that [RAX] is untainted
    jitter.add_breakpoint(0x40000020, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x40000020, taint_mem_0x123FFE8) # Taint [0x123FFE8]
    jitter.add_breakpoint(0x40000020, taint_ECX) # Taint RCX
    jitter.add_breakpoint(0x40000021, test_pushad) # Check PUSHAD
    # Colors
    jitter.add_breakpoint(0x40000021, taint_EAX) # Taint RAX in red
    jitter.add_breakpoint(0x40000021, taint_EBX) # Taint RBX in red
    jitter.add_breakpoint(0x40000021, taint_ECX) # Taint RCX in red
    jitter.add_breakpoint(0x40000021, taint_ECX_blue) # Taint RCX in blue
    jitter.add_breakpoint(0x40000021, taint_EDX_blue) # Taint RDX in blue
    jitter.add_breakpoint(0x40000022, test_colors) # Test colors

    jitter.init_run(code_addr)
    jitter.continue_run()

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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0 # start
        assert regs[0][2] == 7 # end
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0 # start
        assert regs[1][2] == 7 # end
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0 # start
        assert regs[0][2] == 7 # end
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0 # start
        assert regs[1][2] == 7 # end
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        jitter.cpu.untaint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 1
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0 # start
        assert regs[0][2] == 7 # end
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0 # start
        assert regs[0][2] == 7 # end
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
        assert regs[0][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 7
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

    def nothing_tainted(jitter, color):
        no_reg_tainted(jitter, color)
        no_mem_tainted(jitter, color)

    def no_reg_tainted(jitter, color):
        last_regs = jitter.cpu.last_tainted_registers(color)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(color)
        assert not last_regs

    def no_mem_tainted(jitter, color):
        last_mem = jitter.cpu.last_tainted_memory(color)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(color)
        assert not last_mem

    def on_taint_register_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on taint register callback"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 1
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["RBX"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_reg_cb(red)
        jitter.cpu.disable_taint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
        return True

    def on_taint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix reg callback (taint/untaint)"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["zf"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        assert last_regs[1][0] == jitter.jit.codegen.regs_index["pf"]
        assert last_regs[1][1] == 0
        assert last_regs[1][2] == 3
        assert last_regs[2][0] == jitter.jit.codegen.regs_index["nf"]
        assert last_regs[2][1] == 0
        assert last_regs[2][2] == 3
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 2
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["of"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        assert last_regs[1][0] == jitter.jit.codegen.regs_index["cf"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_reg_cb(red)
        jitter.cpu.disable_taint_reg_cb(blue)

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
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["RBX"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_reg_cb(red)
        jitter.cpu.disable_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
        return True

    def on_untaint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix reg callback (taint/untaint) - Part. 2"

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["zf"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        assert last_regs[1][0] == jitter.jit.codegen.regs_index["pf"]
        assert last_regs[1][1] == 0
        assert last_regs[1][2] == 3
        assert last_regs[2][0] == jitter.jit.codegen.regs_index["nf"]
        assert last_regs[2][1] == 0
        assert last_regs[2][2] == 3
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 2
        assert last_regs[0][0] == jitter.jit.codegen.regs_index["of"]
        assert last_regs[0][1] == 0
        assert last_regs[0][2] == 3
        assert last_regs[1][0] == jitter.jit.codegen.regs_index["cf"]
        assert last_regs[1][1] == 0
        assert last_regs[1][2] == 3
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_reg_cb(red)
        jitter.cpu.disable_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
        return True


    def on_taint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on taint memory callback"

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x80000000,4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_taint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix mem callback (taint/untaint) - Part. 2"

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFF8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFEC, 4)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_taint_memory_handler_3(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix colors callback"

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFD8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        no_reg_tainted(jitter, blue)
        last_mem = jitter.cpu.last_tainted_memory(blue)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFCC, 4)
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
        return True

    def on_untaint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test on untaint memory callback"

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x80000000, 4)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_mem_cb(red)
        jitter.cpu.disable_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
        return True

    def on_untaint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        print "\t[+] Test mix mem callback (taint/untaint)"

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFF8, 4)
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert len(last_mem) == 1
        assert last_mem[0] == (0x123FFEC, 4)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_mem_cb(red)
        jitter.cpu.disable_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
        return True

    def second_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_memory_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_MEM, on_untaint_memory_handler_2)
        jitter.cpu.enable_taint_mem_cb(red)
        jitter.cpu.enable_taint_mem_cb(blue)
        jitter.cpu.enable_untaint_mem_cb(red)
        jitter.cpu.enable_untaint_mem_cb(blue)
        return True

    def third_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_register_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_register_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_REG, on_taint_register_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_REG, on_untaint_register_handler_2)
        jitter.cpu.enable_taint_reg_cb(red)
        jitter.cpu.enable_taint_reg_cb(blue)
        jitter.cpu.enable_untaint_reg_cb(red)
        jitter.cpu.enable_untaint_reg_cb(blue)
        return True

    def fourth_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler_3)
        jitter.cpu.enable_taint_mem_cb(red)
        jitter.cpu.enable_taint_mem_cb(blue)
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        return True

    global check_callback_occured
    check_callback_occured = 0

    code_str = '''
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
    '''

    jitter = create_jitter()
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, assemble_code(code_str))

    jitter.add_breakpoint(0x40000005, taint_EAX) # Taint RAX
    jitter.add_breakpoint(0x40000019, second_handlers)
    jitter.add_breakpoint(0x4000001C, third_handlers)
    jitter.add_breakpoint(0x4000001E, fourth_handlers)

    jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_REG, on_taint_register_handler)
    jitter.cpu.enable_taint_reg_cb(red)
    jitter.cpu.enable_taint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_REG, on_untaint_register_handler)
    jitter.cpu.enable_untaint_reg_cb(red)
    jitter.cpu.enable_untaint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_ADD_MEM, on_taint_memory_handler)
    jitter.cpu.enable_taint_mem_cb(red)
    jitter.cpu.enable_taint_mem_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_REMOVE_MEM, on_untaint_memory_handler)
    jitter.cpu.enable_untaint_mem_cb(red)
    jitter.cpu.enable_untaint_mem_cb(blue)

    jitter.init_run(code_addr)
    jitter.continue_run()
    assert check_callback_occured == 9

def test_propagation_precision():
    """Code aiming to test taint propagation precision
    Some corner cases need to be check. For example:
        MOV WORD PTR [EBX], AX
            with AX tainted
        In this case we want [@EBX TO @EBX+2] to be tainted and not
        [@EBX TO @EBX+4].
    """

    print "[+] Test taint propagation precision"

    def test_dst_mem_slice(jitter):

        print "\t[+] Test MOV WORD PTR [EBX], AX"

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert len(mems) == 1
        assert mems[0] == (0x80000000,2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all_memory()
        return True

    def test_dst_reg_slice(jitter):

        print "\t[+] Test MOV BX, AX"

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 2
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert regs[1][0] == jitter.jit.codegen.regs_index["RBX"]
        assert regs[1][1] == 0
        assert regs[1][2] == 1
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all()
        return True

    def test_src_slice(jitter):

        print "\t[+] Test MOV DWORD PTR [EBX], EAX"

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 1
        assert len(mems) == 1
        assert mems[0] == (0x80000000, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all()
        return True

    def test_untaint_src_slice(jitter):

        print "\t[+] Test MOV DWORD PTR [EBX], CX"

        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 1
        assert mems[0] == (0x80000002, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        return True

    def test_ah(jitter):

        print "\t[+] Test MOV DWORD PTR [EBX], AL"

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert len(mems) == 2
        assert mems[0] == (0x80000000, 1)
        assert mems[1] == (0x80000002, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        return True

    def stop_jitter(jitter):
        return False

    def test_multislice(jitter):

        # NOTE not managed for now
        print "\t[+] Test MOV ECX, DWORD PTR [EBX]"

        regs, mems = jitter.cpu.get_all_taint(red)
        print mems
        print regs
        assert len(regs) == 1
        assert regs[0][0] == jitter.jit.codegen.regs_index["RAX"]
        assert regs[0][1] == 0
        assert regs[0][2] == 3
        assert len(mems) == 2
        assert mems[0] == (0x80000002, 2)
        assert mems[1] == (0x80000005, 1)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        return True

    code_str = '''
    main:
       MOV    EBX, 0x80000000
       MOV    WORD PTR [EBX], AX                    ; should taint @16[EBX]
       MOV    BX, AX                                ; should taint BX
       MOV    DWORD PTR [EBX], EAX                  ; with only AX tainted (should taint @16[EBX])
       MOV    WORD PTR [EBX], CX                    ; should untaint @16[EBX]
       MOV    BYTE PTR [EBX], AL                    ; should taint @8[EBX]
       MOV    ECX, DWORD PTR [EBX]                  ; should taint EBX[0,2]+EBX[5,6]
       PUSH   0x1337BEEF                            ; clean exit value
       RET
    '''

    jitter = create_jitter()
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, assemble_code(code_str))

    jitter.add_breakpoint(0x40000000, taint_EAX)
    jitter.add_breakpoint(0x40000008, test_dst_mem_slice)
    jitter.add_breakpoint(0x4000000B, test_dst_reg_slice)
    jitter.add_breakpoint(0x4000000B, taint_AX)
    jitter.add_breakpoint(0x4000000D, test_src_slice)
    jitter.add_breakpoint(0x4000000D, taint_mem_RBX)
    jitter.add_breakpoint(0x40000010, test_untaint_src_slice)
    jitter.add_breakpoint(0x40000010, taint_EAX)
    jitter.add_breakpoint(0x40000012, test_ah)
    jitter.add_breakpoint(0x40000012, stop_jitter)
    jitter.add_breakpoint(0x40000015, test_multislice) # TODO, not working for now

    jitter.init_run(code_addr)
    jitter.continue_run()

test_api()
test_taint_propagation()
test_propagation_precision()
test_callback()
