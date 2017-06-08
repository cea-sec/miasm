from commons import *

def test_taint_propagation():
    """Test taint propagation
    Enumerate all taint propagation scenarios (at least basics and especially
    tricky ones) and test them.
    """

    print "[+] Test taint propagation"

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
        check_reg(regs[0], jitter, "RAX", 0, 3)
        check_reg(regs[1], jitter, "RBX", 0, 3)
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
        check_reg(regs[0], jitter, "RAX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], data_addr, 4)
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
        check_reg(regs[0], jitter, "RBX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], data_addr, 4)
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
        check_mem(mems[0], 0x123FFF8, 4)
        check_mem(mems[1], data_addr, 4)
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
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", 0, 3)
        check_reg(regs[1], jitter, "RBX", 0, 3)
        assert not mems
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
        check_reg(regs[0], jitter, "RAX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], data_addr, 4)
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
        check_reg(regs[0], jitter, "RAX", 0, 3)
        check_reg(regs[1], jitter, "RCX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], 0x123FFF0, 8)
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
        check_reg(regs[0], jitter, "RAX", 0, 3)
        check_reg(regs[1], jitter, "RBX", 0, 3)
        check_reg(regs[2], jitter, "RCX", 0, 3)
        assert len(mems) == 2
        check_mem(mems[0], 0X123FFC8, 4)
        check_mem(mems[1], 0X123FFD0, 8)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RDX", 0, 3)
        check_reg(regs[1], jitter, "RCX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], 0X123FFCC, 8)
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
    jitter.add_breakpoint(code_addr+0x5, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0x7, test_reg_taint_reg)# Check that RBX is tainted
    # REG -> MEM
    jitter.add_breakpoint(code_addr+0x7, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0x9, test_reg_taint_mem)# Check that [RBX] is tainted
    # MEM -> REG
    jitter.add_breakpoint(code_addr+0x9, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(code_addr+0xB, test_mem_taint_reg)# Check that RBX is tainted
    # MEM -> MEM
    jitter.add_breakpoint(code_addr+0xB, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(code_addr+0xD, test_mem_taint_mem)# Check that [RSP] is tainted
    # ADDR -> REG
    jitter.add_breakpoint(code_addr+0xD, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0xF, test_addr_taint_reg)# Check that RBX is tainted
    # ADDR -> MEM
    jitter.add_breakpoint(code_addr+0xF, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0x15, test_addr_taint_mem)# Check that [RAX] is tainted
    # UNTAINT REG
    jitter.add_breakpoint(code_addr+0x15, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0x1A, no_more_taint)# Check that RAX is untainted
    # Multiple taint and untaint
    jitter.add_breakpoint(code_addr+0x1A, taint_mem_RAX) # Taint [RAX]
    jitter.add_breakpoint(code_addr+0x20, no_more_taint)# Check that [RAX] is untainted
    jitter.add_breakpoint(code_addr+0x20, taint_EAX) # Taint RAX
    jitter.add_breakpoint(code_addr+0x20, taint_mem_0x123FFE8) # Taint [0x123FFE8]
    jitter.add_breakpoint(code_addr+0x20, taint_ECX) # Taint RCX
    jitter.add_breakpoint(code_addr+0x21, test_pushad) # Check PUSHAD
    # Colors
    jitter.add_breakpoint(code_addr+0x21, taint_EAX) # Taint RAX in red
    jitter.add_breakpoint(code_addr+0x21, taint_EBX) # Taint RBX in red
    jitter.add_breakpoint(code_addr+0x21, taint_ECX) # Taint RCX in red
    jitter.add_breakpoint(code_addr+0x21, taint_ECX_blue) # Taint RCX in blue
    jitter.add_breakpoint(code_addr+0x21, taint_EDX_blue) # Taint RDX in blue
    jitter.add_breakpoint(code_addr+0x22, test_colors) # Test colors

    jitter.init_run(code_addr)
    jitter.continue_run()


