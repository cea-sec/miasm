from commons import *

def test_propagation_precision():
    """Code aiming to test taint propagation precision
    Some corner cases need to be check. For example:
        MOV WORD PTR [EBX], AX
            with AX tainted
        In this case we want [@EBX TO @EBX+2] to be tainted and not
        [@EBX TO @EBX+4].
    """

    print("[+] Test taint propagation precision")

    def test_dst_mem_slice(jitter):

        print("\t[+] Test MOV WORD PTR [EBX], AX")

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 3)
        assert len(mems) == 1
        check_mem(mems[0], data_addr, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all_memory()
        return True

    def test_dst_reg_slice(jitter):

        print("\t[+] Test MOV BX, AX")

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", 0, 3)
        check_reg(regs[1], jitter, "RBX", 0, 1)
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all()
        return True

    def test_src_slice(jitter):

        print("\t[+] Test MOV DWORD PTR [EBX], EAX")

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 1)
        assert len(mems) == 1
        check_mem(mems[0], data_addr, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        jitter.cpu.untaint_all()
        return True

    def test_untaint_src_slice(jitter):

        print("\t[+] Test MOV DWORD PTR [EBX], CX")

        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 1
        check_mem(mems[0], data_addr+2, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        return True

    def test_ah(jitter):

        print("\t[+] Test MOV DWORD PTR [EBX], AL")

        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 3)
        assert len(mems) == 2
        check_mem(mems[0], data_addr, 1)
        check_mem(mems[1], data_addr+2, 2)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        return True

    def stop_jitter(jitter):
        # NOTE We are stopping the jitter before reachin the multipleslice
        # instruction that we do not handle yet.
        return False

    def test_multislice(jitter):

        # NOTE not managed for now
        print("\t[+] Test MOV ECX, DWORD PTR [EBX]")

        regs, mems = jitter.cpu.get_all_taint(red)
        print(mems) # debug
        print(regs) # debug
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 3)
        assert len(mems) == 2
        check_mem(mems[0], data_addr+2, 2)
        check_mem(mems[1], data_addr+5, 1)
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

    jitter.add_breakpoint(code_addr+0x0, taint_EAX)
    jitter.add_breakpoint(code_addr+0x8, test_dst_mem_slice)
    jitter.add_breakpoint(code_addr+0xB, test_dst_reg_slice)
    jitter.add_breakpoint(code_addr+0xB, taint_AX)
    jitter.add_breakpoint(code_addr+0xD, test_src_slice)
    jitter.add_breakpoint(code_addr+0xD, taint_mem_RBX)
    jitter.add_breakpoint(code_addr+0x10, test_untaint_src_slice)
    jitter.add_breakpoint(code_addr+0x10, taint_EAX)
    jitter.add_breakpoint(code_addr+0x12, test_ah)
    jitter.add_breakpoint(code_addr+0x12, stop_jitter)
    jitter.add_breakpoint(code_addr+0x15, test_multislice) # TODO not working for now

    jitter.init_run(code_addr)
    jitter.continue_run()

