from commons import *
from miasm.core.interval import interval

def test_callbacks():
    """Test callback management
    Test the callback management done by the taint analysis engine
    """

    print("[+] Test callbacks")

    def on_taint_register_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000005
        print("\t[+] Test on taint register callback")

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "RBX", interval([(0, 3)]))
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert not last_regs
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_reg_cb(red)
        jitter.cpu.disable_taint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
        return True

    def on_taint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x4000001A
        print("\t[+] Test mix reg callback (taint/untaint)")

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        check_reg(last_regs[0], jitter, "zf", interval([(0, 0)]))
        check_reg(last_regs[2], jitter, "pf", interval([(0, 0)]))
        check_reg(last_regs[1], jitter, "nf", interval([(0, 0)]))
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "of", interval([(0, 0)]))
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_reg_cb(red)
        jitter.cpu.disable_taint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
        return True

    def on_untaint_register_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000007
        print("\t[+] Test on untaint register callback")

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert not last_regs
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "RBX", interval([(0, 3)]))
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_reg_cb(red)
        jitter.cpu.disable_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_REG))
        return True

    def on_untaint_register_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x4000001A
        print("\t[+] Test mix reg callback (taint/untaint) - Part. 2")

        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 3
        check_reg(last_regs[0], jitter, "zf", interval([(0, 0)]))
        check_reg(last_regs[2], jitter, "pf", interval([(0, 0)]))
        check_reg(last_regs[1], jitter, "nf", interval([(0, 0)]))
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "of", interval([(0, 0)]))
        no_mem_tainted(jitter, red)
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_reg_cb(red)
        jitter.cpu.disable_untaint_reg_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_REG))
        return True

    def on_taint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x4000000C
        print("\t[+] Test on taint memory callback")

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        check_mem(interval(last_mem), interval([(data_addr, data_addr+3)]))
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_MEM))
        return True

    def on_taint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000019
        print("\t[+] Test mix mem callback (taint/untaint) - Part. 2")

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        check_mem(interval(last_mem), interval([(0x123FFF8, 0x123FFF8+3)]))
        last_mem = jitter.cpu.last_untainted_memory(red)
        check_mem(interval(last_mem), interval([(0x123FFEC, 0x123FFEC+3)]))
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_MEM))
        return True

    def on_taint_memory_handler_3(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x4000001C
        print("\t[+] Test mix colors callback")

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        check_mem(interval(last_mem), interval([(0x123FFD8, 0x123FFD8+3)]))
        last_mem = jitter.cpu.last_untainted_memory(red)
        assert not last_mem
        no_reg_tainted(jitter, blue)
        last_mem = jitter.cpu.last_tainted_memory(blue)
        check_mem(interval(last_mem), interval([(0x123FFCC, 0x123FFCC+3)]))
        last_mem = jitter.cpu.last_untainted_memory(blue)
        assert not last_mem

        jitter.cpu.disable_taint_mem_cb(red)
        jitter.cpu.disable_taint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_MEM))
        return True

    def on_untaint_memory_handler(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x4000000E
        print("\t[+] Test on untaint memory callback")

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        assert not last_mem
        last_mem = jitter.cpu.last_untainted_memory(red)
        check_mem(interval(last_mem), interval([(data_addr, data_addr+3)]))
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_mem_cb(red)
        jitter.cpu.disable_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_MEM))
        return True

    def on_untaint_memory_handler_2(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000019
        print("\t[+] Test mix mem callback (taint/untaint)")

        no_reg_tainted(jitter, red)
        last_mem = jitter.cpu.last_tainted_memory(red)
        check_mem(interval(last_mem), interval([(0x123FFF8, 0x123FFF8+3)]))
        last_mem = jitter.cpu.last_untainted_memory(red)
        check_mem(interval(last_mem), interval([(0x123FFEC, 0x123FFEC+3)]))
        nothing_tainted(jitter, blue)

        jitter.cpu.disable_untaint_mem_cb(red)
        jitter.cpu.disable_untaint_mem_cb(blue)

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_MEM))
        return True

    def second_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_memory_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_MEM, on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_UNTAINT_MEM, on_untaint_memory_handler_2)
        jitter.cpu.enable_taint_mem_cb(red)
        jitter.cpu.enable_taint_mem_cb(blue)
        jitter.cpu.enable_untaint_mem_cb(red)
        jitter.cpu.enable_untaint_mem_cb(blue)
        return True

    def third_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_register_handler)
        jitter.exceptions_handler.remove_callback(on_untaint_register_handler)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REG, on_taint_register_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_UNTAINT_REG, on_untaint_register_handler_2)
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["of"], 0, 0)

        jitter.cpu.enable_taint_reg_cb(red)
        jitter.cpu.enable_taint_reg_cb(blue)
        jitter.cpu.enable_untaint_reg_cb(red)
        jitter.cpu.enable_untaint_reg_cb(blue)
        return True

    def fourth_handlers(jitter):
        jitter.exceptions_handler.remove_callback(on_taint_memory_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_MEM, on_taint_memory_handler_3)
        jitter.cpu.enable_taint_mem_cb(red)
        jitter.cpu.enable_taint_mem_cb(blue)
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        return True

    def LODSD_handlers(jitter):
        print("\t[+] LODSD")

        jitter.exceptions_handler.remove_callback(on_taint_register_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REG, on_taint_register_handler_3)
        jitter.cpu.enable_taint_reg_cb(blue)
        jitter.cpu.taint_memory(0x80000000,1,blue) # taint [ESI]
        return True

    def on_taint_register_handler_3(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000022
        last_regs = jitter.cpu.last_tainted_registers(blue)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "RAX", interval([(0, 0)]))

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
        return True

    def last_handlers(jitter):
        print("\t[+] Taint/untaint same register")

        jitter.exceptions_handler.remove_callback(on_taint_register_handler_3)
        jitter.exceptions_handler.remove_callback(on_untaint_register_handler_2)
        jitter.add_exception_handler(csts.EXCEPT_TAINT_REG, on_taint_register_handler_4)
        jitter.add_exception_handler(csts.EXCEPT_UNTAINT_REG, on_untaint_register_handler_4)

        jitter.cpu.enable_taint_reg_cb(red)
        jitter.cpu.enable_untaint_reg_cb(red)

        jitter.cpu.untaint_all()
        taint_AX(jitter)
        taint_register(jitter, red, "RBX", 0, 0)
        taint_register(jitter, red, "RBX", 2, 3)

        return True

    def on_taint_register_handler_4(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000023
        last_regs = jitter.cpu.last_tainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "RBX", interval([(0, 1)]))

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
        return True

    def on_untaint_register_handler_4(jitter):
        global check_callback_occured
        check_callback_occured += 1
        assert  jitter.cpu.EIP == 0x40000023
        last_regs = jitter.cpu.last_untainted_registers(red)
        assert len(last_regs) == 1
        check_reg(last_regs[0], jitter, "RBX", interval([(2, 3)]))

        jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_REG))
        return True

    global check_callback_occured
    check_callback_occured = 0

    code_str = '''
    main:
       MOV    EAX, 0x80000000
       MOV    EBX, EAX                              ; taint_reg_cb
       MOV    EBX, 0x80000000                        ; untaint_reg_cb
       MOV    DWORD PTR [EBX], EAX                  ; taint_mem_cb
       MOV    DWORD PTR [EBX], 0x0                  ; untaint_mem_cb
       MOV    DWORD PTR [0x123FFEC], EAX            ; preparation: taint EBX PUSHAD spot
       PUSHAD                                       ; taint_mem_cb + untaint_mem_cb
       TEST   EAX, EAX                              ; taint_reg_cb + untaint_reg_cb
       PUSHAD                                       ; multiple colors
       MOV    ESI, 0x80000000                       ; LODSD preparation
       LODSD                                        ;
       MOV    EBX, EAX                              ; should taint BX and untaint all the rest 
       PUSH   0x1337BEEF                            ; clean exit value
       RET
    '''

    jitter = create_jitter()
    
    jitter.vm.add_memory_page(code_addr, csts.PAGE_READ | csts.PAGE_WRITE, assemble_code(code_str))

    jitter.add_breakpoint(code_addr+0x5, taint_EAX) # Taint EAX
    jitter.add_breakpoint(code_addr+0x19, second_handlers)
    jitter.add_breakpoint(code_addr+0x1A, third_handlers)
    jitter.add_breakpoint(code_addr+0x1C, fourth_handlers)
    jitter.add_breakpoint(code_addr+0x1D, LODSD_handlers)
    jitter.add_breakpoint(code_addr+0x23, last_handlers)

    jitter.add_exception_handler(csts.EXCEPT_TAINT_REG, on_taint_register_handler)
    jitter.cpu.enable_taint_reg_cb(red)
    jitter.cpu.enable_taint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_UNTAINT_REG, on_untaint_register_handler)
    jitter.cpu.enable_untaint_reg_cb(red)
    jitter.cpu.enable_untaint_reg_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_TAINT_MEM, on_taint_memory_handler)
    jitter.cpu.enable_taint_mem_cb(red)
    jitter.cpu.enable_taint_mem_cb(blue)
    jitter.add_exception_handler(csts.EXCEPT_UNTAINT_MEM, on_untaint_memory_handler)
    jitter.cpu.enable_untaint_mem_cb(red)
    jitter.cpu.enable_untaint_mem_cb(blue)

    jitter.init_run(code_addr)
    jitter.continue_run()
    assert check_callback_occured == 12
