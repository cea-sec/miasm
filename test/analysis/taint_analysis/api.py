from commons import *

def test_api():
    """Test API
    Test all functions made available by the taint analysis engine
    """

    print("[+] Test API")

    jitter = create_jitter()

    def test_api_taint_register(jitter):
        """ Test jitter.cpu.taint_register """

        print("\t[+] Test jitter.cpu.taint_register")

        taint_register(jitter, blue, "RAX")
        taint_register(jitter, blue, "RBX")
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", 0, 7)
        check_reg(regs[1], jitter, "RBX", 0, 7)
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_register(jitter):
        """ Test jitter.cpu.untaint_register """

        print("\t[+] Test jitter.cpu.untaint_register")

        jitter.cpu.untaint_register(blue, jitter.jit.codegen.regs_index["RCX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", 0, 7)
        check_reg(regs[1], jitter, "RBX", 0, 7)
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        jitter.cpu.untaint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 7)
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_all_registers_of_color(jitter):
        """ Test jitter.cpu.untaint_all_registers_of_color """

        print("\t[+] Test jitter.cpu.untaint_all_registers_of_color")

        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all_registers_of_color(blue)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", 0, 7)
        assert not mems
        jitter.cpu.untaint_all_registers_of_color(red)
        no_more_taint(jitter)

    def test_api_untaint_all_registers(jitter):
        """ Test jitter.cpu.untaint_all_registers """

        print("\t[+] Test jitter.cpu.untaint_all_registers")

        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all_registers()
        no_more_taint(jitter)

    def test_api_taint_memory(jitter):
        """ Test jitter.cpu.taint_memory """

        print("\t[+] Test jitter.cpu.taint_memory")

        jitter.cpu.taint_memory(data_addr,4,red)
        jitter.cpu.taint_memory(data_addr+0x6,7,red)
        jitter.cpu.taint_memory(data_addr+0x6,7,blue)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        check_mem(mems[0], data_addr+0x6, 7)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 2
        check_mem(mems[0], data_addr, 4)
        check_mem(mems[1], data_addr+0x6, 7)

    def test_api_untaint_memory(jitter):
        """ Test jitter.cpu.untaint_memory """

        print("\t[+] Test jitter.cpu.untaint_memory")

        jitter.cpu.untaint_memory(data_addr+0x7,3,red)
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        check_mem(mems[0], data_addr+0x6, 7)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert len(mems) == 3
        check_mem(mems[0], data_addr, 4)
        check_mem(mems[1], data_addr+0x6, 1)
        check_mem(mems[2], data_addr+0xa, 3)

    def test_api_untaint_all_memory_of_color(jitter):
        """ Test jitter.cpu.untaint_all_memory_of_color """

        print("\t[+] Test jitter.cpu.untaint_all_memory_of_color")

        jitter.cpu.untaint_all_memory_of_color(red)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert not regs
        assert len(mems) == 1
        check_mem(mems[0], data_addr+0x6, 7)
        jitter.cpu.untaint_all_memory_of_color(blue)
        no_more_taint(jitter)

    def test_api_untaint_all_memory(jitter):
        """ Test jitter.cpu.untaint_all_memory """

        print("\t[+] Test jitter.cpu.untaint_all_memory")

        jitter.cpu.taint_memory(data_addr,4,red)
        jitter.cpu.taint_memory(data_addr+0x6,7,red)
        jitter.cpu.taint_memory(data_addr+0x6,7,blue)
        jitter.cpu.untaint_all_memory()
        no_more_taint(jitter)

    def test_api_untaint_all_of_color(jitter):
        """ Test jitter.cpu.untaint_all_of_color """

        print("\t[+] Test jitter.cpu.untaint_all_of_color")

        jitter.cpu.taint_memory(data_addr,4,red)
        jitter.cpu.taint_memory(data_addr+0x6,7,blue)
        jitter.cpu.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.cpu.untaint_all_of_color(red)
        regs, mems = jitter.cpu.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.cpu.get_all_taint(blue)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RBX", 0, 7)
        assert len(mems) == 1
        check_mem(mems[0], data_addr+0x6, 7)
        jitter.cpu.untaint_all_of_color(blue)
        no_more_taint(jitter)

    def test_api_untaint_all(jitter):
        """ Test jitter.cpu.untaint_all """

        print("\t[+] Test jitter.cpu.untaint_all")

        jitter.cpu.taint_memory(data_addr,4,red)
        jitter.cpu.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.cpu.untaint_all()
        no_more_taint(jitter)

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

