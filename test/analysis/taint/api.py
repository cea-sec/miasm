from commons import *
from miasm.core.interval import interval

def test_api():
    """Test API
    Test all functions made available by the taint analysis engine
    """

    print("[+] Test API")

    jitter = create_jitter()

    def test_api_taint_register(jitter):
        """ Test jitter.taint.taint_register """

        print("\t[+] Test jitter.taint.taint_register")

        taint_register(jitter, blue, "RAX")
        taint_register(jitter, blue, "RBX")
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", interval([(0, 7)]))
        check_reg(regs[1], jitter, "RBX", interval([(0, 7)]))
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_register(jitter):
        """ Test jitter.taint.untaint_register """

        print("\t[+] Test jitter.taint.untaint_register")

        jitter.taint.untaint_register(blue, jitter.jit.codegen.regs_index["RCX"])
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", interval([(0, 7)]))
        check_reg(regs[1], jitter, "RBX", interval([(0, 7)]))
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems
        jitter.taint.untaint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", interval([(0, 7)]))
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems

    def test_api_untaint_all_registers_of_color(jitter):
        """ Test jitter.taint.untaint_all_registers_of_color """

        print("\t[+] Test jitter.taint.untaint_all_registers_of_color")

        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.taint.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.untaint_all_registers_of_color(blue)
        regs, mems = jitter.taint.get_all_taint(blue)
        assert not regs
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", interval([(0, 0xF)]))
        assert not mems
        jitter.taint.untaint_all_registers_of_color(red)
        no_more_taint(jitter)

    def test_api_untaint_all_registers(jitter):
        """ Test jitter.taint.untaint_all_registers """

        print("\t[+] Test jitter.taint.untaint_all_registers")

        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.taint.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.untaint_all_registers()
        no_more_taint(jitter)

    def test_api_taint_memory(jitter):
        """ Test jitter.taint.taint_memory """

        print("\t[+] Test jitter.taint.taint_memory")

        jitter.taint.taint_memory(data_addr,4,red)
        jitter.taint.taint_memory(data_addr+0x6,7,red)
        jitter.taint.taint_memory(data_addr+0x6,7,blue)
        regs, mems = jitter.taint.get_all_taint(blue)
        assert not regs
        check_mem(interval(mems), interval([(data_addr+0x6, data_addr+0x6+6)]))
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert len(mems) == 2
        check_mem(interval(mems), interval([(data_addr, data_addr+3), (data_addr+0x6, data_addr+0x6+6)]))

    def test_api_untaint_memory(jitter):
        """ Test jitter.taint.untaint_memory """

        print("\t[+] Test jitter.taint.untaint_memory")

        jitter.taint.untaint_memory(data_addr+0x7,3,red)
        regs, mems = jitter.taint.get_all_taint(blue)
        assert not regs
        check_mem(interval(mems), interval([(data_addr+0x6, data_addr+0x6+6)]))
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        check_mem(interval(mems), interval([(data_addr, data_addr+3), (data_addr+0x6, data_addr+0x6), (data_addr+0xa, data_addr+0xa+2)]))

    def test_api_untaint_all_memory_of_color(jitter):
        """ Test jitter.taint.untaint_all_memory_of_color """

        print("\t[+] Test jitter.taint.untaint_all_memory_of_color")

        jitter.taint.untaint_all_memory_of_color(red)
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.taint.get_all_taint(blue)
        assert not regs
        check_mem(interval(mems), interval([(data_addr+0x6, data_addr+0x6+6)]))
        jitter.taint.untaint_all_memory_of_color(blue)
        no_more_taint(jitter)

    def test_api_untaint_all_memory(jitter):
        """ Test jitter.taint.untaint_all_memory """

        print("\t[+] Test jitter.taint.untaint_all_memory")

        jitter.taint.taint_memory(data_addr,4,red)
        jitter.taint.taint_memory(data_addr+0x6,7,red)
        jitter.taint.taint_memory(data_addr+0x6,7,blue)
        jitter.taint.untaint_all_memory()
        no_more_taint(jitter)

    def test_api_untaint_all_of_color(jitter):
        """ Test jitter.taint.untaint_all_of_color """

        print("\t[+] Test jitter.taint.untaint_all_of_color")

        jitter.taint.taint_memory(data_addr,4,red)
        jitter.taint.taint_memory(data_addr+0x6,7,blue)
        jitter.taint.taint_register(red, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RBX"])
        jitter.taint.untaint_all_of_color(red)
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RBX", interval([(0, 0xF)]))
        check_mem(interval(mems), interval([(data_addr+0x6, data_addr+0x6+6)]))
        jitter.taint.untaint_all_of_color(blue)
        no_more_taint(jitter)

    def test_api_untaint_all(jitter):
        """ Test jitter.taint.untaint_all """

        print("\t[+] Test jitter.taint.untaint_all")

        jitter.taint.taint_memory(data_addr,4,red)
        jitter.taint.taint_register(blue, jitter.jit.codegen.regs_index["RAX"])
        jitter.taint.untaint_all()
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

