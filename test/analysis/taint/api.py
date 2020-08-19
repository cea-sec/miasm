from commons import *
from miasm.core.interval import interval
from miasm.analysis.taint_helpers import taint, untaint
from miasm.expression.expression import ExprId, ExprMem, ExprInt

def test_api():
    """Test API
    Test all functions made available by the taint analysis engine
    """

    print("[+] Test API")

    jitter = create_jitter()

    def test_api_taint_register(jitter):
        """ Test jitter.taint.taint_register """

        print("\t[+] Test jitter.taint.taint_register")

        taint(jitter, ExprId("RAX", 64), blue)
        taint(jitter, ExprId("RBX", 64), blue)
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

        untaint(jitter, ExprId("RCX", 64), blue)
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 2
        check_reg(regs[0], jitter, "RAX", interval([(0, 7)]))
        check_reg(regs[1], jitter, "RBX", interval([(0, 7)]))
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems
        untaint(jitter, ExprId("RBX", 64), blue)
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

        taint(jitter, ExprId("RAX", 64), blue)
        taint(jitter, ExprId("RBX", 64), blue)
        taint(jitter, ExprId("RAX", 64), red)
        jitter.taint.untaint_all_registers_of_color(blue)
        regs, mems = jitter.taint.get_all_taint(blue)
        assert not regs
        assert not mems
        regs, mems = jitter.taint.get_all_taint(red)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RAX", interval([(0, 7)]))
        assert not mems
        jitter.taint.untaint_all_registers_of_color(red)
        no_more_taint(jitter)

    def test_api_untaint_all_registers(jitter):
        """ Test jitter.taint.untaint_all_registers """

        print("\t[+] Test jitter.taint.untaint_all_registers")

        taint(jitter, ExprId("RAX", 64), blue)
        taint(jitter, ExprId("RBX", 64), blue)
        taint(jitter, ExprId("RAX", 64), red)
        jitter.taint.untaint_all_registers()
        no_more_taint(jitter)

    def test_api_taint_memory(jitter):
        """ Test jitter.taint.taint_memory """

        print("\t[+] Test jitter.taint.taint_memory")

        taint(jitter, ExprMem(ExprInt(data_addr, 32), 32), red)
        taint(jitter, ExprMem(ExprInt(data_addr+0x6, 32), 56), red)
        taint(jitter, ExprMem(ExprInt(data_addr+0x6, 32), 56), blue)
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

        untaint(jitter, ExprMem(ExprInt(data_addr+0x7, 32), 24), red)
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

        taint(jitter, ExprMem(ExprInt(data_addr, 32), 32), red)
        taint(jitter, ExprMem(ExprInt(data_addr+0x6, 32), 64), red)
        taint(jitter, ExprMem(ExprInt(data_addr+0x6, 32), 64), blue)
        jitter.taint.untaint_all_memory()
        no_more_taint(jitter)

    def test_api_untaint_all_of_color(jitter):
        """ Test jitter.taint.untaint_all_of_color """

        print("\t[+] Test jitter.taint.untaint_all_of_color")

        taint(jitter, ExprMem(ExprInt(data_addr, 32), 32), red)
        taint(jitter, ExprMem(ExprInt(data_addr+0x6, 32), 64), blue)
        taint(jitter, ExprId("RAX", 64), red)
        taint(jitter, ExprId("RBX", 64), blue)
        jitter.taint.untaint_all_of_color(red)
        regs, mems = jitter.taint.get_all_taint(red)
        assert not regs
        assert not mems
        regs, mems = jitter.taint.get_all_taint(blue)
        assert len(regs) == 1
        check_reg(regs[0], jitter, "RBX", interval([(0, 0x7)]))
        check_mem(interval(mems), interval([(data_addr+0x6, data_addr+0x6+7)]))
        jitter.taint.untaint_all_of_color(blue)
        no_more_taint(jitter)

    def test_api_untaint_all(jitter):
        """ Test jitter.taint.untaint_all """

        print("\t[+] Test jitter.taint.untaint_all")

        taint(jitter, ExprMem(ExprInt(data_addr, 32), 32), red)
        taint(jitter, ExprId("RAX", 64), blue)
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

