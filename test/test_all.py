import argparse
import time
from utils.test import Test
from utils.testset import TestSet
from utils import cosmetics, monothread, screendisplay

testset = TestSet("../")

# Regression tests
## Architecture
testset += Test(["x86/arch.py"], base_dir="test/arch",
                products=["x86_speed_reg_test.bin",
                          "regression_test16_ia32.bin",
                          "regression_test32_ia32.bin",
                          "regression_test64_ia32.bin"])
for script in ["x86/sem.py",
               "x86/unit/mn_strings.py",
               "x86/unit/mn_float.py",
               "arm/arch.py",
               "arm/sem.py",
               "msp430/arch.py",
               "msp430/sem.py",
               "sh4/arch.py",
               "mips32/arch.py",
               ]:
    testset += Test([script], base_dir="test/arch")
## Core
for script in ["interval.py",
               "graph.py",
               "parse_asm.py",
               ]:
    testset += Test([script], base_dir="test/core")
## Expression
for script in ["modint.py",
               "stp.py",
               "simplifications.py",
               ]:
    testset += Test([script], base_dir="test/expression")
## IR
for script in ["ir2C.py",
               "symbexec.py",
               ]:
    testset += Test([script], base_dir="test/ir")
## OS_DEP
for script in ["win_api_x86_32.py",
               ]:
    testset += Test([script], base_dir="test/os_dep")
# Examples
## Assembler
testset += Test(['asm_x86.py'], base_dir="example",
                products=["demo_x86_32.bin"])
test_arm = Test(["asm_arm.py"], base_dir="example",
                products=["demo_arm_l.bin", "demo_arm_b.bin"])
test_armt = Test(["asm_armt.py"], base_dir="example",
                products=["demo_armt_l.bin", "demo_armt_b.bin"])
test_box = Test(["asm_box_x86_32.py"], base_dir="example",
                products=["box_x86_32.bin"])
test_box_enc = Test(["asm_box_x86_32_enc.py"], base_dir="example",
                    products=["box_x86_32_enc.bin"])
test_box_mod = Test(["asm_box_x86_32_mod.py"], base_dir="example",
                    products=["box_x86_32_mod.bin"])
test_box_mod_self = Test(["asm_box_x86_32_mod_self.py"], base_dir="example",
                         products=["box_x86_32_mod_self.bin"])
test_box_repmod = Test(["asm_box_x86_32_repmod.py"], base_dir="example",
                       products=["box_x86_32_repmod.bin"])
test_msp430 = Test(["asm_msp430_sc.py"], base_dir="example",
                   products=["msp430_sc.bin"])
test_mips32 = Test(["asm_mips32.py"], base_dir="example",
                   products=["mips32_sc_b.bin", "mips32_sc_l.bin"])

testset += test_arm
testset += test_armt
testset += test_box
testset += test_box_enc
testset += test_box_mod
testset += test_box_mod_self
testset += test_box_repmod
testset += test_msp430
testset += test_mips32
for script in [["disasm_01.py"],
               ["disasm_02.py"],
               ["disasm_03.py", "box_upx.exe", "0x410f90"],
               ]:
    testset += Test(script, base_dir="example")
## Expression
testset += Test(["test_dis.py", "-g", "-s", "-m", "arml", "demo_arm_l.bin", "0"],
                base_dir = "example", depends=[test_arm])
testset += Test(["test_dis.py", "-g", "-s", "-m", "armb", "demo_arm_b.bin", "0"],
                base_dir = "example", depends=[test_arm])
testset += Test(["test_dis.py", "-g", "-s", "-m", "armtl", "demo_armt_l.bin", "0"],
                base_dir = "example", depends=[test_armt])
testset += Test(["test_dis.py", "-g", "-s", "-m", "armtb", "demo_armt_b.bin", "0"],
                base_dir = "example", depends=[test_armt])
testset += Test(["test_dis.py", "-g", "-s", "-m", "x86_32", "box_x86_32.bin",
                 "0x401000"], base_dir="example", depends=[test_box])
testset += Test(["test_dis.py", "-g", "-s", "-m", "msp430", "msp430_sc.bin", "0"],
                base_dir = "example", depends=[test_msp430])
testset += Test(["test_dis.py", "-g", "-s", "-m", "mips32l", "mips32_sc_l.bin",
                 "0"], base_dir = "example", depends=[test_mips32])
testset += Test(["test_dis.py", "-g", "-s", "-m", "mips32b", "mips32_sc_b.bin",
                 "0"], base_dir = "example", depends=[test_mips32])
for script in [["symbol_exec.py"],
               ["expression/basic_op.py"],
               ["expression/get_read_write.py"],
               ["expression/basic_simplification.py"],
               ["expression/graph_dataflow.py",
                "expression/sc_connect_back.bin", "0x2e"],
               ["expression/simplification_tools.py"],
               ["expression/asm_to_ir.py"],
               ["expression/expr_grapher.py"],
               ["expression/simplification_add.py"],
               ["expression/solve_condition_stp.py",
                "expression/simple_test.bin"],
               ]:
    testset += Test(script, base_dir="example")
## Jitter
for script, dep in [(["unpack_upx.py", "box_upx.exe"], []), # Take 5 mins on a Core i5
                    (["test_jit_x86_32.py", "x86_32_sc.bin"], []),
                    (["test_jit_arm.py", "md5_arm", "-a", "A684"], []),
                    (["test_jit_msp430.py", "msp430_sc.bin", "0"],
                     [test_msp430]),
                    (["test_jit_mips32.py", "mips32_sc_l.bin", "0"],
                     [test_mips32]),
                    (["test_jit_arm_sc.py", "0", "demo_arm_b.bin", "b", "-a",
                      "0"], [test_arm]),
                    (["test_jit_arm_sc.py", "0", "demo_arm_l.bin", "l", "-a",
                      "0"], [test_arm]),
                    (["sandbox_pe_x86_32.py", "box_x86_32.bin"], [test_box]),
                    (["sandbox_pe_x86_32.py", "box_x86_32_enc.bin"],
                     [test_box_enc]),
                    (["sandbox_pe_x86_32.py", "box_x86_32_mod.bin"],
                     [test_box_mod]),
                    (["sandbox_pe_x86_32.py", "box_x86_32_repmod.bin"],
                     [test_box_repmod]),
                    (["sandbox_pe_x86_32.py", "box_x86_32_mod_self.bin"],
                     [test_box_mod_self]),
                    ]:
    for jitter in ["tcc", "llvm", "python"]:
        testset += Test(script + ["--jitter", jitter], base_dir="example",
                        depends=dep)


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Miasm2 testing tool")
    parser.add_argument("-m", "--mono", help="Force monothreading",
                        action="store_true")
    parser.add_argument("-c", "--coverage", help="Include code coverage",
                        action="store_true")
    args = parser.parse_args()

    multiproc = True
    if args.mono is True or args.coverage is True:
        multiproc = False

    # Handle coverage
    coveragerc = None
    if args.coverage is True:
        try:
            import coverage
        except ImportError:
            print "%(red)s[Coverage]%(end)s " % cosmetics.colors + \
                "Python 'coverage' module is required"
            exit(-1)

        # Create directory
        suffix = "_" + str(int(time.time()))
        cov_dir = tempfile.mkdtemp(suffix, "m2_coverage_")

        # Create configuration file
        coveragerc = os.path.join(cov_dir, ".coveragerc")
        coverage = os.path.join(cov_dir, ".coverage")

        from ConfigParser import ConfigParser
        from os.path import expanduser

        config = ConfigParser()
        config.read(['/etc/coveragerc', expanduser('~/.coveragerc')])
        if not config.has_section('run'):
            config.add_section('run')
        config.set('run', 'data_file', coverage)
        config.write(open(coveragerc, 'w'))

        # Add arguments to tests command line
        testset.add_additionnal_args(["-m", "coverage", "run", "--rcfile",
                                      coveragerc, "-a"])


        # Inform the user
        d = {"blue": cosmetics.colors['blue'],
             "end": cosmetics.colors['end'],
             "cov_dir": cov_dir}
        print "[%(blue)sCoverage%(end)s] Report will be written in %(cov_dir)s" % d

    # Handle llvm modularity
    llvm = True
    try:
        import llvm
    except ImportError:
        llvm = False

    # TODO XXX: fix llvm jitter (deactivated for the moment)
    llvm = False

    if llvm is False:
        print "%(red)s[LLVM]%(end)s Python" % cosmetics.colors + \
            "'py-llvm 3.2' module is required for llvm tests"

        # Remove llvm tests
        for test in testset.tests:
            if "llvm" in test.command_line:
                testset.tests.remove(test)
                print "%(red)s[LLVM]%(end)s Remove" % cosmetics.colors, \
                    " ".join(test.command_line)

        # Let the user see messages
        time.sleep(0.5)

    # Set callbacks
    if multiproc is False:
        testset.set_callback(task_done=monothread.task_done,
                             task_new=monothread.task_new)
        testset.set_cpu_numbers(1)
    else:
        screendisplay.init(testset.cpu_c)
        testset.set_callback(task_done=screendisplay.task_done,
                             task_new=screendisplay.task_new)

    # Run tests
    testset.run()

    # Exit with an error if at least a test failed
    exit(testset.tests_passed())
