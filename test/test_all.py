import argparse
import time
import os

from utils.test import Test
from utils.testset import TestSet
from utils import cosmetics, monothread, screendisplay

testset = TestSet("../")
TAGS = {"regression": "REGRESSION", # Regression tests
        "example": "EXAMPLE", # Examples
        "long": "LONG", # Very time consumming tests
        "llvm": "LLVM", # LLVM dependency is required
        }

# Regression tests
class RegressionTest(Test):
    """Regression tests specificities:
    - @base_dir: test/@base_dir
    - @tags: TAGS["regression"]"""

    def __init__(self, *args, **kwargs):
        super(RegressionTest, self).__init__(*args, **kwargs)
        self.base_dir = os.path.join("test", self.base_dir)
        self.tags.append(TAGS["regression"])

## Architecture
testset += RegressionTest(["x86/arch.py"], base_dir="arch",
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
    testset += RegressionTest([script], base_dir="arch")
## Core
for script in ["interval.py",
               "graph.py",
               "parse_asm.py",
               ]:
    testset += RegressionTest([script], base_dir="core")
## Expression
for script in ["modint.py",
               "stp.py",
               "simplifications.py",
               "expression_helper.py",
               ]:
    testset += RegressionTest([script], base_dir="expression")
## IR
for script in ["ir2C.py",
               "symbexec.py",
               ]:
    testset += RegressionTest([script], base_dir="ir")
## OS_DEP
for script in ["win_api_x86_32.py",
               ]:
    testset += RegressionTest([script], base_dir="os_dep")

# Examples
class Example(Test):
    """Examples specificities:
    - @base_dir: example/@base_dir
    - @tags: TAGS["example"]"""

    def __init__(self, *args, **kwargs):
        super(Example, self).__init__(*args, **kwargs)
        self.base_dir = os.path.join("example", self.base_dir)
        self.tags.append(TAGS["example"])

## Assembler
testset += Example(['asm_x86.py'], products=["demo_x86_32.bin"])
test_arm = Example(["asm_arm.py"], products=["demo_arm_l.bin", "demo_arm_b.bin"])
test_armt = Example(["asm_armt.py"], products=["demo_armt_l.bin",
                                               "demo_armt_b.bin"])
test_box = Example(["asm_box_x86_32.py"], products=["box_x86_32.bin"])
test_box_enc = Example(["asm_box_x86_32_enc.py"],
                       products=["box_x86_32_enc.bin"])
test_box_mod = Example(["asm_box_x86_32_mod.py"],
                       products=["box_x86_32_mod.bin"])
test_box_mod_self = Example(["asm_box_x86_32_mod_self.py"],
                            products=["box_x86_32_mod_self.bin"])
test_box_repmod = Example(["asm_box_x86_32_repmod.py"],
                          products=["box_x86_32_repmod.bin"])
test_msp430 = Example(["asm_msp430_sc.py"], products=["msp430_sc.bin"])
test_mips32 = Example(["asm_mips32.py"], products=["mips32_sc_b.bin",
                                                   "mips32_sc_l.bin"])

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
    testset += Example(script)
## Expression
class ExampleTestDis(Example):
    """TestDis specificities:
    - script: test_dis.py
    - flags: -g -s -m
    - @products: graph_execflow.txt, graph_irflow.txt, lines.txt, out.txt
    """

    def __init__(self, *args, **kwargs):
        super(ExampleTestDis, self).__init__(*args, **kwargs)
        self.command_line = ["test_dis.py", "-g", "-s", "-m"] + \
            self.command_line
        self.products += ["graph_execflow.txt", "graph_irflow.txt", "lines.txt",
                          "out.txt"]

testset += ExampleTestDis(["arml", "demo_arm_l.bin", "0"], depends=[test_arm])
testset += ExampleTestDis(["armb", "demo_arm_b.bin", "0"], depends=[test_arm])
testset += ExampleTestDis(["armtl", "demo_armt_l.bin", "0"],
                   depends=[test_armt])
testset += ExampleTestDis(["armtb", "demo_armt_b.bin", "0"],
                   depends=[test_armt])
testset += ExampleTestDis(["x86_32", "box_x86_32.bin", "0x401000"],
                          depends=[test_box])
testset += ExampleTestDis(["msp430", "msp430_sc.bin", "0"],
                   depends=[test_msp430])
testset += ExampleTestDis(["mips32l", "mips32_sc_l.bin", "0"],
                          depends=[test_mips32])
testset += ExampleTestDis(["mips32b", "mips32_sc_b.bin", "0"],
                          depends=[test_mips32])

testset += Example(["expression/graph_dataflow.py",
                    "expression/sc_connect_back.bin", "0x2e"],
                   products=["data.txt"])
testset += Example(["expression/asm_to_ir.py"],
                   products=["graph.txt", "graph2.txt"])
testset += Example(["expression/get_read_write.py"],
                   products=["graph_instr.txt"])
testset += Example(["expression/solve_condition_stp.py",
                    "expression/simple_test.bin"],
                   products=["graph_instr.txt"])

for script in [["symbol_exec.py"],
               ["expression/basic_op.py"],
               ["expression/basic_simplification.py"],
               ["expression/simplification_tools.py"],
               ["expression/expr_grapher.py"],
               ["expression/simplification_add.py"],
               ["expression/expr_random.py"],
               ]:
    testset += Example(script)
## Jitter

for jitter in ["tcc", "llvm", "python"]:
    # Take 5 min on a Core i5
    tags = {"python": [TAGS["long"]],
            "llvm": [TAGS["llvm"]],
            }
    testset += Example(["unpack_upx.py", "box_upx.exe"] + ["--jitter", jitter],
                       products=["box_upx_exe_unupx.bin"],
                       tags=tags.get(jitter, []))

for script, dep in [(["test_jit_x86_32.py", "x86_32_sc.bin"], []),
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
        tags = [TAGS["llvm"]] if jitter == "llvm" else []
        testset += Example(script + ["--jitter", jitter],
                           depends=dep, tags=tags)


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Miasm2 testing tool")
    parser.add_argument("-m", "--mono", help="Force monothreading",
                        action="store_true")
    parser.add_argument("-c", "--coverage", help="Include code coverage",
                        action="store_true")
    parser.add_argument("-t", "--ommit-tags", help="Ommit tests based on tags \
(tag1,tag2). Available tags are %s. \
By default, no tag is ommited." % ", ".join(TAGS.keys()), default="")
    args = parser.parse_args()

    ## Parse multiproc argument
    multiproc = True
    if args.mono is True or args.coverage is True:
        multiproc = False

    ## Parse ommit-tags argument
    exclude_tags = []
    for tag in args.ommit_tags.split(","):
        if not tag:
            continue
        if tag not in TAGS:
            print "%(red)s[TAG]%(end)s" % cosmetics.colors, \
                "Unkown tag '%s'" % tag
            exit(-1)
        exclude_tags.append(TAGS[tag])

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
        if "llvm" not in exclude_tags:
            exclude_tags.append(TAGS["llvm"])

    # Set callbacks
    if multiproc is False:
        testset.set_callback(task_done=monothread.task_done,
                             task_new=monothread.task_new)
        testset.set_cpu_numbers(1)
    else:
        screendisplay.init(testset.cpu_c)
        testset.set_callback(task_done=screendisplay.task_done,
                             task_new=screendisplay.task_new)

    # Filter testset according to tags
    testset.filter_tags(exclude_tags=exclude_tags)

    # Run tests
    testset.run()

    # Exit with an error if at least a test failed
    exit(testset.tests_passed())
