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
        "z3": "Z3", # Z3 dependecy is needed
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


## Semantic
class SemanticTestAsm(RegressionTest):
    """Assemble an asm file"""

    shellcode_script = os.path.join("..", "example", "asm", "shellcode.py")
    container_dct = {"PE": "--PE"}

    def __init__(self, arch, container, *args, **kwargs):
        super(SemanticTestAsm, self).__init__(*args, **kwargs)
        sample_dir = os.path.join("samples", arch)
        base_filename = os.path.join(sample_dir, self.command_line[0])
        input_filename = base_filename + ".S"
        output_filename = base_filename + ".bin"
        self.command_line = [self.shellcode_script,
                             arch,
                             input_filename,
                             output_filename,
                             self.container_dct.get(container, '')]
        self.products = [output_filename, "graph.txt"]


class SemanticTestExec(RegressionTest):
    """Execute a binary file"""

    launcher_dct = {("PE", "x86_64"): "sandbox_pe_x86_64.py",
                    ("PE", "x86_32"): "sandbox_pe_x86_32.py",
                }
    launcher_base = os.path.join("..", "example", "jitter")

    def __init__(self, arch, container, address, *args, **kwargs):
        super(SemanticTestExec, self).__init__(*args, **kwargs)
        sample_dir = os.path.join("samples", arch)
        base_filename = os.path.join(sample_dir, self.command_line[0])
        input_filename = base_filename + ".bin"
        launcher = os.path.join(self.launcher_base,
                                self.launcher_dct[(container, arch)])
        self.command_line = [launcher,
                             input_filename,
                             "-a", hex(address)]
        self.products = []



test_x86_64_mul_div = SemanticTestAsm("x86_64", "PE", ["mul_div"])
test_x86_32_bsr_bsf = SemanticTestAsm("x86_32", "PE", ["bsr_bsf"])
testset += test_x86_64_mul_div
testset += test_x86_32_bsr_bsf
testset += SemanticTestExec("x86_64", "PE", 0x401000, ["mul_div"],
                            depends=[test_x86_64_mul_div])
testset += SemanticTestExec("x86_32", "PE", 0x401000, ["bsr_bsf"],
                            depends=[test_x86_32_bsr_bsf])

## Core
for script in ["interval.py",
               "graph.py",
               "parse_asm.py",
               "utils.py",
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
testset += RegressionTest(["z3_ir.py"], base_dir="ir/translators",
                          tags=[TAGS["z3"]])
## OS_DEP
for script in ["win_api_x86_32.py",
               ]:
    testset += RegressionTest([script], base_dir="os_dep")

## Analysis
testset += RegressionTest(["depgraph.py"], base_dir="analysis",
                          products=["graph_test_01_00.dot",
                                    "graph_test_02_00.dot",
                                    "graph_test_02_01.dot",
                                    "graph_test_03_00.dot",
                                    "graph_test_03_01.dot",
                                    "graph_test_04_00.dot",
                                    "graph_test_05_00.dot",
                                    "graph_test_06_00.dot",
                                    "graph_test_07_00.dot",
                                    "graph_test_08_00.dot",
                                    "graph_test_08_01.dot",
                                    "graph_test_09_00.dot",
                                    "graph_test_09_01.dot",
                                    "graph_test_10_00.dot",
                                    ] + ["graph_%02d.dot" % test_nb
                                         for test_nb in xrange(1, 11)])

# Examples
class Example(Test):
    """Examples specificities:
    - @base_dir: example/@base_dir
    - @tags: TAGS["example"]"""

    # Directory containing samples for examples
    sample_dir = os.path.join("..", "samples")
    example_dir = ""

    def __init__(self, *args, **kwargs):
        if not self.example_dir:
            raise NotImplementedError("ExampleDir should be inherited")
        super(Example, self).__init__(*args, **kwargs)
        self.base_dir = os.path.join(self.base_dir, "example", self.example_dir)
        self.tags.append(TAGS["example"])

    @classmethod
    def get_sample(cls, sample_name):
        "Return the relative path of @sample_name"
        return os.path.join(cls.sample_dir, sample_name)


## Assembler
class ExampleAssembler(Example):
    """Assembler examples specificities:
    - script path begins with "asm/"
    """
    example_dir = "asm"


testset += ExampleAssembler(["simple.py"])

class ExampleShellcode(ExampleAssembler):
    """Specificities:
    - script: asm/shellcode.py
    - @products: graph.txt + 3rd arg
    - apply get_sample on each products (!= graph.txt)
    - apply get_sample on the 2nd and 3rd arg (source, output)
    """

    def __init__(self, *args, **kwargs):
        super(ExampleShellcode, self).__init__(*args, **kwargs)
        self.command_line = ["shellcode.py",
                             self.command_line[0]] + \
                             map(Example.get_sample, self.command_line[1:3]) + \
                             self.command_line[3:]
        self.products = [self.command_line[3], "graph.txt"]

testset += ExampleShellcode(['x86_32', 'x86_32_manip_ptr.S', "demo_x86_32.bin"])

test_box = {}
test_box_names = ["mod", "mod_self", "repmod", "simple", "enc", "pop_esp"]
for source in test_box_names:
    sample_base = "x86_32_" + source
    args = ["x86_32", sample_base + ".S", sample_base + ".bin", "--PE"]
    if source == "enc":
        args += ["--encrypt","msgbox_encrypted_start", "msgbox_encrypted_stop"]
    test_box[source] = ExampleShellcode(args)
    testset += test_box[source]

test_armb = ExampleShellcode(["armb", "arm_simple.S", "demo_arm_b.bin"])
test_arml = ExampleShellcode(["arml", "arm_simple.S", "demo_arm_l.bin"])
test_armb_sc = ExampleShellcode(["armb", "arm_sc.S", "demo_arm2_b.bin"])
test_arml_sc = ExampleShellcode(["arml", "arm_sc.S", "demo_arm2_l.bin"])
test_armtb = ExampleShellcode(["armtb", "armt.S", "demo_armt_b.bin"])
test_armtl = ExampleShellcode(["armtl", "armt.S", "demo_armt_l.bin"])
test_msp430 = ExampleShellcode(["msp430", "msp430.S", "msp430_sc.bin"])
test_mips32b = ExampleShellcode(["mips32b", "mips32.S", "mips32_sc_b.bin"])
test_mips32l = ExampleShellcode(["mips32l", "mips32.S", "mips32_sc_l.bin"])
test_x86_64 = ExampleShellcode(["x86_64", "x86_64.S", "demo_x86_64.bin",
                                "--PE"])

testset += test_armb
testset += test_arml
testset += test_armb_sc
testset += test_arml_sc
testset += test_armtb
testset += test_armtl
testset += test_msp430
testset += test_mips32b
testset += test_mips32l
testset += test_x86_64

class ExampleDisassembler(Example):
    """Disassembler examples specificities:
    - script path begins with "disasm/"
    """
    example_dir = "disasm"


for script, prods in [(["single_instr.py"], []),
                      (["function.py"], ["graph.txt"]),
                      (["file.py", Example.get_sample("box_upx.exe"),
                        "0x410f90"], ["graph.txt"]),
                      ]:
    testset += ExampleDisassembler(script, products=prods)


class ExampleDisasmFull(ExampleDisassembler):
    """DisasmFull specificities:
    - script: disasm/full.py
    - flags: -g -s
    - @products: graph_execflow.txt, graph_irflow.txt, lines.txt, out.txt
    """

    def __init__(self, *args, **kwargs):
        super(ExampleDisasmFull, self).__init__(*args, **kwargs)
        self.command_line = ["full.py", "-g", "-s"] + self.command_line
        self.products += ["graph_execflow.txt", "graph_irflow.txt", "lines.txt"]


testset += ExampleDisasmFull(["arml", Example.get_sample("demo_arm_l.bin"),
                              "0"], depends=[test_arml])
testset += ExampleDisasmFull(["armb", Example.get_sample("demo_arm_b.bin"),
                              "0"], depends=[test_armb])
testset += ExampleDisasmFull(["arml", Example.get_sample("demo_arm2_l.bin"),
                              "0"], depends=[test_arml_sc])
testset += ExampleDisasmFull(["armb", Example.get_sample("demo_arm2_b.bin"),
                              "0"], depends=[test_armb_sc])
testset += ExampleDisasmFull(["armtl", Example.get_sample("demo_armt_l.bin"),
                              "0"], depends=[test_armtl])
testset += ExampleDisasmFull(["armtb", Example.get_sample("demo_armt_b.bin"),
                              "0"], depends=[test_armtb])
testset += ExampleDisasmFull(["x86_32", Example.get_sample("x86_32_simple.bin"),
                              "0x401000"], depends=[test_box["simple"]])
testset += ExampleDisasmFull(["msp430", Example.get_sample("msp430_sc.bin"),
                              "0"], depends=[test_msp430])
testset += ExampleDisasmFull(["mips32l", Example.get_sample("mips32_sc_l.bin"),
                              "0"], depends=[test_mips32l])
testset += ExampleDisasmFull(["mips32b", Example.get_sample("mips32_sc_b.bin"),
                              "0"], depends=[test_mips32b])
testset += ExampleDisasmFull(["x86_64", Example.get_sample("demo_x86_64.bin"),
                              "0x401000"], depends=[test_x86_64])


## Expression
class ExampleExpression(Example):
    """Expression examples specificities:
    - script path begins with "expression/"
    """
    example_dir = "expression"


testset += ExampleExpression(["graph_dataflow.py",
                              Example.get_sample("sc_connect_back.bin"),
                              "0x2e"],
                             products=["data.txt"])
testset += ExampleExpression(["asm_to_ir.py"],
                             products=["graph.txt", "graph2.txt"])
testset += ExampleExpression(["get_read_write.py"],
                             products=["graph_instr.txt"])
testset += ExampleExpression(["solve_condition_stp.py",
                              Example.get_sample("simple_test.bin")],
                             products=["graph_instr.txt", "out.txt"])

for script in [["basic_op.py"],
               ["basic_simplification.py"],
               ["simplification_tools.py"],
               ["expr_grapher.py"],
               ["simplification_add.py"],
               ["expr_random.py"],
               ["expr_translate.py"],
               ]:
    testset += ExampleExpression(script)

## Symbolic Execution
class ExampleSymbolExec(Example):
    """Symbol Exec examples specificities:
    - script path begins with "symbol_exec/"
    """

    example_dir = "symbol_exec"


testset += ExampleSymbolExec(["single_instr.py"])

## Jitter
class ExampleJitter(Example):
    """Jitter examples specificities:
    - script path begins with "jitter/"
    """
    example_dir = "jitter"
    jitter_engines = ["tcc", "llvm", "python"]


for jitter in ExampleJitter.jitter_engines:
    # Take 5 min on a Core i5
    tags = {"python": [TAGS["long"]],
            "llvm": [TAGS["llvm"]],
            }
    testset += ExampleJitter(["unpack_upx.py",
                              Example.get_sample("box_upx.exe")] +
                             ["--jitter", jitter],
                             products=[Example.get_sample("box_upx_exe_unupx.bin")],
                             tags=tags.get(jitter, []))

for script, dep in [(["x86_32.py", Example.get_sample("x86_32_sc.bin")], []),
                    (["arm.py", Example.get_sample("md5_arm"), "-a", "A684"],
                     []),
                    (["msp430.py", Example.get_sample("msp430_sc.bin"), "0"],
                     [test_msp430]),
                    (["mips32.py", Example.get_sample("mips32_sc_l.bin"), "0"],
                     [test_mips32l]),
                    (["arm_sc.py", "0", Example.get_sample("demo_arm_b.bin"),
                      "b", "-a", "0"], [test_armb]),
                    (["arm_sc.py", "0", Example.get_sample("demo_arm_l.bin"),
                      "l", "-a", "0"], [test_arml]),
                    ] + [(["sandbox_pe_x86_32.py",
                           Example.get_sample("x86_32_" + name + ".bin")],
                          [test_box[name]])
                         for name in test_box_names]:
    for jitter in ExampleJitter.jitter_engines:
        tags = [TAGS["llvm"]] if jitter == "llvm" else []
        testset += ExampleJitter(script + ["--jitter", jitter], depends=dep,
                                 tags=tags)


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
        if TAGS["llvm"] not in exclude_tags:
            exclude_tags.append(TAGS["llvm"])

    # Handle Z3 dependency
    try:
        import z3
    except ImportError:
        print "%(red)s[Z3]%(end)s " % cosmetics.colors + \
            "Z3 and its python binding are necessary for TranslatorZ3."
        if TAGS["z3"] not in exclude_tags:
            exclude_tags.append(TAGS["z3"])

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
