import argparse
import time
import os
import tempfile

from utils.test import Test
from utils.testset import TestSet
from utils import cosmetics, multithread
from multiprocessing import Queue

testset = TestSet("../")
TAGS = {"regression": "REGRESSION", # Regression tests
        "example": "EXAMPLE", # Examples
        "long": "LONG", # Very time consumming tests
        "llvm": "LLVM", # LLVM dependency is required
        "tcc": "TCC", # TCC dependency is required
        "z3": "Z3", # Z3 dependecy is needed
        "qemu": "QEMU", # QEMU tests (several tests)
        }

# Regression tests
class RegressionTest(Test):
    """Regression tests specificities:
    - @base_dir: test/@base_dir
    - @tags: TAGS["regression"]"""

    sample_dir = os.path.join("..", "samples")

    def __init__(self, *args, **kwargs):
        super(RegressionTest, self).__init__(*args, **kwargs)
        self.base_dir = os.path.join("test", self.base_dir)
        self.tags.append(TAGS["regression"])

    @classmethod
    def get_sample(cls, sample_name):
        "Return the relative path of @sample_name"
        return os.path.join(cls.sample_dir, sample_name)
## Architecture
testset += RegressionTest(["x86/arch.py"], base_dir="arch",
                          products=["x86_speed_reg_test.bin",
                                    "regression_test16_ia32.bin",
                                    "regression_test32_ia32.bin",
                                    "regression_test64_ia32.bin"])



### ArchUnit regression tests
class ArchUnitTest(RegressionTest):
    """Test against arch unit regression tests"""

    jitter_engines = ["tcc", "llvm", "gcc"]

    def __init__(self, script, jitter ,*args, **kwargs):
        super(ArchUnitTest, self).__init__([script, jitter], *args, **kwargs)


for script in ["x86/sem.py",
               "x86/unit/mn_strings.py",
               "x86/unit/mn_float.py",
               "x86/unit/mn_stack.py",
               "x86/unit/mn_daa.py",
               "x86/unit/mn_das.py",
               "x86/unit/mn_int.py",
               "x86/unit/mn_pshufb.py",
               "x86/unit/mn_psrl_psll.py",
               "x86/unit/mn_pmaxu.py",
               "x86/unit/mn_pminu.py",
               "x86/unit/mn_pcmpeq.py",
               "x86/unit/mn_punpck.py",
               "x86/unit/mn_pinsr.py",
               "x86/unit/mn_pextr.py",
               "x86/unit/mn_pmovmskb.py",
               "x86/unit/mn_pushpop.py",
               "arm/arch.py",
               "arm/sem.py",
               "aarch64/unit/mn_ubfm.py",
               "aarch64/arch.py",
               "msp430/arch.py",
               "msp430/sem.py",
               "sh4/arch.py",
               "mips32/arch.py",
               "mips32/unit/mn_bcc.py",
               ]:
    for jitter in ArchUnitTest.jitter_engines:
        tags = [TAGS[jitter]] if jitter in TAGS else []
        testset += ArchUnitTest(script, jitter, base_dir="arch", tags=tags)

### QEMU regression tests
class QEMUTest(RegressionTest):
    """Test against QEMU regression tests
    An expected output is provided, computed on a x86 host"""

    SCRIPT_NAME = "testqemu.py"
    SAMPLE_NAME = "test-i386"
    EXPECTED_PATH = "expected"
    jitter_engines = ["tcc", "llvm", "python", "gcc"]

    def __init__(self, name, jitter, *args, **kwargs):
        super(QEMUTest, self).__init__([self.SCRIPT_NAME], *args, **kwargs)
        self.base_dir = os.path.join(self.base_dir, "arch", "x86", "qemu")
        test_name = "test_%s" % name
        expected_output = os.path.join(self.EXPECTED_PATH, test_name) + ".exp"
        self.command_line += [self.SAMPLE_NAME,
                              test_name,
                              expected_output,
                              "--jitter",
                              jitter,
        ]
        self.tags.append(TAGS["qemu"])


# Test name -> supported jitter engines
QEMU_TESTS = [
    # Operations
    "btr",
    "bts",
    "bt",
    "shrd",
    "shld",
    "rcl",
    "rcr",
    "ror",
    "rol",
    "sar",
    "shr",
    "shl",
    "not",
    "neg",
    "dec",
    "inc",
    "sbb",
    "adc",
    "cmp",
    "or",
    "and",
    "xor",
    "sub",
    "add",
    # Specifics
    "bsx",
    "mul",
    "jcc",
    "loop",
    "lea",
    "self_modifying_code",
    "conv",
    "bcd",
    "xchg",
    "string",
    "misc",
    # Unsupported
    # "floats", "segs", "code16", "exceptions", "single_step"
]


for test_name in QEMU_TESTS:
    for jitter in QEMUTest.jitter_engines:
        tags = [TAGS[jitter]] if jitter in TAGS else []
        testset += QEMUTest(test_name, jitter, tags=tags)


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
        self.products = [output_filename, "graph.dot"]


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
        self.tags.append(TAGS["tcc"])


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
               "sembuilder.py",
               "test_types.py",
               ]:
    testset += RegressionTest([script], base_dir="core")
testset += RegressionTest(["asmbloc.py"], base_dir="core",
                          products=["graph.dot", "graph2.dot",
                                    "graph3.dot", "graph4.dot"])
## Expression
for script in ["modint.py",
               "expression.py",
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
testset += RegressionTest(["analysis.py"], base_dir="ir",
                          products=[fname for fnames in (
            ["simp_graph_%02d.dot" % test_nb, "graph_%02d.dot" % test_nb]
            for test_nb in xrange(1, 18))
                                    for fname in fnames])
testset += RegressionTest(["z3_ir.py"], base_dir="ir/translators",
                          tags=[TAGS["z3"]])
testset += RegressionTest(["smt2.py"], base_dir="ir/translators",
                          tags=[TAGS["z3"]])
## OS_DEP
for script in ["win_api_x86_32.py",
               ]:
    testset += RegressionTest([script], base_dir="os_dep", tags=[TAGS['tcc']])

## Analysis
testset += RegressionTest(["depgraph.py"], base_dir="analysis",
                          products=[fname for fnames in (
                              ["graph_test_%02d_00.dot" % test_nb,
                               "exp_graph_test_%02d_00.dot" % test_nb,
                               "graph_%02d.dot" % test_nb]
                              for test_nb in xrange(1, 18))
                                    for fname in fnames] +
                          [fname for fnames in (
                              ["graph_test_%02d_%02d.dot" % (test_nb, res_nb),
                               "exp_graph_test_%02d_%02d.dot" % (test_nb,
                                                                 res_nb)]
                              for (test_nb, res_nb) in ((3, 1), (5, 1), (8, 1),
                                                        (9, 1), (10, 1),
                                                        (12, 1), (13, 1),
                                                        (14, 1), (15, 1)))
                           for fname in fnames])

## Degraph
class TestDepgraph(RegressionTest):
    """Dependency graph test"""
    example_depgraph = os.path.join("..", "..", "example", "symbol_exec",
                                    "depgraph.py")
    launcher = "dg_check.py"


    def __init__(self, test_nb, implicit, base_addr, target_addr, elements,
                 *args, **kwargs):
        super(TestDepgraph, self).__init__([self.launcher],
                                           *args, **kwargs)
        self.base_dir = os.path.join(self.base_dir, "analysis")
        if implicit:
            expected_fname = "dg_test_%.2d_implicit_expected.json"
            self.tags.append(TAGS["z3"])
        else:
            expected_fname = "dg_test_%.2d_expected.json"

        self.command_line += [
            expected_fname % test_nb,
            self.example_depgraph,
            "-m", "x86_32",
            "--json",
            self.get_sample(os.path.join("x86_32",
                                         "dg_test_%.2d.bin" % test_nb)),
            hex(base_addr),
            hex(target_addr)] + elements
        if implicit:
            self.command_line.append("-i")

# Depgraph emulation regression test
test_args = [(0x401000, 0x40100d, ["EAX"]),
             (0x401000, 0x401011, ["EAX"]),
             (0x401000, 0x401018, ["EAX"]),
             (0x401000, 0x401011, ["EAX"]),
             (0x401000, 0x401011, ["EAX"]),
             (0x401000, 0x401016, ["EAX"]),
             (0x401000, 0x401017, ["EAX"]),
             (0x401000, 0x401012, ["EAX", "ECX"]),
             (0x401000, 0x401012, ["ECX"]),
             (0x401000, 0x40101f, ["EAX", "EBX"]),
             (0x401000, 0x401025, ["EAX", "EBX"]),
]
for i, test_args in enumerate(test_args):
    test_dg = SemanticTestAsm("x86_32", "PE", ["dg_test_%.2d" % i])
    testset += test_dg
    testset += TestDepgraph(i, False, *test_args, depends=[test_dg])
    testset += TestDepgraph(i, True, *test_args, depends=[test_dg])

## Jitter
for script in ["jitload.py",
               ]:
    testset += RegressionTest([script], base_dir="jitter", tags=[TAGS["tcc"]])


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
    - @products: graph.dot + 3rd arg
    - apply get_sample on each products (!= graph.dot)
    - apply get_sample on the 2nd and 3rd arg (source, output)
    """

    def __init__(self, *args, **kwargs):
        super(ExampleShellcode, self).__init__(*args, **kwargs)
        self.command_line = ["shellcode.py",
                             self.command_line[0]] + \
                             map(Example.get_sample, self.command_line[1:3]) + \
                             self.command_line[3:]
        self.products = [self.command_line[3], "graph.dot"]

testset += ExampleShellcode(['x86_32', 'x86_32_manip_ptr.S', "demo_x86_32.bin"])

test_box = {}
test_box_names = ["mod", "mod_self", "repmod", "simple", "enc", "pop_esp", "automod"]
for source in test_box_names:
    sample_base = "x86_32_" + source
    args = ["x86_32", sample_base + ".S", sample_base + ".bin", "--PE"]
    if source == "enc":
        args += ["--encrypt","msgbox_encrypted_start", "msgbox_encrypted_stop"]
    test_box[source] = ExampleShellcode(args)
    testset += test_box[source]

test_armb = ExampleShellcode(["armb", "arm_simple.S", "demo_arm_b.bin"])
test_arml = ExampleShellcode(["arml", "arm_simple.S", "demo_arm_l.bin"])
test_aarch64b = ExampleShellcode(["aarch64b", "aarch64_simple.S", "demo_aarch64_b.bin"])
test_aarch64l = ExampleShellcode(["aarch64l", "aarch64_simple.S", "demo_aarch64_l.bin"])
test_armb_sc = ExampleShellcode(["armb", "arm_sc.S", "demo_arm2_b.bin"])
test_arml_sc = ExampleShellcode(["arml", "arm_sc.S", "demo_arm2_l.bin"])
test_armtb = ExampleShellcode(["armtb", "armt.S", "demo_armt_b.bin"])
test_armtl = ExampleShellcode(["armtl", "armt.S", "demo_armt_l.bin"])
test_msp430 = ExampleShellcode(["msp430", "msp430.S", "msp430_sc.bin"])
test_mips32b = ExampleShellcode(["mips32b", "mips32.S", "mips32_sc_b.bin"])
test_mips32l = ExampleShellcode(["mips32l", "mips32.S", "mips32_sc_l.bin"])
test_x86_64 = ExampleShellcode(["x86_64", "x86_64.S", "demo_x86_64.bin",
                                "--PE"])
test_x86_32_if_reg = ExampleShellcode(['x86_32', 'x86_32_if_reg.S', "x86_32_if_reg.bin"])

testset += test_armb
testset += test_arml
testset += test_aarch64b
testset += test_aarch64l
testset += test_armb_sc
testset += test_arml_sc
testset += test_armtb
testset += test_armtl
testset += test_msp430
testset += test_mips32b
testset += test_mips32l
testset += test_x86_64
testset += test_x86_32_if_reg

class ExampleDisassembler(Example):
    """Disassembler examples specificities:
    - script path begins with "disasm/"
    """
    example_dir = "disasm"


for script, prods in [(["single_instr.py"], []),
                      (["callback.py"], []),
                      (["function.py"], ["graph.dot"]),
                      (["file.py", Example.get_sample("box_upx.exe"),
                        "0x407570"], ["graph.dot"]),
                      (["full.py", Example.get_sample("box_upx.exe")],
                       ["graph_execflow.dot", "lines.dot"]),
                      ]:
    testset += ExampleDisassembler(script, products=prods)


class ExampleDisasmFull(ExampleDisassembler):
    """DisasmFull specificities:
    - script: disasm/full.py
    - flags: -g -s
    - @products: graph_execflow.dot, graph_irflow.dot, graph_irflow_raw.dot,
                 lines.dot, out.dot
    """

    def __init__(self, *args, **kwargs):
        super(ExampleDisasmFull, self).__init__(*args, **kwargs)
        self.command_line = ["full.py", "-g", "-s", "-m"] + self.command_line
        self.products += ["graph_execflow.dot", "graph_irflow.dot",
                          "graph_irflow_raw.dot", "lines.dot"]


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
testset += ExampleDisasmFull(["aarch64l", Example.get_sample("demo_aarch64_l.bin"),
                              "0"], depends=[test_aarch64l])
testset += ExampleDisasmFull(["aarch64b", Example.get_sample("demo_aarch64_b.bin"),
                              "0"], depends=[test_aarch64b])
testset += ExampleDisasmFull(["x86_32", Example.get_sample("x86_32_simple.bin"),
                              "0x401000"], depends=[test_box["simple"]])
testset += ExampleDisasmFull(["x86_32", Example.get_sample("x86_32_if_reg.bin"),
                              "0x0"], depends=[test_x86_32_if_reg])
testset += ExampleDisasmFull(["msp430", Example.get_sample("msp430_sc.bin"),
                              "0"], depends=[test_msp430])
testset += ExampleDisasmFull(["mips32l", Example.get_sample("mips32_sc_l.bin"),
                              "0"], depends=[test_mips32l])
testset += ExampleDisasmFull(["mips32b", Example.get_sample("mips32_sc_b.bin"),
                              "0"], depends=[test_mips32b])
testset += ExampleDisasmFull(["x86_64", Example.get_sample("demo_x86_64.bin"),
                              "0x401000"], depends=[test_x86_64])
testset += ExampleDisasmFull(["aarch64l", Example.get_sample("md5_aarch64l"),
                              "0x400A00"], depends=[test_aarch64l])
testset += ExampleDisasmFull(["x86_32", os.path.join("..", "..", "test",
                                                     "arch", "x86", "qemu",
                                                     "test-i386"),
                              "func_iret"])


## Expression
class ExampleExpression(Example):
    """Expression examples specificities:
    - script path begins with "expression/"
    """
    example_dir = "expression"


for args in [[], ["--symb"]]:
    testset += ExampleExpression(["graph_dataflow.py",
                                  Example.get_sample("sc_connect_back.bin"),
                                  "0x2e"] + args,
                                 products=["data.dot"])
testset += ExampleExpression(["asm_to_ir.py"],
                             products=["graph.dot", "graph2.dot"])
testset += ExampleExpression(["get_read_write.py"],
                             products=["graph_instr.dot"])
testset += ExampleExpression(["solve_condition_stp.py",
                              Example.get_sample("simple_test.bin")],
                             products=["graph_instr.dot", "out.dot"])

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
for options, nb_sol, tag in [([], 8, []),
                             (["-i", "--rename-args"], 12, [TAGS["z3"]])]:
    testset += ExampleSymbolExec(["depgraph.py",
                                  Example.get_sample("simple_test.bin"),
                                  "-m", "x86_32", "0x0", "0x8b",
                                  "EAX"] + options,
                                 products=["sol_%d.dot" % nb
                                           for nb in xrange(nb_sol)],
                                 tags=tag)

for options, nb_sol, tag in [([], 4, []),
                             (["-i", "--rename-args"], 4, [TAGS["z3"]])]:
    testset += ExampleSymbolExec(["depgraph.py",
                                  Example.get_sample("x86_32_if_reg.bin"),
                                  "-m", "x86_32", "0x0", "0x19",
                                  "EAX"] + options,
                                 products=["sol_%d.dot" % nb
                                           for nb in xrange(nb_sol)],
                                 depends=[test_x86_32_if_reg],
                                 tags=tag)

## Jitter
class ExampleJitter(Example):
    """Jitter examples specificities:
    - script path begins with "jitter/"
    """
    example_dir = "jitter"
    jitter_engines = ["tcc", "llvm", "python", "gcc"]


for jitter in ExampleJitter.jitter_engines:
    # Take 5 min on a Core i5
    tags = {"python": [TAGS["long"]],
            "llvm": [TAGS["llvm"]],
            "tcc": [TAGS["tcc"]],
            }
    testset += ExampleJitter(["unpack_upx.py",
                              Example.get_sample("box_upx.exe")] +
                             ["--jitter", jitter],
                             products=[Example.get_sample("box_upx_exe_unupx.bin")],
                             tags=tags.get(jitter, []))

for script, dep in [(["x86_32.py", Example.get_sample("x86_32_sc.bin")], []),
                    (["arm.py", Example.get_sample("md5_arm"), "-a", "A684"],
                     []),
                    (["sandbox_elf_aarch64l.py", Example.get_sample("md5_aarch64l"), "-a", "0x400A00"],
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
        tags = [TAGS[jitter]] if jitter in TAGS else []
        testset += ExampleJitter(script + ["--jitter", jitter], depends=dep,
                                 tags=tags)

testset += ExampleJitter(["example_types.py"])


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Miasm2 testing tool")
    parser.add_argument("-m", "--mono", help="Force monothreading",
                        action="store_true")
    parser.add_argument("-c", "--coverage", help="Include code coverage",
                        action="store_true")
    parser.add_argument("-t", "--omit-tags", help="Omit tests based on tags \
(tag1,tag2). Available tags are %s. \
By default, no tag is omitted." % ", ".join(TAGS.keys()), default="")
    parser.add_argument("-n", "--do-not-clean",
                        help="Do not clean tests products", action="store_true")
    args = parser.parse_args()

    ## Parse multiproc argument
    multiproc = True
    if args.mono is True or args.coverage is True:
        multiproc = False

    ## Parse omit-tags argument
    exclude_tags = []
    for tag in args.omit_tags.split(","):
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

    # Handle tcc modularity
    tcc = True
    try:
        from miasm2.jitter import Jittcc
    except ImportError:
        tcc = False

    # TODO XXX: fix llvm jitter (deactivated for the moment)
    llvm = False

    if llvm is False:
        print "%(red)s[LLVM]%(end)s Python" % cosmetics.colors + \
            "'py-llvm 3.2' module is required for llvm tests"

        # Remove llvm tests
        if TAGS["llvm"] not in exclude_tags:
            exclude_tags.append(TAGS["llvm"])

    if tcc is False:
        print "%(red)s[TCC]%(end)s Python" % cosmetics.colors + \
            "'libtcc' module is required for tcc tests"

        # Remove tcc tests
        if TAGS["tcc"] not in exclude_tags:
            exclude_tags.append(TAGS["tcc"])

    # Handle Z3 dependency
    try:
        import z3
    except ImportError:
        print "%(red)s[Z3]%(end)s " % cosmetics.colors + \
            "Z3 and its python binding are necessary for TranslatorZ3."
        if TAGS["z3"] not in exclude_tags:
            exclude_tags.append(TAGS["z3"])
    test_ko = []
    test_ok = []

    # Set callbacks
    if multiproc is False:
        testset.set_cpu_numbers(1)
    testset.set_callback(task_done=lambda test, error:multithread.task_done(test, error, test_ok, test_ko),
                         task_new=multithread.task_new)


    # Filter testset according to tags
    testset.filter_tags(exclude_tags=exclude_tags)

    # Run tests
    testset.run()

    # Finalize
    testset.end(clean=not args.do_not_clean)
    print
    print (cosmetics.colors["green"] +
           "Result: %d/%d pass" % (len(test_ok), len(test_ok) + len(test_ko)) +
           cosmetics.colors["end"])
    for test, error in test_ko:
        command_line = " ".join(test.command_line)
        print cosmetics.colors["red"] + 'ERROR', cosmetics.colors["lightcyan"] + command_line + cosmetics.colors["end"]
        print error
    # Exit with an error if at least a test failed
    exit(testset.tests_passed())
