import subprocess
import sys
import os
import time
import argparse
import tempfile

# Test derivations
def all_jit(assembly_line):
    """Add all available jitter options to assembly_line thanks to '--jitter'
    option.
    @assembly_line: list(str)
    Return a list of assembly lines: list(list(str)).
    """
    out = []
    for jitter in ["tcc", "llvm", "python"]:
        out.append(assembly_line + ["--jitter", jitter])
    return out

# Available tests

all_tests = {
    "test": {
        "architecture": [
            ["arch/x86/arch.py"],
            ["arch/x86/sem.py"],
            ["arch/arm/arch.py"],
            ["arch/arm/sem.py"],
            ["arch/msp430/arch.py"],
            ["arch/msp430/sem.py"],
            ["arch/sh4/arch.py"],
            ["arch/mips32/arch.py"],
        ],
        "core": [
            ["core/interval.py"],
            ["core/graph.py"],
            ["core/parse_asm.py"],
        ],
        "expression": [
            ["expression/modint.py"],
            ["expression/stp.py"],
            ["expression/simplifications.py"],
        ],
        "ir": [
            ["ir/ir2C.py"],
            ["ir/symbexec.py"],
        ],
        "jitter": [
            ["jitter/os_dep/win_api_x86_32.py"],
        ],
        "order": [
            "architecture",
            "core",
            "expression",
            "ir",
            "jitter",
        ],
    },
    "example": {
        "assembler": [
            ["asm_x86.py"],
            ["asm_arm.py"],
            ["asm_box_x86_32.py"],
            ["asm_box_x86_32_enc.py"],
            ["asm_box_x86_32_mod.py"],
            ["asm_box_x86_32_mod_self.py"],
            ["asm_box_x86_32_repmod.py"],
            ["disasm_01.py"],
            ["disasm_02.py"],
            ["disasm_03.py", "box_upx.exe", "0x410f90"],
        ],
        "expression": [
            ["symbol_exec.py"],
            ["expression/manip_expression1.py"],
            ["expression/manip_expression2.py"],
            ["expression/manip_expression3.py"],
            ["expression/manip_expression4.py",
                "expression/sc_connect_back.bin", "0x2e"],
            ["expression/manip_expression5.py"],
            ["expression/manip_expression6.py"],
            ["expression/manip_expression7.py"],
            ["test_dis.py", "-g", "-s", "-m", "arm", "demo_arm.bin", "0"],
            ["test_dis.py", "-g", "-s", "-m",
                "x86_32", "box_x86_32.bin", "0x401000"],
            ["expression/solve_condition_stp.py",
                "expression/simple_test.bin"],
        ],
        "jitter": reduce(lambda x, y: x + y,
                         map(all_jit, [
                    ["unpack_upx.py", "box_upx.exe"], # Take 5 mins on a Core i5
                    ["test_jit_x86_32.py", "x86_32_sc.bin"],
                    ["test_jit_arm.py", "md5_arm", "A684"],
                    ["sandbox_pe_x86_32.py", "box_x86_32.bin"],
                    ["sandbox_pe_x86_32.py", "box_x86_32_enc.bin"],
                    ["sandbox_pe_x86_32.py", "box_x86_32_mod.bin"],
                    ["sandbox_pe_x86_32.py", "box_x86_32_repmod.bin"],
                    ["sandbox_pe_x86_32.py", "box_x86_32_mod_self.bin"],
                    ])),
        "order": [
            "assembler",
            "expression",
            "jitter",
        ],
    },
    "order": [
        "test",
        "example",
    ],
}

# Cosmetic


def getTerminalSize():
    "Return the size of the terminal : COLUMNS, LINES"

    env = os.environ

    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import termios
            import struct
            import os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
                                                 '1234'))
        except:
            return
        return cr
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))
    return int(cr[1]), int(cr[0])


WIDTH = getTerminalSize()[0]
colors = {"red": "\033[91;1m",
          "end": "\033[0m",
          "green": "\033[92;1m",
          "lightcyan": "\033[96m",
          "blue": "\033[94;1m"}


def write_colored(text, color, already_printed=0):
    text_colored = colors[color] + text + colors["end"]
    print " " * (WIDTH - already_printed - len(text)) + text_colored


def write_underline(text):
    print "\033[4m" + text + colors["end"]


def print_conf(conf, value):
    return colors["green"] + conf + ": " + colors["end"] + str(value)


def clr_screen(global_state, pstate):
    "Update the screen to display some information"

    # Header
    to_print = []
    to_print.append(" " * (global_state["termSize"][0] / 2 - 10) + colors[
                    "blue"] + "Miasm2 Regression tests" + colors["end"])
    to_print.append("")
    to_print.append("=" * global_state["termSize"][0])
    to_print.append("")
    to_print.append(print_conf("Current mode", "Multiprocessing"))
    to_print.append(print_conf("Nb CPU detected", global_state["cpu_c"]))
    to_print.append("")
    to_print.append("=" * global_state["termSize"][0])
    to_print.append("")
    to_print.append(
        print_conf("Current section", global_state["section"].upper()))
    to_print.append(
        print_conf("Current subsection", global_state["subsection"].upper()))
    test_done = 0
    test_failed = 0
    message = global_state["message"] + "\n"
    for k, v in pstate.items():
        if v["status"] != "running":
            test_done += 1
            if v["status"] != 0:
                test_failed += 1
                message += colors["red"] + "FAIL: " + colors["end"] + k
                message += v["message"] + "\n"

    to_print.append(print_conf("Success rate", "%d/%d" %
                    (test_done - test_failed, test_done)))
    printed_time = time.strftime(
        "%M:%S", time.gmtime(time.time() - global_state["init_time"]))
    to_print.append(print_conf("Cumulated time", printed_time))
    to_print.append("")
    to_print.append("=" * global_state["termSize"][0])

    cur = "\n".join(to_print)
    cur += "\n"

    # Message
    cur += message
    print cur
    already_printed = cur.count("\n")

    # Current state
    current_job = []
    for t in pstate.values():
        if t["status"] == "running":
            current_job.append(t)
    print "\n" * (global_state["termSize"][1] - already_printed - 3 - len(current_job))

    for j in current_job:
        s = "[" + colors["lightcyan"] + j["command"] + colors["end"]
        s_end = time.strftime(
            "%M:%Ss", time.gmtime(time.time() - j["init_time"]))
        l = len(j["command"]) + len(s_end) + 4 + len(str(j["pid"])) + 2
        s_end += "    " + colors["blue"] + str(j["pid"]) + colors["end"] + "]"
        print "%s%s%s" % (s, " " * (global_state["termSize"][0] - l), s_end)

# Tests handling


def are_tests_finished(test_names, done):
    for t in test_names:
        if t not in done:
            return False
    return True


def are_tests_finished_multi(test_names, pstate):
    for t in test_names:
        t = " ".join(t)
        if t not in pstate.keys():
            return False
        if pstate[t]["status"] == "running":
            return False
    return True


def test_iter(done):
    "Return an iterator on next tests, wait for previous sections"

    for section_name in all_tests["order"]:
        # Go to the right directory
        os.chdir(os.path.join("..", section_name))

        # Update global state
        section_content = all_tests[section_name]
        write_underline(section_name.upper())

        for subsection_name in section_content["order"]:
            subsection_content = section_content[subsection_name]
            write_underline("%s > %s" % (section_name.upper(),
                                         subsection_name.upper()))
            for test_line in subsection_content:
                yield test_line

            while not(are_tests_finished(subsection_content, done)):
                time.sleep(0.050)


def test_iter_multi(global_state, pstate):
    "Multiprocessor version of test_iter"

    # Global message : subsections done
    message = ""

    for section_name in all_tests["order"]:
        # Update global state
        section_content = all_tests[section_name]
        global_state["section"] = section_name

        for subsection_name in section_content["order"]:
            subsection_content = section_content[subsection_name]
            beg_time = time.time()
            global_state["subsection"] = subsection_name

            for test_line in subsection_content:
                yield test_line

            while not(are_tests_finished_multi(subsection_content, pstate)):
                # Wait for task to finish, update the screen
                time.sleep(0.100)
                clr_screen(global_state, pstate)

            message += "%s > %s completed in %.08f seconds\n" % (section_name.upper(),
                                                                 subsection_name.upper(
                                                                 ),
                                                                 time.time() - beg_time)
            global_state["message"] = message

    # Final update
    clr_screen(global_state, pstate)


def run_test(test, coveragerc=None):
    s = "Running tests on %s ..." % " ".join(test)
    sys.stdout.write(s)
    sys.stdout.flush()

    args = test
    if coveragerc is not None:
        args = ["-m", "coverage", "run", "--rcfile", coveragerc, "-a"] + test

    # Launch test
    testpy = subprocess.Popen(["python"] + args, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    outputs = testpy.communicate()

    # Check result
    if testpy.returncode == 0:
        write_colored("OK", "green", len(s))
    else:
        write_colored("ERROR", "red", len(s))
        print outputs[1]


def run_test_parallel(test, current, global_state):

    pid = os.getpid()
    test_key = " ".join(test)

    # Keep current PID
    current[test_key] = {"status": "running",
                         "pid": pid,
                         "command": test_key,
                         "init_time": time.time()}

    # Go to the right directory
    os.chdir(os.path.join("..", global_state["section"]))

    # Launch test
    testpy = subprocess.Popen(["python"] + test, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    outputs = testpy.communicate()

    # Check result
    message = ""
    if testpy.returncode != 0:
        message = outputs[1]

    # Update result
    current[test_key] = {"status": testpy.returncode,
                         "message": message}

# Multiprocessing handling

try:
    from multiprocessing import Manager, Pool, cpu_count
    multiproc = True
except ImportError:
    multiproc = False

# Argument parsing
parser = argparse.ArgumentParser(description="Miasm2 testing tool")
parser.add_argument("-m", "--mono", help="Force monothreading",
                    action="store_true")
parser.add_argument("-c", "--coverage", help="Include code coverage",
                    action="store_true")
args = parser.parse_args()

if args.mono is True or args.coverage is True:
    multiproc = False

# Handle coverage
coveragerc = None
if args.coverage is True:
    try:
        import coverage
    except ImportError:
        print "%(red)s[Coverage]%(end)s Python 'coverage' module is required" % colors
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

    # Inform the user
    d = {"blue": colors['blue'],
         "end": colors['end'],
         "cov_dir": cov_dir}
    print "[%(blue)sCoverage%(end)s] Report will be written in %(cov_dir)s" % d

# Handle llvm modularity

llvm = True
try:
    import llvm
except ImportError:
    llvm = False

# if llvm.version != (3,2):
#    llvm = False

if llvm is False:
    print "%(red)s[LLVM]%(end)s Python 'py-llvm 3.2' module is required for llvm tests" % colors

    # Remove llvm tests
    for test in all_tests["example"]["jitter"]:
        if "llvm" in test:
            all_tests["example"]["jitter"].remove(test)
            print "%(red)s[LLVM]%(end)s Remove" % colors, " ".join(test)

    # Let the user see messages
    time.sleep(0.5)

# Run tests

if multiproc is False:
    done = list()
    for test in test_iter(done):
        run_test(test, coveragerc=coveragerc)
        done.append(test)

else:
    # Parallel version
    cpu_c = cpu_count()
    global_state = {"cpu_c": cpu_c,
                    "init_time": time.time(),
                    "termSize": getTerminalSize(),
                    "message": ""}

    manager = Manager()
    pool = Pool(processes=cpu_c)
    current = manager.dict()

    for test in test_iter_multi(global_state, current):
        pool.apply_async(run_test_parallel, (test,
                                             current,
                                             global_state))

    pool.close()
    pool.join()
