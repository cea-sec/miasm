import time
import signal
from cosmetics import getTerminalSize, colors


global_state = {"termSize": getTerminalSize(),
                "message": "",
                "pstate": []}


def print_conf(conf, value):
    "Print a configuration line"
    return colors["green"] + conf + ": " + colors["end"] + str(value)


def clr_screen():
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
    test_done = 0
    test_failed = 0
    message = global_state["message"] + "\n"
    for v in global_state["pstate"]:
        if v["status"] != "running":
            test_done += 1
            if v["status"] != 0:
                test_failed += 1
                cmd_line = " ".join(v["test"].command_line)
                message += colors["red"] + "FAIL:" + colors["end"] + cmd_line
                message += "\n" + v["message"] + "\n"

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
    for process in global_state["pstate"]:
        if process["status"] == "running":
            current_job.append(process)
    print "\n" * (global_state["termSize"][1] - already_printed - 3 - len(current_job))

    for job in current_job:
        command_line = " ".join(job["test"].command_line)
        base_dir = job["test"].base_dir.upper()
        s = "[" + colors["lightcyan"] + command_line + colors["end"]
        s_end = base_dir
        cur_time = time.strftime(
            "%M:%Ss", time.gmtime(time.time() - job["init_time"]))
        l = len(command_line) + len(s_end) + 4 + len(str(cur_time)) + 2
        s_end += "    " + colors["blue"] + cur_time + colors["end"] + "]"
        print "%s%s%s" % (s, " " * (global_state["termSize"][0] - l), s_end)


def on_signal(sig1, sig2):
    "Update view every second"
    clr_screen()
    signal.alarm(1)


def init(cpu_c):
    """Initialize global state
    @cpu_c: number of cpu (for conf displaying)
    """
    # Init global_state
    global_state["cpu_c"] = cpu_c
    global_state["init_time"] = time.time()

    # Launch view updater
    signal.signal(signal.SIGALRM, on_signal)
    signal.alarm(1)


def task_done(test, error):
    "Report a test done"
    for task in global_state["pstate"]:
        if task["test"] == test:
            if error is not None:
                task["status"] = -1
                task["message"] = error
            else:
                task["status"] = 0
            break
    clr_screen()


def task_new(test):
    "Report a new test"
    global_state["pstate"].append({"status": "running",
                                   "test": test,
                                   "init_time": time.time()})
    clr_screen()
