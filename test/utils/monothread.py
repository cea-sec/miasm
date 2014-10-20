import sys
import cosmetics


def task_done(test, error):
    s = "[%s] Running tests on %s ..." % (test.base_dir.upper(),
                                          " ".join(test.command_line))
    already_printed = len(s)
    if error is not None:
        cosmetics.write_colored("ERROR", "red", already_printed)
        print error
    else:
        cosmetics.write_colored("OK", "green", already_printed)


def task_new(test):
    s = "[%s] Running tests on %s ..." % (test.base_dir.upper(),
                                          " ".join(test.command_line))
    sys.stdout.write(s)
    sys.stdout.flush()
