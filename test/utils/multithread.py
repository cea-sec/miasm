from __future__ import print_function
import sys
from . import cosmetics
import time


def task_done(test, error, test_ok, test_ko):
    command_line = " ".join(test.command_line)
    if error is not None:
        print(cosmetics.colors["red"] + 'ERROR', end=' ')
        print(cosmetics.colors["lightcyan"] + command_line + cosmetics.colors["end"])
        print(error)
        test_ko.append((test, error))
    else:
        print(cosmetics.colors["green"] + 'DONE', end=' ')
        print(cosmetics.colors["lightcyan"] + command_line + cosmetics.colors["end"], end=' ')
        print("%ds" % (time.time() - test.start_time))
        test_ok.append((test, error))


def task_new(test):
    command_line = " ".join(test.command_line)
    print(cosmetics.colors["lightcyan"], end=' ')
    print(test.base_dir.upper(), command_line, end=' ')
    print(cosmetics.colors["end"])
