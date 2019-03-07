from __future__ import print_function
import os
import platform

is_win = platform.system() == "Windows"

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
colors = {
    "red": "\033[91;1m",
    "end": "\033[0m",
    "green": "\033[92;1m",
    "lightcyan": "\033[96m",
    "blue": "\033[94;1m"
}

if is_win:
    colors = {
        "red": "",
        "end": "",
        "green": "",
        "lightcyan": "",
        "blue": ""
    }

def write_colored(text, color, already_printed=0):
    text_colored = colors[color] + text + colors["end"]
    print(" " * (WIDTH - already_printed - len(text)) + text_colored)


def write_underline(text):
    print("\033[4m" + text + colors["end"])
