import os
from pdb import pm
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
from miasm.os_dep import win_api_x86_32_seh
from miasm.jitter.csts import *

def deal_exception_access_violation(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_ACCESS_VIOLATION)
    return True

def deal_exception_breakpoint(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_BREAKPOINT)
    return True

def deal_exception_div(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_INT_DIVIDE_BY_ZERO)
    return True

def deal_exception_privileged_instruction(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_PRIV_INSTRUCTION)
    return True

def deal_exception_illegal_instruction(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_ILLEGAL_INSTRUCTION)
    return True

def deal_exception_single_step(jitter):
    jitter.pc = win_api_x86_32_seh.fake_seh_handler(jitter, win_api_x86_32_seh.EXCEPTION_SINGLE_STEP)
    return True

def return_from_seh(jitter):
    win_api_x86_32_seh.return_from_seh(jitter)
    return True

# Insert here user defined methods

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()
options.usesegm = True
options.use_windows_structs = True

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())

# Install Windows SEH callbacks
sb.jitter.add_exception_handler(EXCEPT_ACCESS_VIOL, deal_exception_access_violation)
sb.jitter.add_exception_handler(EXCEPT_SOFT_BP, deal_exception_breakpoint)
sb.jitter.add_exception_handler(EXCEPT_DIV_BY_ZERO, deal_exception_div)
sb.jitter.add_exception_handler(1<<17, deal_exception_privileged_instruction)
sb.jitter.add_exception_handler(EXCEPT_UNK_MNEMO, deal_exception_illegal_instruction)
sb.jitter.add_exception_handler(EXCEPT_INT_1, deal_exception_single_step)

sb.jitter.add_breakpoint(win_api_x86_32_seh.return_from_exception, return_from_seh)

# Run
sb.run()

assert(sb.jitter.running is False)
