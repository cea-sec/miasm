"""
This module will be removed in favour of win_api_x86_32_structs.py
Cause: Implements more than SEH.
"""
import warnings
from miasm2.os_dep.win_api_x86_32_structs import *

warnings.warn('DEPRECATION WARNING: use "win_api_x86_32_structs" sub-module'\
              ' instead of "win_api_x86_32_seh"')

init_seh = init_win_structs
