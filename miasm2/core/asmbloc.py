"""
This module will be removed in favour of asmblock.py
Cause: French tipo.
"""
import warnings
from miasm2.core.asmblock import *

warnings.warn('DEPRECATION WARNING: use "asmblock" sub-module instead of "asmbloc"')

log_asmbloc = log_asmblock
