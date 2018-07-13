# Toshiba MeP-c4 - pytest unit tests wrapper
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_jit import launch_tests

from test_jit_branchjump import TestBranchJump; launch_tests(TestBranchJump())
from test_jit_repeat import TestRepeat; launch_tests(TestRepeat())
