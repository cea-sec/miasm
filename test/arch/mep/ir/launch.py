# Toshiba MeP-c4 - pytest unit tests wrapper
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_ir import launch_tests

from test_arithmetic import TestArithmetic; launch_tests(TestArithmetic())
from test_bitmanipulation import TestBitManipulation; launch_tests(TestBitManipulation())
from test_branchjump import TestBranchJump; launch_tests(TestBranchJump())
from test_control import TestControl; launch_tests(TestControl())
from test_coprocessor import TestCoprocessor; launch_tests(TestCoprocessor())
from test_datacache import TestDataCache; launch_tests(TestDataCache())
from test_debug import TestDebug; launch_tests(TestDebug())
from test_divide import TestDivide; launch_tests(TestDivide())
from test_extension import TestExtension; launch_tests(TestExtension())
from test_ldz import TestLdz; launch_tests(TestLdz())
from test_loadstore import TestLoadStore; launch_tests(TestLoadStore())
from test_logical import TestLogical; launch_tests(TestLogical())
from test_move import TestMove; launch_tests(TestMove())
from test_multiply import TestMultiply; launch_tests(TestMultiply())
from test_repeat import TestRepeat; launch_tests(TestRepeat())
from test_shift import TestShift; launch_tests(TestShift())
from test_ir import TestMisc; launch_tests(TestMisc())
