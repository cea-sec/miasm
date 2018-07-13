# Toshiba MeP-c4 - pytest unit tests wrapper
# Guillaume Valadon <guillaume@valadon.net>

from ut_helpers_asm import launch_tests

from test_major_opcode_0 import TestMajor0; launch_tests(TestMajor0())
from test_major_opcode_1 import TestMajor1; launch_tests(TestMajor1())
from test_major_opcode_2 import TestMajor2; launch_tests(TestMajor2())
from test_major_opcode_3 import TestMajor3; launch_tests(TestMajor3())
from test_major_opcode_4 import TestMajor4; launch_tests(TestMajor4())
from test_major_opcode_5 import TestMajor5; launch_tests(TestMajor5())
from test_major_opcode_6 import TestMajor6; launch_tests(TestMajor6())
from test_major_opcode_7 import TestMajor7; launch_tests(TestMajor7())
from test_major_opcode_8 import TestMajor8; launch_tests(TestMajor8())
from test_major_opcode_9 import TestMajor9; launch_tests(TestMajor9())
from test_major_opcode_10 import TestMajor10; launch_tests(TestMajor10())
from test_major_opcode_11 import TestMajor11; launch_tests(TestMajor11())
from test_major_opcode_12 import TestMajor12; launch_tests(TestMajor12())
from test_major_opcode_13 import TestMajor13; launch_tests(TestMajor13())
from test_major_opcode_14 import TestMajor14; launch_tests(TestMajor14())
from test_major_opcode_15 import TestMajor15; launch_tests(TestMajor15())
from test_asm import TestMisc; launch_tests(TestMisc())
