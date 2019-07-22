from __future__ import print_function
from pdb import pm
import sys
import subprocess
import json


expected_file = sys.argv[1]
dg = subprocess.Popen([sys.executable] + sys.argv[2:], stdout=subprocess.PIPE)

stdout, _ = dg.communicate()
expected = json.load(open(expected_file))
result = json.loads(stdout.decode())


assert len(expected) == len(result)

assert all(r in result for r in expected)
assert all(r in expected for r in result)
