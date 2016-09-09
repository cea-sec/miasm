from pdb import pm
import sys
import subprocess
import json


expected_file = sys.argv[1]
dg = subprocess.Popen([sys.executable] + sys.argv[2:], stdout=subprocess.PIPE)

stdout, _ = dg.communicate()
expected = json.load(open(expected_file))
result = json.loads(stdout)


expected.sort()
result.sort()

print expected
print result
assert expected == result
