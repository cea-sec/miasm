#
# Expression regression tests  #
#
from pdb import pm
from miasm2.expression.expression import *

assert(ExprInt64(-1) != ExprInt64(-2))
