from builtins import int as int_types

class AstNode(object):
    """
    Ast node object
    """
    def __neg__(self):
        if isinstance(self, AstInt):
            value = AstInt(-self.value)
        else:
            value = AstOp('-', self)
        return value

    def __add__(self, other):
        return AstOp('+', self, other)

    def __sub__(self, other):
        return AstOp('-', self, other)

    def __div__(self, other):
        return AstOp('/', self, other)

    def __mod__(self, other):
        return AstOp('%', self, other)

    def __mul__(self, other):
        return AstOp('*', self, other)

    def __lshift__(self, other):
        return AstOp('<<', self, other)

    def __rshift__(self, other):
        return AstOp('>>', self, other)

    def __xor__(self, other):
        return AstOp('^', self, other)

    def __or__(self, other):
        return AstOp('|', self, other)

    def __and__(self, other):
        return AstOp('&', self, other)


class AstInt(AstNode):
    """
    Ast integer
    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "%s" % self.value


class AstId(AstNode):
    """
    Ast Id
    """
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "%s" % self.name


class AstMem(AstNode):
    """
    Ast memory deref
    """
    def __init__(self, ptr, size):
        assert isinstance(ptr, AstNode)
        assert isinstance(size, int_types)
        self.ptr = ptr
        self.size = size

    def __str__(self):
        return "@%d[%s]" % (self.size, self.ptr)


class AstOp(AstNode):
    """
    Ast operator
    """
    def __init__(self, op, *args):
        assert all(isinstance(arg, AstNode) for arg in args)
        self.op = op
        self.args = args

    def __str__(self):
        if len(self.args) == 1:
            return "(%s %s)" % (self.op, self.args[0])
        return '(' + ("%s" % self.op).join(str(x) for x in self.args) + ')'
