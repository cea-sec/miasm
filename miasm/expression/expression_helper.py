#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# Expressions manipulation functions
from builtins import range
import itertools
import collections
import random
import string
import warnings

from future.utils import viewitems, viewvalues

import miasm.expression.expression as m2_expr


def parity(a):
    tmp = (a) & 0xFF
    cpt = 1
    while tmp != 0:
        cpt ^= tmp & 1
        tmp >>= 1
    return cpt


def merge_sliceto_slice(expr):
    """
    Apply basic factorisation on ExprCompose sub components
    @expr: ExprCompose
    """

    out_args = []
    last_index = 0
    for index, arg in expr.iter_args():
        # Init
        if len(out_args) == 0:
            out_args.append(arg)
            continue

        last_value = out_args[-1]
        # Consecutive

        if last_index + last_value.size == index:
            # Merge consecutive integers
            if (isinstance(arg, m2_expr.ExprInt) and
                isinstance(last_value, m2_expr.ExprInt)):
                new_size = last_value.size + arg.size
                value = int(arg) << last_value.size
                value |= int(last_value)
                out_args[-1] = m2_expr.ExprInt(value, size=new_size)
                continue

            # Merge consecuvite slice
            elif (isinstance(arg, m2_expr.ExprSlice) and
                  isinstance(last_value, m2_expr.ExprSlice)):
                value = arg.arg
                if (last_value.arg == value and
                    last_value.stop == arg.start):
                    out_args[-1] = value[last_value.start:arg.stop]
                    continue

        # Unmergeable
        last_index = index
        out_args.append(arg)

    return out_args


op_propag_cst = ['+', '*', '^', '&', '|', '>>',
                 '<<', "a>>", ">>>", "<<<",
                 "/", "%", 'sdiv', 'smod', 'umod', 'udiv','**']


def is_pure_int(e):
    """
    return True if expr is only composed with integers
    /!\ ExprCond returns True is src1 and src2 are integers
    """
    def modify_cond(e):
        if isinstance(e, m2_expr.ExprCond):
            return e.src1 | e.src2
        return e

    def find_int(e, s):
        if isinstance(e, m2_expr.ExprId) or isinstance(e, m2_expr.ExprMem):
            s.add(e)
        return e
    s = set()
    new_e = e.visit(modify_cond)
    new_e.visit(lambda x: find_int(x, s))
    if s:
        return False
    return True


def is_int_or_cond_src_int(e):
    if isinstance(e, m2_expr.ExprInt):
        return True
    if isinstance(e, m2_expr.ExprCond):
        return (isinstance(e.src1, m2_expr.ExprInt) and
                isinstance(e.src2, m2_expr.ExprInt))
    return False


def fast_unify(seq, idfun=None):
    # order preserving unifying list function
    if idfun is None:
        idfun = lambda x: x
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)

        if marker in seen:
            continue
        seen[marker] = 1
        result.append(item)
    return result

def get_missing_interval(all_intervals, i_min=0, i_max=32):
    """Return a list of missing interval in all_interval
    @all_interval: list of (int, int)
    @i_min: int, minimal missing interval bound
    @i_max: int, maximal missing interval bound"""

    my_intervals = all_intervals[:]
    my_intervals.sort()
    my_intervals.append((i_max, i_max))

    missing_i = []
    last_pos = i_min
    for start, stop in my_intervals:
        if last_pos != start:
            missing_i.append((last_pos, start))
        last_pos = stop
    return missing_i


class Variables_Identifier(object):
    """Identify variables in an expression.
    Returns:
    - variables with their corresponding values
    - original expression with variables translated
    """

    def __init__(self, expr, var_prefix="v"):
        """Set the expression @expr to handle and launch variable identification
        process
        @expr: Expr instance
        @var_prefix: (optional) prefix of the variable name, default is 'v'"""

        # Init
        self.var_indice = itertools.count()
        self.var_asked = set()
        self._vars = {} # VarID -> Expr
        self.var_prefix = var_prefix

        # Launch recurrence
        self.find_variables_rec(expr)

        # Compute inter-variable dependencies
        has_change = True
        while has_change:
            has_change = False
            for var_id, var_value in list(viewitems(self._vars)):
                cur = var_value

                # Do not replace with itself
                to_replace = {
                    v_val:v_id
                    for v_id, v_val in viewitems(self._vars)
                    if v_id != var_id
                }
                var_value = var_value.replace_expr(to_replace)

                if cur != var_value:
                    # Force @self._vars update
                    has_change = True
                    self._vars[var_id] = var_value
                    break

        # Replace in the original equation
        self._equation = expr.replace_expr(
            {
                v_val: v_id for v_id, v_val
                in viewitems(self._vars)
            }
        )

        # Compute variables dependencies
        self._vars_ordered = collections.OrderedDict()
        todo = set(self._vars)
        needs = {}

        ## Build initial needs
        for var_id, var_expr in viewitems(self._vars):
            ### Handle corner cases while using Variable Identifier on an
            ### already computed equation
            needs[var_id] = [
                var_name
                for var_name in var_expr.get_r(mem_read=True)
                if self.is_var_identifier(var_name) and \
                var_name in todo and \
                var_name != var_id
            ]

        ## Build order list
        while todo:
            done = set()
            for var_id in todo:
                all_met = True
                for need in needs[var_id]:
                    if need not in self._vars_ordered:
                        # A dependency is not met
                        all_met = False
                        break
                if not all_met:
                    continue

                # All dependencies are already met, add current
                self._vars_ordered[var_id] = self._vars[var_id]
                done.add(var_id)

            # Update the todo list
            for element_done in done:
                todo.remove(element_done)

    def is_var_identifier(self, expr):
        "Return True iff @expr is a variable identifier"
        if not isinstance(expr, m2_expr.ExprId):
            return False
        return expr in self._vars

    def find_variables_rec(self, expr):
        """Recursive method called by find_variable to expand @expr.
        Set @var_names and @var_values.
        This implementation is faster than an expression visitor because
        we do not rebuild each expression.
        """

        if (expr in self.var_asked):
            # Expr has already been asked
            if expr not in viewvalues(self._vars):
                # Create var
                identifier = m2_expr.ExprId(
                    "%s%s" % (
                        self.var_prefix,
                        next(self.var_indice)
                    ),
                    size = expr.size
                )
                self._vars[identifier] = expr

            # Recursion stop case
            return
        else:
            # First time for @expr
            self.var_asked.add(expr)

        if isinstance(expr, m2_expr.ExprOp):
            for a in expr.args:
                self.find_variables_rec(a)

        elif isinstance(expr, m2_expr.ExprInt):
            pass

        elif isinstance(expr, m2_expr.ExprId):
            pass

        elif isinstance(expr, m2_expr.ExprLoc):
            pass

        elif isinstance(expr, m2_expr.ExprMem):
            self.find_variables_rec(expr.ptr)

        elif isinstance(expr, m2_expr.ExprCompose):
            for arg in expr.args:
                self.find_variables_rec(arg)

        elif isinstance(expr, m2_expr.ExprSlice):
            self.find_variables_rec(expr.arg)

        elif isinstance(expr, m2_expr.ExprCond):
            self.find_variables_rec(expr.cond)
            self.find_variables_rec(expr.src1)
            self.find_variables_rec(expr.src2)

        else:
            raise NotImplementedError("Type not handled: %s" % expr)

    @property
    def vars(self):
        return self._vars_ordered

    @property
    def equation(self):
        return self._equation

    def __str__(self):
        "Display variables and final equation"
        out = ""
        for var_id, var_expr in viewitems(self.vars):
            out += "%s = %s\n" % (var_id, var_expr)
        out += "Final: %s" % self.equation
        return out


class ExprRandom(object):
    """Return an expression randomly generated"""

    # Identifiers length
    identifier_len = 5
    # Identifiers' name charset
    identifier_charset = string.ascii_letters
    # Number max value
    number_max = 0xFFFFFFFF
    # Available operations
    operations_by_args_number = {1: ["-"],
                                 2: ["<<", "<<<", ">>", ">>>"],
                                 "2+": ["+", "*", "&", "|", "^"],
                                 }
    # Maximum number of argument for operations
    operations_max_args_number = 5
    # If set, output expression is a perfect tree
    perfect_tree = True
    # Max argument size in slice, relative to slice size
    slice_add_size = 10
    # Maximum number of layer in compose
    compose_max_layer = 5
    # Maximum size of memory address in bits
    memory_max_address_size = 32
    # Re-use already generated elements to mimic a more realistic behavior
    reuse_element = True
    generated_elements = {} # (depth, size) -> [Expr]

    @classmethod
    def identifier(cls, size=32):
        """Return a random identifier
        @size: (optional) identifier size
        """
        return m2_expr.ExprId("".join([random.choice(cls.identifier_charset)
                                       for _ in range(cls.identifier_len)]),
                              size=size)

    @classmethod
    def number(cls, size=32):
        """Return a random number
        @size: (optional) number max bits
        """
        num = random.randint(0, cls.number_max % (2**size))
        return m2_expr.ExprInt(num, size)

    @classmethod
    def atomic(cls, size=32):
        """Return an atomic Expression
        @size: (optional) Expr size
        """
        available_funcs = [cls.identifier, cls.number]
        return random.choice(available_funcs)(size=size)

    @classmethod
    def operation(cls, size=32, depth=1):
        """Return an ExprOp
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        """
        operand_type = random.choice(list(cls.operations_by_args_number))
        if isinstance(operand_type, str) and "+" in operand_type:
            number_args = random.randint(
                int(operand_type[:-1]),
                cls.operations_max_args_number
            )
        else:
            number_args = operand_type

        args = [cls._gen(size=size, depth=depth - 1)
                for _ in range(number_args)]
        operand = random.choice(cls.operations_by_args_number[operand_type])
        return m2_expr.ExprOp(operand,
                              *args)

    @classmethod
    def slice(cls, size=32, depth=1):
        """Return an ExprSlice
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        """
        start = random.randint(0, size)
        stop = start + size
        return cls._gen(size=random.randint(stop, stop + cls.slice_add_size),
                       depth=depth - 1)[start:stop]

    @classmethod
    def compose(cls, size=32, depth=1):
        """Return an ExprCompose
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        """
        # First layer
        upper_bound = random.randint(1, size)
        args = [cls._gen(size=upper_bound, depth=depth - 1)]

        # Next layers
        while (upper_bound < size):
            if len(args) == (cls.compose_max_layer - 1):
                # We reach the maximum size
                new_upper_bound = size
            else:
                new_upper_bound = random.randint(upper_bound + 1, size)

            args.append(cls._gen(size=new_upper_bound - upper_bound))
            upper_bound = new_upper_bound
        return m2_expr.ExprCompose(*args)

    @classmethod
    def memory(cls, size=32, depth=1):
        """Return an ExprMem
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        """

        address_size = random.randint(1, cls.memory_max_address_size)
        return m2_expr.ExprMem(cls._gen(size=address_size,
                                       depth=depth - 1),
                               size=size)

    @classmethod
    def _gen(cls, size=32, depth=1):
        """Internal function for generating sub-expression according to options
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        /!\ @generated_elements is left modified
        """
        # Perfect tree handling
        if not cls.perfect_tree:
            depth = random.randint(max(0, depth - 2), depth)

        # Element re-use
        if cls.reuse_element and random.choice([True, False]) and \
                (depth, size) in cls.generated_elements:
            return random.choice(cls.generated_elements[(depth, size)])

        # Recursion stop
        if depth == 0:
            return cls.atomic(size=size)

        # Build a more complex expression
        available_funcs = [cls.operation, cls.slice, cls.compose, cls.memory]
        gen = random.choice(available_funcs)(size=size, depth=depth)

        # Save it
        new_value = cls.generated_elements.get((depth, size), []) + [gen]
        cls.generated_elements[(depth, size)] = new_value
        return gen

    @classmethod
    def get(cls, size=32, depth=1, clean=True):
        """Return a randomly generated expression
        @size: (optional) Operation size
        @depth: (optional) Expression depth
        @clean: (optional) Clean expression cache between two calls
        """
        # Init state
        if clean:
            cls.generated_elements = {}

        # Get an element
        got = cls._gen(size=size, depth=depth)

        # Clear state
        if clean:
            cls.generated_elements = {}

        return got

def expr_cmpu(arg1, arg2):
    """
    Returns a one bit long Expression:
    * 1 if @arg1 is strictly greater than @arg2 (unsigned)
    * 0 otherwise.
    """
    warnings.warn('DEPRECATION WARNING: use "expr_is_unsigned_greater" instead"')
    return m2_expr.expr_is_unsigned_greater(arg1, arg2)

def expr_cmps(arg1, arg2):
    """
    Returns a one bit long Expression:
    * 1 if @arg1 is strictly greater than @arg2 (signed)
    * 0 otherwise.
    """
    warnings.warn('DEPRECATION WARNING: use "expr_is_signed_greater" instead"')
    return m2_expr.expr_is_signed_greater(arg1, arg2)


class CondConstraint(object):

    """Stand for a constraint on an Expr"""

    # str of the associated operator
    operator = ""

    def __init__(self, expr):
        self.expr = expr

    def __repr__(self):
        return "<%s %s 0>" % (self.expr, self.operator)

    def to_constraint(self):
        """Transform itself into a constraint using Expr"""
        raise NotImplementedError("Abstract method")


class CondConstraintZero(CondConstraint):

    """Stand for a constraint like 'A == 0'"""
    operator = m2_expr.TOK_EQUAL

    def to_constraint(self):
        return m2_expr.ExprAssign(self.expr, m2_expr.ExprInt(0, self.expr.size))


class CondConstraintNotZero(CondConstraint):

    """Stand for a constraint like 'A != 0'"""
    operator = "!="

    def to_constraint(self):
        cst1, cst2 = m2_expr.ExprInt(0, 1), m2_expr.ExprInt(1, 1)
        return m2_expr.ExprAssign(cst1, m2_expr.ExprCond(self.expr, cst1, cst2))


ConstrainedValue = collections.namedtuple("ConstrainedValue",
                                          ["constraints", "value"])


class ConstrainedValues(set):

    """Set of ConstrainedValue"""

    def __str__(self):
        out = []
        for sol in self:
            out.append("%s with constraints:" % sol.value)
            for constraint in sol.constraints:
                out.append("\t%s" % constraint)
        return "\n".join(out)


def possible_values(expr):
    """Return possible values for expression @expr, associated with their
    condition constraint as a ConstrainedValues instance
    @expr: Expr instance
    """

    consvals = ConstrainedValues()

    # Terminal expression
    if (isinstance(expr, m2_expr.ExprInt) or
        isinstance(expr, m2_expr.ExprId) or
        isinstance(expr, m2_expr.ExprLoc)):
        consvals.add(ConstrainedValue(frozenset(), expr))
    # Unary expression
    elif isinstance(expr, m2_expr.ExprSlice):
        consvals.update(ConstrainedValue(consval.constraints,
                                         consval.value[expr.start:expr.stop])
                        for consval in possible_values(expr.arg))
    elif isinstance(expr, m2_expr.ExprMem):
        consvals.update(ConstrainedValue(consval.constraints,
                                         m2_expr.ExprMem(consval.value,
                                                         expr.size))
                        for consval in possible_values(expr.ptr))
    elif isinstance(expr, m2_expr.ExprAssign):
        consvals.update(possible_values(expr.src))
    # Special case: constraint insertion
    elif isinstance(expr, m2_expr.ExprCond):
        src1cond = CondConstraintNotZero(expr.cond)
        src2cond = CondConstraintZero(expr.cond)
        consvals.update(ConstrainedValue(consval.constraints.union([src1cond]),
                                         consval.value)
                        for consval in possible_values(expr.src1))
        consvals.update(ConstrainedValue(consval.constraints.union([src2cond]),
                                         consval.value)
                        for consval in possible_values(expr.src2))
    # N-ary expression
    elif isinstance(expr, m2_expr.ExprOp):
        # For details, see ExprCompose
        consvals_args = [possible_values(arg) for arg in expr.args]
        for consvals_possibility in itertools.product(*consvals_args):
            args_value = [consval.value for consval in consvals_possibility]
            args_constraint = itertools.chain(*[consval.constraints
                                                for consval in consvals_possibility])
            consvals.add(ConstrainedValue(frozenset(args_constraint),
                                          m2_expr.ExprOp(expr.op, *args_value)))
    elif isinstance(expr, m2_expr.ExprCompose):
        # Generate each possibility for sub-argument, associated with the start
        # and stop bit
        consvals_args = [
            list(possible_values(arg))
            for arg in expr.args
        ]
        for consvals_possibility in itertools.product(*consvals_args):
            # Merge constraint of each sub-element
            args_constraint = itertools.chain(*[consval.constraints
                                                for consval in consvals_possibility])
            # Gen the corresponding constraints / ExprCompose
            args = [consval.value for consval in consvals_possibility]
            consvals.add(
                ConstrainedValue(frozenset(args_constraint),
                                 m2_expr.ExprCompose(*args)))
    else:
        raise RuntimeError("Unsupported type for expr: %s" % type(expr))

    return consvals
