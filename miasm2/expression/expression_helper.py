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
import re
import itertools
import collections

import miasm2.expression.expression as m2_expr


def parity(a):
    tmp = (a) & 0xFFL
    cpt = 1
    while tmp != 0:
        cpt ^= tmp & 1
        tmp >>= 1
    return cpt


def merge_sliceto_slice(args):
    sources = {}
    non_slice = {}
    sources_int = {}
    for a in args:
        if isinstance(a[0], m2_expr.ExprInt):
            # sources_int[a.start] = a
            # copy ExprInt because we will inplace modify arg just below
            # /!\ TODO XXX never ever modify inplace args...
            sources_int[a[1]] = (m2_expr.ExprInt_fromsize(a[2] - a[1],
                                                          a[0].arg.__class__(
                                                          a[0].arg)),
                                 a[1],
                                 a[2])
        elif isinstance(a[0], m2_expr.ExprSlice):
            if not a[0].arg in sources:
                sources[a[0].arg] = []
            sources[a[0].arg].append(a)
        else:
            non_slice[a[1]] = a
    # find max stop to determine size
    max_size = None
    for a in args:
        if max_size is None or max_size < a[2]:
            max_size = a[2]

    # first simplify all num slices
    final_sources = []
    sorted_s = []
    for x in sources_int.values():
        # mask int
        v = x[0].arg & ((1 << (x[2] - x[1])) - 1)
        x[0].arg = v
        sorted_s.append((x[1], x))
    sorted_s.sort()
    while sorted_s:
        start, v = sorted_s.pop()
        out = [m2_expr.ExprInt(v[0].arg), v[1], v[2]]
        size = v[2] - v[1]
        while sorted_s:
            if sorted_s[-1][1][2] != start:
                break
            s_start, s_stop = sorted_s[-1][1][1], sorted_s[-1][1][2]
            size += s_stop - s_start
            a = m2_expr.mod_size2uint[size](
                (int(out[0].arg) << (out[1] - s_start)) +
                 int(sorted_s[-1][1][0].arg))
            out[0].arg = a
            sorted_s.pop()
            out[1] = s_start
        out[0] = m2_expr.ExprInt_fromsize(size, out[0].arg)
        final_sources.append((start, out))

    final_sources_int = final_sources
    # check if same sources have corresponding start/stop
    # is slice AND is sliceto
    simp_sources = []
    for args in sources.values():
        final_sources = []
        sorted_s = []
        for x in args:
            sorted_s.append((x[1], x))
        sorted_s.sort()
        while sorted_s:
            start, v = sorted_s.pop()
            ee = v[0].arg[v[0].start:v[0].stop]
            out = ee, v[1], v[2]
            while sorted_s:
                if sorted_s[-1][1][2] != start:
                    break
                if sorted_s[-1][1][0].stop != out[0].start:
                    break

                start = sorted_s[-1][1][1]
                # out[0].start = sorted_s[-1][1][0].start
                o_e, _, o_stop = out
                o1, o2 = sorted_s[-1][1][0].start, o_e.stop
                o_e = o_e.arg[o1:o2]
                out = o_e, start, o_stop
                # update _size
                # out[0]._size = out[0].stop-out[0].start
                sorted_s.pop()
            out = out[0], start, out[2]

            final_sources.append((start, out))

        simp_sources += final_sources

    simp_sources += final_sources_int

    for i, v in non_slice.items():
        simp_sources.append((i, v))

    simp_sources.sort()
    simp_sources = [x[1] for x in simp_sources]
    return simp_sources


op_propag_cst = ['+', '*', '^', '&', '|', '>>',
                 '<<', "a>>", ">>>", "<<<",
                 "/", "%", 'idiv', 'imod', 'umod', 'udiv']


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

    var_identifier = re.compile("v\d+")

    def __init__(self, expr):
        """Set the expression @expr to handle and launch variable identification
        process"""

        # Init
        self.var_indice = itertools.count()
        self.var_asked = set()
        self._vars = {} # VarID -> Expr

        # Launch recurrence
        self.find_variables_rec(expr)

        # Compute inter-variable dependencies
        has_change = True
        while has_change:
            has_change = False
            for var_id, var_value in self._vars.items():
                cur = var_value

                # Do not replace with itself
                to_replace = {v_val:v_id for v_id, v_val in self._vars.items()
                              if v_id != var_id}
                var_value = var_value.replace_expr(to_replace)

                if cur != var_value:
                    # Force @self._vars update
                    has_change = True
                    self._vars[var_id] = var_value
                    break

        # Replace in the original equation
        self._equation = expr.replace_expr({v_val: v_id for v_id, v_val
                                            in self._vars.items()})

        # Compute variables dependencies
        self._vars_ordered = collections.OrderedDict()
        todo = set(self._vars.keys())
        needs = {}

        ## Build initial needs
        for var_id, var_expr in self._vars.items():
            needs[var_id] = [var_name
                             for var_name in var_expr.get_r(mem_read=True)
                             if self.is_var_identifier(var_name)]

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

    @classmethod
    def is_var_identifier(cls, expr):
        "Return True iff expr seems to be a variable identifier"
        if not isinstance(expr, m2_expr.ExprId):
            return False

        match = cls.var_identifier.match(expr.name)
        return match is not None and match.group(0) == expr.name

    def find_variables_rec(self, expr):
        """Recursive method called by find_variable to expand @expr.
        Set @var_names and @var_values.
        This implementation is faster than an expression visitor because
        we do not rebuild each expression.
        """

        if (expr in self.var_asked):
            # Expr has already been asked

            if (expr not in self._vars.values()):
                # Create var
                identifier = m2_expr.ExprId("v%s" % self.var_indice.next(),
                                    size = expr.size)
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

        elif isinstance(expr, m2_expr.ExprMem):
            self.find_variables_rec(expr.arg)

        elif isinstance(expr, m2_expr.ExprCompose):
            for a in expr.args:
                self.find_variables_rec(list(a)[0])

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
        for var_id, var_expr in self.vars.items():
            out += "%s = %s\n" % (var_id, var_expr)
        out += "Final: %s" % self.equation
        return out
