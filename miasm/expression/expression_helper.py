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
from miasm.expression.expression import *

tab_size_int = {1:uint1,
                8:uint8,
                16:uint16,
                32:uint32,
                64:uint64,
                }

tab_max_uint = {8:uint8(0xFF), 16:uint16(0xFFFF), 32:uint32(0xFFFFFFFF), 64:uint64(0xFFFFFFFFFFFFFFFFL)}


def parity(a):
    tmp = (a)&0xFFL
    cpt = 1
    while tmp!=0:
        cpt^=tmp&1
        tmp>>=1
    return cpt

def merge_sliceto_slice(args):
    sources = {}
    non_slice = {}
    sources_int = {}
    for a in args:
        if isinstance(a[0], ExprInt):
            # sources_int[a.start] = a
            # copy ExprInt because we will inplace modify arg just below
            # /!\ TODO XXX never ever modify inplace args...
            sources_int[a[1]] = (ExprInt(a[0].arg.__class__(a[0].arg)),
                                 a[1],
                                 a[2])
        elif isinstance(a[0], ExprSlice):
            if not a[0].arg in sources:
                sources[a[0].arg] = []
            sources[a[0].arg].append(a)
        else:
            non_slice[a[1]] = a
    # find max stop to determine size
    max_size = None
    for a in args:
        if max_size == None or max_size < a[2]:
            max_size = a[2]

    # first simplify all num slices
    final_sources = []
    sorted_s = []
    for x in sources_int.values():
        #mask int
        v = x[0].arg & ((1<<(x[2]-x[1]))-1)
        x[0].arg = v
        sorted_s.append((x[1], x))
    sorted_s.sort()
    while sorted_s:
        start, v = sorted_s.pop()
        out = [v[0].copy(), v[1], v[2]]
        while sorted_s:
            if sorted_s[-1][1][2] != start:
                break

            start = sorted_s[-1][1][1]
            a = uint64((int(out[0].arg) << (out[1] - start )) + int(sorted_s[-1][1][0].arg))
            out[0].arg = a
            sorted_s.pop()
            out[1] = start

        out_type = tab_size_int[max_size]
        out[0].arg = out_type(out[0].arg)
        final_sources.append((start, out))

    final_sources_int = final_sources

    # check if same sources have corresponding start/stop
    # is slice AND is sliceto
    simp_sources = []
    for s, args in sources.items():
        final_sources = []
        sorted_s = []
        for x in args:
            sorted_s.append((x[1], x))
        sorted_s.sort()
        while sorted_s:
            start, v = sorted_s.pop()
            out = v[0].copy(), v[1], v[2]
            while sorted_s:
                if sorted_s[-1][1][2] != start:
                    break
                if sorted_s[-1][1][0].stop != out[0].start:
                    break

                start = sorted_s[-1][1][1]
                out[0].start = sorted_s[-1][1][0].start
                sorted_s.pop()
            out = out[0], start, out[2]

            final_sources.append((start, out))

        simp_sources+=final_sources

    simp_sources+= final_sources_int

    for i, v in non_slice.items():
        simp_sources.append((i, v))

    simp_sources.sort()

    simp_sources = [x[1] for x in simp_sources]
    return simp_sources



op_assoc = ['+', '*', '^', '&', '|']


def expr_simp(e):
    return e.visit(_expr_simp)

def _expr_simp(e):
    if isinstance(e, ExprOp):
        # merge associatif op
        # ((a+b) + c) => (a + b + c)
        args = []
        for a in e.args:
            if e.op in op_assoc and isinstance(a, ExprOp) and e.op == a.op:
                args += a.args
            else:
                args.append(a)
        op = e.op
        if op in op_assoc:
            args = canonize_expr_list(args)
        # simpl integer manip
        # int OP int => int
        if op in op_assoc + ['>>', '<<']:
            while len(args) >= 2 and isinstance(args[-1], ExprInt) and isinstance(args[-2], ExprInt):
                i1 = args.pop()
                i2 = args.pop()
                if i1.get_size() != i2.get_size():
                    raise ValueError("diff size! %s %r %r"%(str(e),
                                                            i1.get_size(),
                                                            i2.get_size()))
                if op == '+':
                    o = i1.arg + i2.arg
                elif op == '*':
                    o = i1.arg * i2.arg
                elif op == '^':
                    o = i1.arg ^ i2.arg
                elif op == '&':
                    o = i1.arg & i2.arg
                elif op == '|':
                    o = i1.arg | i2.arg
                elif op == '>>':
                    o = i1.arg >> i2.arg
                elif op == '<<':
                    o = i1.arg << i2.arg

                o = ExprInt(tab_size_int[i1.get_size()](o))
                args.append(o)
        # --(A) => A
        if op == '-' and len(args) == 1 and isinstance(args[0], ExprOp) and \
                args[0].op == '-' and len(args[0].args) == 1:
            return args[0].args[0]

        # -(int) => -int
        if op == '-' and len(args) == 1 and isinstance(args[0], ExprInt):
            return ExprInt(-args[0].arg)
        # A op 0 =>A
        if op in ['+', '-', '|', "^", "<<", ">>", "<<<", ">>>"] and len(args) > 1:
            if isinstance(args[-1], ExprInt) and args[-1].arg == 0:
                args.pop()

        # op A => A
        if op in op_assoc + ['>>', '<<', '<<<', '>>>'] and len(args) == 1 :
            return args[0]

        # A-B => A + (-B)
        if op == '-' and len(args) > 1:
            if len(args) > 2:
                raise ValueError('sanity check fail on expr -: should have one or 2 args  %r %s'%(e, e))
            return ExprOp('+', args[0], -args[1])

        # - (A + B +...) => -A + -B + -C
        if op == '-' and len(args) == 1 and isinstance(args[0], ExprOp) and args[0].op == '+':
            args = [-a for a in args[0].args]
            return ExprOp('+', *args)

        i = 0
        while i<len(args)-1:
            j = i+1
            while j < len(args):
                # A ^ A => 0
                if op == '^' and args[i] == args[j]:
                    args[i] = ExprInt(tab_size_int[args[i].get_size()](0))
                    del(args[j])
                    continue
                # A + (- A) => 0
                if op == '+' and isinstance(args[j], ExprOp) and args[j].op == "-":
                    if len(args[j].args) == 1 and args[i] == args[j].args[0]:
                        args[i] = ExprInt(tab_size_int[args[i].get_size()](0))
                        del(args[j])
                        continue
                # (- A) + A => 0
                if op == '+' and isinstance(args[i], ExprOp) and args[i].op == "-":
                    if len(args[i].args) == 1 and args[j] == args[i].args[0]:
                        args[i] = ExprInt(tab_size_int[args[i].get_size()](0))
                        del(args[j])
                        continue
                # A | A => A
                if op == '|' and args[i] == args[j]:
                    del(args[j])
                    continue
                # A & A => A
                if op == '&' and args[i] == args[j]:
                    del(args[j])
                    continue
                j+=1
            i+=1

        # A <<< A.size => A
        if op in ['<<<', '>>>'] and isinstance(args[1], ExprInt) and args[1].arg == args[0].get_size():
            return args[0]


        # A <<< X <<< Y => A <<< (X+Y) (ou <<< >>>)
        if op in ['<<<', '>>>'] and isinstance(args[0], ExprOp) and args[0].op in ['<<<', '>>>']:
            op1 = op
            op2 = args[0].op
            if op1 == op2:
                op = op1
                args1 = args[0].args[1] + args[1]
            else:
                op = op2
                args1 = args[0].args[1] - args[1]

            args0 = args[0].args[0]
            args = [args0, args1]


        # ! (!X + int) => X - int
        # TODO

        # ((A & mask) >> shift) whith mask < 2**shift => 0
        if op == ">>" and isinstance(args[1], ExprInt) and isinstance(args[0], ExprOp) and args[0].op == "&":
            if isinstance(args[0].args[1], ExprInt) and 2**args[1].arg >= args[0].args[1].arg:
                return ExprInt(tab_size_int[args[0].get_size()](0))


        # int == int => 0 or 1
        if op == '==' and isinstance(args[0], ExprInt) and isinstance(args[1], ExprInt):
            if args[0].arg == args[1].arg:
                return ExprInt(tab_size_int[args[0].get_size()](1))
            else:
                return ExprInt(tab_size_int[args[0].get_size()](0))
        #(A|int == 0)  => 0  with int != 0
        if op == '==' and isinstance(args[1], ExprInt) and args[1].arg == 0:
            if isinstance(args[0], ExprOp) and args[0].op == '|' and\
                    isinstance(args[0].args[1], ExprInt) and \
                    args[0].args[1].arg != 0:
                return ExprInt(tab_size_int[args[0].get_size()](0))

        # parity(int) => int
        if op == 'parity' and isinstance(args[0], ExprInt):
            return ExprInt(tab_size_int[args[0].get_size()](parity(args[0].arg)))

        return ExprOp(op, *args)

    # Slice optimization
    elif isinstance(e, ExprSlice):
        # slice(A, 0, a.size) => A
        if e.start == 0 and e.stop == e.arg.get_size():
            return e.arg
        # Slice(int) => int
        elif isinstance(e.arg, ExprInt):
            total_bit = e.stop-e.start
            mask = uint64((1<<(e.stop-e.start))-1)
            if total_bit in tab_size_int:
                return ExprInt(tab_size_int[total_bit]((uint64((e.arg.arg)>>e.start)) & mask))
            else:
                # XXX TODO fix correct size
                #fds
                return ExprInt(type(e.arg.arg)((uint64((e.arg.arg)>>e.start)) & mask))
        # Slice(Slice(A, x), y) => Slice(A, z)
        elif isinstance(e.arg, ExprSlice):
            if e.stop-e.start > e.arg.stop-e.arg.start:
                raise ValueError('slice in slice: getting more val', str(e))

            new_e = ExprSlice(e.arg.arg, e.start + e.arg.start, e.start + e.arg.start + (e.stop - e.start))
            return new_e
        # Slice(Compose(A), x) => Slice(A, y)
        elif isinstance(e.arg, ExprCompose):
            for a in e.arg.args:
                if a[1] <= e.start and a[2]>=e.stop:
                    new_e = a[0][e.start-a[1]:e.stop-a[1]]
                    return new_e
        # XXXX todo hum, is it safe?
        elif isinstance(e.arg, ExprMem) and e.start == 0 and e.arg.size > e.stop and e.stop %8 == 0:
            e = ExprMem(e.arg.arg, size = e.stop)
            return e

        return e

    elif isinstance(e, ExprCompose):
        args = merge_sliceto_slice(e.args)
        # Compose(a) with a.size = compose.size => a
        if len(args) == 1 and args[0][1] == 0 and args[0][2] == e.get_size():
            return args[0][0]

        return ExprCompose(args)


    elif isinstance(e, ExprCond):
        # -A ? B:C => A ? B:C
        if isinstance(e.cond, ExprOp) and e.cond.op == '-' and len(e.cond.args) == 1:
            e = ExprCond(e.cond.args[0], e.src1, e.src2)
        # int ? A:B => A or B
        elif isinstance(e.cond, ExprInt):
            if e.cond.arg == 0:
                e = e.src2
            else:
                e = e.src1
        return e
    else:
        return e


