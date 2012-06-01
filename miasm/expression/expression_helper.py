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

tab_size_int = {8:uint8,
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
        out = v[0].reload_expr(), v[1], v[2]
        while sorted_s:
            if sorted_s[-1][1][2] != start:
                break

            start = sorted_s[-1][1][1]

            a = uint64((int(out[0].arg) << (out[1] - start )) + sorted_s[-1][1][0].arg)
            out.arg = ExprInt(uint32(a))
            sorted_s.pop()
            out[1] = start

        out_type = tab_size_int[max_size]
        out[0].arg = out_type(out[0].arg)
        final_sources.append((start, out))

    final_sources_int = final_sources

    #check if same sources have corresponding start/stop
    #is slice AND is sliceto
    simp_sources = []
    for s, args in sources.items():
        final_sources = []
        sorted_s = []
        for x in args:
            sorted_s.append((x[1], x))
        sorted_s.sort()
        while sorted_s:
            start, v = sorted_s.pop()
            out = v[0].reload_expr(), v[1], v[2]
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


def expr_simp(e):
    if e.is_simp:
        return e
    e = expr_simp_w(e)
    e.is_simp = True
    return e

def expr_simp_w(e):
    if isinstance(e, ExprTop):
        return e
    if isinstance(e, ExprInt):
        return e
    elif isinstance(e, ExprId):
        return e
    elif isinstance(e, ExprAff):
        return ExprAff(expr_simp(e.dst), expr_simp(e.src))
    elif isinstance(e, ExprCond):
        c = expr_simp(e.cond)
        if isinstance(c, ExprInt):
            print e
            fdsfsdf
            if c == 0:
                return expr_simp(e.src2)
            else:
                return expr_simp(e.src1)

        return ExprCond(expr_simp(e.cond), expr_simp(e.src1), expr_simp(e.src2))
    elif isinstance(e, ExprMem):
        if isinstance(e.arg, ExprTop):
            return ExprTop()
        return ExprMem(expr_simp(e.arg), size = e.size)
    elif isinstance(e, ExprOp):
        op, args = e.op, list(e.args)
        """
        if ExprTop() in args:
            return ExprTop()
        """
        #int OP int => int
        if e.op in ['+', '-', '*', '|', '&', '^', '>>', '<<'] and isinstance(args[0], ExprInt) and isinstance(args[1], ExprInt) :
            if args[0].get_size() != args[1].get_size():
                raise ValueError("diff size! %s"%(str(e)))
            if e.op == '+':
                o = args[0].arg + args[1].arg
            elif e.op == '-':
                o = args[0].arg - args[1].arg
            elif e.op == '*':
                o = args[0].arg * args[1].arg
            elif e.op == '|':
                o = args[0].arg | args[1].arg
            elif e.op == '&':
                o = args[0].arg & args[1].arg
            elif e.op == '^':
                o = args[0].arg ^ args[1].arg
            elif e.op == '>>':
                o = args[0].arg >> args[1].arg
            elif e.op == '<<':
                o = args[0].arg << args[1].arg
            else:
                raise ValueError("zarb op %s"%str(e))
            z = ExprInt(tab_size_int[args[0].get_size()](o))
            return z

        #int OP xx => xx OP int
        if e.op in ['+', '*', '|', '&', '^']:
            if isinstance(e.args[0], ExprInt) and not isinstance(e.args[1], ExprInt):
                op, args= e.op, [e.args[1], e.args[0]]
        #A+0 =>A
        if op in ['+', '-', '|', "^", "<<", ">>"]:
            if isinstance(args[0], ExprInt) and args[0].arg == 0 and not op in ['-', "<<", ">>"]:
                return expr_simp(args[1])
            if isinstance(args[1], ExprInt) and args[1].arg == 0:
                return expr_simp(args[0])

        #A&0 =>0
        if op in ['&']:
            if isinstance(args[1], ExprInt) and args[1].arg == 0:
                return args[1]

        #A-(-123) =>A+123
        if op == '-' and isinstance(args[1], ExprInt) and int32(args[1].arg)<0 :
            op = '+'
            args[1] = ExprInt(-args[1].arg)

        #A+(-123) =>A-123
        if op == '+' and isinstance(args[1], ExprInt) and int32(args[1].arg)<0 :
            op = '-'
            args[1] = ExprInt(-args[1].arg)
            #fdsfs
        #A+3+2 => A+5
        if op in ['+', '-'] and isinstance(args[1], ExprInt) and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and isinstance(args[0].args[1], ExprInt):
            op1 = op
            op2 = args[0].op
            if op1 == op2:
                op = op1
                args1 = args[0].args[1].arg + args[1].arg
            else:
                op = op2
                args1 = args[0].args[1].arg - args[1].arg


                #if op == '-':
                #    args1 = -args1
            args0 = args[0].args[0]
            args = [args0, ExprInt(args1)]

        if op in ['+'] and isinstance(args[1], ExprInt) and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and isinstance(args[0].args[0], ExprInt):
            op = args[0].op
            args1 = args[0].args[0].arg + args[1].arg
            args0 = args[0].args[1]
            args = [ExprInt(args1), args0]

        #0 - (a-b) => b-a
        if op == '-' and isinstance(args[0], ExprInt) and args[0].arg == 0 and isinstance(args[1], ExprOp) and args[1].op == "-":
            return expr_simp(args[1].args[1] - args[1].args[0])

        #a<<< x <<< y => a <<< (x+y) (ou <<< >>>)
        if op in ['<<<', '>>>'] and isinstance(args[1], ExprInt) and isinstance(args[0], ExprOp) and args[0].op in ['<<<', '>>>'] and isinstance(args[0].args[1], ExprInt):
            op1 = op
            op2 = args[0].op
            if op1 == op2:
                op = op1
                args1 = args[0].args[1].arg + args[1].arg
            else:
                op = op2
                args1 = args[0].args[1].arg - args[1].arg

            args0 = args[0].args[0]
            args = [args0, ExprInt(args1)]


        #a >>> 0 => a (ou <<<)
        if op in ['<<<', '>>>'] and isinstance(args[1], ExprInt) and args[1].arg == 0:
            e = expr_simp(args[0])
            return e

        #((a >>> b) <<< b) => a
        if op in ['<<<', '>>>'] and isinstance(args[0], ExprOp) and args[0].op in ['<<<', '>>>'] and args[1] == args[0].args[1]:
            oo = op, args[0].op
            if oo in [('<<<', '>>>'), ('>>>', '<<<')]:

                e = expr_simp(args[0].args[0])
                return e


        #( a + int1 ) - (b+int2) => a - (b+ (int1-int2))
        if op in ['+', '-'] and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and isinstance(args[1], ExprOp) and args[1].op in ['+', '-'] and isinstance(args[0].args[1], ExprInt) and isinstance(args[1].args[1], ExprInt):
            op1 = op
            op2 = args[0].op
            op3 = args[1].op

            if op1 == op2:
                m_op = "+"
            else:
                m_op = "-"
            e = ExprOp(op1,
                       args[0].args[0],
                       ExprOp(m_op,
                              ExprOp(op3,
                                     args[1].args[0],
                                     args[1].args[1]
                                     ),
                              args[0].args[1]
                              )
                       )
            e = expr_simp(e)

            return e

        #(a - (a + XXX)) => 0-XXX
        if op in ['-'] and isinstance(args[1], ExprOp) and args[1].op in ['+', '-'] and args[1].args[0] == args[0]:
            if op == args[1].op:
                m_op = "+"
            else:
                m_op = "-"

            z = ExprInt(tab_size_int[args[1].args[1].get_size()](0))
            e = ExprOp(m_op,
                       z,
                       args[1].args[1])
            e = expr_simp(e)

            return e


        #((a +- XXX) -a) => 0+-XXX
        if op in ['-'] and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and args[0].args[0] == args[1]:
            m_op = args[0].op

            z = ExprInt(tab_size_int[args[0].args[1].get_size()](0))
            e = ExprOp(m_op,
                       z,
                       args[0].args[1])
            e = expr_simp(e)

            return e

        #  ((a ^ b) ^ a) => b (or commut)
        if op in ['^'] and isinstance(args[0], ExprOp) and args[0].op in ['^']:
            rest_a = None
            if args[0].args[0] == args[1]:
                rest_a = args[0].args[1]
            elif args[0].args[1] == args[1]:
                rest_a = args[0].args[0]
            if rest_a != None:
                e = expr_simp(rest_a)
                return e
        #  (a ^ (a ^ b) ) => b (or commut)
        if op in ['^'] and isinstance(args[1], ExprOp) and args[1].op in ['^']:
            rest_a = None
            if args[1].args[0] == args[0]:
                rest_a = args[1].args[1]
            elif args[1].args[1] == args[0]:
                rest_a = args[1].args[0]
            if rest_a != None:
                e = expr_simp(rest_a)
                return e


        #  ((a + b) - b) => a (or commut)
        if op in ['-'] and isinstance(args[0], ExprOp) and args[0].op in ['+']:
            rest_a = None
            if args[0].args[1] == args[1]:
                rest_a = args[0].args[0]
                e = expr_simp(rest_a)
                return e

        #  ((a - b) + b) => a (or commut)
        if op in ['+'] and isinstance(args[0], ExprOp) and args[0].op in ['-']:
            rest_a = None
            if args[0].args[1] == args[1]:
                rest_a = args[0].args[0]
                e = expr_simp(rest_a)
                return e

        # a<<< a.size => a
        if op in ['<<<', '>>>'] and isinstance(args[1], ExprInt) and args[1].arg == args[0].get_size():
            return expr_simp(args[0])

        #!!a => a
        if op == '!' and isinstance(args[0], ExprOp) and args[0].op == '!':
            new_e = args[0].args[0]
            return expr_simp(new_e)

        #! (!X + int) => X - int
        if op == '!' and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and isinstance(args[0].args[0], ExprOp) and args[0].args[0].op == '!':
            if args[0].op == '+':
                op = '-'
            else:
                op = '+'
            return expr_simp(ExprOp(op, args[0].args[0].args[0], args[0].args[1]))

        # ((a (op1+-) int)  (op2+-) b) => ((a (op2) b) op1 int))
        if op in ['+', '-'] and isinstance(args[0], ExprOp) and args[0].op in ['+', '-'] and not isinstance(args[1], ExprInt) and args[0].op in ['+', '-'] and isinstance(args[0].args[1], ExprInt):
            op1 = op
            op2 = args[0].op
            e = ExprOp(op2,
                       ExprOp(op1,
                              args[0].args[0],
                              args[1])
                       ,
                       args[0].args[1])
            return expr_simp(e)


        if op == "&" and isinstance(args[0], ExprOp) and args[0].op == '!' and isinstance(args[1], ExprOp) and args[1].op == '!' and isinstance(args[0].args[0], ExprOp) and args[0].args[0].op == '&' and isinstance(args[1].args[0], ExprOp) and args[1].args[0].op == '&':

            ##############1
            a1 = args[0].args[0].args[0]
            if isinstance(a1, ExprOp) and a1.op == '!':
                a1 = a1.args[0]
            elif isinstance(a1, ExprInt):
                a1 = ExprInt(~a1.arg)
            else:
                a1 = None

            b1 = args[0].args[0].args[1]
            if isinstance(b1, ExprOp) and b1.op == '!':
                b1 = b1.args[0]
            elif isinstance(b1, ExprInt):
                b1 = ExprInt(~b1.arg)
            else:
                b1 = None


            a2 = args[1].args[0].args[0]
            b2 = args[1].args[0].args[1]


            if a1 != None and b1 != None and a1 == a2 and b1 == b2:
                new_e = ExprOp('^', a1, b1)
                return expr_simp(new_e)

            ################2
            a1 = args[1].args[0].args[0]
            if isinstance(a1, ExprOp) and a1.op == '!':
                a1 = a1.args[0]
            elif isinstance(a1, ExprInt):
                a1 = ExprInt(~a1.arg)
            else:
                a1 = None

            b1 = args[1].args[0].args[1]
            if isinstance(b1, ExprOp) and b1.op == '!':
                b1 = b1.args[0]
            elif isinstance(b1, ExprInt):
                b1 = ExprInt(~b1.arg)
            else:
                b1 = None


            a2 = args[0].args[0].args[0]
            b2 = args[0].args[0].args[1]


            if a1 != None and b1 != None and a1 == a2 and b1 == b2:
                new_e = ExprOp('^', a1, b1)
                return expr_simp(new_e)


        # (x & mask) >> shift whith mask < 2**shift => 0
        if op == ">>" and isinstance(args[1], ExprInt) and isinstance(args[0], ExprOp) and args[0].op == "&":
            if isinstance(args[0].args[1], ExprInt) and 2**args[1].arg >= args[0].args[1].arg:
                return ExprInt(tab_size_int[args[0].get_size()](0))

        #! (compose a b c) => (compose !a !b !c)
        if op == '!' and isinstance(args[0], ExprCompose):
            args = [(ExprOp('!', x.arg), x[1], x[2]) for x in args[0].args]
            new_e = ExprCompose(args)
            return expr_simp(new_e)
        #!a[0:X] => (!a)[0:X]
        if op == '!' and isinstance(args[0], ExprSlice):
            new_e = ExprSlice(ExprOp('!', args[0].arg), args[0].start, args[0].stop)
            return expr_simp(new_e)


        #! int
        if op == '!' and isinstance(args[0], ExprInt):
            a = args[0]
            e = ExprInt(tab_max_uint[a.get_size()]^a.arg)
            return e

        #a^a=>0 | a-a =>0
        if op in ['^', '-'] and args[0] == args[1]:
            tmp =  ExprInt(tab_size_int[args[0].get_size()](0))
            return tmp

        #a & a => a   or a | a => a
        if op in ['&', '|'] and args[0] == args[1]:
            return expr_simp(args[0])
        # int == int => 0 or 1
        if op == '==' and isinstance(args[0], ExprInt) and isinstance(args[1], ExprInt):
            if args[0].arg == args[1].arg:
                return ExprInt(tab_size_int[args[0].get_size()](1))
            else:
                return ExprInt(tab_size_int[args[0].get_size()](0))
        #( a|int == 0)  => 0  wirh int != 0
        if op == '==' and isinstance(args[1], ExprInt) and args[1].arg ==0 :
            if isinstance(args[0], ExprOp) and args[0].op == '|' and isinstance(args[0].args[1], ExprInt) and \
               args[0].args[1].arg != 0:
                return ExprInt(tab_size_int[args[0].get_size()](0))


        if op == 'parity' and isinstance(args[0], ExprInt):
            return ExprInt(tab_size_int[args[0].get_size()](parity(args[0].arg)))

        new_e = ExprOp(op, *[expr_simp(x) for x in args])
        if new_e == e:
            return new_e
        else:
            return expr_simp(new_e)

    #Slice(int) => new_int
    elif isinstance(e, ExprSlice):
        arg = expr_simp(e.arg)

        if isinstance(arg, ExprTop):
            return ExprTop()
        elif e.start == 0 and e.stop == 32 and arg.get_size() == 32:
            return arg

        elif isinstance(arg, ExprInt):
            total_bit = e.stop-e.start
            mask = uint64((1<<(e.stop-e.start))-1)
            if total_bit in tab_size_int:
                return ExprInt(tab_size_int[total_bit]((uint64((arg.arg)>>e.start)) & mask))
            else:
                return ExprInt(type(arg.arg)((uint64((arg.arg)>>e.start)) & mask))
        elif isinstance(arg, ExprSlice):
            if e.stop-e.start > arg.stop-arg.start:
                raise ValueError('slice in slice: getting more val', str(e))

            new_e = ExprSlice(expr_simp(arg.arg), e.start + arg.start, e.start + arg.start + (e.stop - e.start))
            return expr_simp(new_e)
        elif isinstance(arg, ExprCompose):
            for a in arg.args:
                if a[1] <= e.start and a[2]>=e.stop:
                    new_e = a[0][e.start-a[1]:e.stop-a[1]]
                    new_e = expr_simp(new_e)
                    return new_e
        elif isinstance(arg, ExprOp) and e.start == 0:
            #if (op ..)[0:X] and op result is good size, skip slice
            if e.stop == arg.get_size():
                return expr_simp(arg)
            return ExprSlice(arg, e.start, e.stop)
        elif isinstance(arg, ExprMem) and e.start == 0 and arg.size == e.stop:
            e = expr_simp(arg)
            return e
        #XXXX todo hum, is it safe?
        elif isinstance(arg, ExprMem) and e.start == 0 and arg.size > e.stop and e.stop %8 == 0:
            e = expr_simp(ExprMem(e.arg.arg, size = e.stop))
            return e




        return ExprSlice(arg, e.start, e.stop)
        """
    XXX todo move to exprcompose
    elif isinstance(e, ExprSliceTo):
        if isinstance(e.arg, ExprTop):
            return ExprTop()
        if isinstance(e.arg, ExprSlice) and e.arg.start == 0:
            return expr_simp(ExprSliceTo(expr_simp(e.arg.arg), e.start, e.stop))

        #(.., a[0:X], ..) _to[Y:Z] with X > Z-Y => a[0:X]_to[Y:Z]
        if isinstance(e.arg, ExprCompose) and len(e.arg.args) >1:
            s = e.get_size()
            for a in e.arg.args:
                if a.start == 0 and a.stop >= s:
                    return expr_simp(ExprSliceTo(ExprCompose([a]), e.start, e.stop))



        return ExprSliceTo(expr_simp(e.arg), e.start, e.stop)
        """
    elif isinstance(e, ExprCompose):
        #(.., a_to[x:y], a[:]_to[y:z], ..) => (.., a[x:z], ..)
        e = ExprCompose([(expr_simp(x[0]), x[1], x[2]) for x in e.args])
        args = []
        i = -1
        simp = False
        while i+1 < len(e.args):
            i+=1
            if not args:
                args.append(e.args[i])
                continue
            if args[-1][2] != e.args[i][1]:
                continue
            if not isinstance(e.args[i][0], ExprSlice):
                continue
            if isinstance(args[-1][0], ExprSlice):
                a = args[-1]
            else:
                a = (ExprSlice(args[-1][0], 0, args[-1][0].get_size()),
                     args[-1][1],
                     args[-1][2])
            if a[0].arg != e.args[i][0].arg:
                continue
            if a[2] != e.args[i][1]:
                continue
            args[-1] = (e.args[i][0].arg, a[1], e.args[i][2])
            simp = True

        if simp:
            return expr_simp(ExprCompose(args))



        all_top = True
        for a in e.args:
            if not isinstance(a, ExprTop):
                all_top = False
                break
        if all_top:
            return ExprTop()
        """
        if ExprTop() in e.args:
            return ExprTop()
        """

        args = merge_sliceto_slice(e.args)
        if len(args) == 1:
            a = args[0]
            if isinstance(a[0], ExprInt):
                if a[0].get_size() != a[2]:
                    print a, a[0].get_size(), a[2]
                    raise ValueError("todo cast in compose!", e)
                return a[0]
            uu = expr_simp(a[0][:e.get_size()])
            return uu
        if len(args) != len(e.args):
            return expr_simp(ExprCompose(args))
        else:
            return ExprCompose(args)
    else:
        raise 'bad expr'


def expr_cmp(e1, e2):
    return str(e1) == str(e2)
"""
#replace id by another in expr
def expr_replace(e, repl):
    if isinstance(e, ExprInt):
        return e
    elif isinstance(e, ExprId):
        if e in repl:
            return repl[e]
        return e
    elif isinstance(e, ExprAff):
        return ExprAff(expr_replace(e.dst, repl), expr_replace(e.src, repl))
    elif isinstance(e, ExprCond):
        return ExprCond(expr_replace(e.cond, repl), expr_replace(e.src1, repl), expr_replace(e.src2, repl))
    elif isinstance(e, ExprMem):
        return ExprMem(expr_replace(e.arg, repl), size = e.size)
    elif isinstance(e, ExprOp):
        return ExprOp(e.op, *[expr_replace(x, repl) for x in e.args])
    elif isinstance(e, ExprSlice):
        return ExprSlice(expr_replace(e.arg, repl), e.start, e.stop)
    elif isinstance(e, ExprCompose):
        return ExprCompose([(expr_replace(x[0], repl), x[1], x[2]) for x in e.args])
    else:
        raise ValueError('bad expr', e)



"""
