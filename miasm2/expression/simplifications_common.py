# ----------------------------- #
# Common simplifications passes #
# ----------------------------- #


from miasm2.expression.expression import *
from miasm2.expression.expression_helper import *


def simp_cst_propagation(e_s, e):
    """This passe includes:
     - Constant folding
     - Common logical identities
     - Common binary identities
     """

    # merge associatif op
    if not isinstance(e, ExprOp):
        return e
    args = list(e.args)
    op = e.op
    # simpl integer manip
    # int OP int => int
    # TODO: <<< >>> << >> are architecture dependant
    if op in op_propag_cst:
        while (len(args) >= 2 and
            isinstance(args[-1], ExprInt) and
            isinstance(args[-2], ExprInt)):
            i2 = args.pop()
            i1 = args.pop()
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
            elif op == 'a>>':
                x1 = mod_size2int[i1.arg.size](i1.arg)
                x2 = mod_size2int[i2.arg.size](i2.arg)
                o = mod_size2uint[i1.arg.size](x1 >> x2)
            elif op == '>>>':
                rounds = i2.arg
                o = i1.arg >> i2.arg | i1.arg << (i1.size - i2.arg)
            elif op == '<<<':
                o = i1.arg << i2.arg | i1.arg >> (i1.size - i2.arg)
            elif op == '/':
                o = i1.arg / i2.arg
            elif op == '%':
                o = i1.arg % i2.arg
            elif op == 'idiv':
                assert(i2.arg)
                x1 = mod_size2int[i1.arg.size](i1.arg)
                x2 = mod_size2int[i2.arg.size](i2.arg)
                o = mod_size2uint[i1.arg.size](x1 / x2)
            elif op == 'irem':
                assert(i2.arg)
                x1 = mod_size2int[i1.arg.size](i1.arg)
                x2 = mod_size2int[i2.arg.size](i2.arg)
                o = mod_size2uint[i1.arg.size](x1 % x2)

            o = ExprInt_fromsize(i1.size, o)
            args.append(o)

    # bsf(int) => int
    if op == "bsf" and isinstance(args[0], ExprInt) and args[0].arg != 0:
        i = 0
        while args[0].arg & (1 << i) == 0:
            i += 1
        return ExprInt_from(args[0], i)

    # bsr(int) => int
    if op == "bsr" and isinstance(args[0], ExprInt) and args[0].arg != 0:
        i = args[0].size - 1
        while args[0].arg & (1 << i) == 0:
            i -= 1
        return ExprInt_from(args[0], i)

    # -(-(A)) => A
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
    # A * 1 =>A
    if op == "*" and len(args) > 1:
        if isinstance(args[-1], ExprInt) and args[-1].arg == 1:
            args.pop()

    # for cannon form
    # A * -1 => - A
    if op == "*" and len(args) > 1:
        if (isinstance(args[-1], ExprInt) and
            args[-1].arg == (1 << args[-1].size) - 1):
            args.pop()
            args[-1] = - args[-1]

    # op A => A
    if op in ['+', '*', '^', '&', '|', '>>', '<<',
        'a>>', '<<<', '>>>', 'idiv', 'irem'] and len(args) == 1:
        return args[0]

    # A-B => A + (-B)
    if op == '-' and len(args) > 1:
        if len(args) > 2:
            raise ValueError(
                'sanity check fail on expr -: should have one or 2 args ' +
                '%r %s' % (e, e))
        return ExprOp('+', args[0], -args[1])

    # A op 0 => 0
    if op in ['&', "*"] and isinstance(args[1], ExprInt) and args[1].arg == 0:
        return ExprInt_from(e, 0)

    # - (A + B +...) => -A + -B + -C
    if (op == '-' and
        len(args) == 1 and
        isinstance(args[0], ExprOp) and
        args[0].op == '+'):
        args = [-a for a in args[0].args]
        e = ExprOp('+', *args)
        return e

    # -(a?int1:int2) => (a?-int1:-int2)
    if (op == '-' and
        len(args) == 1 and
        isinstance(args[0], ExprCond) and
        isinstance(args[0].src1, ExprInt) and
        isinstance(args[0].src2, ExprInt)):
        i1 = args[0].src1
        i2 = args[0].src2
        i1 = ExprInt_from(i1, -i1.arg)
        i2 = ExprInt_from(i2, -i2.arg)
        return ExprCond(args[0].cond, i1, i2)

    i = 0
    while i < len(args) - 1:
        j = i + 1
        while j < len(args):
            # A ^ A => 0
            if op == '^' and args[i] == args[j]:
                args[i] = ExprInt_from(args[i], 0)
                del(args[j])
                continue
            # A + (- A) => 0
            if op == '+' and isinstance(args[j], ExprOp) and args[j].op == "-":
                if len(args[j].args) == 1 and args[i] == args[j].args[0]:
                    args[i] = ExprInt_from(args[i], 0)
                    del(args[j])
                    continue
            # (- A) + A => 0
            if op == '+' and isinstance(args[i], ExprOp) and args[i].op == "-":
                if len(args[i].args) == 1 and args[j] == args[i].args[0]:
                    args[i] = ExprInt_from(args[i], 0)
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
            j += 1
        i += 1

    if op in ['|', '&', '%', '/'] and len(args) == 1:
        return args[0]

    # A <<< A.size => A
    if (op in ['<<<', '>>>'] and
        isinstance(args[1], ExprInt) and
        args[1].arg == args[0].size):
        return args[0]

    # A <<< X <<< Y => A <<< (X+Y) (ou <<< >>>)
    if (op in ['<<<', '>>>'] and
        isinstance(args[0], ExprOp) and
        args[0].op in ['<<<', '>>>']):
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

    # ((A & A.mask)
    if op == "&" and args[-1] == e.mask:
        return ExprOp('&', *args[:-1])

    # ((A | A.mask)
    if op == "|" and args[-1] == e.mask:
        return args[-1]

    # ! (!X + int) => X - int
    # TODO

    # ((A & mask) >> shift) whith mask < 2**shift => 0
    if (op == ">>" and
        isinstance(args[1], ExprInt) and
        isinstance(args[0], ExprOp) and args[0].op == "&"):
        if (isinstance(args[0].args[1], ExprInt) and
            2 ** args[1].arg >= args[0].args[1].arg):
            return ExprInt_from(args[0], 0)

    # parity(int) => int
    if op == 'parity' and isinstance(args[0], ExprInt):
        return ExprInt1(parity(args[0].arg))

    # (-a) * b * (-c) * (-d) => (-a) * b * c * d
    if op == "*" and len(args) > 1:
        new_args = []
        counter = 0
        for a in args:
            if isinstance(a, ExprOp) and a.op == '-' and len(a.args) == 1:
                new_args.append(a.args[0])
                counter += 1
            else:
                new_args.append(a)
        if counter % 2:
            return -ExprOp(op, *new_args)
        args = new_args

    return ExprOp(op, *args)


def simp_cond_op_int(e_s, e):
    "Extract conditions from operations"

    if not isinstance(e, ExprOp):
        return e
    if not e.op in ["+", "|", "^", "&", "*", '<<', '>>', 'a>>']:
        return e
    if len(e.args) < 2:
        return e
    if not isinstance(e.args[-1], ExprInt):
        return e
    a_int = e.args[-1]
    conds = []
    for a in e.args[:-1]:
        if not isinstance(a, ExprCond):
            return e
        conds.append(a)
    if not conds:
        return e
    c = conds.pop()
    c = ExprCond(c.cond,
                 ExprOp(e.op, c.src1, a_int),
                 ExprOp(e.op, c.src2, a_int))
    conds.append(c)
    new_e = ExprOp(e.op, *conds)
    return new_e


def simp_cond_factor(e_s, e):
    "Merge similar conditions"
    if not isinstance(e, ExprOp):
        return e
    if not e.op in ["+", "|", "^", "&", "*", '<<', '>>', 'a>>']:
        return e
    if len(e.args) < 2:
        return e
    conds = {}
    not_conds = []
    multi_cond = False
    for a in e.args:
        if not isinstance(a, ExprCond):
            not_conds.append(a)
            continue
        c = a.cond
        if not c in conds:
            conds[c] = []
        else:
            multi_cond = True
        conds[c].append(a)
    if not multi_cond:
        return e
    c_out = not_conds[:]
    for c, vals in conds.items():
        new_src1 = [x.src1 for x in vals]
        new_src2 = [x.src2 for x in vals]
        src1 = e_s.expr_simp_wrapper(ExprOp(e.op, *new_src1))
        src2 = e_s.expr_simp_wrapper(ExprOp(e.op, *new_src2))
        c_out.append(ExprCond(c, src1, src2))

    if len(c_out) == 1:
        new_e = c_out[0]
    else:
        new_e = ExprOp(e.op, *c_out)
    return new_e


def simp_slice(e_s, e):
    "Slice optimization"

    # slice(A, 0, a.size) => A
    if e.start == 0 and e.stop == e.arg.size:
        return e.arg
    # Slice(int) => int
    elif isinstance(e.arg, ExprInt):
        total_bit = e.stop - e.start
        mask = (1 << (e.stop - e.start)) - 1
        return ExprInt_fromsize(total_bit, (e.arg.arg >> e.start) & mask)
    # Slice(Slice(A, x), y) => Slice(A, z)
    elif isinstance(e.arg, ExprSlice):
        if e.stop - e.start > e.arg.stop - e.arg.start:
            raise ValueError('slice in slice: getting more val', str(e))

        new_e = ExprSlice(e.arg.arg, e.start + e.arg.start,
                          e.start + e.arg.start + (e.stop - e.start))
        return new_e
    # Slice(Compose(A), x) => Slice(A, y)
    elif isinstance(e.arg, ExprCompose):
        for a in e.arg.args:
            if a[1] <= e.start and a[2] >= e.stop:
                new_e = a[0][e.start - a[1]:e.stop - a[1]]
                return new_e
    # ExprMem(x, size)[:A] => ExprMem(x, a)
    # XXXX todo hum, is it safe?
    elif (isinstance(e.arg, ExprMem) and
        e.start == 0 and
        e.arg.size > e.stop and e.stop % 8 == 0):
        e = ExprMem(e.arg.arg, size=e.stop)
        return e
    # distributivity of slice and &
    # (a & int)[x:y] => 0 if int[x:y] == 0
    elif (isinstance(e.arg, ExprOp) and
        e.arg.op == "&" and
        isinstance(e.arg.args[-1], ExprInt)):
        tmp = e_s.expr_simp_wrapper(e.arg.args[-1][e.start:e.stop])
        if isinstance(tmp, ExprInt) and tmp.arg == 0:
            return tmp
    # distributivity of slice and exprcond
    # (a?int1:int2)[x:y] => (a?int1[x:y]:int2[x:y])
    elif (isinstance(e.arg, ExprCond) and
        isinstance(e.arg.src1, ExprInt) and
        isinstance(e.arg.src2, ExprInt)):
        src1 = e.arg.src1[e.start:e.stop]
        src2 = e.arg.src2[e.start:e.stop]
        e = ExprCond(e.arg.cond, src1, src2)

    # (a * int)[0:y] => (a[0:y] * int[0:y])
    elif (isinstance(e.arg, ExprOp) and
        e.arg.op == "*" and
        isinstance(e.arg.args[-1], ExprInt)):
        args = [e_s.expr_simp_wrapper(a[e.start:e.stop]) for a in e.arg.args]
        e = ExprOp(e.arg.op, *args)

    return e


def simp_compose(e_s, e):
    "Commons simplification on ExprCompose"
    args = merge_sliceto_slice(e.args)
    out = []
    # compose of compose
    for a in args:
        if isinstance(a[0], ExprCompose):
            for x, start, stop in a[0].args:
                out.append((x, start + a[1], stop + a[1]))
        else:
            out.append(a)
    args = out
    # Compose(a) with a.size = compose.size => a
    if len(args) == 1 and args[0][1] == 0 and args[0][2] == e.size:
        return args[0][0]

    # {(X[X.size-z, 0, z), (0, z, X.size)} => (X >> x)
    if (len(args) == 2 and
        isinstance(args[1][0], ExprInt) and
        args[1][0].arg == 0):
        a1 = args[0]
        a2 = args[1]
        if (isinstance(a1[0], ExprSlice) and
            a1[1] == 0 and a1[0].stop == a1[0].arg.size):
            if a2[1] == a1[0].size and a2[2] == a1[0].arg.size:
                new_e = a1[0].arg >> ExprInt_fromsize(
                    a1[0].arg.size, a1[0].start)
                return new_e

    # Compose with ExprCond with integers for src1/src2 and intergers =>
    # propagage integers
    # {XXX?(0x0,0x1)?(0x0,0x1),0,8, 0x0,8,32} => XXX?(int1, int2)

    ok = True
    expr_cond = None
    expr_ints = []
    for i, a in enumerate(args):
        if not is_int_or_cond_src_int(a[0]):
            ok = False
            break
        expr_ints.append(a)
        if isinstance(a[0], ExprCond):
            if expr_cond is not None:
                ok = False
            expr_cond = i
            cond = a[0]

    if ok and expr_cond is not None:
        src1 = []
        src2 = []
        for i, a in enumerate(expr_ints):
            if i == expr_cond:
                src1.append((a[0].src1, a[1], a[2]))
                src2.append((a[0].src2, a[1], a[2]))
            else:
                src1.append(a)
                src2.append(a)
        src1 = e_s.apply_simp(ExprCompose(src1))
        src2 = e_s.apply_simp(ExprCompose(src2))
        if isinstance(src1, ExprInt) and isinstance(src2, ExprInt):
            return ExprCond(cond.cond, src1, src2)
    return ExprCompose(args)


def simp_cond(e_s, e):
    "Common simplifications on ExprCond"
    if not isinstance(e, ExprCond):
        return e
    # eval exprcond src1/src2 with satifiable/unsatisfiable condition
    # propagation
    if (not isinstance(e.cond, ExprInt)) and e.cond.size == 1:
        src1 = e.src1.replace_expr({e.cond: ExprInt1(1)})
        src2 = e.src2.replace_expr({e.cond: ExprInt1(0)})
        if src1 != e.src1 or src2 != e.src2:
            return ExprCond(e.cond, src1, src2)

    # -A ? B:C => A ? B:C
    if (isinstance(e.cond, ExprOp) and
        e.cond.op == '-' and
        len(e.cond.args) == 1):
        e = ExprCond(e.cond.args[0], e.src1, e.src2)
    # a?x:x
    elif e.src1 == e.src2:
        e = e.src1
    # int ? A:B => A or B
    elif isinstance(e.cond, ExprInt):
        if e.cond.arg == 0:
            e = e.src2
        else:
            e = e.src1
    # a?(a?b:c):x => a?b:x
    elif isinstance(e.src1, ExprCond) and e.cond == e.src1.cond:
        e = ExprCond(e.cond, e.src1.src1, e.src2)
    # a?x:(a?b:c) => a?x:c
    elif isinstance(e.src2, ExprCond) and e.cond == e.src2.cond:
        e = ExprCond(e.cond, e.src1, e.src2.src2)
    # a|int ? b:c => b with int != 0
    elif (isinstance(e.cond, ExprOp) and
        e.cond.op == '|' and
        isinstance(e.cond.args[1], ExprInt) and
        e.cond.args[1].arg != 0):
        return e.src1

    # (C?int1:int2)?(A:B) =>
    elif (isinstance(e.cond, ExprCond) and
          isinstance(e.cond.src1, ExprInt) and
          isinstance(e.cond.src2, ExprInt)):
        int1 = e.cond.src1.arg.arg
        int2 = e.cond.src2.arg.arg
        if int1 and int2:
            e = e.src1
        elif int1 == 0 and int2 == 0:
            e = e.src2
        elif int1 == 0 and int2:
            e = ExprCond(e.cond.cond, e.src2, e.src1)
        elif int1 and int2 == 0:
            e = ExprCond(e.cond.cond, e.src1, e.src2)
    return e
