# ----------------------------- #
# Common simplifications passes #
# ----------------------------- #

from future.utils import viewitems

from miasm.core.modint import mod_size2int, mod_size2uint
from miasm.expression.expression import ExprInt, ExprSlice, ExprMem, \
    ExprCond, ExprOp, ExprCompose, TOK_INF_SIGNED, TOK_INF_UNSIGNED, \
    TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED, TOK_EQUAL
from miasm.expression.expression_helper import parity, op_propag_cst, \
    merge_sliceto_slice
from miasm.expression.simplifications_explicit import simp_flags

def simp_cst_propagation(e_s, expr):
    """This passe includes:
     - Constant folding
     - Common logical identities
     - Common binary identities
     """

    # merge associatif op
    args = list(expr.args)
    op_name = expr.op
    # simpl integer manip
    # int OP int => int
    # TODO: <<< >>> << >> are architecture dependent
    if op_name in op_propag_cst:
        while (len(args) >= 2 and
            args[-1].is_int() and
            args[-2].is_int()):
            int2 = args.pop()
            int1 = args.pop()
            if op_name == '+':
                out = mod_size2uint[int1.size](int(int1) + int(int2))
            elif op_name == '*':
                out = mod_size2uint[int1.size](int(int1) * int(int2))
            elif op_name == '**':
                out = mod_size2uint[int1.size](int(int1) ** int(int2))
            elif op_name == '^':
                out = mod_size2uint[int1.size](int(int1) ^ int(int2))
            elif op_name == '&':
                out = mod_size2uint[int1.size](int(int1) & int(int2))
            elif op_name == '|':
                out = mod_size2uint[int1.size](int(int1) | int(int2))
            elif op_name == '>>':
                if int(int2) > int1.size:
                    out = 0
                else:
                    out = mod_size2uint[int1.size](int(int1) >> int(int2))
            elif op_name == '<<':
                if int(int2) > int1.size:
                    out = 0
                else:
                    out = mod_size2uint[int1.size](int(int1) << int(int2))
            elif op_name == 'a>>':
                tmp1 = mod_size2int[int1.size](int(int1))
                tmp2 = mod_size2uint[int2.size](int(int2))
                if tmp2 > int1.size:
                    is_signed = int(int1) & (1 << (int1.size - 1))
                    if is_signed:
                        out = -1
                    else:
                        out = 0
                else:
                    out = mod_size2uint[int1.size](tmp1 >> tmp2)
            elif op_name == '>>>':
                shifter = int(int2) % int2.size
                out = (int(int1) >> shifter) | (int(int1) << (int2.size - shifter))
            elif op_name == '<<<':
                shifter = int(int2) % int2.size
                out = (int(int1) << shifter) | (int(int1) >> (int2.size - shifter))
            elif op_name == '/':
                if int(int2) == 0:
                    return expr
                out = int(int1) // int(int2)
            elif op_name == '%':
                if int(int2) == 0:
                    return expr
                out = int(int1) % int(int2)
            elif op_name == 'sdiv':
                if int(int2) == 0:
                    return expr
                tmp1 = mod_size2int[int1.size](int(int1))
                tmp2 = mod_size2int[int2.size](int(int2))
                out = mod_size2uint[int1.size](tmp1 // tmp2)
            elif op_name == 'smod':
                if int(int2) == 0:
                    return expr
                tmp1 = mod_size2int[int1.size](int(int1))
                tmp2 = mod_size2int[int2.size](int(int2))
                out = mod_size2uint[int1.size](tmp1 % tmp2)
            elif op_name == 'umod':
                if int(int2) == 0:
                    return expr
                tmp1 = mod_size2uint[int1.size](int(int1))
                tmp2 = mod_size2uint[int2.size](int(int2))
                out = mod_size2uint[int1.size](tmp1 % tmp2)
            elif op_name == 'udiv':
                if int(int2) == 0:
                    return expr
                tmp1 = mod_size2uint[int1.size](int(int1))
                tmp2 = mod_size2uint[int2.size](int(int2))
                out = mod_size2uint[int1.size](tmp1 // tmp2)



            args.append(ExprInt(int(out), int1.size))

    # cnttrailzeros(int) => int
    if op_name == "cnttrailzeros" and args[0].is_int():
        i = 0
        while int(args[0]) & (1 << i) == 0 and i < args[0].size:
            i += 1
        return ExprInt(i, args[0].size)

    # cntleadzeros(int) => int
    if op_name == "cntleadzeros" and args[0].is_int():
        if int(args[0]) == 0:
            return ExprInt(args[0].size, args[0].size)
        i = args[0].size - 1
        while int(args[0]) & (1 << i) == 0:
            i -= 1
        return ExprInt(expr.size - (i + 1), args[0].size)

    # -(-(A)) => A
    if (op_name == '-' and len(args) == 1 and args[0].is_op('-') and
        len(args[0].args) == 1):
        return args[0].args[0]


    # -(int) => -int
    if op_name == '-' and len(args) == 1 and args[0].is_int():
        return ExprInt(-int(args[0]), expr.size)
    # A op 0 =>A
    if op_name in ['+', '|', "^", "<<", ">>", "<<<", ">>>"] and len(args) > 1:
        if args[-1].is_int(0):
            args.pop()
    # A - 0 =>A
    if op_name == '-' and len(args) > 1 and args[-1].is_int(0):
        assert len(args) == 2 # Op '-' with more than 2 args: SantityCheckError
        return args[0]

    # A * 1 =>A
    if op_name == "*" and len(args) > 1 and args[-1].is_int(1):
        args.pop()

    # for cannon form
    # A * -1 => - A
    if op_name == "*" and len(args) > 1 and args[-1] == args[-1].mask:
        args.pop()
        args[-1] = - args[-1]

    # op A => A
    if op_name in ['+', '*', '^', '&', '|', '>>', '<<',
              'a>>', '<<<', '>>>', 'sdiv', 'smod', 'umod', 'udiv'] and len(args) == 1:
        return args[0]

    # A-B => A + (-B)
    if op_name == '-' and len(args) > 1:
        if len(args) > 2:
            raise ValueError(
                'sanity check fail on expr -: should have one or 2 args ' +
                '%r %s' % (expr, expr)
            )
        return ExprOp('+', args[0], -args[1])

    # A op 0 => 0
    if op_name in ['&', "*"] and args[-1].is_int(0):
        return ExprInt(0, expr.size)

    # - (A + B +...) => -A + -B + -C
    if op_name == '-' and len(args) == 1 and args[0].is_op('+'):
        args = [-a for a in args[0].args]
        return ExprOp('+', *args)

    # -(a?int1:int2) => (a?-int1:-int2)
    if (op_name == '-' and len(args) == 1 and
        args[0].is_cond() and
        args[0].src1.is_int() and args[0].src2.is_int()):
        int1 = args[0].src1
        int2 = args[0].src2
        int1 = ExprInt(-int1.arg, int1.size)
        int2 = ExprInt(-int2.arg, int2.size)
        return ExprCond(args[0].cond, int1, int2)

    i = 0
    while i < len(args) - 1:
        j = i + 1
        while j < len(args):
            # A ^ A => 0
            if op_name == '^' and args[i] == args[j]:
                args[i] = ExprInt(0, args[i].size)
                del args[j]
                continue
            # A + (- A) => 0
            if op_name == '+' and args[j].is_op("-"):
                if len(args[j].args) == 1 and args[i] == args[j].args[0]:
                    args[i] = ExprInt(0, args[i].size)
                    del args[j]
                    continue
            # (- A) + A => 0
            if op_name == '+' and args[i].is_op("-"):
                if len(args[i].args) == 1 and args[j] == args[i].args[0]:
                    args[i] = ExprInt(0, args[i].size)
                    del args[j]
                    continue
            # A | A => A
            if op_name == '|' and args[i] == args[j]:
                del args[j]
                continue
            # A & A => A
            if op_name == '&' and args[i] == args[j]:
                del args[j]
                continue
            j += 1
        i += 1

    if op_name in ['+', '^', '|', '&', '%', '/', '**'] and len(args) == 1:
        return args[0]

    # A <<< A.size => A
    if (op_name in ['<<<', '>>>'] and
        args[1].is_int() and
        int(args[1]) == args[0].size):
        return args[0]

    # (A <<< X) <<< Y => A <<< (X+Y) (or <<< >>>) if X + Y does not overflow
    if (op_name in ['<<<', '>>>'] and
        args[0].is_op() and
        args[0].op in ['<<<', '>>>']):
        A = args[0].args[0]
        X = args[0].args[1]
        Y = args[1]
        if op_name != args[0].op and e_s(X - Y) == ExprInt(0, X.size):
            return args[0].args[0]
        elif X.is_int() and Y.is_int():
            new_X = int(X) % expr.size
            new_Y = int(Y) % expr.size
            if op_name == args[0].op:
                rot = (new_X + new_Y) % expr.size
                op = op_name
            else:
                rot = new_Y - new_X
                op = op_name
                if rot < 0:
                    rot = - rot
                    op = {">>>": "<<<", "<<<": ">>>"}[op_name]
            args = [A, ExprInt(rot, expr.size)]
            op_name = op

        else:
            # Do not consider this case, too tricky (overflow on addition /
            # subtraction)
            pass

    # A >> X >> Y  =>  A >> (X+Y) if X + Y does not overflow
    # To be sure, only consider the simplification when X.msb and Y.msb are 0
    if (op_name in ['<<', '>>'] and
        args[0].is_op(op_name)):
        X = args[0].args[1]
        Y = args[1]
        if (e_s(X.msb()) == ExprInt(0, 1) and
            e_s(Y.msb()) == ExprInt(0, 1)):
            args = [args[0].args[0], X + Y]

    # ((var >> int1) << int1) => var & mask
    # ((var << int1) >> int1) => var & mask
    if (op_name in ['<<', '>>'] and
        args[0].is_op() and
        args[0].op in ['<<', '>>'] and
        op_name != args[0]):
        var = args[0].args[0]
        int1 = args[0].args[1]
        int2 = args[1]
        if int1 == int2 and int1.is_int() and int(int1) < expr.size:
            if op_name == '>>':
                mask = ExprInt((1 << (expr.size - int(int1))) - 1, expr.size)
            else:
                mask = ExprInt(
                    ((1 << int(int1)) - 1) ^ ((1 << expr.size) - 1),
                    expr.size
                )
            ret = var & mask
            return ret

    # ((A & A.mask)
    if op_name == "&" and args[-1] == expr.mask:
        args = args[:-1]
        if len(args) == 1:
            return args[0]
        return ExprOp('&', *args)

    # ((A | A.mask)
    if op_name == "|" and args[-1] == expr.mask:
        return args[-1]

    # ! (!X + int) => X - int
    # TODO

    # ((A & mask) >> shift) with mask < 2**shift => 0
    if op_name == ">>" and args[1].is_int() and args[0].is_op("&"):
        if (args[0].args[1].is_int() and
            2 ** int(args[1]) > int(args[0].args[1])):
            return ExprInt(0, args[0].size)

    # parity(int) => int
    if op_name == 'parity' and args[0].is_int():
        return ExprInt(parity(int(args[0])), 1)

    # (-a) * b * (-c) * (-d) => (-a) * b * c * d
    if op_name == "*" and len(args) > 1:
        new_args = []
        counter = 0
        for arg in args:
            if arg.is_op('-') and len(arg.args) == 1:
                new_args.append(arg.args[0])
                counter += 1
            else:
                new_args.append(arg)
        if counter % 2:
            return -ExprOp(op_name, *new_args)
        args = new_args

    # -(a * b * int) => a * b * (-int)
    if op_name == "-" and args[0].is_op('*') and args[0].args[-1].is_int():
        args = args[0].args
        return ExprOp('*', *(list(args[:-1]) + [ExprInt(-int(args[-1]), expr.size)]))

    # A << int with A ExprCompose => move index
    if (op_name == "<<" and args[0].is_compose() and
        args[1].is_int() and int(args[1]) != 0):
        final_size = args[0].size
        shift = int(args[1])
        new_args = []
        # shift indexes
        for index, arg in args[0].iter_args():
            new_args.append((arg, index+shift, index+shift+arg.size))
        # filter out expression
        filter_args = []
        min_index = final_size
        for tmp, start, stop in new_args:
            if start >= final_size:
                continue
            if stop > final_size:
                tmp = tmp[:tmp.size  - (stop - final_size)]
            filter_args.append(tmp)
            min_index = min(start, min_index)
        # create entry 0
        assert min_index != 0
        tmp = ExprInt(0, min_index)
        args = [tmp] + filter_args
        return ExprCompose(*args)

    # A >> int with A ExprCompose => move index
    if op_name == ">>" and args[0].is_compose() and args[1].is_int():
        final_size = args[0].size
        shift = int(args[1])
        new_args = []
        # shift indexes
        for index, arg in args[0].iter_args():
            new_args.append((arg, index-shift, index+arg.size-shift))
        # filter out expression
        filter_args = []
        max_index = 0
        for tmp, start, stop in new_args:
            if stop <= 0:
                continue
            if start < 0:
                tmp = tmp[-start:]
            filter_args.append(tmp)
            max_index = max(stop, max_index)
        # create entry 0
        tmp = ExprInt(0, final_size - max_index)
        args = filter_args + [tmp]
        return ExprCompose(*args)


    # Compose(a) OP Compose(b) with a/b same bounds => Compose(a OP b)
    if op_name in ['|', '&', '^'] and all([arg.is_compose() for arg in args]):
        bounds = set()
        for arg in args:
            bound = tuple([tmp.size for tmp in arg.args])
            bounds.add(bound)
        if len(bounds) == 1:
            new_args = [[tmp] for tmp in args[0].args]
            for sub_arg in args[1:]:
                for i, tmp in enumerate(sub_arg.args):
                    new_args[i].append(tmp)
            args = []
            for i, arg in enumerate(new_args):
                args.append(ExprOp(op_name, *arg))
            return ExprCompose(*args)

    return ExprOp(op_name, *args)


def simp_cond_op_int(_, expr):
    "Extract conditions from operations"


    # x?a:b + x?c:d + e => x?(a+c+e:b+d+e)
    if not expr.op in ["+", "|", "^", "&", "*", '<<', '>>', 'a>>']:
        return expr
    if len(expr.args) < 2:
        return expr
    conds = set()
    for arg in expr.args:
        if arg.is_cond():
            conds.add(arg)
    if len(conds) != 1:
        return expr
    cond = list(conds).pop()

    args1, args2 = [], []
    for arg in expr.args:
        if arg.is_cond():
            args1.append(arg.src1)
            args2.append(arg.src2)
        else:
            args1.append(arg)
            args2.append(arg)

    return ExprCond(cond.cond,
                    ExprOp(expr.op, *args1),
                    ExprOp(expr.op, *args2))


def simp_cond_factor(e_s, expr):
    "Merge similar conditions"
    if not expr.op in ["+", "|", "^", "&", "*", '<<', '>>', 'a>>']:
        return expr
    if len(expr.args) < 2:
        return expr

    if expr.op in ['>>', '<<', 'a>>']:
        assert len(expr.args) == 2

    # Note: the following code is correct for non-commutative operation only if
    # there is 2 arguments. Otherwise, the order is not conserved

    # Regroup sub-expression by similar conditions
    conds = {}
    not_conds = []
    multi_cond = False
    for arg in expr.args:
        if not arg.is_cond():
            not_conds.append(arg)
            continue
        cond = arg.cond
        if not cond in conds:
            conds[cond] = []
        else:
            multi_cond = True
        conds[cond].append(arg)
    if not multi_cond:
        return expr

    # Rebuild the new expression
    c_out = not_conds
    for cond, vals in viewitems(conds):
        new_src1 = [x.src1 for x in vals]
        new_src2 = [x.src2 for x in vals]
        src1 = e_s.expr_simp(ExprOp(expr.op, *new_src1))
        src2 = e_s.expr_simp(ExprOp(expr.op, *new_src2))
        c_out.append(ExprCond(cond, src1, src2))

    if len(c_out) == 1:
        new_e = c_out[0]
    else:
        new_e = ExprOp(expr.op, *c_out)
    return new_e


def simp_slice(e_s, expr):
    "Slice optimization"

    # slice(A, 0, a.size) => A
    if expr.start == 0 and expr.stop == expr.arg.size:
        return expr.arg
    # Slice(int) => int
    if expr.arg.is_int():
        total_bit = expr.stop - expr.start
        mask = (1 << (expr.stop - expr.start)) - 1
        return ExprInt(int((int(expr.arg) >> expr.start) & mask), total_bit)
    # Slice(Slice(A, x), y) => Slice(A, z)
    if expr.arg.is_slice():
        if expr.stop - expr.start > expr.arg.stop - expr.arg.start:
            raise ValueError('slice in slice: getting more val', str(expr))

        return ExprSlice(expr.arg.arg, expr.start + expr.arg.start,
                         expr.start + expr.arg.start + (expr.stop - expr.start))
    if expr.arg.is_compose():
        # Slice(Compose(A), x) => Slice(A, y)
        for index, arg in expr.arg.iter_args():
            if index <= expr.start and index+arg.size >= expr.stop:
                return arg[expr.start - index:expr.stop - index]
        # Slice(Compose(A, B, C), x) => Compose(A, B, C) with truncated A/B/C
        out = []
        for index, arg in expr.arg.iter_args():
            # arg is before slice start
            if expr.start >= index + arg.size:
                continue
            # arg is after slice stop
            elif expr.stop <= index:
                continue
            # arg is fully included in slice
            elif expr.start <= index and index + arg.size <= expr.stop:
                out.append(arg)
                continue
            # arg is truncated at start
            if expr.start > index:
                slice_start = expr.start - index
            else:
                # arg is not truncated at start
                slice_start = 0
            # a is truncated at stop
            if expr.stop < index + arg.size:
                slice_stop = arg.size + expr.stop - (index + arg.size) - slice_start
            else:
                slice_stop = arg.size
            out.append(arg[slice_start:slice_stop])

        return ExprCompose(*out)

    # ExprMem(x, size)[:A] => ExprMem(x, a)
    # XXXX todo hum, is it safe?
    if (expr.arg.is_mem() and
          expr.start == 0 and
          expr.arg.size > expr.stop and expr.stop % 8 == 0):
        return ExprMem(expr.arg.ptr, size=expr.stop)
    # distributivity of slice and &
    # (a & int)[x:y] => 0 if int[x:y] == 0
    if expr.arg.is_op("&") and expr.arg.args[-1].is_int():
        tmp = e_s.expr_simp(expr.arg.args[-1][expr.start:expr.stop])
        if tmp.is_int(0):
            return tmp
    # distributivity of slice and exprcond
    # (a?int1:int2)[x:y] => (a?int1[x:y]:int2[x:y])
    # (a?compose1:compose2)[x:y] => (a?compose1[x:y]:compose2[x:y])
    if (expr.arg.is_cond() and
        (expr.arg.src1.is_int() or expr.arg.src1.is_compose()) and
        (expr.arg.src2.is_int() or expr.arg.src2.is_compose())):
        src1 = expr.arg.src1[expr.start:expr.stop]
        src2 = expr.arg.src2[expr.start:expr.stop]
        return ExprCond(expr.arg.cond, src1, src2)

    # (a * int)[0:y] => (a[0:y] * int[0:y])
    if expr.start == 0 and expr.arg.is_op("*") and expr.arg.args[-1].is_int():
        args = [e_s.expr_simp(a[expr.start:expr.stop]) for a in expr.arg.args]
        return ExprOp(expr.arg.op, *args)

    # (a >> int)[x:y] => a[x+int:y+int] with int+y <= a.size
    # (a << int)[x:y] => a[x-int:y-int] with x-int >= 0
    if (expr.arg.is_op() and expr.arg.op in [">>", "<<"] and
          expr.arg.args[1].is_int()):
        arg, shift = expr.arg.args
        shift = int(shift)
        if expr.arg.op == ">>":
            if shift + expr.stop <= arg.size:
                return arg[expr.start + shift:expr.stop + shift]
        elif expr.arg.op == "<<":
            if expr.start - shift >= 0:
                return arg[expr.start - shift:expr.stop - shift]
        else:
            raise ValueError('Bad case')

    return expr


def simp_compose(e_s, expr):
    "Commons simplification on ExprCompose"
    args = merge_sliceto_slice(expr)
    out = []
    # compose of compose
    for arg in args:
        if arg.is_compose():
            out += arg.args
        else:
            out.append(arg)
    args = out
    # Compose(a) with a.size = compose.size => a
    if len(args) == 1 and args[0].size == expr.size:
        return args[0]

    # {(X[z:], 0, X.size-z), (0, X.size-z, X.size)} => (X >> z)
    if len(args) == 2 and args[1].is_int(0):
        if (args[0].is_slice() and
            args[0].stop == args[0].arg.size and
            args[0].size + args[1].size == args[0].arg.size):
            new_expr = args[0].arg >> ExprInt(args[0].start, args[0].arg.size)
            return new_expr

    # {@X[base + i] 0 X, @Y[base + i + X] X (X + Y)} => @(X+Y)[base + i]
    for i, arg in enumerate(args[:-1]):
        nxt = args[i + 1]
        if arg.is_mem() and nxt.is_mem():
            gap = e_s(nxt.ptr - arg.ptr)
            if gap.is_int() and arg.size % 8 == 0 and int(gap) == arg.size // 8:
                args = args[:i] + [ExprMem(arg.ptr,
                                          arg.size + nxt.size)] + args[i + 2:]
                return ExprCompose(*args)
    # {A, signext(A)[32:64]} => signext(A)
    if len(args) == 2 and args[0].size == args[1].size:
        arg1, arg2 = args
        size = arg1.size
        sign_ext = arg1.signExtend(arg1.size*2)
        if arg2 == sign_ext[size:2*size]:
            return sign_ext


    # {a, x?b:d, x?c:e, f} => x?{a, b, c, f}:{a, d, e, f}
    conds = set(arg.cond for arg in expr.args if arg.is_cond())
    if len(conds) == 1:
        cond = list(conds)[0]
        args1, args2 = [], []
        for arg in expr.args:
            if arg.is_cond():
                args1.append(arg.src1)
                args2.append(arg.src2)
            else:
                args1.append(arg)
                args2.append(arg)
        arg1 = e_s(ExprCompose(*args1))
        arg2 = e_s(ExprCompose(*args2))
        return ExprCond(cond, arg1, arg2)
    return ExprCompose(*args)

def simp_cond(_, expr):
    """
    Common simplifications on ExprCond.
    Eval exprcond src1/src2 with satifiable/unsatisfiable condition propagation
    """
    if (not expr.cond.is_int()) and expr.cond.size == 1:
        src1 = expr.src1.replace_expr({expr.cond: ExprInt(1, 1)})
        src2 = expr.src2.replace_expr({expr.cond: ExprInt(0, 1)})
        if src1 != expr.src1 or src2 != expr.src2:
            return ExprCond(expr.cond, src1, src2)

    # -A ? B:C => A ? B:C
    if expr.cond.is_op('-') and len(expr.cond.args) == 1:
        expr = ExprCond(expr.cond.args[0], expr.src1, expr.src2)
    # a?x:x
    elif expr.src1 == expr.src2:
        expr = expr.src1
    # int ? A:B => A or B
    elif expr.cond.is_int():
        if int(expr.cond) == 0:
            expr = expr.src2
        else:
            expr = expr.src1
    # a?(a?b:c):x => a?b:x
    elif expr.src1.is_cond() and expr.cond == expr.src1.cond:
        expr = ExprCond(expr.cond, expr.src1.src1, expr.src2)
    # a?x:(a?b:c) => a?x:c
    elif expr.src2.is_cond() and expr.cond == expr.src2.cond:
        expr = ExprCond(expr.cond, expr.src1, expr.src2.src2)
    # a|int ? b:c => b with int != 0
    elif (expr.cond.is_op('|') and
          expr.cond.args[1].is_int() and
          expr.cond.args[1].arg != 0):
        return expr.src1

    # (C?int1:int2)?(A:B) =>
    elif (expr.cond.is_cond() and
          expr.cond.src1.is_int() and
          expr.cond.src2.is_int()):
        int1 = int(expr.cond.src1)
        int2 = int(expr.cond.src2)
        if int1 and int2:
            expr = expr.src1
        elif int1 == 0 and int2 == 0:
            expr = expr.src2
        elif int1 == 0 and int2:
            expr = ExprCond(expr.cond.cond, expr.src2, expr.src1)
        elif int1 and int2 == 0:
            expr = ExprCond(expr.cond.cond, expr.src1, expr.src2)

    elif expr.cond.is_compose():
        # {0, X, 0}?(A:B) => X?(A:B)
        args = [arg for arg in expr.cond.args if not arg.is_int(0)]
        if len(args) == 1:
            arg = args.pop()
            return ExprCond(arg, expr.src1, expr.src2)
        elif len(args) < len(expr.cond.args):
            return ExprCond(ExprCompose(*args), expr.src1, expr.src2)
    return expr


def simp_mem(_, expr):
    """
    Common simplifications on ExprMem:
    @32[x?a:b] => x?@32[a]:@32[b]
    """
    if expr.ptr.is_cond():
        cond = expr.ptr
        ret = ExprCond(cond.cond,
                       ExprMem(cond.src1, expr.size),
                       ExprMem(cond.src2, expr.size))
        return ret
    return expr




def test_cc_eq_args(expr, *sons_op):
    """
    Return True if expression's arguments match the list in sons_op, and their
    sub arguments are identical. Ex:
    CC_S<=(
              FLAG_SIGN_SUB(A, B),
              FLAG_SUB_OF(A, B),
              FLAG_EQ_CMP(A, B)
    )
    """
    if not expr.is_op():
        return False
    if len(expr.args) != len(sons_op):
        return False
    all_args = set()
    for i, arg in enumerate(expr.args):
        if not arg.is_op(sons_op[i]):
            return False
        all_args.add(arg.args)
    return len(all_args) == 1


def simp_cc_conds(_, expr):
    """
    High level simplifications. Example:
    CC_U<(FLAG_SUB_CF(A, B) => A <u B
    """
    if (expr.is_op("CC_U>=") and
          test_cc_eq_args(
              expr,
              "FLAG_SUB_CF"
          )):
        expr = ExprCond(
            ExprOp(TOK_INF_UNSIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size))

    elif (expr.is_op("CC_U<") and
          test_cc_eq_args(
              expr,
              "FLAG_SUB_CF"
          )):
        expr = ExprOp(TOK_INF_UNSIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_NEG") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB"
          )):
        expr = ExprOp(TOK_INF_SIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_POS") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB"
          )):
        expr = ExprCond(
            ExprOp(TOK_INF_SIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_EQ") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ"
          )):
        arg = expr.args[0].args[0]
        expr = ExprOp(TOK_EQUAL, arg, ExprInt(0, arg.size))

    elif (expr.is_op("CC_NE") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ"
          )):
        arg = expr.args[0].args[0]
        expr = ExprCond(
            ExprOp(TOK_EQUAL,arg, ExprInt(0, arg.size)),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )
    elif (expr.is_op("CC_NE") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ_CMP"
          )):
        expr = ExprCond(
            ExprOp(TOK_EQUAL, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_EQ") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ_CMP"
          )):
        expr = ExprOp(TOK_EQUAL, *expr.args[0].args)

    elif (expr.is_op("CC_NE") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ_AND"
          )):
        expr = ExprOp("&", *expr.args[0].args)

    elif (expr.is_op("CC_EQ") and
          test_cc_eq_args(
              expr,
              "FLAG_EQ_AND"
          )):
        expr = ExprCond(
            ExprOp("&", *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_S>") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB",
              "FLAG_SUB_OF",
              "FLAG_EQ_CMP",
          )):
        expr = ExprCond(
            ExprOp(TOK_INF_EQUAL_SIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_S>") and
          len(expr.args) == 3 and
          expr.args[0].is_op("FLAG_SIGN_SUB") and
          expr.args[2].is_op("FLAG_EQ_CMP") and
          expr.args[0].args == expr.args[2].args and
          expr.args[1].is_int(0)):
        expr = ExprCond(
            ExprOp(TOK_INF_EQUAL_SIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )



    elif (expr.is_op("CC_S>=") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB",
              "FLAG_SUB_OF"
          )):
        expr = ExprCond(
            ExprOp(TOK_INF_SIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_S>=") and
          len(expr.args) == 2 and
          expr.args[0].is_op("FLAG_SIGN_SUB") and
          expr.args[0].args[1].is_int(0) and
          expr.args[1].is_int(0)):
        expr = ExprOp(
            TOK_INF_EQUAL_SIGNED,
            expr.args[0].args[1],
            expr.args[0].args[0],
        )

    elif (expr.is_op("CC_S<") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB",
              "FLAG_SUB_OF"
          )):
        expr = ExprOp(TOK_INF_SIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_S<=") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_SUB",
              "FLAG_SUB_OF",
              "FLAG_EQ_CMP",
          )):
        expr = ExprOp(TOK_INF_EQUAL_SIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_S<=") and
          len(expr.args) == 3 and
          expr.args[0].is_op("FLAG_SIGN_SUB") and
          expr.args[2].is_op("FLAG_EQ_CMP") and
          expr.args[0].args == expr.args[2].args and
          expr.args[1].is_int(0)):
        expr = ExprOp(TOK_INF_EQUAL_SIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_U<=") and
          test_cc_eq_args(
              expr,
              "FLAG_SUB_CF",
              "FLAG_EQ_CMP",
          )):
        expr = ExprOp(TOK_INF_EQUAL_UNSIGNED, *expr.args[0].args)

    elif (expr.is_op("CC_U>") and
          test_cc_eq_args(
              expr,
              "FLAG_SUB_CF",
              "FLAG_EQ_CMP",
          )):
        expr = ExprCond(
            ExprOp(TOK_INF_EQUAL_UNSIGNED, *expr.args[0].args),
            ExprInt(0, expr.size),
            ExprInt(1, expr.size)
        )

    elif (expr.is_op("CC_S<") and
          test_cc_eq_args(
              expr,
              "FLAG_SIGN_ADD",
              "FLAG_ADD_OF"
          )):
        arg0, arg1 = expr.args[0].args
        expr = ExprOp(TOK_INF_SIGNED, arg0, -arg1)

    return expr



def simp_cond_flag(_, expr):
    """FLAG_EQ_CMP(X, Y)?A:B => (X == Y)?A:B"""
    cond = expr.cond
    if cond.is_op("FLAG_EQ_CMP"):
        return ExprCond(ExprOp(TOK_EQUAL, *cond.args), expr.src1, expr.src2)
    return expr


def simp_sub_cf_zero(_, expr):
    """FLAG_SUB_CF(0, X) => (X)?1:0"""
    if not expr.is_op("FLAG_SUB_CF"):
        return expr
    if not expr.args[0].is_int(0):
        return expr
    return ExprCond(expr.args[1], ExprInt(1, 1), ExprInt(0, 1))

def simp_cond_cc_flag(expr_simp, expr):
    """
    ExprCond(CC_><(bit), X, Y) => ExprCond(bit, X, Y)
    ExprCond(CC_U>=(bit), X, Y) => ExprCond(bit, Y, X)
    """
    if not expr.is_cond():
        return expr
    if not expr.cond.is_op():
        return expr
    expr_op = expr.cond
    if expr_op.op not in ["CC_U<", "CC_U>="]:
        return expr
    arg = expr_op.args[0]
    if arg.size != 1:
        return expr
    if expr_op.op == "CC_U<":
        return ExprCond(arg, expr.src1, expr.src2)
    if expr_op.op == "CC_U>=":
        return ExprCond(arg, expr.src2, expr.src1)
    return expr

def simp_cond_sub_cf(expr_simp, expr):
    """
    ExprCond(FLAG_SUB_CF(A, B), X, Y) => ExprCond(A <u B, X, Y)
    """
    if not expr.is_cond():
        return expr
    if not expr.cond.is_op("FLAG_SUB_CF"):
        return expr
    cond = ExprOp(TOK_INF_UNSIGNED, *expr.cond.args)
    return ExprCond(cond, expr.src1, expr.src2)


def simp_cmp_int(expr_simp, expr):
    """
    ({X, 0} == int) => X == int[:]
    X + int1 == int2 => X == int2-int1
    X ^ int1 == int2 => X == int1^int2
    """
    if (expr.is_op(TOK_EQUAL) and
          expr.args[1].is_int() and
          expr.args[0].is_compose() and
          len(expr.args[0].args) == 2 and
          expr.args[0].args[1].is_int(0)):
        # ({X, 0} == int) => X == int[:]
        src = expr.args[0].args[0]
        int_val = int(expr.args[1])
        new_int = ExprInt(int_val, src.size)
        expr = expr_simp(
            ExprOp(TOK_EQUAL, src, new_int)
        )
    elif not expr.is_op(TOK_EQUAL):
        return expr
    assert len(expr.args) == 2

    left, right = expr.args
    if left.is_int() and not right.is_int():
        left, right = right, left
    if not right.is_int():
        return expr
    if not (left.is_op() and left.op in ['+', '^']):
        return expr
    if not left.args[-1].is_int():
        return expr
    # X + int1 == int2 => X == int2-int1
    # WARNING:
    # X - 0x10 <=u 0x20 gives X in [0x10 0x30]
    # which is not equivalet to A <=u 0x10

    left_orig = left
    left, last_int = left.args[:-1], left.args[-1]

    if len(left) == 1:
        left = left[0]
    else:
        left = ExprOp(left_orig.op, *left)

    if left_orig.op == "+":
        new_int = expr_simp(right - last_int)
    elif left_orig.op == '^':
        new_int = expr_simp(right ^ last_int)
    else:
        raise RuntimeError("Unsupported operator")

    expr = expr_simp(
        ExprOp(TOK_EQUAL, left, new_int),
    )
    return expr



def simp_cmp_int_arg(_, expr):
    """
    (0x10 <= R0) ? A:B
    =>
    (R0 < 0x10) ? B:A
    """
    cond = expr.cond
    if not cond.is_op():
        return expr
    op = cond.op
    if op not in [
            TOK_EQUAL,
            TOK_INF_SIGNED,
            TOK_INF_EQUAL_SIGNED,
            TOK_INF_UNSIGNED,
            TOK_INF_EQUAL_UNSIGNED
    ]:
        return expr
    arg1, arg2 = cond.args
    if arg2.is_int():
        return expr
    if not arg1.is_int():
        return expr
    src1, src2 = expr.src1, expr.src2
    if op == TOK_EQUAL:
        return ExprCond(ExprOp(TOK_EQUAL, arg2, arg1), src1, src2)

    arg1, arg2 = arg2, arg1
    src1, src2 = src2, src1
    if op == TOK_INF_SIGNED:
        op = TOK_INF_EQUAL_SIGNED
    elif op == TOK_INF_EQUAL_SIGNED:
        op = TOK_INF_SIGNED
    elif op == TOK_INF_UNSIGNED:
        op = TOK_INF_EQUAL_UNSIGNED
    elif op == TOK_INF_EQUAL_UNSIGNED:
        op = TOK_INF_UNSIGNED
    return ExprCond(ExprOp(op, arg1, arg2), src1, src2)



def simp_cmp_bijective_op(expr_simp, expr):
    """
    A + B == A => A == 0

    X + A == X + B => A == B
    X ^ A == X ^ B => A == B

    TODO:
    3 * A + B == A + C => 2 * A + B == C
    """

    if not expr.is_op(TOK_EQUAL):
        return expr
    op_a = expr.args[0]
    op_b = expr.args[1]

    # a == a
    if op_a == op_b:
        return ExprInt(1, 1)

    # Case:
    # a + b + c == a
    if op_a.is_op() and op_a.op in ["+", "^"]:
        args = list(op_a.args)
        if op_b in args:
            args.remove(op_b)
            if not args:
                raise ValueError("Can be here")
            elif len(args) == 1:
                op_a = args[0]
            else:
                op_a = ExprOp(op_a.op, *args)
            return ExprOp(TOK_EQUAL, op_a, ExprInt(0, args[0].size))
    # a == a + b + c
    if op_b.is_op() and op_b.op in ["+", "^"]:
        args = list(op_b.args)
        if op_a in args:
            args.remove(op_a)
            if not args:
                raise ValueError("Can be here")
            elif len(args) == 1:
                op_b = args[0]
            else:
                op_b = ExprOp(op_b.op, *args)
            return ExprOp(TOK_EQUAL, op_b, ExprInt(0, args[0].size))

    if not (op_a.is_op() and op_b.is_op()):
        return expr
    if op_a.op != op_b.op:
        return expr
    op = op_a.op
    if op not in ["+", "^"]:
        return expr
    common = set(op_a.args).intersection(op_b.args)
    if not common:
        return expr

    args_a = list(op_a.args)
    args_b = list(op_b.args)
    for value in common:
        while value in args_a and value in args_b:
            args_a.remove(value)
            args_b.remove(value)

    # a + b == a + b + c
    if not args_a:
        return ExprOp(TOK_EQUAL, ExprOp(op, *args_b), ExprInt(0, args_b[0].size))
    # a + b + c == a + b
    if not args_b:
        return ExprOp(TOK_EQUAL, ExprOp(op, *args_a), ExprInt(0, args_a[0].size))
    
    arg_a = ExprOp(op, *args_a)
    arg_b = ExprOp(op, *args_b)
    return ExprOp(TOK_EQUAL, arg_a, arg_b)


def simp_subwc_cf(_, expr):
    """SUBWC_CF(A, B, SUB_CF(C, D)) => SUB_CF({A, C}, {B, D})"""
    if not expr.is_op('FLAG_SUBWC_CF'):
        return expr
    op3 = expr.args[2]
    if not op3.is_op("FLAG_SUB_CF"):
        return expr

    op1 = ExprCompose(expr.args[0], op3.args[0])
    op2 = ExprCompose(expr.args[1], op3.args[1])

    return ExprOp("FLAG_SUB_CF", op1, op2)


def simp_subwc_of(_, expr):
    """SUBWC_OF(A, B, SUB_CF(C, D)) => SUB_OF({A, C}, {B, D})"""
    if not expr.is_op('FLAG_SUBWC_OF'):
        return expr
    op3 = expr.args[2]
    if not op3.is_op("FLAG_SUB_CF"):
        return expr

    op1 = ExprCompose(expr.args[0], op3.args[0])
    op2 = ExprCompose(expr.args[1], op3.args[1])

    return ExprOp("FLAG_SUB_OF", op1, op2)


def simp_sign_subwc_cf(_, expr):
    """SIGN_SUBWC(A, B, SUB_CF(C, D)) => SIGN_SUB({A, C}, {B, D})"""
    if not expr.is_op('FLAG_SIGN_SUBWC'):
        return expr
    op3 = expr.args[2]
    if not op3.is_op("FLAG_SUB_CF"):
        return expr

    op1 = ExprCompose(expr.args[0], op3.args[0])
    op2 = ExprCompose(expr.args[1], op3.args[1])

    return ExprOp("FLAG_SIGN_SUB", op1, op2)

def simp_double_zeroext(_, expr):
    """A.zeroExt(X).zeroExt(Y) => A.zeroExt(Y)"""
    if not (expr.is_op() and expr.op.startswith("zeroExt")):
        return expr
    arg1 = expr.args[0]
    if not (arg1.is_op() and arg1.op.startswith("zeroExt")):
        return expr
    arg2 = arg1.args[0]
    return ExprOp(expr.op, arg2)

def simp_double_signext(_, expr):
    """A.signExt(X).signExt(Y) => A.signExt(Y)"""
    if not (expr.is_op() and expr.op.startswith("signExt")):
        return expr
    arg1 = expr.args[0]
    if not (arg1.is_op() and arg1.op.startswith("signExt")):
        return expr
    arg2 = arg1.args[0]
    return ExprOp(expr.op, arg2)

def simp_zeroext_eq_cst(_, expr):
    """A.zeroExt(X) == int => A == int[:A.size]"""
    if not expr.is_op(TOK_EQUAL):
        return expr
    arg1, arg2 = expr.args
    if not arg2.is_int():
        return expr
    if not (arg1.is_op() and arg1.op.startswith("zeroExt")):
        return expr
    src = arg1.args[0]
    if int(arg2) > (1 << src.size):
        # Always false
        return ExprInt(0, expr.size)
    return ExprOp(TOK_EQUAL, src, ExprInt(int(arg2), src.size))

def simp_cond_zeroext(_, expr):
    """
    X.zeroExt()?(A:B) => X ? A:B
    X.signExt()?(A:B) => X ? A:B
    """
    if not (
            expr.cond.is_op() and
            (
                expr.cond.op.startswith("zeroExt") or
                expr.cond.op.startswith("signExt")
            )
    ):
        return expr

    ret = ExprCond(expr.cond.args[0], expr.src1, expr.src2)
    return ret

def simp_ext_eq_ext(_, expr):
    """
    A.zeroExt(X) == B.zeroExt(X) => A == B
    A.signExt(X) == B.signExt(X) => A == B
    """
    if not expr.is_op(TOK_EQUAL):
        return expr
    arg1, arg2 = expr.args
    if (not ((arg1.is_op() and arg1.op.startswith("zeroExt") and
              arg2.is_op() and arg2.op.startswith("zeroExt")) or
             (arg1.is_op() and arg1.op.startswith("signExt") and
               arg2.is_op() and arg2.op.startswith("signExt")))):
        return expr
    if arg1.args[0].size != arg2.args[0].size:
        return expr
    return ExprOp(TOK_EQUAL, arg1.args[0], arg2.args[0])

def simp_cond_eq_zero(_, expr):
    """(X == 0)?(A:B) => X?(B:A)"""
    cond = expr.cond
    if not cond.is_op(TOK_EQUAL):
        return expr
    arg1, arg2 = cond.args
    if not arg2.is_int(0):
        return expr
    new_expr = ExprCond(arg1, expr.src2, expr.src1)
    return new_expr

def simp_sign_inf_zeroext(expr_s, expr):
    """
    /!\ Ensure before: X.zeroExt(X.size) => X

    X.zeroExt() <s 0 => 0
    X.zeroExt() <=s 0 => X == 0

    X.zeroExt() <s cst => X.zeroExt() <u cst (cst positive)
    X.zeroExt() <=s cst => X.zeroExt() <=u cst (cst positive)

    X.zeroExt() <s cst => 0 (cst negative)
    X.zeroExt() <=s cst => 0 (cst negative)

    """
    if not (expr.is_op(TOK_INF_SIGNED) or expr.is_op(TOK_INF_EQUAL_SIGNED)):
        return expr
    arg1, arg2 = expr.args
    if not arg2.is_int():
        return expr
    if not (arg1.is_op() and arg1.op.startswith("zeroExt")):
        return expr
    src = arg1.args[0]
    assert src.size < arg1.size

    # If cst is zero
    if arg2.is_int(0):
        if expr.is_op(TOK_INF_SIGNED):
            # X.zeroExt() <s 0 => 0
            return ExprInt(0, expr.size)
        else:
            # X.zeroExt() <=s 0 => X == 0
            return ExprOp(TOK_EQUAL, src, ExprInt(0, src.size))

    # cst is not zero
    cst = int(arg2)
    if cst & (1 << (arg2.size - 1)):
        # cst is negative
        return ExprInt(0, expr.size)
    # cst is positive
    if expr.is_op(TOK_INF_SIGNED):
        # X.zeroExt() <s cst => X.zeroExt() <u cst (cst positive)
        return ExprOp(TOK_INF_UNSIGNED, src, expr_s(arg2[:src.size]))
    # X.zeroExt() <=s cst => X.zeroExt() <=u cst (cst positive)
    return ExprOp(TOK_INF_EQUAL_UNSIGNED, src, expr_s(arg2[:src.size]))


def simp_zeroext_and_cst_eq_cst(expr_s, expr):
    """
    A.zeroExt(X) & ... & int == int => A & ... & int[:A.size] == int[:A.size]
    """
    if not expr.is_op(TOK_EQUAL):
        return expr
    arg1, arg2 = expr.args
    if not arg2.is_int():
        return expr
    if not arg1.is_op('&'):
        return expr
    is_ok = True
    sizes = set()
    for arg in arg1.args:
        if arg.is_int():
            continue
        if (arg.is_op() and
            arg.op.startswith("zeroExt")):
            sizes.add(arg.args[0].size)
            continue
        is_ok = False
        break
    if not is_ok:
        return expr
    if len(sizes) != 1:
        return expr
    size = list(sizes)[0]
    if int(arg2) > ((1 << size) - 1):
        return expr
    args = [expr_s(arg[:size]) for arg in arg1.args]
    left = ExprOp('&', *args)
    right = expr_s(arg2[:size])
    ret = ExprOp(TOK_EQUAL, left, right)
    return ret


def test_one_bit_set(arg):
    """
    Return True if arg has form 1 << X
    """
    return arg != 0  and ((arg & (arg - 1)) == 0)

def simp_x_and_cst_eq_cst(_, expr):
    """
    (x & ... & onebitmask == onebitmask) ? A:B => (x & ... & onebitmask) ? A:B
    """
    cond = expr.cond
    if not cond.is_op(TOK_EQUAL):
        return expr
    arg1, mask2 = cond.args
    if not mask2.is_int():
        return expr
    if not test_one_bit_set(int(mask2)):
        return expr
    if not arg1.is_op('&'):
        return expr
    mask1 = arg1.args[-1]
    if mask1 != mask2:
        return expr
    cond = ExprOp('&', *arg1.args)
    return ExprCond(cond, expr.src1, expr.src2)

def simp_cmp_int_int(_, expr):
    """
    IntA <s IntB => int
    IntA <u IntB => int
    IntA <=s IntB => int
    IntA <=u IntB => int
    IntA == IntB => int
    """
    if expr.op not in [
            TOK_EQUAL,
            TOK_INF_SIGNED, TOK_INF_UNSIGNED,
            TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED,
    ]:
        return expr
    if not all(arg.is_int() for arg in expr.args):
        return expr
    int_a, int_b = expr.args
    if expr.is_op(TOK_EQUAL):
        if int_a == int_b:
            return ExprInt(1, 1)
        return ExprInt(0, expr.size)

    if expr.op in [TOK_INF_SIGNED, TOK_INF_EQUAL_SIGNED]:
        int_a = int(mod_size2int[int_a.size](int(int_a)))
        int_b = int(mod_size2int[int_b.size](int(int_b)))
    else:
        int_a = int(mod_size2uint[int_a.size](int(int_a)))
        int_b = int(mod_size2uint[int_b.size](int(int_b)))

    if expr.op in [TOK_INF_SIGNED, TOK_INF_UNSIGNED]:
        ret = int_a < int_b
    else:
        ret = int_a <= int_b

    if ret:
        ret = 1
    else:
        ret = 0
    return ExprInt(ret, 1)


def simp_ext_cst(_, expr):
    """
    Int.zeroExt(X) => Int
    Int.signExt(X) => Int
    """
    if not (expr.op.startswith("zeroExt") or expr.op.startswith("signExt")):
        return expr
    arg = expr.args[0]
    if not arg.is_int():
        return expr
    if expr.op.startswith("zeroExt"):
        ret = int(arg)
    else:
        ret = int(mod_size2int[arg.size](int(arg)))
    ret = ExprInt(ret, expr.size)
    return ret



def simp_ext_cond_int(e_s, expr):
    """
    zeroExt(ExprCond(X, Int, Int)) => ExprCond(X, Int, Int)
    """
    if not (expr.op.startswith("zeroExt") or expr.op.startswith("signExt")):
        return expr
    arg = expr.args[0]
    if not arg.is_cond():
        return expr
    if not (arg.src1.is_int() and arg.src2.is_int()):
        return expr
    src1 = ExprOp(expr.op, arg.src1)
    src2 = ExprOp(expr.op, arg.src2)
    return e_s(ExprCond(arg.cond, src1, src2))


def simp_slice_of_ext(_, expr):
    """
    C.zeroExt(X)[A:B] => 0 if A >= size(C)
    C.zeroExt(X)[A:B] => C[A:B] if B <= size(C)
    A.zeroExt(X)[0:Y] => A.zeroExt(Y)
    """
    if not expr.arg.is_op():
        return expr
    if not expr.arg.op.startswith("zeroExt"):
        return expr
    arg = expr.arg.args[0]

    if expr.start >= arg.size:
        # C.zeroExt(X)[A:B] => 0 if A >= size(C)
        return ExprInt(0, expr.size)
    if expr.stop <= arg.size:
        # C.zeroExt(X)[A:B] => C[A:B] if B <= size(C)
        return arg[expr.start:expr.stop]
    if expr.start == 0:
        # A.zeroExt(X)[0:Y] => A.zeroExt(Y)
        return arg.zeroExtend(expr.stop)
    return expr

def simp_slice_of_sext(e_s, expr):
    """
    with Y <= size(A)
    A.signExt(X)[0:Y] => A[0:Y]
    """
    if not expr.arg.is_op():
        return expr
    if not expr.arg.op.startswith("signExt"):
        return expr
    arg = expr.arg.args[0]
    if expr.start != 0:
        return expr
    if expr.stop <= arg.size:
        return e_s.expr_simp(arg[:expr.stop])
    return expr


def simp_slice_of_op_ext(expr_s, expr):
    """
    (X.zeroExt() + {Z, } + ... + Int)[0:8] => X + ... + int[:]
    (X.zeroExt() | ... | Int)[0:8] => X | ... | int[:]
    ...
    """
    if expr.start != 0:
        return expr
    src = expr.arg
    if not src.is_op():
        return expr
    if src.op not in ['+', '|', '^', '&']:
        return expr
    is_ok = True
    for arg in src.args:
        if arg.is_int():
            continue
        if (arg.is_op() and
            arg.op.startswith("zeroExt") and
            arg.args[0].size == expr.stop):
            continue
        if arg.is_compose():
            continue
        is_ok = False
        break
    if not is_ok:
        return expr
    args = [expr_s(arg[:expr.stop]) for arg in src.args]
    return ExprOp(src.op, *args)


def simp_cond_logic_ext(expr_s, expr):
    """(X.zeroExt() + ... + Int) ? A:B => X + ... + int[:] ? A:B"""
    cond = expr.cond
    if not cond.is_op():
        return expr
    if cond.op not in ["&", "^", "|"]:
        return expr
    is_ok = True
    sizes = set()
    for arg in cond.args:
        if arg.is_int():
            continue
        if (arg.is_op() and
            arg.op.startswith("zeroExt")):
            sizes.add(arg.args[0].size)
            continue
        is_ok = False
        break
    if not is_ok:
        return expr
    if len(sizes) != 1:
        return expr
    size = list(sizes)[0]
    args = [expr_s(arg[:size]) for arg in cond.args]
    cond = ExprOp(cond.op, *args)
    return ExprCond(cond, expr.src1, expr.src2)


def simp_cond_sign_bit(_, expr):
    """(a & .. & 0x80000000) ? A:B => (a & ...) <s 0 ? A:B"""
    cond = expr.cond
    if not cond.is_op('&'):
        return expr
    last = cond.args[-1]
    if not last.is_int(1 << (last.size - 1)):
        return expr
    zero = ExprInt(0, expr.cond.size)
    if len(cond.args) == 2:
        args = [cond.args[0], zero]
    else:
        args = [ExprOp('&', *list(cond.args[:-1])), zero]
    cond = ExprOp(TOK_INF_SIGNED, *args)
    return ExprCond(cond, expr.src1, expr.src2)


def simp_cond_add(expr_s, expr):
    """
    (a+b)?X:Y => (a == b)?Y:X
    (a^b)?X:Y => (a == b)?Y:X
    """
    cond = expr.cond
    if not cond.is_op():
        return expr
    if cond.op not in ['+', '^']:
        return expr
    if len(cond.args) != 2:
        return expr
    arg1, arg2 = cond.args
    if cond.is_op('+'):
        new_cond = ExprOp('==', arg1, expr_s(-arg2))
    elif cond.is_op('^'):
        new_cond = ExprOp('==', arg1, arg2)
    else:
        raise ValueError('Bad case')
    return ExprCond(new_cond, expr.src2, expr.src1)


def simp_cond_eq_1_0(expr_s, expr):
    """
    (a == b)?ExprInt(1, 1):ExprInt(0, 1) => a == b
    (a <s b)?ExprInt(1, 1):ExprInt(0, 1) => a == b
    ...
    """
    cond = expr.cond
    if not cond.is_op():
        return expr
    if cond.op not in [
            TOK_EQUAL,
            TOK_INF_SIGNED, TOK_INF_EQUAL_SIGNED,
            TOK_INF_UNSIGNED, TOK_INF_EQUAL_UNSIGNED
            ]:
        return expr
    if expr.src1 != ExprInt(1, 1) or expr.src2 != ExprInt(0, 1):
        return expr
    return cond


def simp_cond_inf_eq_unsigned_zero(expr_s, expr):
    """
    (a <=u 0) => a == 0
    """
    if not expr.is_op(TOK_INF_EQUAL_UNSIGNED):
        return expr
    if not expr.args[1].is_int(0):
        return expr
    return ExprOp(TOK_EQUAL, expr.args[0], expr.args[1])


def simp_test_signext_inf(expr_s, expr):
    """A.signExt() <s int => A <s int[:]"""
    if not (expr.is_op(TOK_INF_SIGNED) or expr.is_op(TOK_INF_EQUAL_SIGNED)):
        return expr
    arg, cst = expr.args
    if not (arg.is_op() and arg.op.startswith("signExt")):
        return expr
    if not cst.is_int():
        return expr
    base = arg.args[0]
    tmp = int(mod_size2int[cst.size](int(cst)))
    if -(1 << (base.size - 1)) <= tmp < (1 << (base.size - 1)):
        # Can trunc integer
        return ExprOp(expr.op, base, expr_s(cst[:base.size]))
    if (tmp >= (1 << (base.size - 1)) or
        tmp < -(1 << (base.size - 1)) ):
        return ExprInt(1, 1)
    return expr


def simp_test_zeroext_inf(expr_s, expr):
    """A.zeroExt() <u int => A <u int[:]"""
    if not (expr.is_op(TOK_INF_UNSIGNED) or expr.is_op(TOK_INF_EQUAL_UNSIGNED)):
        return expr
    arg, cst = expr.args
    if not (arg.is_op() and arg.op.startswith("zeroExt")):
        return expr
    if not cst.is_int():
        return expr
    base = arg.args[0]
    tmp = int(mod_size2uint[cst.size](int(cst)))
    if 0 <= tmp < (1 << base.size):
        # Can trunc integer
        return ExprOp(expr.op, base, expr_s(cst[:base.size]))
    if tmp >= (1 << base.size):
        return ExprInt(1, 1)
    return expr


def simp_add_multiple(_, expr):
    """
    X + X => 2 * X
    X + X * int1 => X * (1 + int1)
    X * int1 + (- X) => X * (int1 - 1)
    X + (X << int1) => X * (1 + 2 ** int1)
    Correct even if addition overflow/underflow
    """
    if not expr.is_op('+'):
        return expr

    # Extract each argument and its counter
    operands = {}
    for arg in expr.args:
        if arg.is_op('*') and arg.args[1].is_int():
            base_expr, factor = arg.args
            operands[base_expr] = operands.get(base_expr, 0) + int(factor)
        elif arg.is_op('<<') and arg.args[1].is_int():
            base_expr, factor = arg.args
            operands[base_expr] = operands.get(base_expr, 0) + 2 ** int(factor)
        elif arg.is_op("-"):
            arg = arg.args[0]
            if arg.is_op('<<') and arg.args[1].is_int():
                base_expr, factor = arg.args
                operands[base_expr] = operands.get(base_expr, 0) - (2 ** int(factor))
            else:
                operands[arg] = operands.get(arg, 0) - 1
        else:
            operands[arg] = operands.get(arg, 0) + 1
    out = []

    # Best effort to factor common args:
    # (a + b) * 3 + a + b => (a + b) * 4
    # Does not factor:
    # (a + b) * 3 + 2 * a + b => (a + b) * 4 + a
    modified = True
    while modified:
        modified = False
        for arg, count in list(viewitems(operands)):
            if not arg.is_op('+'):
                continue
            components = arg.args
            if not all(component in operands for component in components):
                continue
            counters = set(operands[component] for component in components)
            if len(counters) != 1:
                continue
            counter = counters.pop()
            for component in components:
                del operands[component]
            operands[arg] += counter
            modified = True
            break

    for arg, count in viewitems(operands):
        if count == 0:
            continue
        if count == 1:
            out.append(arg)
            continue
        out.append(arg * ExprInt(count, expr.size))

    if len(out) == len(expr.args):
        # No reductions
        return expr
    if not out:
        return ExprInt(0, expr.size)
    if len(out) == 1:
        return out[0]
    return ExprOp('+', *out)

def simp_compose_and_mask(_, expr):
    """
    {X 0 8, Y 8 32} & 0xFF => zeroExt(X)
    {X 0 8, Y 8 16, Z 16 32} & 0xFFFF => {X 0 8, Y 8 16, 0x0 16 32}
    {X 0 8, 0x123456 8 32} & 0xFFFFFF => {X 0 8, 0x1234 8 24, 0x0 24 32}
    """
    if not expr.is_op('&'):
        return expr
    # handle the case where arg2 = arg1.mask
    if len(expr.args) != 2:
        return expr
    arg1, arg2 = expr.args
    if not arg1.is_compose():
        return expr
    if not arg2.is_int():
        return expr
    int2 = int(arg2)
    if (int2 + 1) & int2 != 0:
        return expr
    mask_size = int2.bit_length() + 7 // 8
    out = []
    for offset, arg in arg1.iter_args():
        if offset == mask_size:
            return ExprCompose(*out).zeroExtend(expr.size)
        elif mask_size > offset and mask_size < offset+arg.size and arg.is_int():
            out.append(ExprSlice(arg, 0, mask_size-offset))
            return ExprCompose(*out).zeroExtend(expr.size)
        else:
            out.append(arg)
    return expr

def simp_bcdadd_cf(_, expr):
    """bcdadd(const, const) => decimal"""
    if not(expr.is_op('bcdadd_cf')):
        return expr
    arg1 = expr.args[0]
    arg2 = expr.args[1]
    if not(arg1.is_int() and arg2.is_int()):
        return expr

    carry = 0
    res = 0
    nib_1, nib_2 = 0, 0
    for i in range(0,16,4):
        nib_1 = (arg1.arg >> i) & (0xF)
        nib_2 = (arg2.arg >> i) & (0xF)
        
        j = (carry + nib_1 + nib_2)
        if (j >= 10):
            carry = 1
            j -= 10
            j &= 0xF
        else:
            carry = 0
    return ExprInt(carry, 1)

def simp_bcdadd(_, expr):
    """bcdadd(const, const) => decimal"""
    if not(expr.is_op('bcdadd')):
        return expr
    arg1 = expr.args[0]
    arg2 = expr.args[1]
    if not(arg1.is_int() and arg2.is_int()):
        return expr

    carry = 0
    res = 0
    nib_1, nib_2 = 0, 0
    for i in range(0,16,4):
        nib_1 = (arg1.arg >> i) & (0xF)
        nib_2 = (arg2.arg >> i) & (0xF)
        
        j = (carry + nib_1 + nib_2)
        if (j >= 10):
            carry = 1
            j -= 10
            j &= 0xF
        else:
            carry = 0
        res += j << i
    return ExprInt(res, arg1.size)


def simp_smod_sext(expr_s, expr):
    """
    a.size == b.size
    smod(a.signExtend(X), b.signExtend(X)) => smod(a, b).signExtend(X)
    """
    if not expr.is_op("smod"):
        return expr
    arg1, arg2 = expr.args
    if arg1.is_op() and arg1.op.startswith("signExt"):
        src1 = arg1.args[0]
        if arg2.is_op() and arg2.op.startswith("signExt"):
            src2 = arg2.args[0]
            if src1.size == src2.size:
                # Case: a.signext(), b.signext()
                return ExprOp("smod", src1, src2).signExtend(expr.size)
            return expr
        elif arg2.is_int():
            src2 = expr_s.expr_simp(arg2[:src1.size])
            if expr_s.expr_simp(src2.signExtend(arg2.size)) == arg2:
                # Case: a.signext(), int
                return ExprOp("smod", src1, src2).signExtend(expr.size)
            return expr
    # Case: int        , b.signext()
    if arg2.is_op() and arg2.op.startswith("signExt"):
        src2 = arg2.args[0]
        if arg1.is_int():
            src1 = expr_s.expr_simp(arg1[:src2.size])
            if expr_s.expr_simp(src1.signExtend(arg1.size)) == arg1:
                # Case: int, b.signext()
                return ExprOp("smod", src1, src2).signExtend(expr.size)
    return expr

# FLAG_SUB_OF(CST1, CST2) => CST
def simp_flag_cst(expr_simp, expr):
    if expr.op not in [
            "FLAG_EQ", "FLAG_EQ_AND", "FLAG_SIGN_SUB", "FLAG_EQ_CMP", "FLAG_ADD_CF",
            "FLAG_SUB_CF", "FLAG_ADD_OF", "FLAG_SUB_OF", "FLAG_EQ_ADDWC", "FLAG_ADDWC_OF",
            "FLAG_SUBWC_OF", "FLAG_ADDWC_CF", "FLAG_SUBWC_CF", "FLAG_SIGN_ADDWC",
            "FLAG_SIGN_SUBWC", "FLAG_EQ_SUBWC",
            "CC_U<=", "CC_U>=", "CC_S<", "CC_S>", "CC_S<=", "CC_S>=", "CC_U>",
            "CC_U<", "CC_NEG", "CC_EQ", "CC_NE", "CC_POS"
    ]:
        return expr
    if not all(arg.is_int() for arg in expr.args):
        return expr
    new_expr = expr_simp(simp_flags(expr_simp, expr))
    return new_expr
