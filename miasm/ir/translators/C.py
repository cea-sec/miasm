from miasm.ir.translators.translator import Translator
from miasm.core.utils import size2mask
from miasm.expression.expression import ExprInt, ExprCond, ExprCompose, \
    TOK_EQUAL, \
    TOK_INF_SIGNED, TOK_INF_UNSIGNED, \
    TOK_INF_EQUAL_SIGNED, TOK_INF_EQUAL_UNSIGNED, \
    is_associative

def int_size_to_bn(value, size):
    if size < 32:
        int_str = "%.8x" % value
        size_nibble = 8
    else:
        # size must be multiple of 4
        size = ((size + 31) // 32) * 32
        size_nibble = size // 4
        fmt_str = "%%.%dx" % size_nibble
        int_str = fmt_str % value
    assert len(int_str) == size_nibble
    return int_str, size_nibble


TOK_CMP_TO_NATIVE_C = {
    TOK_EQUAL: "==",
    TOK_INF_SIGNED: "<",
    TOK_INF_UNSIGNED: "<",
    TOK_INF_EQUAL_SIGNED: "<=",
    TOK_INF_EQUAL_UNSIGNED: "<=",
}

TOK_CMP_TO_BIGNUM_C = {
    TOK_EQUAL: "equal",
    TOK_INF_SIGNED: "inf_signed",
    TOK_INF_UNSIGNED: "inf_unsigned",
    TOK_INF_EQUAL_SIGNED: "inf_equal_signed",
    TOK_INF_EQUAL_UNSIGNED: "inf_equal_unsigned",
}


def get_c_common_next_pow2(size):
    # For uncommon expression size, use at least uint8
    size = max(size, 8)
    next_power = 1
    while next_power < size:
        next_power <<= 1
    size = next_power
    return size


class TranslatorC(Translator):
    "Translate a Miasm expression to an equivalent C code"

    # Implemented language
    __LANG__ = "C"

    # Operations translation
    dct_shift = {'a>>': "right_arith",
                 '>>': "right_logic",
                 '<<': "left_logic",
                 }
    dct_rot = {'<<<': 'rot_left',
               '>>>': 'rot_right',
               }

    NATIVE_INT_MAX_SIZE = 64

    def __init__(self, loc_db=None, **kwargs):
        """Instance a C translator
        @loc_db: LocationDB instance
        """
        super(TranslatorC, self).__init__(**kwargs)
        # symbol pool
        self.loc_db = loc_db

    def _size2mask(self, size):
        """Return a C string corresponding to the size2mask operation, with support for
        @size <= 64"""
        assert size <= 64
        mask = size2mask(size)
        return "0x%x" % mask

    def from_ExprId(self, expr):
        return str(expr)

    def from_ExprInt(self, expr):
        if expr.size <= self.NATIVE_INT_MAX_SIZE:
            assert expr.size <= 64
            out = "0x%x" % int(expr)
            if expr.size == 64:
                out += "ULL"
            return out
        value, int_size = int_size_to_bn(int(expr), expr.size)
        return 'bignum_from_string("%s", %d)' % (value, int_size)

    def from_ExprLoc(self, expr):
        loc_key = expr.loc_key
        if self.loc_db is None:
            return str(loc_key)
        offset = self.loc_db.get_location_offset(loc_key)
        if offset is None:
            return str(loc_key)

        if expr.size <= self.NATIVE_INT_MAX_SIZE:
            return "0x%x" % offset

        value, int_size = int_size_to_bn(offset, 64)
        return 'bignum_from_string("%s", %d)' % (value, int_size)

    def from_ExprAssign(self, expr):
        new_dst = self.from_expr(expr.dst)
        new_src = self.from_expr(expr.src)
        return "%s = %s" % (new_dst, new_src)

    def from_ExprCond(self, expr):
        cond = self.from_expr(expr.cond)
        src1 = self.from_expr(expr.src1)
        src2 = self.from_expr(expr.src2)
        if not expr.cond.size <= self.NATIVE_INT_MAX_SIZE:
            cond = "(!bignum_is_zero(%s))" % cond
        out = "(%s?%s:%s)" % (cond, src1, src2)
        return out

    def from_ExprMem(self, expr):
        ptr = expr.ptr
        if ptr.size <= self.NATIVE_INT_MAX_SIZE:
            new_ptr = self.from_expr(ptr)
            if expr.size <= self.NATIVE_INT_MAX_SIZE:
                # Native ptr, Native Mem
                return "MEM_LOOKUP_%.2d(jitcpu, %s)" % (expr.size, new_ptr)
            else:
                # Native ptr, BN mem
                return "MEM_LOOKUP_INT_BN(jitcpu, %d, %s)" % (expr.size, new_ptr)
        # BN ptr
        new_ptr = self.from_expr(ptr)

        if expr.size <= self.NATIVE_INT_MAX_SIZE:
            # BN ptr, Native Mem
            return "MEM_LOOKUP_BN_INT(jitcpu, %d, %s)" % (expr.size, new_ptr)
        else:
            # BN ptr, BN mem
            return "MEM_LOOKUP_BN_BN(jitcpu, %d, %s)" % (expr.size, new_ptr)

    def from_ExprOp(self, expr):
        if len(expr.args) == 1:
            if expr.op == 'parity':
                arg = expr.args[0]
                out = self.from_expr(arg)
                if arg.size <= self.NATIVE_INT_MAX_SIZE:
                    out = "(%s&%s)" % (out, self._size2mask(arg.size))
                else:
                    out = 'bignum_mask(%s, 8)' % (out, 8)
                    out = 'bignum_to_uint64(%s)' % out
                out = 'parity(%s)' % out
                return out

            elif expr.op.startswith("zeroExt_"):
                arg = expr.args[0]
                if expr.size == arg.size:
                    return arg
                return self.from_expr(ExprCompose(arg, ExprInt(0, expr.size - arg.size)))

            elif expr.op.startswith("signExt_"):
                arg = expr.args[0]
                if expr.size == arg.size:
                    return arg
                add_size = expr.size - arg.size
                new_expr = ExprCompose(
                    arg,
                    ExprCond(
                        arg.msb(),
                        ExprInt(size2mask(add_size), add_size),
                        ExprInt(0, add_size)
                    )
                )
                return self.from_expr(new_expr)


            elif expr.op in ['cntleadzeros', 'cnttrailzeros']:
                arg = expr.args[0]
                out = self.from_expr(arg)
                if arg.size <= self.NATIVE_INT_MAX_SIZE:
                    out = "%s(0x%x, %s)" % (expr.op, expr.args[0].size, out)
                else:
                    out = "bignum_%s(%s, %d)" % (expr.op, out, arg.size)
                return out

            elif expr.op == '!':
                arg = expr.args[0]
                out = self.from_expr(arg)
                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = "(~ %s)&%s" % (out, self._size2mask(arg.size))
                else:
                    out = "bignum_not(%s)" % out
                    out = "bignum_mask(%s, expr.size)" % out
                return out

            elif expr.op in [
                    "ftan", "frndint", "f2xm1", "fsin", "fsqrt", "fabs", "fcos",
                    "fchs",
            ]:
                return "fpu_%s%d(%s)" % (
                    expr.op,
                    expr.size,
                    self.from_expr(expr.args[0]),
                )
            elif (expr.op.startswith("access_")    or
                  expr.op.startswith("load_")      or
                  expr.op.startswith("fxam_c")):
                arg = expr.args[0]
                out = self.from_expr(arg)
                out = "%s(%s)" % (expr.op, out)
                return out

            elif expr.op == "-":
                arg = expr.args[0]
                out = self.from_expr(arg)
                if arg.size <= self.NATIVE_INT_MAX_SIZE:
                    out = "(%s(%s))" % (expr.op, out)
                    out = "(%s&%s)" % (out, self._size2mask(arg.size))
                else:
                    out = "bignum_sub(bignum_from_uint64(0), %s)" % out
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out

            elif expr.op.startswith("fpround_"):
                return "%s_fp%d(%s)" % (
                    expr.op,
                    expr.size,
                    self.from_expr(expr.args[0]),
                )
            elif expr.op == "sint_to_fp":
                size = expr.size
                arg = expr.args[0]
                if size not in [32, 64]:
                    raise RuntimeError(
                        "Unsupported size for sint_to_fp: %r" % size
                    )
                return "%s_%d(%s)" % (expr.op, size, self.from_expr(arg))
            elif expr.op.startswith("fp_to_sint"):
                dest_size = expr.size
                arg_size = expr.args[0].size
                if (arg_size, dest_size) in [
                        (32, 32), (64, 64), (64, 32),
                ]:
                    func = "fp%d_to_sint%d" % (arg_size, dest_size)
                else:
                    raise RuntimeError(
                        "Unsupported size for fp_to_sint: %r to %r" % (
                            arg_size,
                            dest_size
                        ))
                return "%s(%s)" % (func, self.from_expr(expr.args[0]))
            elif expr.op.startswith("fpconvert_fp"):
                dest_size = expr.size
                arg_size = expr.args[0].size
                if (arg_size, dest_size) in [
                        (32, 64), (64, 32)
                ]:
                    func = "fp%d_to_fp%d" % (arg_size, dest_size)
                else:
                    raise RuntimeError(
                        "Unsupported size for fpconvert: %r to %r" % (arg_size,
                                                                      dest_size)
                    )
                return "%s(%s)" % (func, self.from_expr(expr.args[0]))
            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) == 2:
            if expr.op in self.dct_shift:
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])
                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = 'SHIFT_%s(%d, %s, %s)' % (
                        self.dct_shift[expr.op].upper(),
                        expr.args[0].size,
                        arg0,
                        arg1
                    )
                else:
                    op = {
                        "<<": "lshift",
                        ">>": "rshift",
                        "a>>": "a_rshift"
                    }
                    out = "bignum_%s(%s, bignum_to_uint64(%s))" % (
                        op[expr.op], arg0, arg1
                    )
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out

            elif is_associative(expr):
                args = [self.from_expr(arg)
                        for arg in expr.args]
                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = (" %s " % expr.op).join(args)
                    out = "((%s)&%s)" % (out, self._size2mask(expr.size))
                else:
                    op_to_bn_func = {
                    "+": "add",
                    "*": "mul",
                    "|": "or",
                    "^": "xor",
                    "&": "and",
                    }
                    args = list(expr.args)
                    out = self.from_expr(args.pop())
                    while args:
                        out = 'bignum_mask(bignum_%s(%s, %s), %d)' % (
                            op_to_bn_func[expr.op],
                            out,
                            self.from_expr(args.pop()),
                            expr.size
                    )
                return out

            elif expr.op in ['-']:
                return '(((%s&%s) %s (%s&%s))&%s)' % (
                    self.from_expr(expr.args[0]),
                    self._size2mask(expr.args[0].size),
                    str(expr.op),
                    self.from_expr(expr.args[1]),
                    self._size2mask(expr.args[1].size),
                    self._size2mask(expr.args[0].size)
                )
            elif expr.op in self.dct_rot:
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])
                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = '(%s(%s, %s, %s) &%s)' % (
                        self.dct_rot[expr.op],
                        expr.args[0].size,
                        arg0,
                        arg1,
                        self._size2mask(expr.args[0].size),
                    )
                else:
                    op = {
                        ">>>": "ror",
                        "<<<": "rol"
                    }
                    out = "bignum_%s(%s, %d, bignum_to_uint64(%s))" % (
                        op[expr.op], arg0, expr.size, arg1
                    )
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out

            elif expr.op == 'x86_cpuid':
                return "%s(%s, %s)" % (expr.op,
                                       self.from_expr(expr.args[0]),
                                       self.from_expr(expr.args[1]))
            elif expr.op.startswith("fcom"):
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])
                if not expr.args[0].size <= self.NATIVE_INT_MAX_SIZE:
                    raise ValueError("Bad semantic: fpu do operations do not support such size")
                out = "fpu_%s(%s, %s)" % (expr.op, arg0, arg1)
                return out

            elif expr.op in ["fadd", "fsub", "fdiv", 'fmul', "fscale",
                             "fprem", "fyl2x", "fpatan"]:
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])
                if not expr.args[0].size <= self.NATIVE_INT_MAX_SIZE:
                    raise ValueError("Bad semantic: fpu do operations do not support such size")
                out = "fpu_%s%d(%s, %s)" % (expr.op, expr.size, arg0, arg1)
                return out

            elif expr.op == "segm":
                return "segm2addr(jitcpu, %s, %s)" % (
                    self.from_expr(expr.args[0]),
                    self.from_expr(expr.args[1])
                )

            elif expr.op in ['udiv', 'umod']:
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])

                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = '%s%d(%s, %s)' % (
                        expr.op,
                        expr.args[0].size,
                        arg0,
                        arg1
                    )
                else:
                    out = "bignum_%s(%s, %s)" % (
                        expr.op,
                        arg0,
                        arg1
                    )
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out



            elif expr.op in ['sdiv', 'smod']:
                arg0 = self.from_expr(expr.args[0])
                arg1 = self.from_expr(expr.args[1])

                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    out = '%s%d(%s, %s)' % (
                        expr.op,
                        expr.args[0].size,
                        arg0,
                        arg1
                    )
                else:
                    out = "bignum_%s(%s, %s, %d)" % (
                        expr.op,
                        arg0,
                        arg1,
                        expr.size
                    )
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out

            elif expr.op in ["bcdadd", "bcdadd_cf"]:
                return "%s_%d(%s, %s)" % (
                    expr.op, expr.args[0].size,
                    self.from_expr(expr.args[0]),
                    self.from_expr(expr.args[1])
                )


            elif expr.op in [
                    TOK_EQUAL,
                    TOK_INF_SIGNED,
                    TOK_INF_UNSIGNED,
                    TOK_INF_EQUAL_SIGNED,
                    TOK_INF_EQUAL_UNSIGNED,
            ]:
                arg0, arg1 = expr.args
                if expr.size <= self.NATIVE_INT_MAX_SIZE:
                    size = get_c_common_next_pow2(arg0.size)
                    op = TOK_CMP_TO_NATIVE_C[expr.op]
                    if expr.op in [TOK_INF_SIGNED, TOK_INF_EQUAL_SIGNED]:
                        arg0 = arg0.signExtend(size)
                        arg1 = arg1.signExtend(size)
                        arg0_C = self.from_expr(arg0)
                        arg1_C = self.from_expr(arg1)
                        cast = "(int%d_t)" % size
                    else:
                        arg0 = arg0.signExtend(size)
                        arg1 = arg1.signExtend(size)
                        arg0_C = self.from_expr(arg0)
                        arg1_C = self.from_expr(arg1)
                        cast = "(uint%d_t)" % size
                    out = '((%s%s %s %s%s)?1:0)' % (
                        cast,
                        arg0_C,
                        op,
                        cast,
                        arg1_C
                    )
                else:
                    op = TOK_CMP_TO_BIGNUM_C[expr.op]
                    out = "bignum_is_%s(%s, %s)" % (
                        op,
                        arg0,
                        arg1
                    )
                    out = "bignum_mask(%s, %d)"% (out, expr.size)
                return out


            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) >= 3 and is_associative(expr):  # ?????
            oper = ['(%s&%s)' % (
                self.from_expr(arg),
                self._size2mask(arg.size),
            )
                    for arg in expr.args]
            oper = str(expr.op).join(oper)
            return "((%s)&%s)" % (
                oper,
                self._size2mask(expr.args[0].size)
            )
        else:
            raise NotImplementedError('Unknown op: %s' % expr.op)

    def from_ExprSlice(self, expr):
        out = self.from_expr(expr.arg)
        if expr.arg.size <= self.NATIVE_INT_MAX_SIZE:
            # XXX check mask for 64 bit & 32 bit compat
            out = "((%s>>%d) &%s)" % (
                out, expr.start,
                self._size2mask(expr.stop - expr.start)
            )
        else:
            out = "bignum_rshift(%s, %d)" % (out, expr.start)
            out = "bignum_mask(%s, %d)" % (out, expr.stop - expr.start)

            if expr.size <= self.NATIVE_INT_MAX_SIZE:
                # Convert bignum to int
                out = "bignum_to_uint64(%s)" % out
        return out

    def from_ExprCompose(self, expr):
        if expr.size <= self.NATIVE_INT_MAX_SIZE:

            out = []
            size = get_c_common_next_pow2(expr.size)
            dst_cast = "uint%d_t" % size
            for index, arg in expr.iter_args():
                out.append("(((%s)(%s & %s)) << %d)" % (
                    dst_cast,
                    self.from_expr(arg),
                    self._size2mask(arg.size),
                    index)
                )
            out = ' | '.join(out)
            return '(' + out + ')'
        else:
            # Convert all parts to bignum
            args = []
            for index, arg in expr.iter_args():
                arg_str = self.from_expr(arg)
                if arg.size <= self.NATIVE_INT_MAX_SIZE:
                    arg_str = '((%s) & %s)' % (arg_str, self._size2mask(arg.size))
                    arg_str = 'bignum_from_uint64(%s)' % arg_str
                else:
                    arg_str = 'bignum_mask(%s, %d)' % (arg_str, arg.size)
                arg_str = 'bignum_lshift(%s, %d)' % (arg_str, index)
                args.append(arg_str)
            out = args.pop()
            while args:
                arg = args.pop()
                out = "bignum_or(%s, %s)" % (out, arg)
            return out


# Register the class
Translator.register(TranslatorC)
