from miasm2.ir.translators.translator import Translator
from miasm2.core import asmblock
from miasm2.expression.modint import size2mask


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


    def from_ExprId(self, expr):
        if isinstance(expr.name, asmblock.AsmLabel):
            return "0x%x" % expr.name.offset
        return str(expr)

    def from_ExprInt(self, expr):
        return "0x%x" % expr.arg.arg

    def from_ExprAff(self, expr):
        return "%s = %s" % tuple(map(self.from_expr, (expr.dst, expr.src)))

    def from_ExprCond(self, expr):
        return "(%s?%s:%s)" % tuple(map(self.from_expr,
                                        (expr.cond, expr.src1, expr.src2)))

    def from_ExprMem(self, expr):
        return "MEM_LOOKUP_%.2d(jitcpu, %s)" % (expr.size,
                                                self.from_expr(expr.arg))

    def from_ExprOp(self, expr):
        if len(expr.args) == 1:
            if expr.op == 'parity':
                return "parity(%s&0x%x)" % (self.from_expr(expr.args[0]),
                                            size2mask(expr.args[0].size))
            elif expr.op in ['cntleadzeros', 'cnttrailzeros']:
                return "%s(0x%x, %s)" % (expr.op,
                                             expr.args[0].size,
                                             self.from_expr(expr.args[0]))
            elif expr.op in ['clz']:
                return "%s(%s)" % (expr.op,
                                   self.from_expr(expr.args[0]))
            elif expr.op == '!':
                return "(~ %s)&0x%x" % (self.from_expr(expr.args[0]),
                                        size2mask(expr.args[0].size))
            elif expr.op in ["hex2bcd", "bcd2hex"]:
                return "%s_%d(%s)" % (expr.op, expr.args[0].size,
                                      self.from_expr(expr.args[0]))
            elif (expr.op.startswith("double_to_") or
                  expr.op.endswith("_to_double")   or
                  expr.op.startswith("access_")    or
                  expr.op.startswith("load_")      or
                  expr.op.startswith("fxam_c")     or
                  expr.op in ["-", "ftan", "frndint", "f2xm1",
                              "fsin", "fsqrt", "fabs", "fcos", "fchs"]):
                return "%s(%s)" % (expr.op, self.from_expr(expr.args[0]))
            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) == 2:
            if expr.op == "==":
                return '(((%s&0x%x) == (%s&0x%x))?1:0)' % (
                    self.from_expr(expr.args[0]), size2mask(expr.args[0].size),
                    self.from_expr(expr.args[1]), size2mask(expr.args[1].size))
            elif expr.op in self.dct_shift:
                return 'SHIFT_%s(%d, %s, %s)' % (self.dct_shift[expr.op].upper(),
                                                 expr.args[0].size,
                                                 self.from_expr(expr.args[0]),
                                                 self.from_expr(expr.args[1]))
            elif expr.is_associative() or expr.op in ["%", "/"]:
                oper = ['(%s&0x%x)' % (self.from_expr(arg), size2mask(arg.size))
                        for arg in expr.args]
                oper = str(expr.op).join(oper)
                return "((%s)&0x%x)" % (oper, size2mask(expr.args[0].size))
            elif expr.op in ['-']:
                return '(((%s&0x%x) %s (%s&0x%x))&0x%x)' % (
                    self.from_expr(expr.args[0]), size2mask(expr.args[0].size),
                    str(expr.op),
                    self.from_expr(expr.args[1]), size2mask(expr.args[1].size),
                    size2mask(expr.args[0].size))
            elif expr.op in self.dct_rot:
                return '(%s(%s, %s, %s) &0x%x)' % (self.dct_rot[expr.op],
                                                   expr.args[0].size,
                                                   self.from_expr(expr.args[0]),
                                                   self.from_expr(expr.args[1]),
                                                   size2mask(expr.args[0].size))
            elif expr.op == 'x86_cpuid':
                return "%s(%s, %s)" % (expr.op,
                                       self.from_expr(expr.args[0]),
                                       self.from_expr(expr.args[1]))
            elif (expr.op.startswith("fcom")  or
                  expr.op in ["fadd", "fsub", "fdiv", 'fmul', "fscale",
                              "fprem", "fprem_lsb", "fyl2x", "fpatan"]):
                return "fpu_%s(%s, %s)" % (expr.op,
                                           self.from_expr(expr.args[0]),
                                           self.from_expr(expr.args[1]))
            elif expr.op == "segm":
                return "segm2addr(jitcpu, %s, %s)" % (
                    self.from_expr(expr.args[0]), self.from_expr(expr.args[1]))
            elif expr.op in ['udiv', 'umod', 'idiv', 'imod']:
                return '%s%d((vm_cpu_t*)jitcpu->cpu, %s, %s)' % (expr.op,
                                                                 expr.args[0].size,
                                                                 self.from_expr(expr.args[0]),
                                                                 self.from_expr(expr.args[1]))
            elif expr.op in ["bcdadd", "bcdadd_cf"]:
                return "%s_%d(%s, %s)" % (expr.op, expr.args[0].size,
                                          self.from_expr(expr.args[0]),
                                          self.from_expr(expr.args[1]))
            else:
                raise NotImplementedError('Unknown op: %r' % expr.op)

        elif len(expr.args) >= 3 and expr.is_associative():  # ?????
            oper = ['(%s&0x%x)' % (self.from_expr(arg), size2mask(arg.size))
                    for arg in expr.args]
            oper = str(expr.op).join(oper)
            return "((%s)&0x%x)" % (oper, size2mask(expr.args[0].size))

        else:
            raise NotImplementedError('Unknown op: %s' % expr.op)

    def from_ExprSlice(self, expr):
        # XXX check mask for 64 bit & 32 bit compat
        return "((%s>>%d) & 0x%X)" % (self.from_expr(expr.arg),
                                      expr.start,
                                      (1 << (expr.stop - expr.start)) - 1)

    def from_ExprCompose(self, expr):
        out = []
        # XXX check mask for 64 bit & 32 bit compat
        if expr.size in [8, 16, 32, 64, 128]:
            size = expr.size
        else:
            # Uncommon expression size
            size = expr.size
            next_power = 1
            while next_power <= size:
                next_power <<= 1
            size = next_power

        dst_cast = "uint%d_t" % size
        for index, arg in expr.iter_args():
            out.append("(((%s)(%s & 0x%X)) << %d)" % (dst_cast,
                                                      self.from_expr(arg),
                                                      (1 << arg.size) - 1,
                                                      index))
        out = ' | '.join(out)
        return '(' + out + ')'


# Register the class
Translator.register(TranslatorC)
