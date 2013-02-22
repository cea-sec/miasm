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
from miasm.tools.modint import uint1, uint8, uint16, uint32, uint64
from miasm.tools.modint import int8, int16, int32, int64
tip = 'tip'

def slice_rest(size, start, stop):
    if start >=size or stop > size: raise 'bad slice rest %s %s %s'%(str(size), str(start), str(stop))
    if start == stop: return [(0,size)]
    rest = []
    if start !=0:
        rest.append((0, start))
    if stop < size:
        rest.append((stop, size))

    return rest

size2type ={8:uint8,
            16:uint16,
            32:uint32,
            64:uint64
            }

tab_int_size = {uint8:8,
                uint16:16,
                uint32:32,
                uint64:64
                }

my_size_mask = {1:1, 8:0xFF, 16:0xFFFF, 32:0xFFFFFFFF,  64:0xFFFFFFFFFFFFFFFFL}


def is_int(a):
    t = [uint1, uint8, uint16, uint32, uint64]
    return any([isinstance(a, x) for x in t])



def get_missing_interval(all_intervals, i_min = 0, i_max = 32):
    my_intervals = all_intervals[:]
    my_intervals.sort()
    my_intervals.append((i_max, i_max))

    missing_i = []
    last_pos = i_min
    for start, stop in my_intervals:
        if last_pos  != start:
            missing_i.append((last_pos, start))
        last_pos = stop
    return missing_i


def visit_chk(visitor):
    def wrapped(e, cb):
        #print 'visit', e
        e_new = visitor(e, cb)
        e_new2 = cb(e_new)
        return e_new2
    return wrapped


class Expr:
    is_term = False
    is_simp = False
    is_eval = False
    def __init__(self, arg):
        self.arg = arg
    def __str__(self):
        return str(self.arg)
    def __getitem__(self, i):
        if not isinstance(i, slice):
            print i
            raise "bad slice"
        start, stop, step = i.indices(self.get_size())
        return ExprSlice(self, start, stop)
    def get_r(self, mem_read=False):
        return self.arg.get_r(mem_read)
    def get_w(self):
        return self.arg.get_w()
    def get_size(self):
        return arg.get_size()
    def __repr__(self):
        return "<%s 0x%x>"%(self.__class__.__name__, id(self))
    def __ne__(self, a):
        return not self.__eq__(a)
    def toC(self):
        print self
        fdsfs
        return self.arg.toC()
    def __add__(self, a):
        return ExprOp('+', self, a)
    def __sub__(self, a):
        #return ExprOp('-', self, a)
        return ExprOp('+', self, ExprOp('-', a))
    def __div__(self, a):
        return ExprOp('/', self, a)
    def __mul__(self, a):
        return ExprOp('*', self, a)
    def __lshift__(self, a):
        return ExprOp('<<', self, a)
    def __rshift__(self, a):
        return ExprOp('>>', self, a)
    def __xor__(self, a):
        return ExprOp('^', self, a)
    def __or__(self, a):
        return ExprOp('|', self, a)
    def __and__(self, a):
        return ExprOp('&', self, a)
    def __neg__(self):
        return ExprOp('-', self)
    def __invert__(self):
        s = self.get_size()
        return ExprOp('^', self, ExprInt(size2type[s](my_size_mask[s])))
    def copy(self):
        """
        deep copy of the expression
        """
        return self.visit(lambda x:x)
    def replace_expr(self, dct = {}):
        """
        find and replace sub expression using dct
        """
        def my_replace(e, dct):
            if e in dct:
                return dct[e]
            return e
        return self.visit(lambda e:my_replace(e, dct))
    def canonize(self):
        def my_canon(e):
            if isinstance(e, ExprOp):
                args = canonize_expr_list(e.args)
                return ExprOp(e.op, *args)
            elif isinstance(e, ExprCompose):
                return ExprCompose(canonize_expr_list_compose(e.args))
            else:
                return e
        return self.visit(my_canon)

class ExprTop(Expr):
    def __init__(self, e=None):
        fdqs
        self.e = e
        pass
    def __str__(self):
        return "top(%s)"%str(self.e)
    def get_r(self, mem_read=False):
        raise ValueError("get_r on TOP")
    def get_w(self):
        raise ValueError("get_r on TOP")
    def get_size(self):
        raise ValueError("get_size on TOP")
    def __eq__(self, a):
        return isinstance(a, ExprTop)
    def __hash__(self):
        return 0x1337beef
    def toC(self):
        raise ValueError('cannot toC TOP')

class ExprInt(Expr):
    def __init__(self, arg):
        if not is_int(arg):
            raise 'arg must by numpy int! %s'%str(arg)
        self.arg = arg
    def __str__(self):
        if self.arg < 0:
            return str("-0x%X"%-int(self.arg&0xffffffffffffffffL))
        else:
            return str("0x%X"%int(self.arg&0xffffffffffffffffL))
    def get_r(self, mem_read=False):
        return set()
    def get_w(self):
        return set()
    def get_size(self):
        return self.arg.size
    def __contains__(self, e):
        return self == e
    def __eq__(self, a):
        if not isinstance(a, ExprInt):
            return False
        return self.arg == a.arg
    def __hash__(self):
        return hash(self.arg)
    def __repr__(self):
        return Expr.__repr__(self)[:-1]+" 0x%X>"%int(self.arg&0xffffffffffffffffL)
    def toC(self):
        return str(self)
    @visit_chk
    def visit(self, cb):
        return self
    def copy(self):
        return ExprInt(self.arg)

class ExprId(Expr):
    def __init__(self, name, size = 32, is_term = False):
        self.name, self.size = name, size
        self.is_term = is_term
    def __str__(self):
        return str(self.name)
    def get_r(self, mem_read=False):
        return set([self])
    def get_w(self):
        return set([self])
    def get_size(self):
        return self.size
    def __contains__(self, e):
        return self == e
    def __eq__(self, a):
        if not isinstance(a, ExprId):
            return False
        if self.name == a.name and self.size != a.size:
            fdsfdsfdsdsf
        return self.name == a.name and self.size == a.size
    def __hash__(self):
        return hash(self.name)
    def __repr__(self):
        return Expr.__repr__(self)[:-1]+" %s>"%self.name
    def toC(self):
        return str(self)
    @visit_chk
    def visit(self, cb):
        return self
    def copy(self):
        return ExprId(self.name, self.size)

memreg = ExprId('MEM')



class ExprAff(Expr):
    def __init__(self, dst, src):
        #if dst is slice=> replace with id make composed src
        if isinstance(dst, ExprSlice):
            self.dst = dst.arg
            rest = [(ExprSlice(dst.arg, r[0], r[1]), r[0], r[1]) for r in slice_rest(dst.arg.size, dst.start, dst.stop)]
            all_a = [(src, dst.start, dst.stop)] + rest
            all_a.sort(key=lambda x:x[1])
            self.src = ExprCompose(all_a)
        else:
            self.dst, self.src = dst,src
    def __str__(self):
        return "%s = %s"%(str(self.dst), str(self.src))
    def get_r(self, mem_read=False):
        return self.src.get_r(mem_read)
    def get_w(self):
        if isinstance(self.dst, ExprMem):
            return set([self.dst]) #[memreg]
        else:
            return self.dst.get_w()
    #return dst size? XXX
    def get_size(self):
        return self.dst.get_size()
    def __contains__(self, e):
        return self == e or self.src.__contains__(e) or self.dst.__contains__(e)
    def __eq__(self, a):
        if not isinstance(a, ExprAff):
            return False
        return self.src == a.src and self.dst == a.dst
    def __hash__(self):
        return hash(self.dst)^hash(self.src)
    def toC(self):
        return "%s = %s"%(self.dst.toC(), self.src.toC())
    #XXX /!\ for hackish expraff to slice
    def get_modified_slice(self):
        dst = self.dst
        if not isinstance(self.src, ExprCompose):
            raise ValueError("get mod slice not on expraff slice", str(self))
        modified_s = []
        for x in self.src.args:
            if not isinstance(x[0], ExprSlice) or x[0].arg != dst or x[1] != x[0].start or x[2] != x[0].stop:
                modified_s.append(x)
        return modified_s
    @visit_chk
    def visit(self, cb):
        dst, src = self.dst.visit(cb), self.src.visit(cb)
        if dst == self.dst and src == self.src:
            return self
        else:
            return ExprAff(dst, src)
    def copy(self):
        return ExprAff(self.dst.copy(), self.src.copy())

class ExprCond(Expr):
    def __init__(self, cond, src1, src2):
        self.cond, self.src1, self.src2 = cond, src1, src2
    def __str__(self):
        return "%s?(%s,%s)"%(str(self.cond), str(self.src1), str(self.src2))
    def get_r(self, mem_read=False):
        out=self.cond.get_r(mem_read).union(self.src1.get_r(mem_read)).union(self.src2.get_r(mem_read))
        return out
    def get_w(self):
        return set()
    #return src1 size? XXX
    def get_size(self):
        return self.src1.get_size()
    def __contains__(self, e):
        return self == e or self.cond.__contains__(e) or self.src1.__contains__(e) or self.src2.__contains__(e)
    def __eq__(self, a):
        if not isinstance(a, ExprCond):
            return False
        return self.cond == a.cond and self.src1 == a.src1 and self.src2 == a.src2
    def __hash__(self):
        return hash(self.cond)^hash(self.src1)^hash(self.src2)
    def toC(self):
        return "(%s?%s:%s)"%(self.cond.toC(), self.src1.toC(), self.src2.toC())
    @visit_chk
    def visit(self, cb):
        cond = self.cond.visit(cb)
        src1 = self.src1.visit(cb)
        src2 = self.src2.visit(cb)
        if cond == self.cond and \
                src1 == self.src1 and \
                src2 == self.src2:
            return self
        return ExprCond(cond, src1, src2)
    def copy(self):
        return ExprCond(self.cond.copy(),
                        self.src1.copy(),
                        self.src2.copy())

class ExprMem(Expr):
    def __init__(self, arg, size = 32, segm = None):
        if not isinstance(arg, Expr): raise 'arg must be expr'
        self.arg, self.size, self.segm = arg, size, segm
    def __str__(self):
        if self.segm:
            return "%s:@%d[%s]"%(self.segm, self.size, str(self.arg))
        else:
            return "@%d[%s]"%(self.size, str(self.arg))
    def get_r(self, mem_read=False):
        if mem_read:
            return set(self.arg.get_r(mem_read).union(set([self])))
        else:
            return set([self])
    def get_w(self):
        return set([self]) #[memreg]
    def get_size(self):
        return self.size
    def __contains__(self, e):
        return self == e or self.arg.__contains__(e)
    def __eq__(self, a):
        if not isinstance(a, ExprMem):
            return False
        return self.arg == a.arg and self.size == a.size and self.segm == a.segm
    def __hash__(self):
        return hash(self.arg)^hash(self.size)^hash(self.segm)
    def toC(self):
        if self.segm:
            return "MEM_LOOKUP_%.2d_SEGM(%s, %s)"%(self.size, self.segm.toC(), self.arg.toC())
        else:
            return "MEM_LOOKUP_%.2d(%s)"%(self.size, self.arg.toC())
    @visit_chk
    def visit(self, cb):
        segm = self.segm
        if isinstance(segm, Expr):
            segm = self.segm.visit(cb)
        else:
            segm = None
        arg = self.arg.visit(cb)
        if segm == self.segm and arg == self.arg:
            return self
        return ExprMem(arg, self.size, segm)
    def copy(self):
        arg = self.arg.copy()
        if self.segm:
            segm = self.segm.copy()
        else:
            segm = None
        return ExprMem(arg, size = self.size, segm = segm)


op_assoc = ['+', '*', '^', '&', '|']
class ExprOp(Expr):
    def __init__(self, op, *args):
        self.op, self.args = op, args
        if isinstance(op, Expr):
            fdsfsdf
    def __str__(self):
        if self.op in op_assoc:
            return '(' + self.op.join([str(x) for x in self.args]) + ')'
        if len(self.args) == 2:
            return '('+str(self.args[0]) + ' ' + self.op + ' ' + str(self.args[1]) + ')'
        elif len(self.args)> 2:
            return self.op + '(' + ', '.join([str(x) for x in self.args]) + ')'
        else:
            return reduce(lambda x,y:x+' '+str(y), self.args, '('+str(self.op))+')'
    def get_r(self, mem_read=False):
        return reduce(lambda x,y:x.union(y.get_r(mem_read)), self.args, set())
    def get_w(self):
        raise ValueError('op cannot be written!', self)
    #return 1st arg size XXX
    def get_size(self):
        a = self.args[0].get_size()
        if len(self.args)>1:
            if not a:
                a = self.args[1].get_size()
        return a
    def __contains__(self, e):
        if self == e:
            return True
        for a in self.args:
            if  a.__contains__(e):
                return True
        return False
    def __eq__(self, a):
        if not isinstance(a, ExprOp):
            return False
        if self.op !=a.op:
            return False
        if len(self.args) != len(a.args):
            return False
        for i, x in enumerate(self.args):
            if not x == a.args[i]:
                return False
        return True
    def __hash__(self):
        h = hash(self.op)
        for a in self.args:
            h^=hash(a)
        return h
    def toC(self):
        dct_shift= {'a>>':"right_arith",
                    '>>':"right_logic",
                    '<<':"left_logic",
                    'a<<':"left_logic"}
        dct_rot = {'<<<':'rot_left',
                   '>>>':'rot_right'}
        if len(self.args)==1:
            if self.op == 'parity':
                return "parity(%s&0x%x)"%(self.args[0].toC(), my_size_mask[self.args[0].get_size()])
            elif self.op == '!':
                return "(~ %s)&0x%x"%(self.args[0].toC(), my_size_mask[self.args[0].get_size()])
            elif self.op in ['int_16_to_double', 'int_32_to_double', 'int_64_to_double']:
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op == 'double_to_int_32':
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op in ['mem_32_to_double', 'mem_64_to_double']:
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op.startswith("double_to_mem_"):
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op in ["ftan", "frndint", "f2xm1", "fsin", "fsqrt", "fabs", "fcos"]:
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op in ["-"]:
                return "%s(%s)"%(self.op, self.args[0].toC())
            else:
                print self.op
                raise ValueError('unknown op!!', str(self.op))
                return '('+str(self.op)+self.args[0].toC()+')'
        elif len(self.args)==2:
            if self.op == "==":
                return '(((%s&0x%x) == (%s&0x%x))?1:0)'%(self.args[0].toC(), my_size_mask[self.args[0].get_size()], self.args[1].toC(), my_size_mask[self.args[1].get_size()])
            elif self.op in dct_shift:
                return 'shift_%s_%.2d(%s , %s)'%(dct_shift[self.op],
                                                 self.args[0].get_size(),
                                                 self.args[0].toC(),
                                                 self.args[1].toC())
            elif self.op in op_assoc:
                o = ['(%s&0x%x)'%(a.toC(), my_size_mask[a.get_size()]) for a in self.args]
                o = str(self.op).join(o)
                return "((%s)&0x%x)"%(o, my_size_mask[self.args[0].get_size()])
            elif self.op in ['-']:
                return '(((%s&0x%x) %s (%s&0x%x))&0x%x)'%(self.args[0].toC(),
                                                          my_size_mask[self.args[0].get_size()],
                                                          str(self.op),
                                                          self.args[1].toC(),
                                                          my_size_mask[self.args[1].get_size()],
                                                          my_size_mask[self.args[0].get_size()])
            elif self.op in dct_rot:
                return '(%s(%s, %s, %s) &0x%x)'%(dct_rot[self.op],
                                                 self.args[0].get_size(),
                                                 self.args[0].toC(),
                                                 self.args[1].toC(),
                                                 my_size_mask[self.args[0].get_size()])
            elif self.op == '*lo':
                return 'mul_lo_op(%s, %s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op == 'umul32_lo':
                return 'mul_lo_op(%s, %s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op in ['imul16_lo', 'imul32_lo']:
                return 'imul_lo_op_%s(%s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op in ['imul16_hi', 'imul32_hi']:
                return 'imul_hi_op_%s(%s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op == '*hi':
                return 'mul_hi_op(%s, %s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op == 'umul32_hi':
                return 'mul_hi_op(%s, %s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op == 'umul08':
                return 'mul_hi_op(%s, %s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op in ['umul16_lo', 'umul16_hi']:
                return '%s(%s, %s)' %(self.op,
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op in ['bsr', 'bsf']:
                return 'my_%s(%s, %s)'%(self.op,
                                 self.args[0].toC(),
                                 self.args[1].toC())
            elif self.op in ['imul08']:
                return 'my_%s(%s, %s)'%(self.op,
                                        self.args[0].toC(),
                                        self.args[1].toC())
            elif self.op.startswith('cpuid'):
                return "%s(%s, %s)"%(self.op, self.args[0].toC(), self.args[1].toC())
            elif self.op.startswith("fcom"):
                return "%s(%s, %s)"%(self.op, self.args[0].toC(), self.args[1].toC())
            elif self.op in ["fadd", "fsub", "fdiv", 'fmul', "fscale"]:
                return "%s(%s, %s)"%(self.op, self.args[0].toC(), self.args[1].toC())
            else:
                print self.op
                raise ValueError('unknown op!!', str(self.op))
        elif len(self.args)==3:
            dct_div= {'div8':"div_op",
                      'div16':"div_op",
                      'div32':"div_op",
                      'idiv32':"div_op", #XXX to test
                      'rem8':"rem_op",
                      'rem16':"rem_op",
                      'rem32':"rem_op",
                      'irem32':"rem_op", #XXX to test
                      '<<<c_rez':'rcl_rez_op',
                      '<<<c_cf':'rcl_cf_op',
                      '>>>c_rez':'rcr_rez_op',
                      '>>>c_cf':'rcr_cf_op',
                      }
            if not self.op in dct_div:
                fsdff
            return '(%s(%s, %s, %s, %s) &0x%x)'%(dct_div[self.op],
                                                 self.args[0].get_size(),
                                                 self.args[0].toC(),
                                                 self.args[1].toC(),
                                                 self.args[2].toC(),
                                                 my_size_mask[self.args[0].get_size()])
        else:
            raise ValueError('not imple', str(self))
    @visit_chk
    def visit(self, cb):
        args = [a.visit(cb) for a in self.args]
        modified = any([x[0] != x[1] for x in zip(self.args, args)])
        if modified:
            return ExprOp(self.op, *args)
        return self
    def copy(self):
        args = [a.copy() for a in self.args]
        return ExprOp(self.op, *args)

class ExprSlice(Expr):
    def __init__(self, arg, start, stop):
        self.arg, self.start, self.stop = arg, start, stop
    def __str__(self):
        return "%s[%d:%d]"%(str(self.arg), self.start, self.stop)
    def get_r(self, mem_read=False):
        return self.arg.get_r(mem_read)
    def get_w(self):
        return self.arg.get_w()
    def get_size(self):
        return self.stop-self.start
    def __contains__(self, e):
        if self == e:
            return True
        return self.arg.__contains__(e)
    def __eq__(self, a):
        if not isinstance(a, ExprSlice):
            return False
        return self.arg == a.arg and self.start == a.start and self.stop == a.stop
    def __hash__(self):
        return hash(self.arg)^hash(self.start)^hash(self.stop)
    def toC(self):
        # XXX check mask for 64 bit & 32 bit compat
        return "((%s>>%d) & 0x%X)"%(self.arg.toC(),
                                    self.start,
                                    (1<<(self.stop-self.start))-1)
    @visit_chk
    def visit(self, cb):
        arg = self.arg.visit(cb)
        if arg == self.arg:
            return self
        return ExprSlice(arg, self.start, self.stop)
    def copy(self):
        return ExprSlice(self.arg.copy(), self.start, self.stop)

class ExprCompose(Expr):
    def __init__(self, args):
        self.args = args
    def __str__(self):
        return '('+', '.join(['%s,%d,%d'%(str(x[0]), x[1], x[2]) for x in self.args])+')'
    def get_r(self, mem_read=False):
        return reduce(lambda x,y:x.union(y[0].get_r(mem_read)), self.args, set())
    def get_w(self):
        return reduce(lambda x,y:x.union(y[0].get_r(mem_read)), self.args, set())
    def get_size(self):
        return max([x[2] for x in self.args]) - min([x[1] for x in self.args])
    def __contains__(self, e):
        if self == e:
            return True
        for a in self.args:
            if a == e:
                return True
            if a[0].__contains__(e):
                return True
        return False
    def __eq__(self, a):
        if not isinstance(a, ExprCompose):
            return False
        if len(self.args) != len(a.args):
            return False
        for (e1, start1, stop1), (e2, start2, stop2) in zip(self.args, a.args):
            if e1 != e2 or start1 != start2 or stop1 != stop2:
                return False
        return True
    def __hash__(self):
        h = 0
        for a in self.args:
            h^=hash(a[0])^hash(a[1])^hash(a[2])
        return h
    def toC(self):
        out = []
        # XXX check mask for 64 bit & 32 bit compat
        for x in self.args:
            out.append("((%s & 0x%X) << %d)"%(x[0].toC(),
                                              (1<<(x[2]-x[1]))-1,
                                              x[1]))
        out = ' | '.join(out)
        return '('+out+')'
    @visit_chk
    def visit(self, cb):
        args = [(a[0].visit(cb), a[1], a[2]) for a in self.args]
        modified = any([x[0] != x[1] for x in zip(self.args, args)])
        if modified:
            return ExprCompose(args)
        return self
    def copy(self):
        args = [(a[0].copy(), a[1], a[2]) for a in self.args]
        return ExprCompose(args)

class set_expr:
    def __init__(self, l = []):
        self._list = []
        for a in l:
            self.add(a)
    def add(self, a):
        astr = str(a)
        for x in self._list:
            if str(x) == astr:
                return
        self._list.append(a)
    def discard(self, a):
        astr = str(a)
        for x in self._list:
            if str(x) == astr:
                self._list.remove(x)
                return True
        return False
    def remove(self ,a):
        if not self.discard(a):
            raise ValueError('value not found %s'%str(a))
    def update(self, list_a):
        if not isinstance(list_a, list) and not isinstance(list_a, set):
            raise ValueError('arg must be list or set')
        for a in list_a:
            self.add(a)
    def __contains__(self, a):
        astr = str(a)
        for x in self._list:
            if astr == str(x):
                return True
        return False
    def __str__(self):
        o = []
        o.append('[')
        for x in self._list:
            o.append(str(x))
        o.append(']')
        return " ".join(o)
    def __repr__(self):
        return "set_expr["+", ".join([str(x) for x in self._list])+"]"
    def __iter__(self):
        return self._list.__iter__()


expr_order_dict = {ExprId: 1,
                   ExprCond: 2,
                   ExprMem: 3,
                   ExprOp: 4,
                   ExprSlice: 5,
                   ExprCompose: 7,
                   ExprInt: 8,
                   }

def compare_exprs_compose(e1, e2):
    # sort by start bit address, then expr then stop but address
    x = cmp(e1[1], e2[1])
    if x: return x
    x = compare_exprs(e1[0], e2[0])
    if x: return x
    x = cmp(e1[2], e2[2])
    return x

def compare_expr_list_compose(l1_e, l2_e):
    for i in xrange(min(len(l1_e), len(l2_e))):
        x = compare_exprs_compose(l1_e[i], l2_e[i])
        if x: return x
    return cmp(len(l1_e), len(l2_e))

def compare_expr_list(l1_e, l2_e):
    for i in xrange(min(len(l1_e), len(l2_e))):
        x = compare_exprs(l1_e[i], l2_e[i])
        if x: return x
    return cmp(len(l1_e), len(l2_e))

# compare 2 expressions for canonization
# 0  => ==
# 1  => e1 > e2
# -1 => e1 < e2
def compare_exprs(e1, e2):
    c1 = e1.__class__
    c2 = e2.__class__
    if c1 != c2:
        return cmp(expr_order_dict[c1], expr_order_dict[c2])
    if e1 == e2:
        return 0
    if c1 == ExprInt:
        return cmp(e1.arg, e2.arg)
    elif c1 == ExprId:
        x = cmp(e1.name, e2.name)
        if x: return x
        return cmp(e1.size, e2.size)
    elif c1 == ExprAff:
        fds
    elif c2 == ExprCond:
        x = compare_exprs(e1.cond, e2.cond)
        if x: return x
        x = compare_exprs(e1.src1, e2.src1)
        if x: return x
        x = compare_exprs(e1.src2, e2.src2)
        return x
    elif c1 == ExprMem:
        x = compare_exprs(e1.arg, e2.arg)
        if x: return x
        return cmp(e1.size, e2.size)
    elif c1 == ExprOp:
        if e1.op != e2.op:
            return cmp(e1.op, e2.op)
        return compare_expr_list(e1.args, e2.args)
    elif c1 == ExprSlice:
        x = compare_exprs(e1.arg, e2.arg)
        if x: return x
        x = cmp(e1.start, e2.start)
        if x: return x
        x = cmp(e1.stop, e2.stop)
        return x
    elif c1 == ExprCompose:
        return compare_expr_list_compose(e1.args, e2.args)
    raise ValueError("not imppl %r %r"%(e1, e2))



def canonize_expr_list(l):
    l = list(l)
    l.sort(cmp=compare_exprs)
    return l

def canonize_expr_list_compose(l):
    l = l[:]
    l.sort(cmp=compare_exprs_compose)
    return l

tab_uintsize ={1:uint1,
               8:uint8,
               16:uint16,
               32:uint32,
               64:uint64
               }

def ExprInt8(i):
    return ExprInt(uint8(i))
def ExprInt16(i):
    return ExprInt(uint16(i))
def ExprInt32(i):
    return ExprInt(uint32(i))
def ExprInt64(i):
    return ExprInt(uint64(i))

def ExprInt_from(e, i):
    return ExprInt(tab_uintsize[e.get_size()](i))


def get_expr_ids_visit(e, ids):
    if isinstance(e, ExprId):
        ids.add(e)
    return e

def get_expr_ids(e):
    ids = set()
    e.visit(lambda x:get_expr_ids_visit(x, ids))
    return ids

def test_set(e, v, tks, result):
    if not v in tks:
        return e == v
    if v in result and result[v] != e:
        return False
    result[v] = e
    return result

def MatchExpr(e, m, tks, result = None):
    """
    try to match m expression with e expression with tks jokers
    result is output dictionnary with matching joker values
    """
    if result == None:
        result = {}
    #print 'match', e, m, tks, result
    if m in tks:
        return test_set(e, m, tks, result)
    if isinstance(e, ExprInt):
        return test_set(e, m, tks, result)
    elif isinstance(e, ExprId):
        return test_set(e, m, tks, result)
    elif isinstance(e, ExprOp):
        if not isinstance(m, ExprOp):
            return False
        for a1, a2 in zip(e.args, m.args):
            r = MatchExpr(a1, a2, tks, result)
            if r == False:
                return False
        return result
    elif isinstance(e, ExprMem):
        if not isinstance(m, ExprMem):
            return False
        if e.size != m.size:
            return False
        return MatchExpr(e.arg, m.arg, tks, result)
    elif isinstance(e, ExprSlice):
        if not isinstance(m, ExprSlice):
            return False
        if e.start != m.start or e.stop != m.stop:
            return False
        return MatchExpr(e.arg, m.arg, tks, result)
    elif isinstance(e, ExprCond):
        if not isinstance(m, ExprCond):
            return False
        r = MatchExpr(e.cond, m.cond, tks, result)
        if not r: return False
        r = MatchExpr(e.src1, m.src1, tks, result)
        if not r: return False
        r = MatchExpr(e.src2, m.src2, tks, result)
        if not r: return False
        return result
    elif isinstance(e, ExprCompose):
        if not isinstance(m, ExprCompose):
            return False
        for a1, a2 in zip(e.args, m.args):
            if a1[1] != a2[1] or a1[2] != a2[2]:
                return False
            r = MatchExpr(a1[0], a2[0], tks, result)
            if not r:
                return False
        return result
    else:
        fds
if __name__ == '__main__':
    x = ExprId('x')
    y = ExprId('y')
    z = ExprId('z')
    a = ExprId('a')
    b = ExprId('b')
    c = ExprId('c')

    print MatchExpr(x, a, [a])
    print MatchExpr(ExprInt32(12), a, [a])
    print MatchExpr(x+y, a, [a])
    print MatchExpr(x+y, a+y, [a])
    print MatchExpr(x+y, x+a, [a])
    print MatchExpr(x+y, a+b, [a, b])
    print MatchExpr(x+ExprId(12), a+b, [a, b])
    print MatchExpr(ExprMem(x), a, [a])
    print MatchExpr(ExprMem(x), ExprMem(a), [a])
    print MatchExpr(x[0:8], a, [a])
    print MatchExpr(x[0:8], a[0:8], [a])
    print MatchExpr(ExprCond(x, y, z), a, [a])
    print MatchExpr(ExprCond(x, y, z),
                    ExprCond(a, b, c), [a, b, c])
    print MatchExpr(ExprCompose([(x, 0, 8), (y, 8, 16)]), a, [a])
    print MatchExpr(ExprCompose([(x, 0, 8), (y, 8, 16)]),
                    ExprCompose([(a, 0, 8), (b, 8, 16)]), [a, b])

    e1 = ExprMem((a&ExprInt32(0xFFFFFFFC))+ExprInt32(0x10), 32)
    e2 = ExprMem((a&ExprInt32(0xFFFFFFFC))+b, 32)
    print MatchExpr(e1, e2, [b])
