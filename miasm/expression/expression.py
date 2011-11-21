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
from numpy import uint8, uint16, uint32, uint64, int8, int16, int32, int64
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
        
tab_int_size = {int8:8,
                uint8:8,
                int16:16,
                uint16:16,
                int32:32,
                uint32:32,
                int64:64,
                uint64:64
                }

my_size_mask = {1:1, 8:0xFF, 16:0xFFFF, 32:0xFFFFFFFF,  64:0xFFFFFFFFFFFFFFFFL}


def is_int(a):
    t = [int8, int16, int32, int64,
         uint8, uint16, uint32, uint64]
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
        start, stop, step = i.indices(0x1337BEEF)
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
        return ExprOp('-', self, a)
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
        
class ExprTop(Expr):
    def __init__(self, e=None):
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
    def reload_expr(self, g = {}):
        return ExprTop(self.e)
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
        return 8*self.arg.nbytes
    def reload_expr(self, g = {}):
        return ExprInt(self.arg)
    def __contains__(self, e):
        return self == e
    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        return self
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
    def reload_expr(self, g = {}):
        if self in g:
            return g[self]
        else:
            return ExprId(self.name, self.size)
        if self in g:
            return g[self]
        return self
    def __contains__(self, e):
        return self == e
    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        return self
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

memreg = ExprId('MEM')



class ExprAff(Expr):
    def __init__(self, dst, src):
        
        #if dst is slice=> replace with id make composed src
        if isinstance(dst, ExprSlice):
            self.dst = dst.arg
            rest = [ExprSliceTo(ExprSlice(dst.arg, *r), *r) for r in slice_rest(dst.arg.size, dst.start, dst.stop)]
            all_a = [(dst.start, ExprSliceTo(src, dst.start, dst.stop))]+ [(x.start, x) for x in rest]
            all_a.sort()
            self.src = ExprCompose([x[1] for x in all_a])
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
    def reload_expr(self, g = {}):
        if self in g:
            return g[self]
        dst = self.dst
        if isinstance(dst, Expr):
            dst = self.dst.reload_expr(g)
        src = self.src
        if isinstance(src, Expr):
            src = self.src.reload_expr(g)
        
        return ExprAff(dst, src )
    def __contains__(self, e):
        return self == e or self.src.__contains__(e) or self.dst.__contains__(e)
    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        dst = self.dst.replace_expr(g)
        src = self.src.replace_expr(g)
        return ExprAff(dst, src)
        
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
            if x.arg.arg != dst or x.start != x.arg.start or x.stop != x.arg.stop:
                modified_s.append(x)

        return modified_s


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
    def reload_expr(self, g = {}):
        src1 = self.src1
        if isinstance(src1, Expr):
            src1 = self.src1.reload_expr(g)
        src2 = self.src2
        if isinstance(src2, Expr):
            src2 = self.src2.reload_expr(g)
        cond = self.cond
        if isinstance(cond, Expr):
            cond = self.cond.reload_expr(g)
        return ExprCond(cond, src1, src2 )
    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        cond = self.cond.replace_expr(g)
        src1 = self.src1.replace_expr(g)
        src2 = self.src2.replace_expr(g)
        return ExprCond(cond, src1, src2 )
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

class ExprMem(Expr):
    def __init__(self, arg, size = 32):
        if not isinstance(arg, Expr): raise 'arg must be expr'
        self.arg, self.size = arg, size
    def __str__(self):
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
    def reload_expr(self, g = {}):
        if self in g:
            return g[self]
        arg = self.arg
        if isinstance(arg, Expr):
            arg = self.arg.reload_expr(g)

        return ExprMem(arg, self.size )
    def __contains__(self, e):
        return self == e or self.arg.__contains__(e)

    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        arg = self.arg.replace_expr(g)
        return ExprMem(arg, self.size )

    def __eq__(self, a):
        if not isinstance(a, ExprMem):
            return False
        return self.arg == a.arg and self.size == a.size
    def __hash__(self):
        return hash(self.arg)^hash(self.size)

    def toC(self):
        return "MEM_LOOKUP_%.2d(%s)"%(self.size, self.arg.toC())


class ExprOp(Expr):
    def __init__(self, op, *args):
        self.op, self.args = op, args
    def __str__(self):
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
    def reload_expr(self, g = {}):
        args = []
        for a in self.args:
            if isinstance(a, Expr):
                args.append(a.reload_expr(g))
            else:
                args.append(a)    
        
        return ExprOp(self.op, *args )
    def __contains__(self, e):
        if self == e:
            return True
        for a in self.args:
            if  a.__contains__(e):
                return True
        return False
    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        args = []
        for a in self.args:
            args.append(a.replace_expr(g))
        return ExprOp(self.op, *args )

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
            elif self.op in ['int_32_to_double', 'int_64_to_double']:
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op == 'double_to_int_32':
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op in ['mem_32_to_double', 'mem_64_to_double']:
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op.startswith("double_to_mem_"):
                return "%s(%s)"%(self.op, self.args[0].toC())
            elif self.op in ["ftan", "frndint", "f2xm1", "fsin", "fsqrt", "fabs", "fcos"]:
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
            elif self.op in ['+', '-', '*', '^', '&', '|']:
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

            elif self.op == 'imul32_lo':
                return 'imul_lo_op_%s(%s, %s)' %(
                            self.args[0].get_size(),
                            self.args[0].toC(),
                            self.args[1].toC())
            elif self.op == 'imul32_hi':
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
    def reload_expr(self, g = {}):
        arg = self.arg.reload_expr(g)

        return ExprSlice(arg, self.start, self.stop )
    def __contains__(self, e):
        if self == e:
            return True
        for a in self.args:
            if  a.__contains__(e):
                return True
        return False

    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        arg = self.arg.replace_expr(g)
        return ExprSlice(arg, self.start, self.stop )

    def __eq__(self, a):
        if not isinstance(a, ExprSlice):
            return False
        return self.arg == a.arg and self.start == a.start and self.stop == a.stop

    def __hash__(self):
        return hash(self.arg)^hash(self.start)^hash(self.stop)

    def toC(self):
        # XXX gen mask in python for 64 bit & 32 bit compat
        return "((%s>>%d) & ((0xFFFFFFFF>>(32-%d))))"%(self.arg.toC(), self.start, self.stop-self.start)


class ExprSliceTo(Expr):
    def __init__(self, arg, start, stop):
        self.arg, self.start, self.stop = arg, start, stop
    def __str__(self):
        return "%s_to[%d:%d]"%(str(self.arg), self.start, self.stop)
    def get_r(self, mem_read=False):
        return self.arg.get_r(mem_read)
    def get_w(self):
        return self.arg.get_w()
    def get_size(self):
        return self.stop-self.start
    def reload_expr(self, g = {}):
        if isinstance(self.arg, Expr):
            arg = self.arg.reload_expr(g)
        else:
            arg = self.arg

        return ExprSliceTo(arg, self.start, self.stop )
    def __contains__(self, e):
        return self == e or self.arg.__contains__(e)

    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        arg = self.arg.replace_expr(g)
        return ExprSliceTo(arg, self.start, self.stop)

    def __eq__(self, a):
        if not isinstance(a, ExprSliceTo):
            return False
        return self.arg == a.arg and self.start == a.start and self.stop == a.stop
    def __hash__(self):
        return hash(self.arg)^hash(self.start)^hash(self.stop)

    def toC(self):
        # XXX gen mask in python for 64 bit & 32 bit compat
        return "((%s & (0xFFFFFFFF>>(32-%d))) << %d)"%(self.arg.toC(), self.stop-self.start, self.start)

class ExprCompose(Expr):
    def __init__(self, args):
        self.args = args
    def __str__(self):
        return '('+', '.join([str(x) for x in self.args])+')'
    def get_r(self, mem_read=False):
        return reduce(lambda x,y:x.union(y.get_r(mem_read)), self.args, set())
    def get_w(self):
        return reduce(lambda x,y:x.union(y.get_r(mem_read)), self.args, set())
    def get_size(self):
        return max([x.stop for x in self.args]) - min([x.start for x in self.args])
    def reload_expr(self, g = {}):
        args = []
        for a in self.args:
            if isinstance(a, Expr):
                args.append(a.reload_expr(g))
            else:
                args.append(a)

        return ExprCompose(args )
    def __contains__(self, e):
        if self == e:
            return True
        for a in self.args:
            if  a.__contains__(e):
                return True
        return False

    def replace_expr(self, g = {}):
        if self in g:
            return g[self]
        args = []
        for a in self.args:
            args.append(a.replace_expr(g))
        return ExprCompose(args )

    def __eq__(self, a):
        if not isinstance(a, ExprCompose):
            return False
        if not len(self.args) == len(a.args):
            return False
        for i, x in enumerate(self.args):
            if not x == a.args[i]:
                return False
        return True
    def __hash__(self):
        h = 0
        for a in self.args:
            h^=hash(a)
        return h

    def toC(self):
        out = ' | '.join([x.toC() for x in self.args])
        return '('+out+')'
        
                       
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
