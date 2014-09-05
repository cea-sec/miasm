from miasm2.expression.expression import *
from miasm2.expression.simplifications import expr_simp
from miasm2.core import asmbloc
import logging


log = logging.getLogger("symbexec")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)


class symbols():

    def __init__(self, init=None):
        if init is None:
            init = {}
        self.symbols_id = {}
        self.symbols_mem = {}
        for k, v in init.items():
            self[k] = v

    def __contains__(self, a):
        if not isinstance(a, ExprMem):
            return self.symbols_id.__contains__(a)
        if not self.symbols_mem.__contains__(a.arg):
            return False
        return self.symbols_mem[a.arg][0].size == a.size

    def __getitem__(self, a):
        if not isinstance(a, ExprMem):
            return self.symbols_id.__getitem__(a)
        if not a.arg in self.symbols_mem:
            raise KeyError, a
        m = self.symbols_mem.__getitem__(a.arg)
        if m[0].size != a.size:
            raise KeyError, a
        return m[1]

    def __setitem__(self, a, v):
        if not isinstance(a, ExprMem):
            self.symbols_id.__setitem__(a, v)
            return
        self.symbols_mem.__setitem__(a.arg, (a, v))

    def __iter__(self):
        for a in self.symbols_id:
            yield a
        for a in self.symbols_mem:
            yield self.symbols_mem[a][0]

    def __delitem__(self, a):
        if not isinstance(a, ExprMem):
            self.symbols_id.__delitem__(a)
        else:
            self.symbols_mem.__delitem__(a.arg)

    def items(self):
        k = self.symbols_id.items() + [x for x in self.symbols_mem.values()]
        return k

    def keys(self):
        k = self.symbols_id.keys() + [x[0] for x in self.symbols_mem.values()]
        return k

    def copy(self):
        p = symbols()
        p.symbols_id = dict(self.symbols_id)
        p.symbols_mem = dict(self.symbols_mem)
        return p

    def inject_info(self, info):
        s = symbols()
        for k, v in self.items():
            k = expr_simp(k.replace_expr(info))
            v = expr_simp(v.replace_expr(info))
            s[k] = v
        return s


class symbexec:

    def __init__(self, ir_arch, known_symbols,
                 func_read=None,
                 func_write=None,
                 sb_expr_simp=expr_simp):
        self.symbols = symbols()
        for k, v in known_symbols.items():
            self.symbols[k] = v
        self.func_read = func_read
        self.func_write = func_write
        self.ir_arch = ir_arch
        self.expr_simp = sb_expr_simp

    def find_mem_by_addr(self, e):
        if e in self.symbols.symbols_mem:
            return self.symbols.symbols_mem[e][0]
        return None

    def eval_ExprId(self, e, eval_cache=None):
        if isinstance(e.name, asmbloc.asm_label) and e.name.offset is not None:
            return ExprInt_from(e, e.name.offset)
        if not e in self.symbols:
            # raise ValueError('unknown symbol %s'% e)
            return e
        return self.symbols[e]

    def eval_ExprInt(self, e, eval_cache=None):
        return e

    def eval_ExprMem(self, e, eval_cache=None):
        a_val = self.expr_simp(self.eval_expr(e.arg, eval_cache))
        if a_val != e.arg:
            a = self.expr_simp(ExprMem(a_val, size=e.size))
        else:
            a = e
        if a in self.symbols:
            return self.symbols[a]
        tmp = None
        # test if mem lookup is known
        if a_val in self.symbols.symbols_mem:
            tmp = self.symbols.symbols_mem[a_val][0]
        if tmp is None:

            v = self.find_mem_by_addr(a_val)
            if not v:
                out = []
                ov = self.get_mem_overlapping(a, eval_cache)
                off_base = 0
                ov.sort()
                # ov.reverse()
                for off, x in ov:
                    # off_base = off * 8
                    # x_size = self.symbols[x].size
                    if off >= 0:
                        m = min(a.size - off * 8, x.size)
                        ee = ExprSlice(self.symbols[x], 0, m)
                        ee = self.expr_simp(ee)
                        out.append((ee, off_base, off_base + m))
                        off_base += m
                    else:
                        m = min(a.size - off * 8, x.size)
                        ee = ExprSlice(self.symbols[x], -off * 8, m)
                        ff = self.expr_simp(ee)
                        new_off_base = off_base + m + off * 8
                        out.append((ff, off_base, new_off_base))
                        off_base = new_off_base
                if out:
                    missing_slice = self.rest_slice(out, 0, a.size)
                    for sa, sb in missing_slice:
                        ptr = self.expr_simp(a_val + ExprInt32(sa / 8))
                        mm = ExprMem(ptr, size=sb - sa)
                        mm.is_term = True
                        mm.is_simp = True
                        out.append((mm, sa, sb))
                    out.sort(key=lambda x: x[1])
                    # for e, sa, sb in out:
                    #    print str(e), sa, sb
                    ee = ExprSlice(ExprCompose(out), 0, a.size)
                    ee = self.expr_simp(ee)
                    return ee
            if self.func_read and isinstance(a.arg, ExprInt):
                return self.func_read(a)
            else:
                # XXX hack test
                a.is_term = True
                return a
        # bigger lookup
        if a.size > tmp.size:
            rest = a.size
            ptr = a_val
            out = []
            ptr_index = 0
            while rest:
                v = self.find_mem_by_addr(ptr)
                if v is None:
                    # raise ValueError("cannot find %s in mem"%str(ptr))
                    val = ExprMem(ptr, 8)
                    v = val
                    diff_size = 8
                elif rest >= v.size:
                    val = self.symbols[v]
                    diff_size = v.size
                else:
                    diff_size = rest
                    val = self.symbols[v][0:diff_size]
                val = (val, ptr_index, ptr_index + diff_size)
                out.append(val)
                ptr_index += diff_size
                rest -= diff_size
                ptr = self.expr_simp(self.eval_expr(ExprOp('+', ptr,
                    ExprInt_from(ptr, v.size / 8)), eval_cache))
            e = self.expr_simp(ExprCompose(out))
            return e
        # part lookup
        tmp = self.expr_simp(ExprSlice(self.symbols[tmp], 0, a.size))
        return tmp

    def eval_expr_visit(self, e, eval_cache=None):
        # print 'visit', e, e.is_term
        if e.is_term:
            return e
        c = e.__class__
        deal_class = {ExprId: self.eval_ExprId,
                      ExprInt: self.eval_ExprInt,
                      ExprMem: self.eval_ExprMem,
                      }
        # print 'eval', e
        if c in deal_class:
            e = deal_class[c](e, eval_cache)
        # print "ret", e
        if not (isinstance(e, ExprId) or isinstance(e, ExprInt)):
            e.is_term = True
        return e

    def eval_expr(self, e, eval_cache=None):
        r = e.visit(lambda x: self.eval_expr_visit(x, eval_cache))
        return r

    def modified_regs(self, init_state=None):
        if init_state is None:
            init_state = self.ir_arch.arch.regs.regs_init
        ids = self.symbols.symbols_id.keys()
        ids.sort()
        for i in ids:
            if i in init_state and \
                    i in self.symbols.symbols_id and \
                    self.symbols.symbols_id[i] == init_state[i]:
                continue
            yield i

    def modified_mems(self, init_state=None):
        mems = self.symbols.symbols_mem.values()
        mems.sort()
        for m, _ in mems:
            yield m

    def modified(self, init_state=None):
        for r in self.modified_regs(init_state):
            yield r
        for m in self.modified_mems(init_state):
            yield m

    def dump_id(self):
        ids = self.symbols.symbols_id.keys()
        ids.sort()
        for i in ids:
            if i in self.ir_arch.arch.regs.regs_init and \
                    i in self.symbols.symbols_id and \
                    self.symbols.symbols_id[i] == self.ir_arch.arch.regs.regs_init[i]:
                continue
            print i, self.symbols.symbols_id[i]

    def dump_mem(self):
        mems = self.symbols.symbols_mem.values()
        mems.sort()
        for m, v in mems:
            print m, v

    def rest_slice(self, slices, start, stop):
        o = []
        last = start
        for _, a, b in slices:
            if a == last:
                last = b
                continue
            o.append((last, a))
            last = b
        if last != stop:
            o.append((b, stop))
        return o

    def substract_mems(self, a, b):
        ex = ExprOp('-', b.arg, a.arg)
        ex = self.expr_simp(self.eval_expr(ex, {}))
        if not isinstance(ex, ExprInt):
            return None
        ptr_diff = int(int32(ex.arg))
        out = []
        if ptr_diff < 0:
            #    [a     ]
            #[b      ]XXX
            sub_size = b.size + ptr_diff * 8
            if sub_size >= a.size:
                pass
            else:
                ex = ExprOp('+', a.arg, ExprInt_from(a.arg, sub_size / 8))
                ex = self.expr_simp(self.eval_expr(ex, {}))

                rest_ptr = ex
                rest_size = a.size - sub_size

                val = self.symbols[a][sub_size:a.size]
                out = [(ExprMem(rest_ptr, rest_size), val)]
        else:
            #[a         ]
            # XXXX[b   ]YY

            #[a     ]
            # XXXX[b     ]

            out = []
            # part X
            if ptr_diff > 0:
                val = self.symbols[a][0:ptr_diff * 8]
                out.append((ExprMem(a.arg, ptr_diff * 8), val))
            # part Y
            if ptr_diff * 8 + b.size < a.size:

                ex = ExprOp('+', b.arg, ExprInt_from(b.arg, b.size / 8))
                ex = self.expr_simp(self.eval_expr(ex, {}))

                rest_ptr = ex
                rest_size = a.size - (ptr_diff * 8 + b.size)
                val = self.symbols[a][ptr_diff * 8 + b.size:a.size]
                out.append((ExprMem(ex, val.size), val))
        return out

    # give mem stored overlapping requested mem ptr
    def get_mem_overlapping(self, e, eval_cache=None):
        if not isinstance(e, ExprMem):
            raise ValueError('mem overlap bad arg')
        ov = []
        # suppose max mem size is 64 bytes, compute all reachable addresses
        to_test = []
        base_ptr = self.expr_simp(e.arg)
        for i in xrange(-7, e.size / 8):
            ex = self.expr_simp(
                self.eval_expr(base_ptr + ExprInt_from(e.arg, i), eval_cache))
            to_test.append((i, ex))

        for i, x in to_test:
            if not x in self.symbols.symbols_mem:
                continue
            ex = self.expr_simp(self.eval_expr(e.arg - x, eval_cache))
            if not isinstance(ex, ExprInt):
                raise ValueError('ex is not ExprInt')
            ptr_diff = int32(ex.arg)
            if ptr_diff >= self.symbols.symbols_mem[x][1].size / 8:
                # print "too long!"
                continue
            ov.append((i, self.symbols.symbols_mem[x][0]))
        return ov

    def eval_ir_expr(self, exprs):
        pool_out = {}

        eval_cache = {}

        for e in exprs:
            if not isinstance(e, ExprAff):
                raise TypeError('not affect', str(e))

            src = self.eval_expr(e.src, eval_cache)
            if isinstance(e.dst, ExprMem):
                a = self.eval_expr(e.dst.arg, eval_cache)
                a = self.expr_simp(a)
                # search already present mem
                tmp = None
                # test if mem lookup is known
                tmp = ExprMem(a, e.dst.size)
                dst = tmp
                if self.func_write and isinstance(dst.arg, ExprInt):
                    self.func_write(self, dst, src, pool_out)
                else:
                    pool_out[dst] = src

            elif isinstance(e.dst, ExprId):
                pool_out[e.dst] = src
            else:
                raise ValueError("affected zarb", str(e.dst))

        return pool_out.items()

    def eval_ir(self, ir):
        mem_dst = []
        # src_dst = [(x.src, x.dst) for x in ir]
        src_dst = self.eval_ir_expr(ir)

        for dst, src in src_dst:
            if isinstance(dst, ExprMem):
                mem_overlap = self.get_mem_overlapping(dst)
                for _, base in mem_overlap:
                    diff_mem = self.substract_mems(base, dst)
                    del(self.symbols[base])
                    for new_mem, new_val in diff_mem:
                        new_val.is_term = True
                        self.symbols[new_mem] = new_val
            src_o = self.expr_simp(src)
            # print 'SRCo', src_o
            # src_o.is_term = True
            self.symbols[dst] = src_o
            if isinstance(dst, ExprMem):
                mem_dst.append(dst)
        return mem_dst

    def emulbloc(self, bloc_ir, step=False):
        for ir in bloc_ir.irs:
            self.eval_ir(ir)
            if step:
                print '_' * 80
                self.dump_id()
        return self.eval_expr(self.ir_arch.IRDst)

    def emul_ir_bloc(self, myir, ad, step = False):
        b = myir.get_bloc(ad)
        if b is not None:
            ad = self.emulbloc(b, step = step)
        return ad

    def emul_ir_blocs(self, myir, ad, lbl_stop=None, step = False):
        while True:
            b = myir.get_bloc(ad)
            if b is None:
                break
            if b.label == lbl_stop:
                break
            ad = self.emulbloc(b, step = step)
        return ad

    def del_mem_above_stack(self, sp):
        sp_val = self.symbols[sp]
        for mem_ad, (mem, _) in self.symbols.symbols_mem.items():
            # print mem_ad, sp_val
            diff = self.eval_expr(mem_ad - sp_val, {})
            diff = expr_simp(diff)
            if not isinstance(diff, ExprInt):
                continue
            m = expr_simp(diff.msb())
            if m.arg == 1:
                del(self.symbols[mem])

