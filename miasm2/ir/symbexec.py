import warnings
import logging

import miasm2.expression.expression as m2_expr
from miasm2.expression.modint import int32
from miasm2.expression.simplifications import expr_simp
from miasm2.core import asmblock
from miasm2.ir.ir import AssignBlock
from miasm2.core.interval import interval


log = logging.getLogger("symbexec")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)


class SymbolMngr(object):
    """
    Store registers and memory symbolic values
    """

    def __init__(self, init=None):
        if init is None:
            init = {}
        self.symbols_id = {}
        self.symbols_mem = {}
        for expr, value in init.items():
            self[expr] = value

    def __contains__(self, expr):
        if not isinstance(expr, m2_expr.ExprMem):
            return self.symbols_id.__contains__(expr)
        if not self.symbols_mem.__contains__(expr.arg):
            return False
        return self.symbols_mem[expr.arg][0].size == expr.size

    def __getitem__(self, expr):
        if not isinstance(expr, m2_expr.ExprMem):
            return self.symbols_id.__getitem__(expr)
        if not expr.arg in self.symbols_mem:
            raise KeyError(expr)
        mem, value = self.symbols_mem.__getitem__(expr.arg)
        if mem.size != expr.size:
            raise KeyError(expr)
        return value

    def get(self, expr, default=None):
        if not isinstance(expr, m2_expr.ExprMem):
            return self.symbols_id.get(expr, default)
        if not expr.arg in self.symbols_mem:
            return default
        mem, value = self.symbols_mem.__getitem__(expr.arg)
        if mem.size != expr.size:
            return default
        return value

    def __setitem__(self, expr, value):
        if not isinstance(expr, m2_expr.ExprMem):
            self.symbols_id.__setitem__(expr, value)
            return
        assert expr.size == value.size
        self.symbols_mem.__setitem__(expr.arg, (expr, value))

    def __iter__(self):
        for expr in self.symbols_id:
            yield expr
        for expr in self.symbols_mem:
            yield self.symbols_mem[expr][0]

    def __delitem__(self, expr):
        if not isinstance(expr, m2_expr.ExprMem):
            self.symbols_id.__delitem__(expr)
        else:
            self.symbols_mem.__delitem__(expr.arg)

    def items(self):
        return self.symbols_id.items() + [x for x in self.symbols_mem.values()]

    def keys(self):
        return (self.symbols_id.keys() +
                [x[0] for x in self.symbols_mem.values()])

    def copy(self):
        new_symbols = SymbolMngr()
        new_symbols.symbols_id = dict(self.symbols_id)
        new_symbols.symbols_mem = dict(self.symbols_mem)
        return new_symbols

    def inject_info(self, info):
        new_symbols = SymbolMngr()
        for expr, value in self.items():
            expr = expr_simp(expr.replace_expr(info))
            value = expr_simp(value.replace_expr(info))
            new_symbols[expr] = value
        return new_symbols


class SymbolicExecutionEngine(object):
    """
    Symbolic execution engine
    Allow IR code emulation in symbolic domain
    """

    def __init__(self, ir_arch, known_symbols,
                 func_read=None,
                 func_write=None,
                 sb_expr_simp=expr_simp):
        self.symbols = SymbolMngr()
        for expr, value in known_symbols.items():
            self.symbols[expr] = value
        self.func_read = func_read
        self.func_write = func_write
        self.ir_arch = ir_arch
        self.expr_simp = sb_expr_simp

    def find_mem_by_addr(self, expr):
        """
        Return memory keys with pointer equal to @expr
        @expr: address of the searched memory variable
        """
        if expr in self.symbols.symbols_mem:
            return self.symbols.symbols_mem[expr][0]
        return None

    def get_mem_state(self, expr):
        """
        Evaluate the @expr memory in the current state using @cache
        @expr: the memory key
        """
        ptr, size = expr.arg, expr.size
        ret = self.find_mem_by_addr(ptr)
        if not ret:
            overlaps = self.get_mem_overlapping(expr)
            if not overlaps:
                if self.func_read and ptr.is_int():
                    expr = self.func_read(expr)
                return expr

            out = []
            off_base = 0
            for off, mem in overlaps:
                if off >= 0:
                    new_size = min(size - off * 8, mem.size)
                    tmp = self.expr_simp(self.symbols[mem][0:new_size])
                    out.append((tmp, off_base, off_base + new_size))
                    off_base += new_size
                else:
                    new_size = min(size - off * 8, mem.size)
                    tmp = self.expr_simp(self.symbols[mem][-off * 8:new_size])
                    new_off_base = off_base + new_size + off * 8
                    out.append((tmp, off_base, new_off_base))
                    off_base = new_off_base

            missing_slice = self.rest_slice(out, 0, size)
            for slice_start, slice_stop in missing_slice:
                ptr = self.expr_simp(ptr + m2_expr.ExprInt(slice_start / 8, ptr.size))
                mem = m2_expr.ExprMem(ptr, slice_stop - slice_start)
                if self.func_read and ptr.is_int():
                    mem = self.func_read(mem)
                out.append((mem, slice_start, slice_stop))
            out.sort(key=lambda x: x[1])
            args = [expr for (expr, _, _) in out]
            ret = self.expr_simp(m2_expr.ExprCompose(*args)[:size])
            return ret

        # bigger lookup
        if size > ret.size:
            rest = size
            out = []
            while rest:
                mem = self.find_mem_by_addr(ptr)
                if mem is None:
                    mem = m2_expr.ExprMem(ptr, 8)
                    if self.func_read and ptr.is_int():
                        value = self.func_read(mem)
                    else:
                        value = mem
                elif rest >= mem.size:
                    value = self.symbols[mem]
                else:
                    value = self.symbols[mem][:rest]
                out.append(value)
                rest -= value.size
                ptr = self.expr_simp(ptr + m2_expr.ExprInt(mem.size / 8, ptr.size))
            ret = self.expr_simp(m2_expr.ExprCompose(*out))
            return ret
        # part lookup
        ret = self.expr_simp(self.symbols[ret][:size])
        return ret


    def apply_expr_on_state_visit_cache(self, expr, state, cache, level=0):
        """
        Deep First evaluate nodes:
            1. evaluate node's sons
            2. simplify
        """

        #print '\t'*level, "Eval:", expr
        if expr in cache:
            ret = cache[expr]
            #print "In cache!", ret
        elif isinstance(expr, m2_expr.ExprInt):
            return expr
        elif isinstance(expr, m2_expr.ExprId):
            if isinstance(expr.name, asmblock.AsmLabel) and expr.name.offset is not None:
                ret = m2_expr.ExprInt(expr.name.offset, expr.size)
            else:
                ret = state.get(expr, expr)
        elif isinstance(expr, m2_expr.ExprMem):
            ptr = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
            ret = m2_expr.ExprMem(ptr, expr.size)
            ret = self.get_mem_state(ret)
            assert expr.size == ret.size
        elif isinstance(expr, m2_expr.ExprCond):
            cond = self.apply_expr_on_state_visit_cache(expr.cond, state, cache, level+1)
            src1 = self.apply_expr_on_state_visit_cache(expr.src1, state, cache, level+1)
            src2 = self.apply_expr_on_state_visit_cache(expr.src2, state, cache, level+1)
            ret = m2_expr.ExprCond(cond, src1, src2)
        elif isinstance(expr, m2_expr.ExprSlice):
            arg = self.apply_expr_on_state_visit_cache(expr.arg, state, cache, level+1)
            ret = m2_expr.ExprSlice(arg, expr.start, expr.stop)
        elif isinstance(expr, m2_expr.ExprOp):
            args = []
            for oarg in expr.args:
                arg = self.apply_expr_on_state_visit_cache(oarg, state, cache, level+1)
                assert oarg.size == arg.size
                args.append(arg)
            ret = m2_expr.ExprOp(expr.op, *args)
        elif isinstance(expr, m2_expr.ExprCompose):
            args = []
            for arg in expr.args:
                args.append(self.apply_expr_on_state_visit_cache(arg, state, cache, level+1))
            ret = m2_expr.ExprCompose(*args)
        else:
            raise TypeError("Unknown expr type")
        #print '\t'*level, "Result", ret
        ret = self.expr_simp(ret)
        #print '\t'*level, "Result simpl", ret

        assert expr.size == ret.size
        cache[expr] = ret
        return ret

    def apply_expr_on_state(self, expr, cache):
        if cache is None:
            cache = {}
        ret = self.apply_expr_on_state_visit_cache(expr, self.symbols, cache)
        return ret

    def eval_expr(self, expr, eval_cache=None):
        return self.apply_expr_on_state(expr, eval_cache)

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
        if init_state is None:
            init_state = self.ir_arch.arch.regs.regs_init
        mems = self.symbols.symbols_mem.values()
        mems.sort()
        for mem, _ in mems:
            if mem in init_state and \
                    mem in self.symbols.symbols_mem and \
                    self.symbols.symbols_mem[mem] == init_state[mem]:
                continue
            yield mem

    def modified(self, init_state=None):
        for reg in self.modified_regs(init_state):
            yield reg
        for mem in self.modified_mems(init_state):
            yield mem

    def dump_id(self):
        """
        Dump modififed registers symbols only
        """
        ids = self.symbols.symbols_id.keys()
        ids.sort()
        for expr in ids:
            if (expr in self.ir_arch.arch.regs.regs_init and
                expr in self.symbols.symbols_id and
                self.symbols.symbols_id[expr] == self.ir_arch.arch.regs.regs_init[expr]):
                continue
            print expr, "=", self.symbols.symbols_id[expr]

    def dump_mem(self):
        """
        Dump modififed memory symbols
        """
        mems = self.symbols.symbols_mem.values()
        mems.sort()
        for mem, value in mems:
            print mem, value

    def rest_slice(self, slices, start, stop):
        """
        Return the complementary slices of @slices in the range @start, @stop
        @slices: base slices
        @start, @stop: interval range
        """
        out = []
        last = start
        for _, slice_start, slice_stop in slices:
            if slice_start == last:
                last = slice_stop
                continue
            out.append((last, slice_start))
            last = slice_stop
        if last != stop:
            out.append((slice_stop, stop))
        return out

    def substract_mems(self, arg1, arg2):
        """
        Return the remaining memory areas of @arg1 - @arg2
        @arg1, @arg2: ExprMem
        """

        ptr_diff = self.expr_simp(arg2.arg - arg1.arg)
        ptr_diff = int(int32(ptr_diff.arg))

        zone1 = interval([(0, arg1.size/8-1)])
        zone2 = interval([(ptr_diff, ptr_diff + arg2.size/8-1)])
        zones = zone1 - zone2

        out = []
        for start, stop in zones:
            ptr = arg1.arg + m2_expr.ExprInt(start, arg1.arg.size)
            ptr = self.expr_simp(ptr)
            value = self.expr_simp(self.symbols[arg1][start*8:(stop+1)*8])
            mem = m2_expr.ExprMem(ptr, (stop - start + 1)*8)
            assert mem.size == value.size
            out.append((mem, value))

        return out

    def get_mem_overlapping(self, expr):
        """
        Gives mem stored overlapping memory in @expr
        Hypothesis: Max mem size is 64 bytes, compute all reachable addresses
        @expr: target memory
        """

        overlaps = []
        base_ptr = self.expr_simp(expr.arg)
        for i in xrange(-7, expr.size / 8):
            new_ptr = base_ptr + m2_expr.ExprInt(i, expr.arg.size)
            new_ptr = self.expr_simp(new_ptr)

            mem, origin = self.symbols.symbols_mem.get(new_ptr, (None, None))
            if mem is None:
                continue

            ptr_diff = -i
            if ptr_diff >= origin.size / 8:
                # access is too small to overlap the memory target
                continue
            overlaps.append((i, mem))

        return overlaps

    def eval_ir_expr(self, assignblk):
        """
        Evaluate AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        pool_out = {}
        eval_cache = {}
        for dst, src in assignblk.iteritems():
            src = self.eval_expr(src, eval_cache)
            if isinstance(dst, m2_expr.ExprMem):
                ptr = self.eval_expr(dst.arg, eval_cache)
                # test if mem lookup is known
                tmp = m2_expr.ExprMem(ptr, dst.size)
                pool_out[tmp] = src

            elif isinstance(dst, m2_expr.ExprId):
                pool_out[dst] = src
            else:
                raise ValueError("affected zarb", str(dst))

        return pool_out.iteritems()

    def apply_change(self, dst, src):
        """
        Apply @dst = @src on the current state WITHOUT evaluating both side
        @dst: Expr, destination
        @src: Expr, source
        """
        if isinstance(dst, m2_expr.ExprMem):
            mem_overlap = self.get_mem_overlapping(dst)
            for _, base in mem_overlap:
                diff_mem = self.substract_mems(base, dst)
                del self.symbols[base]
                for new_mem, new_val in diff_mem:
                    self.symbols[new_mem] = new_val
        src_o = self.expr_simp(src)

        # Force update. Ex:
        # EBX += 1 (state: EBX = EBX+1)
        # EBX -= 1 (state: EBX = EBX, must be updated)
        self.symbols[dst] = src_o
        if dst == src_o:
            # Avoid useless X = X information
            del self.symbols[dst]
        if isinstance(dst, m2_expr.ExprMem):
            if self.func_write and isinstance(dst.arg, m2_expr.ExprInt):
                self.func_write(self, dst, src_o)
                del self.symbols[dst]

    def eval_ir(self, assignblk):
        """
        Apply an AssignBlock on the current state
        @assignblk: AssignBlock instance
        """
        mem_dst = []
        src_dst = self.eval_ir_expr(assignblk)
        for dst, src in src_dst:
            self.apply_change(dst, src)
            if isinstance(dst, m2_expr.ExprMem):
                mem_dst.append(dst)
        return mem_dst

    def emulbloc(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: irbloc instance
        @step: display intermediate steps
        """
        for assignblk in irb.irs:
            if step:
                print 'Assignblk:'
                print assignblk
                print '_' * 80
            self.eval_ir(assignblk)
            if step:
                self.dump_id()
                self.dump_mem()
                print '_' * 80
        return self.eval_expr(self.ir_arch.IRDst)

    def emul_ir_bloc(self, _, addr, step=False):
        warnings.warn('DEPRECATION WARNING: use "emul_ir_block(self, addr, step=False)" instead of emul_ir_bloc')
        return self.emul_ir_block(addr, step)

    def emul_ir_block(self, addr, step=False):
        irblock = self.ir_arch.get_bloc(addr)
        if irblock is not None:
            addr = self.emulbloc(irblock, step=step)
        return addr

    def emul_ir_blocs(self, _, addr, lbl_stop=None, step=False):
        warnings.warn('DEPRECATION WARNING: use "emul_ir_blocks(self, addr, lbl_stop=None, step=False):" instead of emul_ir_blocs')
        return self.emul_ir_blocks(addr, lbl_stop, step)

    def emul_ir_blocks(self, addr, lbl_stop=None, step=False):
        while True:
            irblock = self.ir_arch.get_bloc(addr)
            if irblock is None:
                break
            if irblock.label == lbl_stop:
                break
            addr = self.emulbloc(irblock, step=step)
        return addr

    def del_mem_above_stack(self, stack_ptr):
        """
        Remove all stored memory values with following properties:
        * pointer based on initial stack value
        * pointer below current stack pointer
        """
        stack_ptr = self.eval_expr(stack_ptr)
        for mem_addr, (mem, _) in self.symbols.symbols_mem.items():
            diff = self.expr_simp(mem_addr - stack_ptr)
            if not isinstance(diff, m2_expr.ExprInt):
                continue
            sign_bit = self.expr_simp(diff.msb())
            if sign_bit.arg == 1:
                del self.symbols[mem]

    def apply_expr(self, expr):
        """Evaluate @expr and apply side effect if needed (ie. if expr is an
        assignment). Return the evaluated value"""

        # Update value if needed
        if isinstance(expr, m2_expr.ExprAff):
            ret = self.eval_expr(expr.src)
            self.eval_ir(AssignBlock([expr]))
        else:
            ret = self.eval_expr(expr)

        return ret

class symbexec(SymbolicExecutionEngine):
    """
    DEPRECATED object
    Use SymbolicExecutionEngine instead of symbexec
    """

    def __init__(self, ir_arch, known_symbols,
                 func_read=None,
                 func_write=None,
                 sb_expr_simp=expr_simp):
        warnings.warn("Deprecated API: use SymbolicExecutionEngine")
        super(symbexec, self).__init__(ir_arch, known_symbols,
                                       func_read,
                                       func_write,
                                       sb_expr_simp=expr_simp)
