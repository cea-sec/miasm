#!/usr/bin/env python
#-*- coding:utf-8 -*-

from miasm2.ir.symbexec import symbexec
from miasm2.core.graph import DiGraph
from miasm2.expression.expression import *


class ira:

    def sort_dst(self, todo, done):
        out = set()
        while todo:
            dst = todo.pop()
            if self.ExprIsLabel(dst):
                done.add(dst)
            elif isinstance(dst, ExprMem) or isinstance(dst, ExprInt):
                done.add(dst)
            elif isinstance(dst, ExprCond):
                todo.add(dst.src1)
                todo.add(dst.src2)
            elif isinstance(dst, ExprId):
                out.add(dst)
            else:
                done.add(dst)
        return out

    def dst_trackback(self, b):
        dst = b.dst
        todo = set([dst])
        out = set()
        done = set()

        for irs in reversed(b.irs):
            if len(todo) == 0:
                break
            out = self.sort_dst(todo, done)
            found = set()
            follow = set()
            for i in irs:
                if not out:
                    break
                for o in out:
                    if i.dst == o:
                        follow.add(i.src)
                        found.add(o)
                for o in found:
                    out.remove(o)

            for o in out:
                if not o in found:
                    follow.add(o)
            todo = follow
        out = self.sort_dst(todo, done)

        return done

    def gen_graph(self, link_all = False):
        """
        Gen irbloc digraph
        @link_all: also gen edges to non present irblocs
        """
        self.g = DiGraph()
        for lbl, b in self.blocs.items():
            # print 'add', lbl
            self.g.add_node(lbl)
            # dst = self.get_bloc_dst(b)
            dst = self.dst_trackback(b)
            # print "\tdst", dst
            for d in dst:
                if isinstance(d, ExprInt):
                    d = ExprId(
                        self.symbol_pool.getby_offset_create(int(d.arg)))
                if self.ExprIsLabel(d):
                    if d.name in self.blocs or link_all is True:
                        self.g.add_edge(lbl, d.name)

    def graph(self):
        out = """
    digraph asm_graph {
    size="80,50";
    node [
    fontsize = "16",
    shape = "box"
    ];
    """
        all_lbls = {}
        for lbl in self.g.nodes():
            if not lbl in self.blocs:
                continue
            b = self.blocs[lbl]
            ir_txt = [str(lbl)]
            for irs in b.irs:
                for l in irs:
                    ir_txt.append(str(l))
                ir_txt.append("")
            ir_txt.append("DstBloc: %s" % str(b.dst))
            ir_txt.append("")
            all_lbls[id(lbl)] = "\l\\\n".join(ir_txt)
        for l, v in all_lbls.items():
            out += '%s [label="%s"];\n' % (l, v)

        for a, b in self.g.edges():
            out += '%s -> %s;\n' % (id(a), id(b))
        out += '}'
        return out

    def remove_dead(self, b):
        for ir, _, c_out in zip(b.irs, b.c_in, b.c_out):
            j = 0
            while j < len(ir):
                i_cur = ir[j]
                if not isinstance(i_cur.dst, ExprId):
                    pass
                elif (isinstance(i_cur.src, ExprOp) and
                    i_cur.src.op.startswith('call')):
                    # /!\ never remove ir calls
                    pass
                elif not i_cur.dst in c_out:
                    del(ir[j])
                    continue
                j += 1

    def remove_blocs_dead(self):
        for b in self.blocs.values():
            self.remove_dead(b)

    # for test XXX TODO
    def set_dead_regs(self, b):
        pass

    def add_unused_regs(self):
        pass

    def compute_in_out(self, b):
        # get out/in from bloc sons
        modified = False
        # set b in
        if b.c_in[-1] != set(b.r[-1].union(b.c_out[-1].difference(b.w[-1]))):
            modified = True
        b.c_in[-1] = set(b.r[-1].union(b.c_out[-1].difference(b.w[-1])))

        # set b out
        c_out = set()
        has_son = False
        for n_son in self.g.successors(b.label):
            # print n_me, n_son
            has_son = True
            if not n_son in self.blocs:
                print "leaf has lost her sons!"
                continue
            b_son = self.blocs[n_son]
            c_out.update(b_son.c_in[0])
        if not has_son:
            # special case: leaf nodes architecture dependant
            c_out = self.get_out_regs(b)
        if b.c_out[-1] != set(c_out):
            modified = True
        b.c_out[-1] = set(c_out)

        # get out/in for bloc
        for i in reversed(xrange(len(b.irs))):
            if b.c_in[i] != set(b.r[i].union(b.c_out[i].difference(b.w[i]))):
                modified = True
            b.c_in[i] = set(b.r[i].union(b.c_out[i].difference(b.w[i])))
            if b.c_out[i] != set(b.c_in[i + 1]):
                modified = True
            b.c_out[i] = set(b.c_in[i + 1])
        return modified

    def test_in_out_fix(self):
        fixed = True
        for n in self.g.nodes():
            if not n in self.blocs:
                # leaf has lost her son
                continue
            b = self.blocs[n]
            if b.c_in != b.l_in or b.c_out != b.l_out:
                fixed = False
            b.l_in = [set(x) for x in b.c_in]
            b.l_out = [set(x) for x in b.c_out]
        return fixed

    def compute_dead(self):
        self.get_rw()

        it = 0
        fixed_point = False
        print 'iteration...',
        while not fixed_point:
            print it,
            it += 1
            for n in self.g.nodes():
                if not n in self.blocs:
                    # leaf has lost her son
                    continue
                b = self.blocs[n]
                self.compute_in_out(b)

            fixed_point = self.test_in_out_fix()
        print

    def dead_simp(self):
        self.compute_dead()
        self.remove_blocs_dead()
        self.simplify_blocs()

    def gen_equations(self):
        for irb in self.blocs.values():
            symbols_init = {}
            for r in self.arch.regs.all_regs_ids:
                x = ExprId(r.name, r.size)
                x.is_term = True
                symbols_init[r] = x
            sb = symbexec(self.arch, dict(symbols_init))
            sb.emulbloc(irb)
            eqs = []
            for n_w in sb.symbols:
                v = sb.symbols[n_w]
                if n_w in symbols_init and symbols_init[n_w] == v:
                    continue
                eqs.append(ExprAff(n_w, v))
            print '*' * 40
            print irb
            for eq in eqs:
                eq
            irb.irs = [eqs]
            irb.lines = [None]
