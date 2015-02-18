#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging

from miasm2.ir.symbexec import symbexec
from miasm2.core.graph import DiGraph
from miasm2.expression.expression \
    import ExprAff, ExprCond, ExprId, ExprInt, ExprMem, ExprOp

log = logging.getLogger("analysis")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)

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

    def gen_graph(self, link_all = True):
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
        """Output the graphviz script"""
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
            irb = self.blocs[lbl]
            ir_txt = [str(lbl)]
            for irs in irb.irs:
                for l in irs:
                    ir_txt.append(str(l))
                ir_txt.append("")
            ir_txt.append("")
            all_lbls[hash(lbl)] = "\l\\\n".join(ir_txt)
        for l, v in all_lbls.items():
            # print l, v
            out += '%s [label="%s"];\n' % (l, v)

        for a, b in self.g.edges():
            # print 'edge', a, b, hash(a), hash(b)
            out += '%s -> %s;\n' % (hash(a), hash(b))
        out += '}'
        return out

    def remove_dead(self, irb):
        """Remove dead affectations using previous liveness analysis
        @irb: irbloc instance
        Return True iff the bloc state has changed
        PRE: compute_in_out(@irb)
        """

        # print 'state1'
        # self.dump_bloc_state(irb)

        modified = False
        for ir, _, c_out in zip(irb.irs, irb.c_in, irb.c_out):
            j = 0
            while j < len(ir):
                i_cur = ir[j]
                if not isinstance(i_cur.dst, ExprId):
                    pass
                elif i_cur.dst == self.IRDst:
                    # never delete irdst
                    pass
                elif (isinstance(i_cur.src, ExprOp) and
                    i_cur.src.op.startswith('call')):
                    # /!\ never remove ir calls
                    pass
                elif not i_cur.dst in c_out:
                    del(ir[j])
                    modified = True
                    continue
                j += 1

        # print 'state2'
        # self.dump_bloc_state(irb)

        return modified

    def remove_blocs_dead(self):
        """Call remove_dead on each irbloc
        Return True iff one of the bloc state has changed
        """
        modified = False
        for b in self.blocs.values():
            modified |= self.remove_dead(b)
        return modified

    # for test XXX TODO
    def set_dead_regs(self, b):
        pass

    def add_unused_regs(self):
        pass

    def dump_bloc_state(self, irb):
        print '*'*80
        for i, (ir, c_in, c_out) in enumerate(zip(irb.irs, irb.c_in, irb.c_out)):
            print 'ir'
            for x in ir:
                print '\t', x
            print 'R', [str(x) for x in irb.r[i]]#c_in]
            print 'W', [str(x) for x in irb.w[i]]#c_out]
            print 'IN', [str(x) for x in c_in]
            print 'OUT', [str(x) for x in c_out]

        print 'OUT final', [str(x) for x in irb.c_out[-1]]

    def compute_in_out(self, irb):
        """Liveness computation for a single bloc
        @irb: irbloc instance
        Return True iff bloc state has changed
        """
        # get out/in from bloc sons
        modified = False
        # set b in
        if irb.c_in[-1] != set(irb.r[-1].union(irb.c_out[-1].difference(irb.w[-1]))):
            modified = True
        irb.c_in[-1] = set(irb.r[-1].union(irb.c_out[-1].difference(irb.w[-1])))

        # set b out
        c_out = set()
        has_son = False
        for n_son in self.g.successors(irb.label):
            has_son = True
            if not n_son in self.blocs:
                # If the son is not defined, we will propagate our current out
                # nodes to the in nodes's son
                son_c_in = irb.c_out_missing
            else:
                son_c_in = self.blocs[n_son].c_in[0]
            c_out.update(son_c_in)
        if not has_son:
            # special case: leaf nodes architecture dependant
            c_out = self.get_out_regs(irb)
        if irb.c_out[-1] != set(c_out):
            modified = True
        irb.c_out[-1] = set(c_out)

        # get out/in for bloc
        for i in reversed(xrange(len(irb.irs))):
            if irb.c_in[i] != set(irb.r[i].union(irb.c_out[i].difference(irb.w[i]))):
                modified = True
            irb.c_in[i] = set(irb.r[i].union(irb.c_out[i].difference(irb.w[i])))
            if irb.c_out[i] != set(irb.c_in[i + 1]):
                modified = True
            irb.c_out[i] = set(irb.c_in[i + 1])

        return modified

    def test_in_out_fix(self):
        """Return True iff a fixed point has been reached during liveness
        analysis"""

        fixed = True
        for node in self.g.nodes():
            if not node in self.blocs:
                # leaf has lost her son
                continue
            irb = self.blocs[node]
            if irb.c_in != irb.l_in or irb.c_out != irb.l_out:
                fixed = False
            irb.l_in = [set(x) for x in irb.c_in]
            irb.l_out = [set(x) for x in irb.c_out]
        return fixed

    def fill_missing_son_c_in(self):
        """Find nodes with missing sons in graph, and add virtual link to all
        written variables of all parents.
        PRE: gen_graph() and get_rw()"""

        for node in self.g.nodes():
            if not node in self.blocs:
                continue
            self.blocs[node].c_out_missing = set()
            has_all_son = True
            for node_son in self.g.successors(node):
                if not node_son in self.blocs:
                    has_all_son = False
                    break
            if has_all_son:
                continue
            parents = self.g.get_all_parents(node)
            for parent in parents:
                irb = self.blocs[parent]
                for var_w in irb.w:
                    self.blocs[node].c_out_missing.update(var_w)

    def compute_dead(self):
        """Iterate liveness analysis until a fixed point is reached.
        PRE: gen_graph()
        """

        it = 0
        fixed_point = False
        log.debug('iteration...')
        while not fixed_point:
            log.debug(it)
            it += 1
            for n in self.g.nodes():
                if not n in self.blocs:
                    # leaf has lost her son
                    continue
                irb = self.blocs[n]
                self.compute_in_out(irb)

            fixed_point = self.test_in_out_fix()

    def dead_simp(self):
        """This function is used to analyse relation of a * complete function *
        This mean the blocs under study represent a solid full function graph.

        Ref: CS 5470 Compiler Techniques and Principles (Liveness
        analysis/Dataflow equations)

        PRE: call to gen_graph
        """

        modified = True
        while modified:
            log.debug('dead_simp step')

            # Update r/w variables for all irblocs
            self.get_rw()
            # Fill c_in for missing sons
            self.fill_missing_son_c_in()

            # Liveness step
            self.compute_dead()
            modified = self.remove_blocs_dead()

        # Simplify expressions
        self.simplify_blocs()

    def gen_equations(self):
        for irb in self.blocs.values():
            symbols_init = {}
            for r in self.arch.regs.all_regs_ids:
                x = ExprId(r.name, r.size)
                x.is_term = True
                symbols_init[r] = x
            sb = symbexec(self, dict(symbols_init))
            sb.emulbloc(irb)
            eqs = []
            for n_w in sb.symbols:
                v = sb.symbols[n_w]
                if n_w in symbols_init and symbols_init[n_w] == v:
                    continue
                eqs.append(ExprAff(n_w, v))
            print '*' * 40
            print irb
            irb.irs = [eqs]
            irb.lines = [None]

    def sizeof_char(self):
        "Return the size of a char in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_short(self):
        "Return the size of a short in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_int(self):
        "Return the size of an int in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_long(self):
        "Return the size of a long in bits"
        raise NotImplementedError("Abstract method")

    def sizeof_pointer(self):
        "Return the size of a void* in bits"
        raise NotImplementedError("Abstract method")
