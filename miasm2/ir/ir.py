#-*- coding:utf-8 -*-

#
# Copyright (C) 2013 Fabrice Desclaux
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
import warnings

from itertools import chain

import miasm2.expression.expression as m2_expr
from miasm2.expression.expression_helper import get_missing_interval
from miasm2.expression.simplifications import expr_simp
from miasm2.core.asmblock import AsmSymbolPool, expr_is_label, AsmLabel, \
    AsmBlock
from miasm2.core.graph import DiGraph


class AssignBlock(dict):

    def __init__(self, irs=None):
        """@irs seq"""
        if irs is None:
            irs = []
        super(AssignBlock, self).__init__()

        for expraff in irs:
            # Concurrent assignments are handled in __setitem__
            self[expraff.dst] = expraff.src

    def __setitem__(self, dst, src):
        """
        Special cases:
        * if dst is an ExprSlice, expand it to affect the full Expression
        * if dst already known, sources are merged
        """
        if dst.size != src.size:
            raise RuntimeError(
                "sanitycheck: args must have same size! %s" %
                ([(str(arg), arg.size) for arg in [dst, src]]))

        if isinstance(dst, m2_expr.ExprSlice):
            # Complete the source with missing slice parts
            new_dst = dst.arg
            rest = [(m2_expr.ExprSlice(dst.arg, r[0], r[1]), r[0], r[1])
                    for r in dst.slice_rest()]
            all_a = [(src, dst.start, dst.stop)] + rest
            all_a.sort(key=lambda x: x[1])
            args = [expr for (expr, _, _) in all_a]
            new_src = m2_expr.ExprCompose(*args)
        else:
            new_dst, new_src = dst, src

        if new_dst in self and isinstance(new_src, m2_expr.ExprCompose):
            if not isinstance(self[new_dst], m2_expr.ExprCompose):
                # prev_RAX = 0x1122334455667788
                # input_RAX[0:8] = 0x89
                # final_RAX -> ? (assignment are in parallel)
                raise RuntimeError("Concurent access on same bit not allowed")

            # Consider slice grouping
            expr_list = [(new_dst, new_src),
                         (new_dst, self[new_dst])]
            # Find collision
            e_colision = reduce(lambda x, y: x.union(y),
                                (self.get_modified_slice(dst, src)
                                 for (dst, src) in expr_list),
                                set())

            # Sort interval collision
            known_intervals = sorted([(x[1], x[2]) for x in e_colision])

            for i, (_, stop) in enumerate(known_intervals[:-1]):
                if stop > known_intervals[i + 1][0]:
                    raise RuntimeError(
                        "Concurent access on same bit not allowed")

            # Fill with missing data
            missing_i = get_missing_interval(known_intervals, 0, new_dst.size)
            remaining = ((m2_expr.ExprSlice(new_dst, *interval),
                          interval[0],
                          interval[1])
                         for interval in missing_i)

            # Build the merging expression
            args = list(e_colision.union(remaining))
            args.sort(key=lambda x: x[1])
            starts = [start for (_, start, _) in args]
            assert len(set(starts)) == len(starts)
            args = [expr for (expr, _, _) in args]
            new_src = m2_expr.ExprCompose(*args)

        super(AssignBlock, self).__setitem__(new_dst, new_src)

    @staticmethod
    def get_modified_slice(dst, src):
        """Return an Expr list of extra expressions needed during the
        object instanciation"""
        if not isinstance(src, m2_expr.ExprCompose):
            raise ValueError("Get mod slice not on expraff slice", str(src))
        modified_s = []
        for index, arg in src.iter_args():
            if not (isinstance(arg, m2_expr.ExprSlice) and
                    arg.arg == dst and
                    index == arg.start and
                    index+arg.size == arg.stop):
                # If x is not the initial expression
                modified_s.append((arg, index, index+arg.size))
        return modified_s

    def get_w(self):
        """Return a set of elements written"""
        return set(self.keys())

    def get_rw(self, mem_read=False, cst_read=False):
        """Return a dictionnary associating written expressions to a set of
        their read requirements
        @mem_read: (optional) mem_read argument of `get_r`
        @cst_read: (optional) cst_read argument of `get_r`
        """
        out = {}
        for dst, src in self.iteritems():
            src_read = src.get_r(mem_read=mem_read, cst_read=cst_read)
            if isinstance(dst, m2_expr.ExprMem) and mem_read:
                # Read on destination happens only with ExprMem
                src_read.update(dst.arg.get_r(mem_read=mem_read,
                                              cst_read=cst_read))
            out[dst] = src_read
        return out

    def get_r(self, mem_read=False, cst_read=False):
        """Return a set of elements reads
        @mem_read: (optional) mem_read argument of `get_r`
        @cst_read: (optional) cst_read argument of `get_r`
        """
        return set(
            chain.from_iterable(self.get_rw(mem_read=mem_read,
                                            cst_read=cst_read).itervalues()))

    def __str__(self):
        out = []
        for dst, src in sorted(self.iteritems()):
            out.append("%s = %s" % (dst, src))
        return "\n".join(out)

    def dst2ExprAff(self, dst):
        """Return an ExprAff corresponding to @dst equation
        @dst: Expr instance"""
        return m2_expr.ExprAff(dst, self[dst])


class IRBlock(object):
    """Intermediate representation block object.

    Stand for an intermediate representation  basic block.
    """

    def __init__(self, label, irs, lines=None):
        """
        @label: AsmLabel of the IR basic block
        @irs: list of AssignBlock
        @lines: list of native instructions
        """

        assert isinstance(label, AsmLabel)
        if lines is None:
            lines = []
        self.label = label
        self.irs = irs
        self.lines = lines
        self.except_automod = True
        self._dst = None
        self._dst_linenb = None

    def _get_dst(self):
        """Find the IRDst affectation and update dst, dst_linenb accordingly"""
        if self._dst is not None:
            return self._dst
        final_dst = None
        final_linenb = None
        for linenb, assignblk in enumerate(self.irs):
            for dst, src in assignblk.iteritems():
                if isinstance(dst, m2_expr.ExprId) and dst.name == "IRDst":
                    if final_dst is not None:
                        raise ValueError('Multiple destinations!')
                    final_dst = src
                    final_linenb = linenb
        self._dst = final_dst
        self._dst_linenb = final_linenb
        return final_dst

    def _set_dst(self, value):
        """Find and replace the IRDst affectation's source by @value"""
        if self._dst_linenb is None:
            self._get_dst()

        assignblk = self.irs[self._dst_linenb]
        for dst in assignblk:
            if isinstance(dst, m2_expr.ExprId) and dst.name == "IRDst":
                del assignblk[dst]
                assignblk[dst] = value
                # Sanity check is already done in _get_dst
                break
        self._dst = value

    dst = property(_get_dst, _set_dst)

    @property
    def dst_linenb(self):
        """Line number of the IRDst setting statement in the current irs"""
        return self._dst_linenb

    def get_rw(self, regs_ids):
        """
        Computes the variables read and written by each instructions
        Initialize attributes needed for in/out and reach computation.
        @regs_ids : ids of registers used in IR
        """
        keep_exprid = lambda elts: filter(lambda expr: isinstance(expr,
                                                                  m2_expr.ExprId),
                                          elts)
        for idx, assignblk in enumerate(self.irs):
            assignblk._cur_reach = {reg: set() for reg in regs_ids}
            assignblk._prev_reach = {reg: set() for reg in regs_ids}
            assignblk._cur_kill = {reg: set() for reg in regs_ids}
            assignblk._prev_kill = {reg: set() for reg in regs_ids}
            # LineNumber -> dict:
            #               Register: set(definition(irb label, index))
            assignblk.defout = {reg: set() for reg in regs_ids}
            assignblk.defout.update({dst: set([(self.label, idx, dst)])
                                     for dst in assignblk
                                     if isinstance(dst, m2_expr.ExprId)})

    def __str__(self):
        out = []
        out.append('%s' % self.label)
        for assignblk in self.irs:
            for dst, src in assignblk.iteritems():
                out.append('\t%s = %s' % (dst, src))
            out.append("")
        return "\n".join(out)


class irbloc(IRBlock):
    """
    DEPRECATED object
    Use IRBlock instead of irbloc
    """

    def __init__(self, label, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "IRBlock" instead of "irblock"')
        super(irbloc, self).__init__(label, irs, lines)


class DiGraphIR(DiGraph):

    """DiGraph for IR instances"""

    def __init__(self, blocks, *args, **kwargs):
        """Instanciate a DiGraphIR
        @blocks: IR blocks
        """
        self._blocks = blocks
        super(DiGraphIR, self).__init__(*args, **kwargs)

    def node2lines(self, node):
        yield self.DotCellDescription(text=str(node.name),
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})
        if node not in self._blocks:
            yield [self.DotCellDescription(text="NOT PRESENT", attr={})]
            raise StopIteration
        for i, assignblk in enumerate(self._blocks[node].irs):
            for dst, src in assignblk.iteritems():
                line = "%s = %s" % (dst, src)
                if self._dot_offset:
                    yield [self.DotCellDescription(text="%-4d" % i, attr={}),
                           self.DotCellDescription(text=line, attr={})]
                else:
                    yield self.DotCellDescription(text=line, attr={})
            yield self.DotCellDescription(text="", attr={})

    def edge_attr(self, src, dst):
        if src not in self._blocks or dst not in self._blocks:
            return {}
        src_irdst = self._blocks[src].dst
        edge_color = "blue"
        if isinstance(src_irdst, m2_expr.ExprCond):
            if (expr_is_label(src_irdst.src1) and
                    src_irdst.src1.name == dst):
                edge_color = "limegreen"
            elif (expr_is_label(src_irdst.src2) and
                  src_irdst.src2.name == dst):
                edge_color = "red"
        return {"color": edge_color}

    def node_attr(self, node):
        if node not in self._blocks:
            return {'style': 'filled', 'fillcolor': 'red'}
        return {}

    def dot(self, offset=False):
        """
        @offset: (optional) if set, add the corresponding line number in each
        node
        """
        self._dot_offset = offset
        return super(DiGraphIR, self).dot()


class IntermediateRepresentation(object):
    """
    Intermediate representation object

    Allow native assembly to intermediate representation traduction
    """

    def __init__(self, arch, attrib, symbol_pool=None):
        if symbol_pool is None:
            symbol_pool = AsmSymbolPool()
        self.symbol_pool = symbol_pool
        self.blocks = {}
        self.pc = arch.getpc(attrib)
        self.sp = arch.getsp(attrib)
        self.arch = arch
        self.attrib = attrib
        # Lazy structure
        self._graph = None

    @property
    def blocs(self):
        warnings.warn('DEPRECATION WARNING: use ".blocks" instead of ".blocs"')
        return self.blocks

    def get_ir(self, instr):
        raise NotImplementedError("Abstract Method")

    def instr2ir(self, l):
        ir_bloc_cur, extra_assignblk = self.get_ir(l)
        assignblk = AssignBlock(ir_bloc_cur)
        for irb in extra_assignblk:
            irb.irs = map(AssignBlock, irb.irs)
        return assignblk, extra_assignblk

    def get_label(self, ad):
        """Transforms an ExprId/ExprInt/label/int into a label
        @ad: an ExprId/ExprInt/label/int"""

        if (isinstance(ad, m2_expr.ExprId) and
                isinstance(ad.name, AsmLabel)):
            ad = ad.name
        if isinstance(ad, m2_expr.ExprInt):
            ad = int(ad)
        if isinstance(ad, (int, long)):
            ad = self.symbol_pool.getby_offset_create(ad)
        elif isinstance(ad, AsmLabel):
            ad = self.symbol_pool.getby_name_create(ad.name)
        return ad

    def get_bloc(self, ad):
        """Returns the irbloc associated to an ExprId/ExprInt/label/int
        @ad: an ExprId/ExprInt/label/int"""

        label = self.get_label(ad)
        return self.blocks.get(label, None)

    def add_instr(self, l, ad=0, gen_pc_updt=False):
        b = AsmBlock(self.gen_label())
        b.lines = [l]
        self.add_bloc(b, gen_pc_updt)

    def getby_offset(self, offset):
        out = set()
        for irb in self.blocks.values():
            for l in irb.lines:
                if l.offset <= offset < l.offset + l.l:
                    out.add(irb)
        return out

    def gen_pc_update(self, c, l):
        c.irs.append(AssignBlock([m2_expr.ExprAff(self.pc,
                                                  m2_expr.ExprInt(l.offset,
                                                                  self.pc.size)
                                                 )]))
        c.lines.append(l)

    def pre_add_instr(self, block, instr, irb_cur, ir_blocks_all, gen_pc_updt):
        """Function called before adding an instruction from the the native @block to
        the current irbloc.

        Returns None if the addition needs an irblock split, @irb_cur in other
        cases.

        @block: native block source
        @instr: native instruction
        @irb_cur: current irbloc
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions

        """

        return irb_cur

    def add_instr_to_irblock(self, block, instr, irb_cur, ir_blocks_all, gen_pc_updt):
        """
        Add the IR effects of an instruction to the current irblock.

        Returns None if the addition needs an irblock split, @irb_cur in other
        cases.

        @block: native block source
        @instr: native instruction
        @irb_cur: current irbloc
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions
        """

        irb_cur = self.pre_add_instr(block, instr, irb_cur, ir_blocks_all, gen_pc_updt)
        if irb_cur is None:
            return None

        assignblk, ir_blocks_extra = self.instr2ir(instr)

        if gen_pc_updt is not False:
            self.gen_pc_update(irb_cur, instr)

        irb_cur.irs.append(assignblk)
        irb_cur.lines.append(instr)

        if ir_blocks_extra:
            for irblock in ir_blocks_extra:
                irblock.lines = [instr] * len(irblock.irs)
            ir_blocks_all += ir_blocks_extra
            irb_cur = None
        return irb_cur

    def add_bloc(self, block, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @gen_pc_updt: insert PC update effects between instructions
        """

        irb_cur = None
        ir_blocks_all = []
        for instr in block.lines:
            if irb_cur is None:
                label = self.get_instr_label(instr)
                irb_cur = IRBlock(label, [], [])
                ir_blocks_all.append(irb_cur)
            irb_cur = self.add_instr_to_irblock(block, instr, irb_cur,
                                                ir_blocks_all, gen_pc_updt)
        self.post_add_bloc(block, ir_blocks_all)
        return ir_blocks_all

    def expr_fix_regs_for_mode(self, e, *args, **kwargs):
        return e

    def expraff_fix_regs_for_mode(self, e, *args, **kwargs):
        return e

    def irbloc_fix_regs_for_mode(self, irbloc, *args, **kwargs):
        return

    def is_pc_written(self, b):
        all_pc = self.arch.pc.values()
        for irs in b.irs:
            for ir in irs:
                if ir.dst in all_pc:
                    return ir
        return None

    def set_empty_dst_to_next(self, block, ir_blocks):
        for irblock in ir_blocks:
            if irblock.dst is not None:
                continue
            next_lbl = block.get_next()
            if next_lbl is None:
                dst = m2_expr.ExprId(self.get_next_label(block.lines[-1]),
                                     self.pc.size)
            else:
                dst = m2_expr.ExprId(next_lbl,
                                     self.pc.size)
            irblock.irs.append(AssignBlock([m2_expr.ExprAff(self.IRDst, dst)]))
            irblock.lines.append(irblock.lines[-1])

    def post_add_bloc(self, block, ir_blocks):
        self.set_empty_dst_to_next(block, ir_blocks)

        for irblock in ir_blocks:
            self.irbloc_fix_regs_for_mode(irblock, self.attrib)
            self.blocks[irblock.label] = irblock

        # Forget graph if any
        self._graph = None

    def get_instr_label(self, instr):
        """Returns the label associated to an instruction
        @instr: current instruction"""

        return self.symbol_pool.getby_offset_create(instr.offset)

    def gen_label(self):
        # TODO: fix hardcoded offset
        l = self.symbol_pool.gen_label()
        return l

    def get_next_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset + instr.l)
        return l

    def simplify_blocs(self):
        for irblock in self.blocks.values():
            for assignblk in irblock.irs:
                for dst, src in assignblk.items():
                    del assignblk[dst]
                    assignblk[expr_simp(dst)] = expr_simp(src)

    def replace_expr_in_ir(self, bloc, rep):
        for assignblk in bloc.irs:
            for dst, src in assignblk.items():
                del assignblk[dst]
                assignblk[dst.replace_expr(rep)] = src.replace_expr(rep)

    def get_rw(self, regs_ids=None):
        """
        Calls get_rw(irb) for each bloc
        @regs_ids : ids of registers used in IR
        """
        if regs_ids is None:
            regs_ids = []
        for irblock in self.blocks.values():
            irblock.get_rw(regs_ids)

    def _extract_dst(self, todo, done):
        """
        Naive extraction of @todo destinations
        WARNING: @todo and @done are modified
        """
        out = set()
        while todo:
            dst = todo.pop()
            if expr_is_label(dst):
                done.add(dst)
            elif isinstance(dst, (m2_expr.ExprMem, m2_expr.ExprInt)):
                done.add(dst)
            elif isinstance(dst, m2_expr.ExprCond):
                todo.add(dst.src1)
                todo.add(dst.src2)
            elif isinstance(dst, m2_expr.ExprId):
                out.add(dst)
            else:
                done.add(dst)
        return out

    def dst_trackback(self, irb):
        """
        Naive backtracking of IRDst
        @irb: irbloc instance
        """
        todo = set([irb.dst])
        done = set()

        for assignblk in reversed(irb.irs):
            if not todo:
                break
            out = self._extract_dst(todo, done)
            found = set()
            follow = set()
            for dst in out:
                if dst in assignblk:
                    follow.add(assignblk[dst])
                    found.add(dst)

            follow.update(out.difference(found))
            todo = follow

        return done

    def _gen_graph(self):
        """
        Gen irbloc digraph
        """
        self._graph = DiGraphIR(self.blocks)
        for lbl, b in self.blocks.iteritems():
            self._graph.add_node(lbl)
            dst = self.dst_trackback(b)
            for d in dst:
                if isinstance(d, m2_expr.ExprInt):
                    d = m2_expr.ExprId(
                        self.symbol_pool.getby_offset_create(int(d)))
                if expr_is_label(d):
                    self._graph.add_edge(lbl, d.name)

    @property
    def graph(self):
        """Get a DiGraph representation of current IR instance.
        Lazy property, building the graph on-demand"""
        if self._graph is None:
            self._gen_graph()
        return self._graph



class ir(IntermediateRepresentation):
    """
    DEPRECATED object
    Use IntermediateRepresentation instead of ir
    """

    def __init__(self, label, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "IntermediateRepresentation" instead of "ir"')
        super(ir, self).__init__(label, irs, lines)
