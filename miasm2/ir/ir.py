#!/usr/bin/env python
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


import miasm2.expression.expression as m2_expr
from miasm2.expression.expression_helper import get_missing_interval
from miasm2.core import asmbloc
from miasm2.expression.simplifications import expr_simp
from miasm2.core.graph import DiGraph
from miasm2.core.asmbloc import asm_symbol_pool


class irbloc:

    def __init__(self, label, dst=None, irs=None, lines=None):
        assert(isinstance(label, asmbloc.asm_label))
        self.label = label
        self.dst = dst
        self.lines = []
        self.irs = []
        if irs is not None:
            self.irs = irs
        if lines is not None:
            self.lines = lines
        self.except_automod = True

    def get_rw(self):
        self.r = []
        self.w = []
        self.c_out = []
        self.c_in = []
        self.l_out = []
        self.l_in = []
        for ir in self.irs:
            r, w = set(), set()
            for i in ir:
                r.update([x for x in i.get_r(True) if isinstance(x, m2_expr.ExprId)])
                w.update([x for x in i.get_w() if isinstance(x, m2_expr.ExprId)])
                if isinstance(i.dst, m2_expr.ExprMem):
                    r.update([x for x in i.dst.arg.get_r(True)
                    if isinstance(x, m2_expr.ExprId)])
            self.r.append(r)
            self.w.append(w)
            self.c_out.append(set())
            self.c_in.append(set())
            self.l_out.append(set())
            self.l_in.append(set())
        # get rw for dst
        i = self.dst
        r, w = set(), set()
        if i is not None:
            r.update([x for x in i.get_r(True) if isinstance(x, m2_expr.ExprId)])
        self.r.append(r)
        self.w.append(w)
        self.c_out.append(set())
        self.c_in.append(set())
        self.l_out.append(set())
        self.l_in.append(set())

    def __str__(self):
        o = []
        o.append('%s' % self.label)
        for expr in self.irs:
            for e in expr:
                o.append('\t%s' % e)
            o.append("")
        o.append('\tDst: %s' % self.dst)

        return "\n".join(o)


class ir(object):

    def __init__(self, arch, attrib, symbol_pool=None):
        if symbol_pool is None:
            symbol_pool = asm_symbol_pool()
        self.symbol_pool = symbol_pool
        self.blocs = {}
        self.pc = arch.getpc(attrib)
        self.sp = arch.getsp(attrib)
        self.arch = arch
        self.attrib = attrib

    def instr2ir(self, l):
        dst, ir_bloc_cur, ir_blocs_extra = self.get_ir(l)
        return dst, ir_bloc_cur, ir_blocs_extra

    def get_bloc(self, ad):
        if isinstance(ad, m2_expr.ExprId) and isinstance(ad.name,
                                                         asmbloc.asm_label):
            ad = ad.name
        if isinstance(ad, m2_expr.ExprInt):
            ad = int(ad.arg)
        if type(ad) in [int, long]:
            ad = self.symbol_pool.getby_offset(ad)
        elif isinstance(ad, asmbloc.asm_label):
            ad = self.symbol_pool.getby_name(ad.name)
        return self.blocs.get(ad, None)

    def add_instr(self, l, ad=0, gen_pc_updt = False):
        b = asmbloc.asm_bloc(l)
        b.lines = [l]
        self.add_bloc(b, gen_pc_updt)

    def merge_multi_affect(self, affect_list):
        """
        If multiple affection to a same ExprId are present in @affect_list,
        merge them (in place).
        For instance, XCGH AX, AL semantic is
        [
            RAX = {RAX[0:8],0,8, RAX[0:8],8,16, RAX[16:64],16,64}
            RAX = {RAX[8:16],0,8, RAX[8:64],8,64}
        ]
        This function will update @affect_list to replace previous ExprAff by
        [
            RAX = {RAX[8:16],0,8, RAX[0:8],8,16, RAX[16:64],16,64}
        ]
        """

        # Extract side effect
        effect = {}
        for expr in affect_list:
            effect[expr.dst] = effect.get(expr.dst, []) + [expr]

        # Find candidates
        for dst, expr_list in effect.items():
            if len(expr_list) <= 1:
                continue

            # Only treat ExprCompose list
            if any(map(lambda e: not(isinstance(e.src, m2_expr.ExprCompose)),
                       expr_list)):
                continue

            # Find collision
            e_colision = reduce(
                lambda x, y: x + y, [e.get_modified_slice() for e in expr_list])

            # Sort interval collision
            known_intervals = sorted([(x[1], x[2]) for x in set(e_colision)])

            # Fill with missing data
            missing_i = get_missing_interval(known_intervals, 0, e.src.size)

            rest = [(m2_expr.ExprSlice(dst, r[0], r[1]), r[0], r[1])
                    for r in missing_i]

            # Build the merging expression
            slices = e_colision + rest
            slices.sort(key=lambda x: x[1])
            final_dst = m2_expr.ExprCompose(slices)

            # Remove unused expression
            for expr in expr_list:
                affect_list.remove(expr)

            # Add the merged one
            affect_list.append(m2_expr.ExprAff(dst, final_dst))


    def getby_offset(self, offset):
        out = set()
        for irb in self.blocs.values():
            for l in irb.lines:
                if l.offset <= offset < l.offset + l.l:
                    out.add(irb)
        return out

    def gen_pc_update(self, c, l):
        c.irs.append([m2_expr.ExprAff(self.pc, m2_expr.ExprInt_from(self.pc,
                                                                    l.offset))])
        c.lines.append(l)

    def add_bloc(self, bloc, gen_pc_updt = False):
        c = None
        ir_blocs_all = []
        for l in bloc.lines:
            if c is None:
                # print 'new c'
                label = self.get_label(l)
                c = irbloc(label)
                ir_blocs_all.append(c)
                bloc_dst = None
            # print 'Translate', l
            dst, ir_bloc_cur, ir_blocs_extra = self.instr2ir(l)
            # print ir_bloc_cur
            # for xxx in ir_bloc_cur:
            #    print "\t", xxx
            assert((dst is None) or (bloc_dst is None))
            bloc_dst = dst
            if bloc_dst is not None:
                c.dst = bloc_dst

            if gen_pc_updt is not False:
                self.gen_pc_update(c, l)

            c.irs.append(ir_bloc_cur)
            c.lines.append(l)
            if ir_blocs_extra:
                # print 'split'
                for b in ir_blocs_extra:
                    b.lines = [l] * len(b.irs)
                ir_blocs_all += ir_blocs_extra
                c = None
        self.post_add_bloc(bloc, ir_blocs_all)
        return ir_blocs_all

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

    def set_empty_dst_to_next(self, bloc, ir_blocs):
        for b in ir_blocs:
            if b.dst is not None:
                continue
            dst = m2_expr.ExprId(self.get_next_label(bloc.lines[-1]),
                                 self.pc.size)
            b.dst = dst

    def gen_edges(self, bloc, ir_blocs):
        pass

    def post_add_bloc(self, bloc, ir_blocs):
        self.set_empty_dst_to_next(bloc, ir_blocs)
        self.gen_edges(bloc, ir_blocs)

        for irb in ir_blocs:
            self.irbloc_fix_regs_for_mode(irb, self.attrib)

            # Detect multi-affectation
            for affect_list in irb.irs:
                self.merge_multi_affect(affect_list)

            self.blocs[irb.label] = irb


    def get_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset)
        return l

    def gen_label(self):
        # TODO: fix hardcoded offset
        l = self.symbol_pool.gen_label()
        return l

    def get_next_label(self, instr):
        l = self.symbol_pool.getby_offset_create(instr.offset + instr.l)
        return l

    def simplify_blocs(self):
        for b in self.blocs.values():
            for ir in b.irs:
                for i, r in enumerate(ir):
                    ir[i].src = expr_simp(r.src)
                    ir[i].dst = expr_simp(r.dst)

    def replace_expr_in_ir(self, bloc, rep):
        for irs in bloc.irs:
            for i, l in enumerate(irs):
                irs[i] = l.replace_expr(rep)

    def get_rw(self):
        for b in self.blocs.values():
            b.get_rw()

    def ExprIsLabel(self, l):
        return isinstance(l, m2_expr.ExprId) and isinstance(l.name,
                                                            asmbloc.asm_label)
