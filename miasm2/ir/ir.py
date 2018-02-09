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
from miasm2.core.asmblock import AsmSymbolPool, expr_is_label, AsmLabel, \
    AsmBlock
from miasm2.core.graph import DiGraph


class AssignBlock(object):
    """Represent parallel IR assignment, such as:
    EAX = EBX
    EBX = EAX

    -> Exchange between EBX and EAX

    AssignBlock can be seen as a dictionnary where keys are the destinations
    (ExprId or ExprMem), and values their corresponding sources.

    Also provides common manipulation on this assignments.

    """
    __slots__ = ["_assigns", "_instr"]

    def __init__(self, irs=None, instr=None):
        """Create a new AssignBlock
        @irs: (optional) sequence of ExprAff, or dictionnary dst (Expr) -> src
              (Expr)
        @instr: (optional) associate an instruction with this AssignBlock

        """
        if irs is None:
            irs = []
        self._instr = instr
        self._assigns = {} # ExprAff.dst -> ExprAff.src

        # Concurrent assignments are handled in _set
        if hasattr(irs, "iteritems"):
            for dst, src in irs.iteritems():
                self._set(dst, src)
        else:
            for expraff in irs:
                self._set(expraff.dst, expraff.src)

    @property
    def instr(self):
        """Return the associated instruction, if any"""
        return self._instr

    def _set(self, dst, src):
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

        if new_dst in self._assigns and isinstance(new_src, m2_expr.ExprCompose):
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

        # Sanity check
        if not isinstance(new_dst, (m2_expr.ExprId, m2_expr.ExprMem)):
            raise TypeError("Destination cannot be a %s" % type(new_dst))

        self._assigns[new_dst] = new_src

    def __setitem__(self, dst, src):
        raise RuntimeError('AssignBlock is immutable')

    def __getitem__(self, key):
        return self._assigns[key]

    def __contains__(self, key):
        return key in self._assigns

    def iteritems(self):
        for dst, src in self._assigns.iteritems():
            yield dst, src

    def items(self):
        return [(dst, src) for dst, src in self.iteritems()]

    def itervalues(self):
        for src in self._assigns.itervalues():
            yield src

    def keys(self):
        return self._assigns.keys()

    def values(self):
        return self._assigns.values()

    def __iter__(self):
        for dst in self._assigns:
            yield dst

    def __delitem__(self, _):
        raise RuntimeError('AssignBlock is immutable')

    def update(self, _):
        raise RuntimeError('AssignBlock is immutable')

    def __eq__(self, other):
        if self.keys() != other.keys():
            return False
        return all(other[dst] == src for dst, src in self.iteritems())

    def __len__(self):
        return len(self._assigns)

    def get(self, key, default):
        return self._assigns.get(key, default)

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
        for dst, src in sorted(self._assigns.iteritems()):
            out.append("%s = %s" % (dst, src))
        return "\n".join(out)

    def dst2ExprAff(self, dst):
        """Return an ExprAff corresponding to @dst equation
        @dst: Expr instance"""
        return m2_expr.ExprAff(dst, self[dst])

    def simplify(self, simplifier):
        """Return a new AssignBlock with expression simplified
        @simplifier: ExpressionSimplifier instance"""
        new_assignblk = {}
        for dst, src in self.iteritems():
            if dst == src:
                continue
            src = simplifier(src)
            dst = simplifier(dst)
            new_assignblk[dst] = src
        return AssignBlock(irs=new_assignblk, instr=self.instr)


class IRBlock(object):
    """Intermediate representation block object.

    Stand for an intermediate representation  basic block.
    """

    __slots__ = ["label", "_assignblks", "_dst", "_dst_linenb"]

    def __init__(self, label, assignblks):
        """
        @label: AsmLabel of the IR basic block
        @assignblks: list of AssignBlock
        """

        assert isinstance(label, AsmLabel)
        self.label = label
        for assignblk in assignblks:
            assert isinstance(assignblk, AssignBlock)
        self._assignblks = tuple(assignblks)
        self._dst = None
        self._dst_linenb = None


    @property
    def assignblks(self):
        return self._assignblks

    @property
    def irs(self):
        warnings.warn('DEPRECATION WARNING: use "irblock.assignblks" instead of "irblock.irs"')
        return self._assignblks

    def __iter__(self):
        """Iterate on assignblks"""
        return self._assignblks.__iter__()

    def __getitem__(self, index):
        """Getitem on assignblks"""
        return self._assignblks.__getitem__(index)

    def __len__(self):
        """Length of assignblks"""
        return self._assignblks.__len__()

    def is_dst_set(self):
        return self._dst is not None

    def cache_dst(self):
        final_dst = None
        final_linenb = None
        for linenb, assignblk in enumerate(self):
            for dst, src in assignblk.iteritems():
                if dst.is_id("IRDst"):
                    if final_dst is not None:
                        raise ValueError('Multiple destinations!')
                    final_dst = src
                    final_linenb = linenb
        self._dst = final_dst
        self._dst_linenb = final_linenb
        return final_dst

    @property
    def dst(self):
        """Return the value of IRDst for the IRBlock"""
        if self.is_dst_set():
            return self._dst
        return self.cache_dst()

    def set_dst(self, value):
        """Generate a new IRBlock with a dst (IRBlock) fixed to @value"""
        irs = []
        dst_found = False
        for assignblk in self:
            new_assignblk = {}
            for dst, src in assignblk.iteritems():
                if dst.is_id("IRDst"):
                    assert dst_found is False
                    dst_found = True
                    new_assignblk[dst] = value
                else:
                    new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.label, irs)

    @property
    def dst_linenb(self):
        """Line number of the IRDst setting statement in the current irs"""
        if not self.is_dst_set():
            self.cache_dst()
        return self._dst_linenb

    def __str__(self):
        out = []
        out.append('%s' % self.label)
        for assignblk in self:
            for dst, src in assignblk.iteritems():
                out.append('\t%s = %s' % (dst, src))
            out.append("")
        return "\n".join(out)


    def modify_exprs(self, mod_dst=None, mod_src=None):
        """
        Generate a new IRBlock with its AssignBlock expressions modified
        according to @mod_dst and @mod_src
        @mod_dst: function called to modify Expression destination
        @mod_src: function called to modify Expression source
        """

        if mod_dst is None:
            mod_dst = lambda expr:expr
        if mod_src is None:
            mod_src = lambda expr:expr

        assignblks = []
        for assignblk in self:
            new_assignblk = {}
            for dst, src in assignblk.iteritems():
                new_assignblk[mod_dst(dst)] = mod_src(src)
            assignblks.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.label, assignblks)


class irbloc(IRBlock):
    """
    DEPRECATED object
    Use IRBlock instead of irbloc
    """

    def __init__(self, label, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "IRBlock" instead of "irblock"')
        super(irbloc, self).__init__(label, irs)


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
        for i, assignblk in enumerate(self._blocks[node]):
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

    def instr2ir(self, instr):
        ir_bloc_cur, extra_irblocks = self.get_ir(instr)
        for index, irb in enumerate(extra_irblocks):
            irs = []
            for assignblk in irb:
                irs.append(AssignBlock(assignblk, instr))
            extra_irblocks[index] = IRBlock(irb.label, irs)
        assignblk = AssignBlock(ir_bloc_cur, instr)
        return assignblk, extra_irblocks

    def get_label(self, addr):
        """Transforms an ExprId/ExprInt/label/int into a label
        @addr: an ExprId/ExprInt/label/int"""

        if (isinstance(addr, m2_expr.ExprId) and
                isinstance(addr.name, AsmLabel)):
            addr = addr.name
        if isinstance(addr, AsmLabel):
            return addr

        try:
            addr = int(addr)
        except (ValueError, TypeError):
            return None

        return self.symbol_pool.getby_offset_create(addr)

    def get_block(self, addr):
        """Returns the irbloc associated to an ExprId/ExprInt/label/int
        @addr: an ExprId/ExprInt/label/int"""

        label = self.get_label(addr)
        return self.blocks.get(label, None)

    def get_bloc(self, addr):
        """
        DEPRECATED function
        Use get_block instead of get_block
        """
        warnings.warn('DEPRECATION WARNING: use "get_block" instead of "get_bloc"')
        return self.get_block(addr)

    def add_instr(self, line, addr=0, gen_pc_updt=False):
        block = AsmBlock(self.gen_label())
        block.lines = [line]
        self.add_block(block, gen_pc_updt)

    def getby_offset(self, offset):
        out = set()
        for irb in self.blocks.values():
            for assignblk in irb:
                instr = assignblk.instr
                if instr.offset <= offset < instr.offset + instr.l:
                    out.add(irb)
        return out

    def gen_pc_update(self, assignments, instr):
        offset = m2_expr.ExprInt(instr.offset, self.pc.size)
        assignments.append(AssignBlock({self.pc:offset}, instr))

    def pre_add_instr(self, block, instr, assignments, ir_blocks_all, gen_pc_updt):
        """Function called before adding an instruction from the the native @block to
        the current irbloc.

        Returns a couple. The first element is the new irblock. The second the a
        bool:
        * True if the current irblock must be split
        * False in other cases.

        @block: native block source
        @instr: native instruction
        @irb_cur: current irbloc
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions

        """

        return False

    def add_instr_to_irblock(self, block, instr, assignments, ir_blocks_all, gen_pc_updt):
        """
        Add the IR effects of an instruction to the current irblock.

        Returns a couple. The first element is the new irblock. The second the a
        bool:
        * True if the current irblock must be split
        * False in other cases.

        @block: native block source
        @instr: native instruction
        @irb_cur: current irbloc
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions
        """

        split = self.pre_add_instr(block, instr, assignments, ir_blocks_all, gen_pc_updt)
        if split:
            return True

        assignblk, ir_blocks_extra = self.instr2ir(instr)

        if gen_pc_updt is not False:
            self.gen_pc_update(assignments, instr)

        assignments.append(assignblk)
        ir_blocks_all += ir_blocks_extra
        if ir_blocks_extra:
            return True
        return False

    def add_block(self, block, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @gen_pc_updt: insert PC update effects between instructions
        """

        label = None
        ir_blocks_all = []
        for instr in block.lines:
            if label is None:
                assignments = []
                label = self.get_instr_label(instr)
            split = self.add_instr_to_irblock(block, instr, assignments,
                                              ir_blocks_all, gen_pc_updt)
            if split:
                ir_blocks_all.append(IRBlock(label, assignments))
                label = None
                assignments = []
        if label is not None:
            ir_blocks_all.append(IRBlock(label, assignments))

        new_ir_blocks_all = self.post_add_block(block, ir_blocks_all)
        for irblock in new_ir_blocks_all:
            self.blocks[irblock.label] = irblock
        return new_ir_blocks_all

    def add_bloc(self, block, gen_pc_updt=False):
        """
        DEPRECATED function
        Use add_block instead of add_block
        """
        warnings.warn('DEPRECATION WARNING: use "add_block" instead of "add_bloc"')
        return self.add_block(block, gen_pc_updt)

    def expr_fix_regs_for_mode(self, expr, *args, **kwargs):
        return expr

    def expraff_fix_regs_for_mode(self, expr, *args, **kwargs):
        return expr

    def irbloc_fix_regs_for_mode(self, irblock, *args, **kwargs):
        return irblock

    def is_pc_written(self, block):
        """Return the first Assignblk of the @blockin which PC is written
        @block: IRBlock instance"""
        all_pc = self.arch.pc.values()
        for assignblk in block:
            if assignblk.dst in all_pc:
                return assignblk
        return None

    def set_empty_dst_to_next(self, block, ir_blocks):
        for index, irblock in enumerate(ir_blocks):
            if irblock.dst is not None:
                continue
            next_lbl = block.get_next()
            if next_lbl is None:
                dst = m2_expr.ExprId(self.get_next_label(block.lines[-1]),
                                     self.pc.size)
            else:
                dst = m2_expr.ExprId(next_lbl,
                                     self.pc.size)
            assignblk = AssignBlock({self.IRDst: dst}, irblock[-1].instr)
            ir_blocks[index] = IRBlock(irblock.label, list(irblock.assignblks) + [assignblk])

    def post_add_block(self, block, ir_blocks):
        self.set_empty_dst_to_next(block, ir_blocks)

        new_irblocks = []
        for irblock in ir_blocks:
            new_irblock = self.irbloc_fix_regs_for_mode(irblock, self.attrib)
            self.blocks[irblock.label] = new_irblock
            new_irblocks.append(new_irblock)
        # Forget graph if any
        self._graph = None
        return new_irblocks

    def post_add_bloc(self, block, ir_blocks):
        """
        DEPRECATED function
        Use post_add_block instead of post_add_bloc
        """
        warnings.warn('DEPRECATION WARNING: use "post_add_block" instead of "post_add_bloc"')
        return self.post_add_block(block, ir_blocks)

    def get_instr_label(self, instr):
        """Returns the label associated to an instruction
        @instr: current instruction"""

        return self.symbol_pool.getby_offset_create(instr.offset)

    def gen_label(self):
        # TODO: fix hardcoded offset
        label = self.symbol_pool.gen_label()
        return label

    def get_next_label(self, instr):
        label = self.symbol_pool.getby_offset_create(instr.offset + instr.l)
        return label

    def simplify(self, simplifier):
        """
        Simplify expressions in each irblocks
        @simplifier: ExpressionSimplifier instance
        """
        for label, block in self.blocks.iteritems():
            assignblks = []
            for assignblk in block:
                new_assignblk = assignblk.simplify(simplifier)
                assignblks.append(new_assignblk)
            self.blocks[label] = IRBlock(label, assignblks)

    def replace_expr_in_ir(self, bloc, rep):
        for assignblk in bloc:
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

        for assignblk in reversed(irb):
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
        for lbl, block in self.blocks.iteritems():
            self._graph.add_node(lbl)
            for dst in self.dst_trackback(block):
                if dst.is_int():
                    dst_lbl = self.symbol_pool.getby_offset_create(int(dst))
                    dst = m2_expr.ExprId(dst_lbl, self.pc.size)
                if expr_is_label(dst):
                    self._graph.add_edge(lbl, dst.name)

    @property
    def graph(self):
        """Get a DiGraph representation of current IR instance.
        Lazy property, building the graph on-demand"""
        if self._graph is None:
            self._gen_graph()
        return self._graph

    def remove_empty_assignblks(self):
        modified = False
        for label, block in self.blocks.iteritems():
            irs = []
            for assignblk in block:
                if len(assignblk):
                    irs.append(assignblk)
                else:
                    modified = True
            self.blocks[label] = IRBlock(label, irs)
        return modified

    def remove_jmp_blocks(self):
        """
        Remove irblock with only IRDst set, by linking it's parent destination to
        the block destination.
        """

        # Find candidates
        jmp_blocks = set()
        for block in self.blocks.itervalues():
            if len(block) != 1:
                continue
            assignblk = block[0]
            if len(assignblk) > 1:
                continue
            assert set(assignblk.keys()) == set([self.IRDst])
            if len(self.graph.successors(block.label)) != 1:
                continue
            if not expr_is_label(assignblk[self.IRDst]):
                continue
            jmp_blocks.add(block.label)

        # Remove them, relink graph
        modified = False
        for label in jmp_blocks:
            block = self.blocks[label]
            dst_label = block.dst.name
            parents = self.graph.predecessors(block.label)
            for lbl in parents:
                parent = self.blocks.get(lbl, None)
                if parent is None:
                    continue
                dst = parent.dst
                if dst.is_id(block.label):
                    dst = m2_expr.ExprId(dst_label, dst.size)

                    self.graph.discard_edge(lbl, block.label)
                    self.graph.discard_edge(block.label, dst_label)

                    self.graph.add_uniq_edge(lbl, dst_label)
                    modified = True
                elif dst.is_cond():
                    src1, src2 = dst.src1, dst.src2
                    if src1.is_id(block.label):
                        dst = m2_expr.ExprCond(dst.cond, m2_expr.ExprId(dst_label, dst.size), dst.src2)
                        self.graph.discard_edge(lbl, block.label)
                        self.graph.discard_edge(block.label, dst_label)
                        self.graph.add_uniq_edge(lbl, dst_label)
                        modified = True
                    if src2.is_id(block.label):
                        dst = m2_expr.ExprCond(dst.cond, dst.src1, m2_expr.ExprId(dst_label, dst.size))
                        self.graph.discard_edge(lbl, block.label)
                        self.graph.discard_edge(block.label, dst_label)
                        self.graph.add_uniq_edge(lbl, dst_label)
                        modified = True
                    if dst.src1 == dst.src2:
                        dst = src1
                else:
                    continue
                new_parent = parent.set_dst(dst)
                self.blocks[parent.label] = new_parent

        # Remove unlinked useless nodes
        for label in jmp_blocks:
            if (len(self.graph.predecessors(label)) == 0 and
                len(self.graph.successors(label)) == 0):
                self.graph.del_node(label)
                del self.blocks[label]
        return modified

    def merge_blocks(self):
        """
        Group irblock with one and only one son if this son has one and only one
        parent
        """
        modified = False
        todo = set(self.graph.nodes())
        while todo:
            block = todo.pop()
            sons = self.graph.successors(block)
            if len(sons) != 1:
                continue
            son = list(sons)[0]
            if self.graph.predecessors(son) != [block]:
                continue
            if block not in self.blocks:
                continue
            if son not in self.blocks:
                continue
            # Block has one son, son has one parent => merge
            assignblks =[]
            for assignblk in self.blocks[block]:
                if self.IRDst not in assignblk:
                    assignblks.append(assignblk)
                    continue
                affs = {}
                for dst, src in assignblk.iteritems():
                    if dst != self.IRDst:
                        affs[dst] = src
                assignblks.append(AssignBlock(affs, assignblk.instr))

            assignblks += self.blocks[son].assignblks
            new_block = IRBlock(block, assignblks)

            self.graph.discard_edge(block, son)

            for lson in self.graph.successors(son):
                self.graph.add_uniq_edge(block, lson)
                self.graph.discard_edge(son, lson)
            del self.blocks[son]
            self.graph.del_node(son)

            self.blocks[block] = new_block
            todo.add(block)
            modified = True
        return modified


class ir(IntermediateRepresentation):
    """
    DEPRECATED object
    Use IntermediateRepresentation instead of ir
    """

    def __init__(self, label, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "IntermediateRepresentation" instead of "ir"')
        super(ir, self).__init__(label, irs, lines)
