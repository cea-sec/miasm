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
from builtins import zip
import warnings

from itertools import chain
from future.utils import viewvalues, viewitems

import miasm.expression.expression as m2_expr
from miasm.expression.expression_helper import get_missing_interval
from miasm.core.asmblock import AsmBlock, AsmBlockBad, AsmConstraint
from miasm.core.graph import DiGraph
from miasm.ir.translators import Translator
from functools import reduce
from miasm.core import utils
import re


def _expr_loc_to_symb(expr, loc_db):
    if not expr.is_loc():
        return expr
    if loc_db is None:
        name = str(expr)
    else:
        names = loc_db.get_location_names(expr.loc_key)
        if not names:
            name = loc_db.pretty_str(expr.loc_key)
        else:
            # Use only one name for readability
            name = sorted(names)[0]
    return m2_expr.ExprId(name, expr.size)


ESCAPE_CHARS = re.compile('[' + re.escape('{}') + '&|<>' + ']')

class TranslatorHtml(Translator):
    __LANG__ = "custom_expr_color"

    @staticmethod
    def _fix_chars(token):
        return "&#%04d;" % ord(token.group())

    def __init__(self, loc_db=None, **kwargs):
        super(TranslatorHtml, self).__init__(**kwargs)
        self.loc_db = loc_db

    def str_protected_child(self, child, parent):
        return ("(%s)" % (
            self.from_expr(child)) if m2_expr.should_parenthesize_child(child, parent)
                else self.from_expr(child)
        )

    def from_ExprInt(self, expr):
        out = str(expr)
        out = '<font color="%s">%s</font>' % (utils.COLOR_INT, out)
        return out

    def from_ExprId(self, expr):
        out = str(expr)
        out = '<font color="%s">%s</font>' % (utils.COLOR_ID, out)
        return out

    def from_ExprLoc(self, expr):

        if self.loc_db is None:
            name = ESCAPE_CHARS.sub(self._fix_chars, str((expr)))
        else:
            names = self.loc_db.get_location_names(expr.loc_key)
            if not names:
                name = self.loc_db.pretty_str(expr.loc_key)
            else:
                # Use only one name for readability
                name = sorted(names)[0]
        name = ESCAPE_CHARS.sub(self._fix_chars, name)
        out = '<font color="%s">%s</font>' % (utils.COLOR_LOC, name)
        return out

    def from_ExprMem(self, expr):
        ptr = self.from_expr(expr.ptr)
        size = '@' + str(expr.size)
        size = '<font color="%s">%s</font>' % (utils.COLOR_MEM, size)
        bracket_left = ESCAPE_CHARS.sub(self._fix_chars, '[')
        bracket_right = ESCAPE_CHARS.sub(self._fix_chars, ']')
        out = '%s%s%s%s' % (size, bracket_left, ptr, bracket_right)
        return out

    def from_ExprSlice(self, expr):
        base = self.from_expr(expr.arg)
        start = str(expr.start)
        stop = str(expr.stop)
        bracket_left = ESCAPE_CHARS.sub(self._fix_chars, '[')
        bracket_right = ESCAPE_CHARS.sub(self._fix_chars, ']')
        out = "(%s)%s%s:%s%s" % (base, bracket_left, start, stop, bracket_right)
        return out

    def from_ExprCompose(self, expr):
        out = ESCAPE_CHARS.sub(self._fix_chars, "{")
        out += ", ".join(["%s, %s, %s" % (self.from_expr(subexpr),
                                          str(idx),
                                          str(idx + subexpr.size))
                          for idx, subexpr in expr.iter_args()])
        out += ESCAPE_CHARS.sub(self._fix_chars, "}")
        return out

    def from_ExprCond(self, expr):
        cond = self.str_protected_child(expr.cond, expr)
        src1 = self.from_expr(expr.src1)
        src2 = self.from_expr(expr.src2)
        out = "%s?(%s,%s)" % (cond, src1, src2)
        return out

    def from_ExprOp(self, expr):
        op = ESCAPE_CHARS.sub(self._fix_chars, expr._op)
        if expr._op == '-':		# Unary minus
            return '-' + self.str_protected_child(expr._args[0], expr)
        if expr.is_associative() or expr.is_infix():
            return (' ' + op + ' ').join([self.str_protected_child(arg, expr)
                                          for arg in expr._args])

        op = '<font color="%s">%s</font>' % (utils.COLOR_OP_FUNC, op)
        return (op + '(' +
                ', '.join(
                    self.from_expr(arg)
                    for arg in expr._args
                ) + ')')

    def from_ExprAssign(self, expr):
        return "%s = %s" % tuple(map(expr.from_expr, (expr.dst, expr.src)))


def color_expr_html(expr, loc_db):
    translator = TranslatorHtml(loc_db=loc_db)
    return translator.from_expr(expr)

def slice_rest(expr):
    "Return the completion of the current slice"
    size = expr.arg.size
    if expr.start >= size or expr.stop > size:
        raise ValueError('bad slice rest %s %s %s' %
                         (size, expr.start, expr.stop))

    if expr.start == expr.stop:
        return [(0, size)]

    rest = []
    if expr.start != 0:
        rest.append((0, expr.start))
    if expr.stop < size:
        rest.append((expr.stop, size))

    return rest



class AssignBlock(object):
    """Represent parallel IR assignment, such as:
    EAX = EBX
    EBX = EAX

    -> Exchange between EBX and EAX

    AssignBlock can be seen as a dictionary where keys are the destinations
    (ExprId or ExprMem), and values their corresponding sources.

    Also provides common manipulation on this assignments.

    """
    __slots__ = ["_assigns", "_instr"]

    def __init__(self, irs=None, instr=None):
        """Create a new AssignBlock
        @irs: (optional) sequence of ExprAssign, or dictionary dst (Expr) -> src
              (Expr)
        @instr: (optional) associate an instruction with this AssignBlock

        """
        if irs is None:
            irs = []
        self._instr = instr
        self._assigns = {} # ExprAssign.dst -> ExprAssign.src

        # Concurrent assignments are handled in _set
        if hasattr(irs, "items"):
            for dst, src in viewitems(irs):
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
        * if dst is an ExprSlice, expand it to assign the full Expression
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
                    for r in slice_rest(dst)]
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
                raise RuntimeError("Concurrent access on same bit not allowed")

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
                        "Concurrent access on same bit not allowed")

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
        for dst, src in viewitems(self._assigns):
            yield dst, src

    def items(self):
        return [(dst, src) for dst, src in viewitems(self._assigns)]

    def itervalues(self):
        for src in viewvalues(self._assigns):
            yield src

    def keys(self):
        return list(self._assigns)

    def values(self):
        return list(viewvalues(self._assigns))

    def __iter__(self):
        for dst in self._assigns:
            yield dst

    def __delitem__(self, _):
        raise RuntimeError('AssignBlock is immutable')

    def update(self, _):
        raise RuntimeError('AssignBlock is immutable')

    def __eq__(self, other):
        if set(self.keys()) != set(other.keys()):
            return False
        return all(other[dst] == src for dst, src in viewitems(self))

    def __ne__(self, other):
        return not self == other

    def __len__(self):
        return len(self._assigns)

    def get(self, key, default):
        return self._assigns.get(key, default)

    @staticmethod
    def get_modified_slice(dst, src):
        """Return an Expr list of extra expressions needed during the
        object instantiation"""
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
        """Return a dictionary associating written expressions to a set of
        their read requirements
        @mem_read: (optional) mem_read argument of `get_r`
        @cst_read: (optional) cst_read argument of `get_r`
        """
        out = {}
        for dst, src in viewitems(self):
            src_read = src.get_r(mem_read=mem_read, cst_read=cst_read)
            if isinstance(dst, m2_expr.ExprMem) and mem_read:
                # Read on destination happens only with ExprMem
                src_read.update(dst.ptr.get_r(mem_read=mem_read,
                                              cst_read=cst_read))
            out[dst] = src_read
        return out

    def get_r(self, mem_read=False, cst_read=False):
        """Return a set of elements reads
        @mem_read: (optional) mem_read argument of `get_r`
        @cst_read: (optional) cst_read argument of `get_r`
        """
        return set(
            chain.from_iterable(
                viewvalues(
                    self.get_rw(
                        mem_read=mem_read,
                        cst_read=cst_read
                    )
                )
            )
        )

    def __str__(self):
        out = []
        for dst, src in sorted(viewitems(self._assigns)):
            out.append("%s = %s" % (dst, src))
        return "\n".join(out)

    def dst2ExprAssign(self, dst):
        """Return an ExprAssign corresponding to @dst equation
        @dst: Expr instance"""
        return m2_expr.ExprAssign(dst, self[dst])

    def simplify(self, simplifier):
        """
        Return a new AssignBlock with expression simplified

        @simplifier: ExpressionSimplifier instance
        """
        new_assignblk = {}
        for dst, src in viewitems(self):
            if dst == src:
                continue
            new_src = simplifier(src)
            new_dst = simplifier(dst)
            new_assignblk[new_dst] = new_src
        return AssignBlock(irs=new_assignblk, instr=self.instr)

    def to_string(self, loc_db=None):
        out = []
        for dst, src in viewitems(self):
            new_src = src.visit(lambda expr:_expr_loc_to_symb(expr, loc_db))
            new_dst = dst.visit(lambda expr:_expr_loc_to_symb(expr, loc_db))
            line = "%s = %s" % (new_dst, new_src)
            out.append(line)
            out.append("")
        return "\n".join(out)

class IRBlock(object):
    """Intermediate representation block object.

    Stand for an intermediate representation  basic block.
    """

    __slots__ = ["_loc_db", "_loc_key", "_assignblks", "_dst", "_dst_linenb"]

    def __init__(self, loc_db, loc_key, assignblks):
        """
        @loc_key: LocKey of the IR basic block
        @assignblks: list of AssignBlock
        """

        assert isinstance(loc_key, m2_expr.LocKey)
        self._loc_key = loc_key
        self._loc_db = loc_db
        for assignblk in assignblks:
            assert isinstance(assignblk, AssignBlock)
        self._assignblks = tuple(assignblks)
        self._dst = None
        self._dst_linenb = None

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            return False
        if self.loc_key != other.loc_key:
            return False
        if self.loc_db != other.loc_db:
            return False
        if len(self.assignblks) != len(other.assignblks):
            return False
        for assignblk1, assignblk2 in zip(self.assignblks, other.assignblks):
            if assignblk1 != assignblk2:
                return False
        return True

    def __ne__(self, other):
        return not self == other

    def get_label(self):
        warnings.warn('DEPRECATION WARNING: use ".loc_key" instead of ".label"')
        return self.loc_key

    loc_key = property(lambda self:self._loc_key)
    loc_db = property(lambda self:self._loc_db)
    label = property(get_label)

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
            for dst, src in viewitems(assignblk):
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
            for dst, src in viewitems(assignblk):
                if dst.is_id("IRDst"):
                    assert dst_found is False
                    dst_found = True
                    new_assignblk[dst] = value
                else:
                    new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.loc_db, self.loc_key, irs)

    @property
    def dst_linenb(self):
        """Line number of the IRDst setting statement in the current irs"""
        if not self.is_dst_set():
            self.cache_dst()
        return self._dst_linenb

    def to_string(self):
        out = []
        names = self.loc_db.get_location_names(self.loc_key)
        if not names:
            node_name = "%s:" % self.loc_db.pretty_str(self.loc_key)
        else:
            node_name = "".join("%s:\n" % name for name in names)
        out.append(node_name)

        for assignblk in self:
            out.append(assignblk.to_string(self.loc_db))
        return '\n'.join(out)

    def __str__(self):
        return self.to_string()

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
            for dst, src in viewitems(assignblk):
                new_assignblk[mod_dst(dst)] = mod_src(src)
            assignblks.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.loc_db, self.loc_key, assignblks)

    def simplify(self, simplifier):
        """
        Simplify expressions in each assignblock
        @simplifier: ExpressionSimplifier instance
        """
        modified = False
        assignblks = []
        for assignblk in self:
            new_assignblk = assignblk.simplify(simplifier)
            if assignblk != new_assignblk:
                modified = True
            assignblks.append(new_assignblk)
        return modified, IRBlock(self.loc_db, self.loc_key, assignblks)


class irbloc(IRBlock):
    """
    DEPRECATED object
    Use IRBlock instead of irbloc
    """

    def __init__(self, loc_key, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "IRBlock" instead of "irblock"')
        super(irbloc, self).__init__(loc_key, irs)



class IRCFG(DiGraph):

    """DiGraph for IR instances"""

    def __init__(self, irdst, loc_db, blocks=None, *args, **kwargs):
        """Instantiate a IRCFG
        @loc_db: LocationDB instance
        @blocks: IR blocks
        """
        self.loc_db = loc_db
        if blocks is None:
            blocks = {}
        self._blocks = blocks
        self._irdst = irdst
        super(IRCFG, self).__init__(*args, **kwargs)

    @property
    def IRDst(self):
        return self._irdst

    @property
    def blocks(self):
        return self._blocks

    def add_irblock(self, irblock):
        """
        Add the @irblock to the current IRCFG
        @irblock: IRBlock instance
        """
        self.blocks[irblock.loc_key] = irblock
        self.add_node(irblock.loc_key)

        for dst in self.dst_trackback(irblock):
            if dst.is_int():
                dst_loc_key = self.loc_db.get_or_create_offset_location(int(dst))
                dst = m2_expr.ExprLoc(dst_loc_key, irblock.dst.size)
            if dst.is_loc():
                self.add_uniq_edge(irblock.loc_key, dst.loc_key)

    def escape_text(self, text):
        return text

    def node2lines(self, node):
        node_name = self.loc_db.pretty_str(node)
        yield self.DotCellDescription(
            text="%s" % node_name,
            attr={
                'align': 'center',
                'colspan': 2,
                'bgcolor': 'grey',
            }
        )
        if node not in self._blocks:
            yield [self.DotCellDescription(text="NOT PRESENT", attr={'bgcolor': 'red'})]
            return
        for i, assignblk in enumerate(self._blocks[node]):
            for dst, src in viewitems(assignblk):
                line = "%s = %s" % (
                    color_expr_html(dst, self.loc_db),
                    color_expr_html(src, self.loc_db)
                )
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
            src1, src2 = src_irdst.src1, src_irdst.src2
            if src1.is_loc(dst):
                edge_color = "limegreen"
            elif src2.is_loc(dst):
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
        return super(IRCFG, self).dot()

    def get_loc_key(self, addr):
        """Transforms an ExprId/ExprInt/loc_key/int into a loc_key
        @addr: an ExprId/ExprInt/loc_key/int"""

        if isinstance(addr, m2_expr.LocKey):
            return addr
        elif isinstance(addr, m2_expr.ExprLoc):
            return addr.loc_key

        try:
            addr = int(addr)
        except (ValueError, TypeError):
            return None

        return self.loc_db.get_offset_location(addr)


    def get_or_create_loc_key(self, addr):
        """Transforms an ExprId/ExprInt/loc_key/int into a loc_key
        If the offset @addr is not in the LocationDB, create it
        @addr: an ExprId/ExprInt/loc_key/int"""

        loc_key = self.get_loc_key(addr)
        if loc_key is not None:
            return loc_key

        return self.loc_db.add_location(offset=int(addr))

    def get_block(self, addr):
        """Returns the irbloc associated to an ExprId/ExprInt/loc_key/int
        @addr: an ExprId/ExprInt/loc_key/int"""

        loc_key = self.get_loc_key(addr)
        if loc_key is None:
            return None
        return self.blocks.get(loc_key, None)

    def getby_offset(self, offset):
        """
        Return the set of loc_keys of irblocks containing @offset
        @offset: address
        """
        out = set()
        for irb in viewvalues(self.blocks):
            for assignblk in irb:
                instr = assignblk.instr
                if instr is None:
                    continue
                if instr.offset <= offset < instr.offset + instr.l:
                    out.add(irb.loc_key)
        return out


    def simplify(self, simplifier):
        """
        Simplify expressions in each irblocks
        @simplifier: ExpressionSimplifier instance
        """
        modified = False
        for loc_key, block in list(viewitems(self.blocks)):
            assignblks = []
            for assignblk in block:
                new_assignblk = assignblk.simplify(simplifier)
                if assignblk != new_assignblk:
                    modified = True
                assignblks.append(new_assignblk)
            self.blocks[loc_key] = IRBlock(self.loc_db, loc_key, assignblks)
        return modified

    def _extract_dst(self, todo, done):
        """
        Naive extraction of @todo destinations
        WARNING: @todo and @done are modified
        """
        out = set()
        while todo:
            dst = todo.pop()
            if dst.is_loc():
                done.add(dst)
            elif dst.is_mem() or dst.is_int():
                done.add(dst)
            elif dst.is_cond():
                todo.add(dst.src1)
                todo.add(dst.src2)
            elif dst.is_id():
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


class DiGraphIR(IRCFG):
    """
    DEPRECATED object
    Use IRCFG instead of DiGraphIR
    """

    def __init__(self, *args, **kwargs):
        warnings.warn('DEPRECATION WARNING: use "IRCFG" instead of "DiGraphIR"')
        raise NotImplementedError("Deprecated")


class Lifter(object):
    """
    Intermediate representation object

    Allow native assembly to intermediate representation traduction
    """

    def __init__(self, arch, attrib, loc_db):
        self.pc = arch.getpc(attrib)
        self.sp = arch.getsp(attrib)
        self.arch = arch
        self.attrib = attrib
        self.loc_db = loc_db
        self.IRDst = None

    def get_ir(self, instr):
        raise NotImplementedError("Abstract Method")

    def new_ircfg(self, *args, **kwargs):
        """
        Return a new instance of IRCFG
        """
        return IRCFG(self.IRDst, self.loc_db, *args, **kwargs)

    def new_ircfg_from_asmcfg(self, asmcfg, *args, **kwargs):
        """
        Return a new instance of IRCFG from an @asmcfg
        @asmcfg: AsmCFG instance
        """

        ircfg = IRCFG(self.IRDst, self.loc_db, *args, **kwargs)
        for block in asmcfg.blocks:
            self.add_asmblock_to_ircfg(block, ircfg)
        return ircfg

    def instr2ir(self, instr):
        ir_bloc_cur, extra_irblocks = self.get_ir(instr)
        for index, irb in enumerate(extra_irblocks):
            irs = []
            for assignblk in irb:
                irs.append(AssignBlock(assignblk, instr))
            extra_irblocks[index] = IRBlock(self.loc_db, irb.loc_key, irs)
        assignblk = AssignBlock(ir_bloc_cur, instr)
        return assignblk, extra_irblocks

    def add_instr_to_ircfg(self, instr, ircfg, loc_key=None, gen_pc_updt=False):
        """
        Add the native instruction @instr to the @ircfg
        @instr: instruction instance
        @ircfg: IRCFG instance
        @loc_key: loc_key instance of the instruction destination
        @gen_pc_updt: insert PC update effects between instructions
        """

        if loc_key is None:
            offset = getattr(instr, "offset", None)
            loc_key = self.loc_db.get_or_create_offset_location(offset)
        block = AsmBlock(self.loc_db, loc_key)
        block.lines = [instr]
        self.add_asmblock_to_ircfg(block, ircfg, gen_pc_updt)
        return loc_key

    def gen_pc_update(self, assignments, instr):
        offset = m2_expr.ExprInt(instr.offset, self.pc.size)
        assignments.append(AssignBlock({self.pc:offset}, instr))

    def add_instr_to_current_state(self, instr, block, assignments, ir_blocks_all, gen_pc_updt):
        """
        Add the IR effects of an instruction to the current state.

        Returns a bool:
        * True if the current assignments list must be split
        * False in other cases.

        @instr: native instruction
        @block: native block source
        @assignments: list of current AssignBlocks
        @ir_blocks_all: list of additional effects
        @gen_pc_updt: insert PC update effects between instructions
        """
        if gen_pc_updt is not False:
            self.gen_pc_update(assignments, instr)

        assignblk, ir_blocks_extra = self.instr2ir(instr)
        assignments.append(assignblk)
        ir_blocks_all += ir_blocks_extra
        if ir_blocks_extra:
            return True
        return False

    def add_asmblock_to_ircfg(self, block, ircfg, gen_pc_updt=False):
        """
        Add a native block to the current IR
        @block: native assembly block
        @ircfg: IRCFG instance
        @gen_pc_updt: insert PC update effects between instructions
        """

        loc_key = block.loc_key
        ir_blocks_all = []

        if isinstance(block, AsmBlockBad):
            return ir_blocks_all

        assignments = []
        for instr in block.lines:
            if loc_key is None:
                assignments = []
                loc_key = self.get_loc_key_for_instr(instr)
            split = self.add_instr_to_current_state(
                instr, block, assignments,
                ir_blocks_all, gen_pc_updt
            )
            if split:
                ir_blocks_all.append(IRBlock(self.loc_db, loc_key, assignments))
                loc_key = None
                assignments = []
        if loc_key is not None:
            ir_blocks_all.append(IRBlock(self.loc_db, loc_key, assignments))

        new_ir_blocks_all = self.post_add_asmblock_to_ircfg(block, ircfg, ir_blocks_all)
        for irblock in new_ir_blocks_all:
            ircfg.add_irblock(irblock)
        return new_ir_blocks_all

    def add_block(self, block, gen_pc_updt=False):
        """
        DEPRECATED function
        Use add_asmblock_to_ircfg instead of add_block
        """
        warnings.warn("""DEPRECATION WARNING
        ircfg is now out of Lifter
        Use:
        ircfg = lifter.new_ircfg()
        lifter.add_asmblock_to_ircfg(block, ircfg)
        """)
        raise RuntimeError("API Deprecated")

    def add_bloc(self, block, gen_pc_updt=False):
        """
        DEPRECATED function
        Use add_asmblock_to_ircfg instead of add_bloc
        """
        self.add_block(block, gen_pc_updt)

    def get_next_loc_key(self, instr):
        loc_key = self.loc_db.get_or_create_offset_location(instr.offset + instr.l)
        return loc_key

    def get_loc_key_for_instr(self, instr):
        """Returns the loc_key associated to an instruction
        @instr: current instruction"""
        return self.loc_db.get_or_create_offset_location(instr.offset)

    def gen_loc_key_and_expr(self, size):
        """
        Return a loc_key and it's corresponding ExprLoc
        @size: size of expression
        """
        loc_key = self.loc_db.add_location()
        return loc_key, m2_expr.ExprLoc(loc_key, size)

    def expr_fix_regs_for_mode(self, expr, *args, **kwargs):
        return expr

    def expraff_fix_regs_for_mode(self, expr, *args, **kwargs):
        return expr

    def irbloc_fix_regs_for_mode(self, irblock, *args, **kwargs):
        return irblock

    def is_pc_written(self, block):
        """Return the first Assignblk of the @block in which PC is written
        @block: IRBlock instance"""
        all_pc = viewvalues(self.arch.pc)
        for assignblk in block:
            if assignblk.dst in all_pc:
                return assignblk
        return None

    def set_empty_dst_to_next(self, block, ir_blocks):
        for index, irblock in enumerate(ir_blocks):
            if irblock.dst is not None:
                continue
            next_loc_key = block.get_next()
            if next_loc_key is None:
                loc_key = None
                if block.lines:
                    line = block.lines[-1]
                    if line.offset is not None:
                        loc_key = self.loc_db.get_or_create_offset_location(line.offset + line.l)
                if loc_key is None:
                    loc_key = self.loc_db.add_location()
                block.add_cst(loc_key, AsmConstraint.c_next)
            else:
                loc_key = next_loc_key
            dst = m2_expr.ExprLoc(loc_key, self.pc.size)
            if irblock.assignblks:
                instr = irblock.assignblks[-1].instr
            else:
                instr = None
            assignblk = AssignBlock({self.IRDst: dst}, instr)
            ir_blocks[index] = IRBlock(self.loc_db, irblock.loc_key, list(irblock.assignblks) + [assignblk])

    def post_add_asmblock_to_ircfg(self, block, ircfg, ir_blocks):
        self.set_empty_dst_to_next(block, ir_blocks)

        new_irblocks = []
        for irblock in ir_blocks:
            new_irblock = self.irbloc_fix_regs_for_mode(irblock, self.attrib)
            ircfg.add_irblock(new_irblock)
            new_irblocks.append(new_irblock)
        return new_irblocks


class IntermediateRepresentation(Lifter):
    """
    DEPRECATED object
    Use Lifter instead of IntermediateRepresentation
    """

    def __init__(self, arch, attrib, loc_db):
        warnings.warn('DEPRECATION WARNING: use "Lifter" instead of "IntermediateRepresentation"')
        super(IntermediateRepresentation, self).__init__(arch, attrib, loc_db)


class ir(Lifter):
    """
    DEPRECATED object
    Use Lifter instead of ir
    """

    def __init__(self, loc_key, irs, lines=None):
        warnings.warn('DEPRECATION WARNING: use "Lifter" instead of "ir"')
        super(ir, self).__init__(loc_key, irs, lines)
