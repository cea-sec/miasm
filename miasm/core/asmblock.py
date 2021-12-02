#-*- coding:utf-8 -*-

from builtins import map
from builtins import range
import logging
import warnings
from collections import namedtuple
from builtins import int as int_types

from future.utils import viewitems, viewvalues

from miasm.expression.expression import ExprId, ExprInt, get_expr_locs
from miasm.expression.expression import LocKey
from miasm.expression.simplifications import expr_simp
from miasm.core.utils import Disasm_Exception, pck
from miasm.core.graph import DiGraph, DiGraphSimplifier, MatchGraphJoker
from miasm.core.interval import interval


log_asmblock = logging.getLogger("asmblock")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log_asmblock.addHandler(console_handler)
log_asmblock.setLevel(logging.WARNING)


class AsmRaw(object):

    def __init__(self, raw=b""):
        self.raw = raw

    def __str__(self):
        return repr(self.raw)

    def to_string(self, loc_db):
        return str(self)

    def to_html(self, loc_db):
        return str(self)


class AsmConstraint(object):
    c_to = "c_to"
    c_next = "c_next"

    def __init__(self, loc_key, c_t=c_to):
        # Sanity check
        assert isinstance(loc_key, LocKey)

        self.loc_key = loc_key
        self.c_t = c_t

    def to_string(self, loc_db=None):
        if loc_db is None:
            return "%s:%s" % (self.c_t, self.loc_key)
        else:
            return "%s:%s" % (
                self.c_t,
                loc_db.pretty_str(self.loc_key)
            )

    def __str__(self):
        return self.to_string()


class AsmConstraintNext(AsmConstraint):

    def __init__(self, loc_key):
        super(AsmConstraintNext, self).__init__(
            loc_key,
            c_t=AsmConstraint.c_next
        )


class AsmConstraintTo(AsmConstraint):

    def __init__(self, loc_key):
        super(AsmConstraintTo, self).__init__(
            loc_key,
            c_t=AsmConstraint.c_to
        )


class AsmBlock(object):

    def __init__(self, loc_db, loc_key, alignment=1):
        assert isinstance(loc_key, LocKey)

        self.bto = set()
        self.lines = []
        self.loc_db = loc_db
        self._loc_key = loc_key
        self.alignment = alignment

    loc_key = property(lambda self:self._loc_key)

    def to_string(self):
        out = []
        out.append(self.loc_db.pretty_str(self.loc_key))

        for instr in self.lines:
            out.append(instr.to_string(self.loc_db))
        if self.bto:
            lbls = ["->"]
            for dst in self.bto:
                if dst is None:
                    lbls.append("Unknown? ")
                else:
                    lbls.append(dst.to_string(self.loc_db) + " ")
            lbls = '\t'.join(sorted(lbls))
            out.append(lbls)
        return '\n'.join(out)

    def __str__(self):
        return self.to_string()

    def addline(self, l):
        self.lines.append(l)

    def addto(self, c):
        assert isinstance(self.bto, set)
        self.bto.add(c)

    def split(self, offset):
        loc_key = self.loc_db.get_or_create_offset_location(offset)
        log_asmblock.debug('split at %x', offset)
        offsets = [x.offset for x in self.lines]
        offset = self.loc_db.get_location_offset(loc_key)
        if offset not in offsets:
            log_asmblock.warning(
                'cannot split block at %X ' % offset +
                'middle instruction? default middle')
            offsets.sort()
            return None
        new_block = AsmBlock(self.loc_db, loc_key)
        i = offsets.index(offset)

        self.lines, new_block.lines = self.lines[:i], self.lines[i:]
        flow_mod_instr = self.get_flow_instr()
        log_asmblock.debug('flow mod %r', flow_mod_instr)
        c = AsmConstraint(loc_key, AsmConstraint.c_next)
        # move dst if flowgraph modifier was in original block
        # (usecase: split delayslot block)
        if flow_mod_instr:
            for xx in self.bto:
                log_asmblock.debug('lbl %s', xx)
            c_next = set(
                x for x in self.bto if x.c_t == AsmConstraint.c_next
            )
            c_to = [x for x in self.bto if x.c_t != AsmConstraint.c_next]
            self.bto = set([c] + c_to)
            new_block.bto = c_next
        else:
            new_block.bto = self.bto
            self.bto = set([c])
        return new_block

    def get_range(self):
        """Returns the offset hull of an AsmBlock"""
        if len(self.lines):
            return (self.lines[0].offset,
                    self.lines[-1].offset + self.lines[-1].l)
        else:
            return 0, 0

    def get_offsets(self):
        return [x.offset for x in self.lines]

    def add_cst(self, loc_key, constraint_type):
        """
        Add constraint between current block and block at @loc_key
        @loc_key: LocKey instance of constraint target
        @constraint_type: AsmConstraint c_to/c_next
        """
        assert isinstance(loc_key, LocKey)
        c = AsmConstraint(loc_key, constraint_type)
        self.bto.add(c)

    def get_flow_instr(self):
        if not self.lines:
            return None
        for i in range(-1, -1 - self.lines[0].delayslot - 1, -1):
            if not 0 <= i < len(self.lines):
                return None
            l = self.lines[i]
            if l.splitflow() or l.breakflow():
                raise NotImplementedError('not fully functional')

    def get_subcall_instr(self):
        if not self.lines:
            return None
        delayslot = self.lines[0].delayslot
        end_index = len(self.lines) - 1
        ds_max_index = max(end_index - delayslot, 0)
        for i in range(end_index, ds_max_index - 1, -1):
            l = self.lines[i]
            if l.is_subcall():
                return l
        return None

    def get_next(self):
        for constraint in self.bto:
            if constraint.c_t == AsmConstraint.c_next:
                return constraint.loc_key
        return None

    @staticmethod
    def _filter_constraint(constraints):
        """Sort and filter @constraints for AsmBlock.bto
        @constraints: non-empty set of AsmConstraint instance

        Always the same type -> one of the constraint
        c_next and c_to -> c_next
        """
        # Only one constraint
        if len(constraints) == 1:
            return next(iter(constraints))

        # Constraint type -> set of corresponding constraint
        cbytype = {}
        for cons in constraints:
            cbytype.setdefault(cons.c_t, set()).add(cons)

        # Only one type -> any constraint is OK
        if len(cbytype) == 1:
            return next(iter(constraints))

        # At least 2 types -> types = {c_next, c_to}
        # c_to is included in c_next
        return next(iter(cbytype[AsmConstraint.c_next]))

    def fix_constraints(self):
        """Fix next block constraints"""
        # destination -> associated constraints
        dests = {}
        for constraint in self.bto:
            dests.setdefault(constraint.loc_key, set()).add(constraint)

        self.bto = set(
            self._filter_constraint(constraints)
            for constraints in viewvalues(dests)
        )


class AsmBlockBad(AsmBlock):

    """Stand for a *bad* ASM block (malformed, unreachable,
    not disassembled, ...)"""


    ERROR_UNKNOWN = -1
    ERROR_CANNOT_DISASM = 0
    ERROR_NULL_STARTING_BLOCK = 1
    ERROR_FORBIDDEN = 2
    ERROR_IO = 3


    ERROR_TYPES = {
        ERROR_UNKNOWN: "Unknown error",
        ERROR_CANNOT_DISASM: "Unable to disassemble",
        ERROR_NULL_STARTING_BLOCK: "Null starting block",
        ERROR_FORBIDDEN: "Address forbidden by dont_dis",
        ERROR_IO: "IOError",
    }

    def __init__(self, loc_db, loc_key=None, alignment=1, errno=ERROR_UNKNOWN, *args, **kwargs):
        """Instantiate an AsmBlock_bad.
        @loc_key, @alignment: same as AsmBlock.__init__
        @errno: (optional) specify a error type associated with the block
        """
        super(AsmBlockBad, self).__init__(loc_db, loc_key, alignment, *args, **kwargs)
        self._errno = errno

    errno = property(lambda self: self._errno)

    def __str__(self):
        error_txt = self.ERROR_TYPES.get(self._errno, self._errno)
        return "%s\n\tBad block: %s" % (
            self.loc_key,
            error_txt
        )

    def addline(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot have line")

    def addto(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot have bto")

    def split(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot be split")


class AsmCFG(DiGraph):

    """Directed graph standing for a ASM Control Flow Graph with:
     - nodes: AsmBlock
     - edges: constraints between blocks, synchronized with AsmBlock's "bto"

    Specialized the .dot export and force the relation between block to be uniq,
    and associated with a constraint.

    Offer helpers on AsmCFG management, such as research by loc_key, sanity
    checking and mnemonic size guessing.
    """

    # Internal structure for pending management
    AsmCFGPending = namedtuple("AsmCFGPending",
                               ["waiter", "constraint"])

    def __init__(self, loc_db, *args, **kwargs):
        super(AsmCFG, self).__init__(*args, **kwargs)
        # Edges -> constraint
        self.edges2constraint = {}
        # Expected LocKey -> set( (src, dst), constraint )
        self._pendings = {}
        # Loc_Key2block built on the fly
        self._loc_key_to_block = {}
        # loc_db
        self.loc_db = loc_db


    def copy(self):
        """Copy the current graph instance"""
        graph = self.__class__(self.loc_db)
        return graph + self

    def __len__(self):
        """Return the number of blocks in AsmCFG"""
        return len(self._nodes)

    @property
    def blocks(self):
        return viewvalues(self._loc_key_to_block)

    # Manage graph with associated constraints
    def add_edge(self, src, dst, constraint):
        """Add an edge to the graph
        @src: LocKey instance, source
        @dst: LocKey instance, destination
        @constraint: constraint associated to this edge
        """
        # Sanity check
        assert isinstance(src, LocKey)
        assert isinstance(dst, LocKey)
        known_cst = self.edges2constraint.get((src, dst), None)
        if known_cst is not None:
            assert known_cst == constraint
            return

        # Add the edge to src.bto if needed
        block_src = self.loc_key_to_block(src)
        if block_src:
            if dst not in [cons.loc_key for cons in block_src.bto]:
                block_src.bto.add(AsmConstraint(dst, constraint))

        # Add edge
        self.edges2constraint[(src, dst)] = constraint
        super(AsmCFG, self).add_edge(src, dst)

    def add_uniq_edge(self, src, dst, constraint):
        """
        Synonym for `add_edge`
        """
        self.add_edge(src, dst, constraint)

    def del_edge(self, src, dst):
        """Delete the edge @src->@dst and its associated constraint"""
        src_blk = self.loc_key_to_block(src)
        dst_blk = self.loc_key_to_block(dst)
        assert src_blk is not None
        assert dst_blk is not None
        # Delete from src.bto
        to_remove = [cons for cons in src_blk.bto if cons.loc_key == dst]
        if to_remove:
            assert len(to_remove) == 1
            src_blk.bto.remove(to_remove[0])

        # Del edge
        del self.edges2constraint[(src, dst)]
        super(AsmCFG, self).del_edge(src, dst)

    def del_block(self, block):
        super(AsmCFG, self).del_node(block.loc_key)
        del self._loc_key_to_block[block.loc_key]


    def add_node(self, node):
        assert isinstance(node, LocKey)
        return super(AsmCFG, self).add_node(node)

    def add_block(self, block):
        """
        Add the block @block to the current instance, if it is not already in
        @block: AsmBlock instance

        Edges will be created for @block.bto, if destinations are already in
        this instance. If not, they will be resolved when adding these
        aforementioned destinations.
        `self.pendings` indicates which blocks are not yet resolved.

        """
        status = super(AsmCFG, self).add_node(block.loc_key)

        if not status:
            return status

        # Update waiters
        if block.loc_key in self._pendings:
            for bblpend in self._pendings[block.loc_key]:
                self.add_edge(bblpend.waiter.loc_key, block.loc_key, bblpend.constraint)
            del self._pendings[block.loc_key]

        # Synchronize edges with block destinations
        self._loc_key_to_block[block.loc_key] = block

        for constraint in block.bto:
            dst = self._loc_key_to_block.get(constraint.loc_key,
                                           None)
            if dst is None:
                # Block is yet unknown, add it to pendings
                to_add = self.AsmCFGPending(waiter=block,
                                            constraint=constraint.c_t)
                self._pendings.setdefault(constraint.loc_key,
                                          set()).add(to_add)
            else:
                # Block is already in known nodes
                self.add_edge(block.loc_key, dst.loc_key, constraint.c_t)

        return status

    def merge(self, graph):
        """Merge with @graph, taking in account constraints"""
        # Add known blocks
        for block in graph.blocks:
            self.add_block(block)
        # Add nodes not already in it (ie. not linked to a block)
        for node in graph.nodes():
            self.add_node(node)
        # -> add_edge(x, y, constraint)
        for edge in graph._edges:
            # May fail if there is an incompatibility in edges constraints
            # between the two graphs
            self.add_edge(*edge, constraint=graph.edges2constraint[edge])

    def escape_text(self, text):
        return text


    def node2lines(self, node):
        loc_key_name = self.loc_db.pretty_str(node)
        yield self.DotCellDescription(text=loc_key_name,
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})
        block = self._loc_key_to_block.get(node, None)
        if block is None:
            return
        if isinstance(block, AsmBlockBad):
            yield [
                self.DotCellDescription(
                    text=block.ERROR_TYPES.get(block._errno,
                                               block._errno
                    ),
                    attr={})
            ]
            return
        for line in block.lines:
            if self._dot_offset:
                yield [self.DotCellDescription(text="%.8X" % line.offset,
                                               attr={}),
                       self.DotCellDescription(text=line.to_html(self.loc_db), attr={})]
            else:
                yield self.DotCellDescription(text=line.to_html(self.loc_db), attr={})

    def node_attr(self, node):
        block = self._loc_key_to_block.get(node, None)
        if isinstance(block, AsmBlockBad):
            return {'style': 'filled', 'fillcolor': 'red'}
        return {}

    def edge_attr(self, src, dst):
        cst = self.edges2constraint.get((src, dst), None)
        edge_color = "blue"

        if len(self.successors(src)) > 1:
            if cst == AsmConstraint.c_next:
                edge_color = "red"
            else:
                edge_color = "limegreen"

        return {"color": edge_color}

    def dot(self, offset=False):
        """
        @offset: (optional) if set, add the corresponding offsets in each node
        """
        self._dot_offset = offset
        return super(AsmCFG, self).dot()

    # Helpers
    @property
    def pendings(self):
        """Dictionary of loc_key -> set(AsmCFGPending instance) indicating
        which loc_key are missing in the current instance.
        A loc_key is missing if a block which is already in nodes has constraints
        with him (thanks to its .bto) and the corresponding block is not yet in
        nodes
        """
        return self._pendings

    def rebuild_edges(self):
        """Consider blocks '.bto' and rebuild edges according to them, ie:
        - update constraint type
        - add missing edge
        - remove no more used edge

        This method should be called if a block's '.bto' in nodes have been
        modified without notifying this instance to resynchronize edges.
        """
        self._pendings = {}
        for block in self.blocks:
            edges = []
            # Rebuild edges from bto
            for constraint in block.bto:
                dst = self._loc_key_to_block.get(constraint.loc_key,
                                                  None)
                if dst is None:
                    # Missing destination, add to pendings
                    self._pendings.setdefault(
                        constraint.loc_key,
                        set()
                    ).add(
                        self.AsmCFGPending(
                            block,
                            constraint.c_t
                        )
                    )
                    continue
                edge = (block.loc_key, dst.loc_key)
                edges.append(edge)
                if edge in self._edges:
                    # Already known edge, constraint may have changed
                    self.edges2constraint[edge] = constraint.c_t
                else:
                    # An edge is missing
                    self.add_edge(edge[0], edge[1], constraint.c_t)

            # Remove useless edges
            for succ in self.successors(block.loc_key):
                edge = (block.loc_key, succ)
                if edge not in edges:
                    self.del_edge(*edge)

    def get_bad_blocks(self):
        """Iterator on AsmBlockBad elements"""
        # A bad asm block is always a leaf
        for loc_key in self.leaves():
            block = self._loc_key_to_block.get(loc_key, None)
            if isinstance(block, AsmBlockBad):
                yield block

    def get_bad_blocks_predecessors(self, strict=False):
        """Iterator on loc_keys with an AsmBlockBad destination
        @strict: (optional) if set, return loc_key with only bad
        successors
        """
        # Avoid returning the same block
        done = set()
        for badblock in self.get_bad_blocks():
            for predecessor in self.predecessors_iter(badblock.loc_key):
                if predecessor not in done:
                    if (strict and
                        not all(isinstance(self._loc_key_to_block.get(block, None), AsmBlockBad)
                                for block in self.successors_iter(predecessor))):
                        continue
                    yield predecessor
                    done.add(predecessor)

    def getby_offset(self, offset):
        """Return asmblock containing @offset"""
        for block in self.blocks:
            if block.lines[0].offset <= offset < \
                    (block.lines[-1].offset + block.lines[-1].l):
                return block
        return None

    def loc_key_to_block(self, loc_key):
        """
        Return the asmblock corresponding to loc_key @loc_key, None if unknown
        loc_key
        @loc_key: LocKey instance
        """
        return self._loc_key_to_block.get(loc_key, None)

    def sanity_check(self):
        """Do sanity checks on blocks' constraints:
        * no pendings
        * no multiple next constraint to same block
        * no next constraint to self
        """

        if len(self._pendings) != 0:
            raise RuntimeError(
                "Some blocks are missing: %s" % list(
                    map(
                        str,
                        self._pendings
                    )
                )
            )

        next_edges = {
            edge: constraint
            for edge, constraint in viewitems(self.edges2constraint)
            if constraint == AsmConstraint.c_next
        }

        for loc_key in self._nodes:
            if loc_key not in self._loc_key_to_block:
                raise RuntimeError("Not supported yet: every node must have a corresponding AsmBlock")
            # No next constraint to self
            if (loc_key, loc_key) in next_edges:
                raise RuntimeError('Bad constraint: self in next')

            # No multiple next constraint to same block
            pred_next = list(ploc_key
                             for (ploc_key, dloc_key) in next_edges
                             if dloc_key == loc_key)

            if len(pred_next) > 1:
                raise RuntimeError("Too many next constraints for block %r"
                                   "(%s)" % (loc_key,
                                             pred_next))

    def guess_blocks_size(self, mnemo):
        """Asm and compute max block size
        Add a 'size' and 'max_size' attribute on each block
        @mnemo: metamn instance"""
        for block in self.blocks:
            size = 0
            for instr in block.lines:
                if isinstance(instr, AsmRaw):
                    # for special AsmRaw, only extract len
                    if isinstance(instr.raw, list):
                        data = None
                        if len(instr.raw) == 0:
                            l = 0
                        else:
                            l = (instr.raw[0].size // 8) * len(instr.raw)
                    elif isinstance(instr.raw, str):
                        data = instr.raw.encode()
                        l = len(data)
                    elif isinstance(instr.raw, bytes):
                        data = instr.raw
                        l = len(data)
                    else:
                        raise NotImplementedError('asm raw')
                else:
                    # Assemble the instruction to retrieve its len.
                    # If the instruction uses symbol it will fail
                    # In this case, the max_instruction_len is used
                    try:
                        candidates = mnemo.asm(instr)
                        l = len(candidates[-1])
                    except:
                        l = mnemo.max_instruction_len
                    data = None
                instr.data = data
                instr.l = l
                size += l

            block.size = size
            block.max_size = size
            log_asmblock.info("size: %d max: %d", block.size, block.max_size)

    def apply_splitting(self, loc_db, dis_block_callback=None, **kwargs):
        warnings.warn('DEPRECATION WARNING: apply_splitting is member of disasm_engine')
        raise RuntimeError("Moved api")

    def __str__(self):
        out = []
        for block in self.blocks:
            out.append(str(block))
        for loc_key_a, loc_key_b in self.edges():
            out.append("%s -> %s" % (loc_key_a, loc_key_b))
        return '\n'.join(out)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, hex(id(self)))

# Out of _merge_blocks to be computed only once
_acceptable_block = lambda graph, loc_key: (not isinstance(graph.loc_key_to_block(loc_key), AsmBlockBad) and
                                   len(graph.loc_key_to_block(loc_key).lines) > 0)
_parent = MatchGraphJoker(restrict_in=False, filt=_acceptable_block)
_son = MatchGraphJoker(restrict_out=False, filt=_acceptable_block)
_expgraph = _parent >> _son


def _merge_blocks(dg, graph):
    """Graph simplification merging AsmBlock with one and only one son with this
    son if this son has one and only one parent"""

    # Blocks to ignore, because they have been removed from the graph
    to_ignore = set()

    for match in _expgraph.match(graph):

        # Get matching blocks
        lbl_block, lbl_succ = match[_parent], match[_son]
        block = graph.loc_key_to_block(lbl_block)
        succ = graph.loc_key_to_block(lbl_succ)

        # Ignore already deleted blocks
        if (block in to_ignore or
            succ in to_ignore):
            continue

        # Remove block last instruction if needed
        last_instr = block.lines[-1]
        if last_instr.delayslot > 0:
            # TODO: delayslot
            raise RuntimeError("Not implemented yet")

        if last_instr.is_subcall():
            continue
        if last_instr.breakflow() and last_instr.dstflow():
            block.lines.pop()

        # Merge block
        block.lines += succ.lines
        for nextb in graph.successors_iter(lbl_succ):
            graph.add_edge(lbl_block, nextb, graph.edges2constraint[(lbl_succ, nextb)])

        graph.del_block(succ)
        to_ignore.add(lbl_succ)


bbl_simplifier = DiGraphSimplifier()
bbl_simplifier.enable_passes([_merge_blocks])


def conservative_asm(mnemo, instr, symbols, conservative):
    """
    Asm instruction;
    Try to keep original instruction bytes if it exists
    """
    candidates = mnemo.asm(instr, symbols)
    if not candidates:
        raise ValueError('cannot asm:%s' % str(instr))
    if not hasattr(instr, "b"):
        return candidates[0], candidates
    if instr.b in candidates:
        return instr.b, candidates
    if conservative:
        for c in candidates:
            if len(c) == len(instr.b):
                return c, candidates
    return candidates[0], candidates


def fix_expr_val(expr, symbols):
    """Resolve an expression @expr using @symbols"""
    def expr_calc(e):
        if isinstance(e, ExprId):
            # Example:
            # toto:
            # .dword label
            loc_key = symbols.get_name_location(e.name)
            offset = symbols.get_location_offset(loc_key)
            e = ExprInt(offset, e.size)
        return e
    result = expr.visit(expr_calc)
    result = expr_simp(result)
    if not isinstance(result, ExprInt):
        raise RuntimeError('Cannot resolve symbol %s' % expr)
    return result


def fix_loc_offset(loc_db, loc_key, offset, modified):
    """
    Fix the @loc_key offset to @offset. If the @offset has changed, add @loc_key
    to @modified
    @loc_db: current loc_db
    """
    loc_offset = loc_db.get_location_offset(loc_key)
    if loc_offset == offset:
        return
    if loc_offset is not None:
        loc_db.unset_location_offset(loc_key)
    loc_db.set_location_offset(loc_key, offset)
    modified.add(loc_key)


class BlockChain(object):

    """Manage blocks linked with an asm_constraint_next"""

    def __init__(self, loc_db, blocks):
        self.loc_db = loc_db
        self.blocks = blocks
        self.place()

    @property
    def pinned(self):
        """Return True iff at least one block is pinned"""
        return self.pinned_block_idx is not None

    def _set_pinned_block_idx(self):
        self.pinned_block_idx = None
        for i, block in enumerate(self.blocks):
            loc_key = block.loc_key
            if self.loc_db.get_location_offset(loc_key) is not None:
                if self.pinned_block_idx is not None:
                    raise ValueError("Multiples pinned block detected")
                self.pinned_block_idx = i

    def place(self):
        """Compute BlockChain min_offset and max_offset using pinned block and
        blocks' size
        """
        self._set_pinned_block_idx()
        self.max_size = 0
        for block in self.blocks:
            self.max_size += block.max_size + block.alignment - 1

        # Check if chain has one block pinned
        if not self.pinned:
            return

        loc = self.blocks[self.pinned_block_idx].loc_key
        offset_base = self.loc_db.get_location_offset(loc)
        assert(offset_base % self.blocks[self.pinned_block_idx].alignment == 0)

        self.offset_min = offset_base
        for block in self.blocks[:self.pinned_block_idx - 1:-1]:
            self.offset_min -= block.max_size + \
                (block.alignment - block.max_size) % block.alignment

        self.offset_max = offset_base
        for block in self.blocks[self.pinned_block_idx:]:
            self.offset_max += block.max_size + \
                (block.alignment - block.max_size) % block.alignment

    def merge(self, chain):
        """Best effort merge two block chains
        Return the list of resulting blockchains"""
        self.blocks += chain.blocks
        self.place()
        return [self]

    def fix_blocks(self, modified_loc_keys):
        """Propagate a pinned to its blocks' neighbour
        @modified_loc_keys: store new pinned loc_keys"""

        if not self.pinned:
            raise ValueError('Trying to fix unpinned block')

        # Propagate offset to blocks before pinned block
        pinned_block = self.blocks[self.pinned_block_idx]
        offset = self.loc_db.get_location_offset(pinned_block.loc_key)
        if offset % pinned_block.alignment != 0:
            raise RuntimeError('Bad alignment')

        for block in self.blocks[:self.pinned_block_idx - 1:-1]:
            new_offset = offset - block.size
            new_offset = new_offset - new_offset % pinned_block.alignment
            fix_loc_offset(self.loc_db,
                           block.loc_key,
                           new_offset,
                           modified_loc_keys)

        # Propagate offset to blocks after pinned block
        offset = self.loc_db.get_location_offset(pinned_block.loc_key) + pinned_block.size

        last_block = pinned_block
        for block in self.blocks[self.pinned_block_idx + 1:]:
            offset += (- offset) % last_block.alignment
            fix_loc_offset(self.loc_db,
                           block.loc_key,
                           offset,
                           modified_loc_keys)
            offset += block.size
            last_block = block
        return modified_loc_keys


class BlockChainWedge(object):

    """Stand for wedges between blocks"""

    def __init__(self, loc_db, offset, size):
        self.loc_db = loc_db
        self.offset = offset
        self.max_size = size
        self.offset_min = offset
        self.offset_max = offset + size

    def merge(self, chain):
        """Best effort merge two block chains
        Return the list of resulting blockchains"""
        self.loc_db.set_location_offset(chain.blocks[0].loc_key, self.offset_max)
        chain.place()
        return [self, chain]


def group_constrained_blocks(asmcfg):
    """
    Return the BlockChains list built from grouped blocks in asmcfg linked by
    asm_constraint_next
    @asmcfg: an AsmCfg instance
    """
    log_asmblock.info('group_constrained_blocks')

    # Group adjacent asmcfg
    remaining_blocks = list(asmcfg.blocks)
    known_block_chains = {}

    while remaining_blocks:
        # Create a new block chain
        block_list = [remaining_blocks.pop()]

        # Find sons in remainings blocks linked with a next constraint
        while True:
            # Get next block
            next_loc_key = block_list[-1].get_next()
            if next_loc_key is None or asmcfg.loc_key_to_block(next_loc_key) is None:
                break
            next_block = asmcfg.loc_key_to_block(next_loc_key)

            # Add the block at the end of the current chain
            if next_block not in remaining_blocks:
                break
            block_list.append(next_block)
            remaining_blocks.remove(next_block)

        # Check if son is in a known block group
        if next_loc_key is not None and next_loc_key in known_block_chains:
            block_list += known_block_chains[next_loc_key]
            del known_block_chains[next_loc_key]

        known_block_chains[block_list[0].loc_key] = block_list

    out_block_chains = []
    for loc_key in known_block_chains:
        chain = BlockChain(asmcfg.loc_db, known_block_chains[loc_key])
        out_block_chains.append(chain)
    return out_block_chains


def get_blockchains_address_interval(blockChains, dst_interval):
    """Compute the interval used by the pinned @blockChains
    Check if the placed chains are in the @dst_interval"""

    allocated_interval = interval()
    for chain in blockChains:
        if not chain.pinned:
            continue
        chain_interval = interval([(chain.offset_min, chain.offset_max - 1)])
        if chain_interval not in dst_interval:
            raise ValueError('Chain placed out of destination interval')
        allocated_interval += chain_interval
    return allocated_interval


def resolve_symbol(blockChains, loc_db, dst_interval=None):
    """Place @blockChains in the @dst_interval"""

    log_asmblock.info('resolve_symbol')
    if dst_interval is None:
        dst_interval = interval([(0, 0xFFFFFFFFFFFFFFFF)])

    forbidden_interval = interval(
        [(-1, 0xFFFFFFFFFFFFFFFF + 1)]) - dst_interval
    allocated_interval = get_blockchains_address_interval(blockChains,
                                                          dst_interval)
    log_asmblock.debug('allocated interval: %s', allocated_interval)

    pinned_chains = [chain for chain in blockChains if chain.pinned]

    # Add wedge in forbidden intervals
    for start, stop in forbidden_interval.intervals:
        wedge = BlockChainWedge(
            loc_db, offset=start, size=stop + 1 - start)
        pinned_chains.append(wedge)

    # Try to place bigger blockChains first
    pinned_chains.sort(key=lambda x: x.offset_min)
    blockChains.sort(key=lambda x: -x.max_size)

    fixed_chains = list(pinned_chains)

    log_asmblock.debug("place chains")
    for chain in blockChains:
        if chain.pinned:
            continue
        fixed = False
        for i in range(1, len(fixed_chains)):
            prev_chain = fixed_chains[i - 1]
            next_chain = fixed_chains[i]

            if prev_chain.offset_max + chain.max_size < next_chain.offset_min:
                new_chains = prev_chain.merge(chain)
                fixed_chains[i - 1:i] = new_chains
                fixed = True
                break
        if not fixed:
            raise RuntimeError('Cannot find enough space to place blocks')

    return [chain for chain in fixed_chains if isinstance(chain, BlockChain)]


def get_block_loc_keys(block):
    """Extract loc_keys used by @block"""
    symbols = set()
    for instr in block.lines:
        if isinstance(instr, AsmRaw):
            if isinstance(instr.raw, list):
                for expr in instr.raw:
                    symbols.update(get_expr_locs(expr))
        else:
            for arg in instr.args:
                symbols.update(get_expr_locs(arg))
    return symbols


def assemble_block(mnemo, block, conservative=False):
    """Assemble a @block
    @conservative: (optional) use original bytes when possible
    """
    offset_i = 0

    for instr in block.lines:
        if isinstance(instr, AsmRaw):
            if isinstance(instr.raw, list):
                # Fix special AsmRaw
                data = b""
                for expr in instr.raw:
                    expr_int = fix_expr_val(expr, block.loc_db)
                    data += pck[expr_int.size](int(expr_int))
                instr.data = data

            instr.offset = offset_i
            offset_i += instr.l
            continue

        # Assemble an instruction
        saved_args = list(instr.args)
        instr.offset = block.loc_db.get_location_offset(block.loc_key) + offset_i

        # Replace instruction's arguments by resolved ones
        instr.args = instr.resolve_args_with_symbols(block.loc_db)

        if instr.dstflow():
            instr.fixDstOffset()

        old_l = instr.l
        cached_candidate, _ = conservative_asm(
            mnemo, instr, block.loc_db,
            conservative
        )
        if len(cached_candidate) != instr.l:
            # The output instruction length is different from the one we guessed
            # Retry assembly with updated length
            instr.l = len(cached_candidate)
            instr.args = saved_args
            instr.args = instr.resolve_args_with_symbols(block.loc_db)
            if instr.dstflow():
                instr.fixDstOffset()
            cached_candidate, _ = conservative_asm(
                mnemo, instr, block.loc_db,
                conservative
            )
            assert len(cached_candidate) == instr.l

        # Restore original arguments
        instr.args = saved_args

        # We need to update the block size
        block.size = block.size - old_l + len(cached_candidate)
        instr.data = cached_candidate
        instr.l = len(cached_candidate)

        offset_i += instr.l


def asmblock_final(mnemo, asmcfg, blockChains, conservative=False):
    """Resolve and assemble @blockChains until fixed point is
    reached"""

    log_asmblock.debug("asmbloc_final")

    # Init structures
    blocks_using_loc_key = {}
    for block in asmcfg.blocks:
        exprlocs = get_block_loc_keys(block)
        loc_keys = set(expr.loc_key for expr in exprlocs)
        for loc_key in loc_keys:
            blocks_using_loc_key.setdefault(loc_key, set()).add(block)

    block2chain = {}
    for chain in blockChains:
        for block in chain.blocks:
            block2chain[block] = chain

    # Init worklist
    blocks_to_rework = set(asmcfg.blocks)

    # Fix and re-assemble blocks until fixed point is reached
    while True:

        # Propagate pinned blocks into chains
        modified_loc_keys = set()
        for chain in blockChains:
            chain.fix_blocks(modified_loc_keys)

        for loc_key in modified_loc_keys:
            # Retrieve block with modified reference
            mod_block = asmcfg.loc_key_to_block(loc_key)
            if mod_block is not None:
                blocks_to_rework.add(mod_block)

            # Enqueue blocks referencing a modified loc_key
            if loc_key not in blocks_using_loc_key:
                continue
            for block in blocks_using_loc_key[loc_key]:
                blocks_to_rework.add(block)

        # No more work
        if not blocks_to_rework:
            break

        while blocks_to_rework:
            block = blocks_to_rework.pop()
            assemble_block(mnemo, block, conservative)


def asm_resolve_final(mnemo, asmcfg, dst_interval=None):
    """Resolve and assemble @asmcfg into interval
    @dst_interval"""

    asmcfg.sanity_check()

    asmcfg.guess_blocks_size(mnemo)
    blockChains = group_constrained_blocks(asmcfg)
    resolved_blockChains = resolve_symbol(blockChains, asmcfg.loc_db, dst_interval)
    asmblock_final(mnemo, asmcfg, resolved_blockChains)
    patches = {}
    output_interval = interval()

    for block in asmcfg.blocks:
        offset = asmcfg.loc_db.get_location_offset(block.loc_key)
        for instr in block.lines:
            if not instr.data:
                # Empty line
                continue
            assert len(instr.data) == instr.l
            patches[offset] = instr.data
            instruction_interval = interval([(offset, offset + instr.l - 1)])
            if not (instruction_interval & output_interval).empty:
                raise RuntimeError("overlapping bytes %X" % int(offset))
            output_interval = output_interval.union(instruction_interval)
            instr.offset = offset
            offset += instr.l
    return patches


class disasmEngine(object):

    """Disassembly engine, taking care of disassembler options and mutli-block
    strategy.

    Engine options:

    + Object supporting membership test (offset in ..)
     - dont_dis: stop the current disassembly branch if reached
     - split_dis: force a basic block end if reached,
                  with a next constraint on its successor
     - dont_dis_retcall_funcs: stop disassembly after a call to one
                               of the given functions

    + On/Off
     - follow_call: recursively disassemble CALL destinations
     - dontdis_retcall: stop on CALL return addresses
     - dont_dis_nulstart_bloc: stop if a block begin with a few \x00

    + Number
     - lines_wd: maximum block's size (in number of instruction)
     - blocs_wd: maximum number of distinct disassembled block

    + callback(mdis, cur_block, offsets_to_dis)
     - dis_block_callback: callback after each new disassembled block
    """

    def __init__(self, arch, attrib, bin_stream, loc_db, **kwargs):
        """Instantiate a new disassembly engine
        @arch: targeted architecture
        @attrib: architecture attribute
        @bin_stream: bytes source
        @kwargs: (optional) custom options
        """
        self.arch = arch
        self.attrib = attrib
        self.bin_stream = bin_stream
        self.loc_db = loc_db

        # Setup options
        self.dont_dis = []
        self.split_dis = []
        self.follow_call = False
        self.dontdis_retcall = False
        self.lines_wd = None
        self.blocs_wd = None
        self.dis_block_callback = None
        self.dont_dis_nulstart_bloc = False
        self.dont_dis_retcall_funcs = set()

        # Override options if needed
        self.__dict__.update(kwargs)

    def _dis_block(self, offset, job_done=None):
        """Disassemble the block at offset @offset
        @job_done: a set of already disassembled addresses
        Return the created AsmBlock and future offsets to disassemble
        """

        if job_done is None:
            job_done = set()
        lines_cpt = 0
        in_delayslot = False
        delayslot_count = self.arch.delayslot
        offsets_to_dis = set()
        add_next_offset = False
        loc_key = self.loc_db.get_or_create_offset_location(offset)
        cur_block = AsmBlock(self.loc_db, loc_key)
        log_asmblock.debug("dis at %X", int(offset))
        while not in_delayslot or delayslot_count > 0:
            if in_delayslot:
                delayslot_count -= 1

            if offset in self.dont_dis:
                if not cur_block.lines:
                    job_done.add(offset)
                    # Block is empty -> bad block
                    cur_block = AsmBlockBad(self.loc_db, loc_key, errno=AsmBlockBad.ERROR_FORBIDDEN)
                else:
                    # Block is not empty, stop the desassembly pass and add a
                    # constraint to the next block
                    loc_key_cst = self.loc_db.get_or_create_offset_location(offset)
                    cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                break

            if lines_cpt > 0 and offset in self.split_dis:
                loc_key_cst = self.loc_db.get_or_create_offset_location(offset)
                cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                offsets_to_dis.add(offset)
                break

            lines_cpt += 1
            if self.lines_wd is not None and lines_cpt > self.lines_wd:
                log_asmblock.debug("lines watchdog reached at %X", int(offset))
                break

            if offset in job_done:
                loc_key_cst = self.loc_db.get_or_create_offset_location(offset)
                cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                break

            off_i = offset
            error = None
            try:
                instr = self.arch.dis(self.bin_stream, self.attrib, offset)
            except Disasm_Exception as e:
                log_asmblock.warning(e)
                instr = None
                error = AsmBlockBad.ERROR_CANNOT_DISASM
            except IOError as e:
                log_asmblock.warning(e)
                instr = None
                error = AsmBlockBad.ERROR_IO


            if instr is None:
                log_asmblock.warning("cannot disasm at %X", int(off_i))
                if not cur_block.lines:
                    job_done.add(offset)
                    # Block is empty -> bad block
                    cur_block = AsmBlockBad(self.loc_db, loc_key, errno=error)
                else:
                    # Block is not empty, stop the desassembly pass and add a
                    # constraint to the next block
                    loc_key_cst = self.loc_db.get_or_create_offset_location(off_i)
                    cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
                break

            # XXX TODO nul start block option
            if (self.dont_dis_nulstart_bloc and
                not cur_block.lines and
                instr.b.count(b'\x00') == instr.l):
                log_asmblock.warning("reach nul instr at %X", int(off_i))
                # Block is empty -> bad block
                cur_block = AsmBlockBad(self.loc_db, loc_key, errno=AsmBlockBad.ERROR_NULL_STARTING_BLOCK)
                break

            # special case: flow graph modificator in delayslot
            if in_delayslot and instr and (instr.splitflow() or instr.breakflow()):
                add_next_offset = True
                break

            job_done.add(offset)
            log_asmblock.debug("dis at %X", int(offset))

            offset += instr.l
            log_asmblock.debug(instr)
            log_asmblock.debug(instr.args)

            cur_block.addline(instr)
            if not instr.breakflow():
                continue
            # test split
            if instr.splitflow() and not (instr.is_subcall() and self.dontdis_retcall):
                add_next_offset = True
            if instr.dstflow():
                instr.dstflow2label(self.loc_db)
                destinations = instr.getdstflow(self.loc_db)
                known_dsts = []
                for dst in destinations:
                    if not dst.is_loc():
                        continue
                    loc_key = dst.loc_key
                    loc_key_offset = self.loc_db.get_location_offset(loc_key)
                    known_dsts.append(loc_key)
                    if loc_key_offset in self.dont_dis_retcall_funcs:
                        add_next_offset = False
                if (not instr.is_subcall()) or self.follow_call:
                    cur_block.bto.update([AsmConstraint(loc_key, AsmConstraint.c_to) for loc_key in known_dsts])

            # get in delayslot mode
            in_delayslot = True
            delayslot_count = instr.delayslot

        for c in cur_block.bto:
            loc_key_offset = self.loc_db.get_location_offset(c.loc_key)
            offsets_to_dis.add(loc_key_offset)

        if add_next_offset:
            loc_key_cst = self.loc_db.get_or_create_offset_location(offset)
            cur_block.add_cst(loc_key_cst, AsmConstraint.c_next)
            offsets_to_dis.add(offset)

        # Fix multiple constraints
        cur_block.fix_constraints()

        if self.dis_block_callback is not None:
            self.dis_block_callback(self, cur_block, offsets_to_dis)
        return cur_block, offsets_to_dis

    def dis_block(self, offset):
        """Disassemble the block at offset @offset and return the created
        AsmBlock
        @offset: targeted offset to disassemble
        """
        current_block, _ = self._dis_block(offset)
        return current_block

    def dis_multiblock(self, offset, blocks=None, job_done=None):
        """Disassemble every block reachable from @offset regarding
        specific disasmEngine conditions
        Return an AsmCFG instance containing disassembled blocks
        @offset: starting offset
        @blocks: (optional) AsmCFG instance of already disassembled blocks to
                merge with
        """
        log_asmblock.info("dis block all")
        if job_done is None:
            job_done = set()
        if blocks is None:
            blocks = AsmCFG(self.loc_db)
        todo = [offset]

        bloc_cpt = 0
        while len(todo):
            bloc_cpt += 1
            if self.blocs_wd is not None and bloc_cpt > self.blocs_wd:
                log_asmblock.debug("blocks watchdog reached at %X", int(offset))
                break

            target_offset = int(todo.pop(0))
            if (target_offset is None or
                    target_offset in job_done):
                continue
            cur_block, nexts = self._dis_block(target_offset, job_done)
            todo += nexts
            blocks.add_block(cur_block)

        self.apply_splitting(blocks)
        return blocks

    def apply_splitting(self, blocks):
        """Consider @blocks' bto destinations and split block in @blocks if one
        of these destinations jumps in the middle of this block.  In order to
        work, they must be only one block in @self per loc_key in

        @blocks: Asmcfg
        """
        # Get all possible destinations not yet resolved, with a resolved
        # offset
        block_dst = []
        for loc_key in blocks.pendings:
            offset = self.loc_db.get_location_offset(loc_key)
            if offset is not None:
                block_dst.append(offset)

        todo = set(blocks.blocks)
        rebuild_needed = False

        while todo:
            # Find a block with a destination inside another one
            cur_block = todo.pop()
            range_start, range_stop = cur_block.get_range()

            for off in block_dst:
                if not (off > range_start and off < range_stop):
                    continue

                # `cur_block` must be split at offset `off`from miasm.core.locationdb import LocationDB

                new_b = cur_block.split(off)
                log_asmblock.debug("Split block %x", off)
                if new_b is None:
                    log_asmblock.error("Cannot split %x!!", off)
                    continue

                # Remove pending from cur_block
                # Links from new_b will be generated in rebuild_edges
                for dst in new_b.bto:
                    if dst.loc_key not in blocks.pendings:
                        continue
                    blocks.pendings[dst.loc_key] = set(pending for pending in blocks.pendings[dst.loc_key]
                                                     if pending.waiter != cur_block)

                # The new block destinations may need to be disassembled
                if self.dis_block_callback:
                    offsets_to_dis = set(
                        self.loc_db.get_location_offset(constraint.loc_key)
                        for constraint in new_b.bto
                    )
                    self.dis_block_callback(self, new_b, offsets_to_dis)

                # Update structure
                rebuild_needed = True
                blocks.add_block(new_b)

                # The new block must be considered
                todo.add(new_b)
                range_start, range_stop = cur_block.get_range()

        # Rebuild edges to match new blocks'bto
        if rebuild_needed:
            blocks.rebuild_edges()

    def dis_instr(self, offset):
        """Disassemble one instruction at offset @offset and return the
        corresponding instruction instance
        @offset: targeted offset to disassemble
        """
        old_lineswd = self.lines_wd
        self.lines_wd = 1
        try:
            block = self.dis_block(offset)
        finally:
            self.lines_wd = old_lineswd

        instr = block.lines[0]
        return instr
