#-*- coding:utf-8 -*-

import logging
import inspect
import warnings
from collections import namedtuple

import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.modint import moduint, modint
from miasm2.core.utils import Disasm_Exception, pck
from miasm2.core.graph import DiGraph, DiGraphSimplifier, MatchGraphJoker
from miasm2.core.interval import interval


log_asmblock = logging.getLogger("asmblock")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_asmblock.addHandler(console_handler)
log_asmblock.setLevel(logging.WARNING)


def is_int(a):
    return isinstance(a, int) or isinstance(a, long) or \
        isinstance(a, moduint) or isinstance(a, modint)


def expr_is_label(e):
    return isinstance(e, m2_expr.ExprId) and isinstance(e.name, AsmLabel)


def expr_is_int_or_label(e):
    return isinstance(e, m2_expr.ExprInt) or \
        (isinstance(e, m2_expr.ExprId) and isinstance(e.name, AsmLabel))


class AsmLabel(object):

    "Stand for an assembly label"

    def __init__(self, name="", offset=None):
        self.fixedblocs = False
        if is_int(name):
            name = "loc_%.16X" % (int(name) & 0xFFFFFFFFFFFFFFFF)
        self.name = name
        self.attrib = None
        if offset is None:
            self.offset = offset
        else:
            self.offset = int(offset)

    def __str__(self):
        if isinstance(self.offset, (int, long)):
            return "%s:0x%08x" % (self.name, self.offset)
        else:
            return "%s:%s" % (self.name, str(self.offset))

    def __repr__(self):
        rep = '<%s ' % self.__class__.__name__
        if self.name:
            rep += repr(self.name) + ' '
        rep += '>'
        return rep


class asm_label(AsmLabel):

    def __init__(self, name="", offset=None):
        warnings.warn('DEPRECATION WARNING: use "AsmLabel" instead of "asm_label"')
        super(asm_label, self).__init__(name, offset)

class AsmRaw(object):

    def __init__(self, raw=""):
        self.raw = raw

    def __str__(self):
        return repr(self.raw)


class asm_raw(AsmRaw):

    def __init__(self, raw=""):
        warnings.warn('DEPRECATION WARNING: use "AsmRaw" instead of "asm_raw"')
        super(asm_label, self).__init__(raw)


class AsmConstraint(object):
    c_to = "c_to"
    c_next = "c_next"

    def __init__(self, label, c_t=c_to):
        # Sanity check
        assert isinstance(label, AsmLabel)

        self.label = label
        self.c_t = c_t

    def __str__(self):
        return "%s:%s" % (str(self.c_t), str(self.label))


class asm_constraint(AsmConstraint):

    def __init__(self, label, c_t=AsmConstraint.c_to):
        warnings.warn('DEPRECATION WARNING: use "AsmConstraint" instead of "asm_constraint"')
        super(asm_constraint, self).__init__(label, c_t)


class AsmConstraintNext(AsmConstraint):

    def __init__(self, label):
        super(AsmConstraintNext, self).__init__(
            label, c_t=AsmConstraint.c_next)


class asm_constraint_next(AsmConstraint):

    def __init__(self, label):
        warnings.warn('DEPRECATION WARNING: use "AsmConstraintNext" instead of "asm_constraint_next"')
        super(asm_constraint_next, self).__init__(label)


class AsmConstraintTo(AsmConstraint):

    def __init__(self, label):
        super(AsmConstraintTo, self).__init__(
            label, c_t=AsmConstraint.c_to)

class asm_constraint_to(AsmConstraint):

    def __init__(self, label):
        warnings.warn('DEPRECATION WARNING: use "AsmConstraintTo" instead of "asm_constraint_to"')
        super(asm_constraint_to, self).__init__(label)


class AsmBlock(object):

    def __init__(self, label, alignment=1):
        assert isinstance(label, AsmLabel)
        self.bto = set()
        self.lines = []
        self.label = label
        self.alignment = alignment

    def __str__(self):
        out = []
        out.append(str(self.label))
        for l in self.lines:
            out.append(str(l))
        if self.bto:
            lbls = ["->"]
            for l in self.bto:
                if l is None:
                    lbls.append("Unknown? ")
                else:
                    lbls.append(str(l) + " ")
            lbls = '\t'.join(lbls)
            out.append(lbls)
        return '\n'.join(out)

    def addline(self, l):
        self.lines.append(l)

    def addto(self, c):
        assert isinstance(self.bto, set)
        self.bto.add(c)

    def split(self, offset, l):
        log_asmblock.debug('split at %x', offset)
        i = -1
        offsets = [x.offset for x in self.lines]
        if not l.offset in offsets:
            log_asmblock.warning(
                'cannot split bloc at %X ' % offset +
                'middle instruction? default middle')
            offsets.sort()
            return None
        new_bloc = AsmBlock(l)
        i = offsets.index(offset)

        self.lines, new_bloc.lines = self.lines[:i], self.lines[i:]
        flow_mod_instr = self.get_flow_instr()
        log_asmblock.debug('flow mod %r', flow_mod_instr)
        c = AsmConstraint(l, AsmConstraint.c_next)
        # move dst if flowgraph modifier was in original bloc
        # (usecase: split delayslot bloc)
        if flow_mod_instr:
            for xx in self.bto:
                log_asmblock.debug('lbl %s', xx)
            c_next = set(
                [x for x in self.bto if x.c_t == AsmConstraint.c_next])
            c_to = [x for x in self.bto if x.c_t != AsmConstraint.c_next]
            self.bto = set([c] + c_to)
            new_bloc.bto = c_next
        else:
            new_bloc.bto = self.bto
            self.bto = set([c])
        return new_bloc

    def get_range(self):
        """Returns the offset hull of an AsmBlock"""
        if len(self.lines):
            return (self.lines[0].offset,
                    self.lines[-1].offset + self.lines[-1].l)
        else:
            return 0, 0

    def get_offsets(self):
        return [x.offset for x in self.lines]

    def add_cst(self, offset, c_t, symbol_pool):
        if isinstance(offset, (int, long)):
            l = symbol_pool.getby_offset_create(offset)
        elif isinstance(offset, str):
            l = symbol_pool.getby_name_create(offset)
        elif isinstance(offset, AsmLabel):
            l = offset
        else:
            raise ValueError('unknown offset type %r' % offset)
        c = AsmConstraint(l, c_t)
        self.bto.add(c)

    def get_flow_instr(self):
        if not self.lines:
            return None
        for i in xrange(-1, -1 - self.lines[0].delayslot - 1, -1):
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
        for i in xrange(end_index, ds_max_index - 1, -1):
            l = self.lines[i]
            if l.is_subcall():
                return l
        return None

    def get_next(self):
        for x in self.bto:
            if x.c_t == AsmConstraint.c_next:
                return x.label
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
            dests.setdefault(constraint.label, set()).add(constraint)

        self.bto = set(self._filter_constraint(constraints)
                       for constraints in dests.itervalues())


class asm_bloc(object):

    def __init__(self, label, alignment=1):
        warnings.warn('DEPRECATION WARNING: use "AsmBlock" instead of "asm_bloc"')
        super(asm_bloc, self).__init__(label, alignment)


class AsmBlockBad(AsmBlock):

    """Stand for a *bad* ASM block (malformed, unreachable,
    not disassembled, ...)"""

    ERROR_TYPES = {-1: "Unknown error",
                   0: "Unable to disassemble",
                   1: "Null starting block",
                   2: "Address forbidden by dont_dis",
                   }

    def __init__(self, label=None, alignment=1, errno=-1, *args, **kwargs):
        """Instanciate an AsmBlock_bad.
        @label, @alignement: same as AsmBlock.__init__
        @errno: (optional) specify a error type associated with the block
        """
        super(AsmBlockBad, self).__init__(label, alignment, *args, **kwargs)
        self._errno = errno

    def __str__(self):
        error_txt = self.ERROR_TYPES.get(self._errno, self._errno)
        return "\n".join([str(self.label),
                          "\tBad block: %s" % error_txt])

    def addline(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot have line")

    def addto(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot have bto")

    def split(self, *args, **kwargs):
        raise RuntimeError("An AsmBlockBad cannot be splitted")


class asm_block_bad(AsmBlockBad):

    def __init__(self, label=None, alignment=1, errno=-1, *args, **kwargs):
        warnings.warn('DEPRECATION WARNING: use "AsmBlockBad" instead of "asm_block_bad"')
        super(asm_block_bad, self).__init__(label, alignment, *args, **kwargs)


class AsmSymbolPool(object):

    def __init__(self):
        self._labels = []
        self._name2label = {}
        self._offset2label = {}
        self._label_num = 0

    def add_label(self, name, offset=None):
        """
        Create and add a label to the symbol_pool
        @name: label's name
        @offset: (optional) label's offset
        """
        label = AsmLabel(name, offset)

        # Test for collisions
        if (label.offset in self._offset2label and
                label != self._offset2label[label.offset]):
            raise ValueError('symbol %s has same offset as %s' %
                             (label, self._offset2label[label.offset]))
        if (label.name in self._name2label and
                label != self._name2label[label.name]):
            raise ValueError('symbol %s has same name as %s' %
                             (label, self._name2label[label.name]))

        self._labels.append(label)
        if label.offset is not None:
            self._offset2label[label.offset] = label
        if label.name != "":
            self._name2label[label.name] = label
        return label

    def remove_label(self, label):
        """
        Delete a @label
        """
        self._name2label.pop(label.name, None)
        self._offset2label.pop(label.offset, None)
        if label in self._labels:
            self._labels.remove(label)

    def del_label_offset(self, label):
        """Unpin the @label from its offset"""
        self._offset2label.pop(label.offset, None)
        label.offset = None

    def getby_offset(self, offset):
        """Retrieve label using its @offset"""
        return self._offset2label.get(offset, None)

    def getby_name(self, name):
        """Retrieve label using its @name"""
        return self._name2label.get(name, None)

    def getby_name_create(self, name):
        """Get a label from its @name, create it if it doesn't exist"""
        label = self.getby_name(name)
        if label is None:
            label = self.add_label(name)
        return label

    def getby_offset_create(self, offset):
        """Get a label from its @offset, create it if it doesn't exist"""
        label = self.getby_offset(offset)
        if label is None:
            label = self.add_label(offset, offset)
        return label

    def rename_label(self, label, newname):
        """Rename the @label name to @newname"""
        if newname in self._name2label:
            raise ValueError('Symbol already known')
        self._name2label.pop(label.name, None)
        label.name = newname
        self._name2label[label.name] = label

    def set_offset(self, label, offset):
        """Pin the @label from at @offset
        Note that there is a special case when the offset is a list
        it happens when offsets are recomputed in resolve_symbol*
        """
        if label is None:
            raise ValueError('label should not be None')
        if not label.name in self._name2label:
            raise ValueError('label %s not in symbol pool' % label)
        if offset is not None and offset in self._offset2label:
            raise ValueError('Conflict in label %s' % label)
        self._offset2label.pop(label.offset, None)
        label.offset = offset
        if is_int(label.offset):
            self._offset2label[label.offset] = label

    @property
    def items(self):
        """Return all labels"""
        return self._labels

    def __str__(self):
        return reduce(lambda x, y: x + str(y) + '\n', self._labels, "")

    def __getitem__(self, item):
        if item in self._name2label:
            return self._name2label[item]
        if item in self._offset2label:
            return self._offset2label[item]
        raise KeyError('unknown symbol %r' % item)

    def __contains__(self, item):
        return item in self._name2label or item in self._offset2label

    def merge(self, symbol_pool):
        """Merge with another @symbol_pool"""
        self._labels += symbol_pool._labels
        self._name2label.update(symbol_pool._name2label)
        self._offset2label.update(symbol_pool._offset2label)

    def gen_label(self):
        """Generate a new unpinned label"""
        label = self.add_label("lbl_gen_%.8X" % (self._label_num))
        self._label_num += 1
        return label


class asm_symbol_pool(AsmSymbolPool):

    def __init__(self):
        warnings.warn('DEPRECATION WARNING: use "AsmSymbolPool" instead of "asm_symbol_pool"')
        super(asm_symbol_pool, self).__init__()


class AsmCFG(DiGraph):

    """Directed graph standing for a ASM Control Flow Graph with:
     - nodes: AsmBlock
     - edges: constraints between blocks, synchronized with AsmBlock's "bto"

    Specialized the .dot export and force the relation between block to be uniq,
    and associated with a constraint.

    Offer helpers on AsmCFG management, such as research by label, sanity
    checking and mnemonic size guessing.
    """

    # Internal structure for pending management
    AsmCFGPending = namedtuple("AsmCFGPending",
                               ["waiter", "constraint"])

    def __init__(self, *args, **kwargs):
        super(AsmCFG, self).__init__(*args, **kwargs)
        # Edges -> constraint
        self.edges2constraint = {}
        # Expected AsmLabel -> set( (src, dst), constraint )
        self._pendings = {}
        # Label2block built on the fly
        self._label2block = {}

    # Compatibility with old list API
    def append(self, *args, **kwargs):
        raise DeprecationWarning("AsmCFG is a graph, use add_node")

    def remove(self, *args, **kwargs):
        raise DeprecationWarning("AsmCFG is a graph, use del_node")

    def __getitem__(self, *args, **kwargs):
        raise DeprecationWarning("Order of AsmCFG elements is not reliable")

    def __iter__(self):
        """Iterator on AsmBlock composing the current graph"""
        return iter(self._nodes)

    def __len__(self):
        """Return the number of blocks in AsmCFG"""
        return len(self._nodes)

    # Manage graph with associated constraints
    def add_edge(self, src, dst, constraint):
        """Add an edge to the graph
        @src: AsmBlock instance, source
        @dst: AsmBlock instance, destination
        @constraint: constraint associated to this edge
        """
        # Sanity check
        assert (src, dst) not in self.edges2constraint

        # Add the edge to src.bto if needed
        if dst.label not in [cons.label for cons in src.bto]:
            src.bto.add(AsmConstraint(dst.label, constraint))

        # Add edge
        self.edges2constraint[(src, dst)] = constraint
        super(AsmCFG, self).add_edge(src, dst)

    def add_uniq_edge(self, src, dst, constraint):
        """Add an edge from @src to @dst if it doesn't already exist"""
        if (src not in self._nodes_succ or
                dst not in self._nodes_succ[src]):
            self.add_edge(src, dst, constraint)

    def del_edge(self, src, dst):
        """Delete the edge @src->@dst and its associated constraint"""
        # Delete from src.bto
        to_remove = [cons for cons in src.bto if cons.label == dst.label]
        if to_remove:
            assert len(to_remove) == 1
            src.bto.remove(to_remove[0])

        # Del edge
        del self.edges2constraint[(src, dst)]
        super(AsmCFG, self).del_edge(src, dst)

    def add_node(self, block):
        """Add the block @block to the current instance, if it is not already in
        @block: AsmBlock instance

        Edges will be created for @block.bto, if destinations are already in
        this instance. If not, they will be resolved when adding these
        aforementionned destinations.
        `self.pendings` indicates which blocks are not yet resolved.
        """
        status = super(AsmCFG, self).add_node(block)
        if not status:
            return status

        # Update waiters
        if block.label in self._pendings:
            for bblpend in self._pendings[block.label]:
                self.add_edge(bblpend.waiter, block, bblpend.constraint)
            del self._pendings[block.label]

        # Synchronize edges with block destinations
        self._label2block[block.label] = block
        for constraint in block.bto:
            dst = self._label2block.get(constraint.label,
                                        None)
            if dst is None:
                # Block is yet unknown, add it to pendings
                to_add = self.AsmCFGPending(waiter=block,
                                            constraint=constraint.c_t)
                self._pendings.setdefault(constraint.label,
                                          set()).add(to_add)
            else:
                # Block is already in known nodes
                self.add_edge(block, dst, constraint.c_t)

        return status

    def del_node(self, block):
        super(AsmCFG, self).del_node(block)
        del self._label2block[block.label]

    def merge(self, graph):
        """Merge with @graph, taking in account constraints"""
        # -> add_edge(x, y, constraint)
        for node in graph._nodes:
            self.add_node(node)
        for edge in graph._edges:
            # Use "_uniq_" beacause the edge can already exist due to add_node
            self.add_uniq_edge(*edge, constraint=graph.edges2constraint[edge])

    def node2lines(self, node):
        yield self.DotCellDescription(text=str(node.label.name),
                                      attr={'align': 'center',
                                            'colspan': 2,
                                            'bgcolor': 'grey'})

        if isinstance(node, AsmBlockBad):
            yield [self.DotCellDescription(
                text=node.ERROR_TYPES.get(node._errno,
                                          node._errno),
                                           attr={})]
            raise StopIteration
        for line in node.lines:
            if self._dot_offset:
                yield [self.DotCellDescription(text="%.8X" % line.offset,
                                               attr={}),
                       self.DotCellDescription(text=str(line), attr={})]
            else:
                yield self.DotCellDescription(text=str(line), attr={})

    def node_attr(self, node):
        if isinstance(node, AsmBlockBad):
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
        """Dictionary of label -> set(AsmCFGPending instance) indicating
        which label are missing in the current instance.
        A label is missing if a block which is already in nodes has constraints
        with him (thanks to its .bto) and the corresponding block is not yet in
        nodes
        """
        return self._pendings

    def _build_label2block(self):
        self._label2block = {block.label: block
                             for block in self._nodes}

    def label2block(self, label):
        """Return the block corresponding to label @label
        @label: AsmLabel instance or ExprId(AsmLabel) instance"""
        return self._label2block[label]

    def rebuild_edges(self):
        """Consider blocks '.bto' and rebuild edges according to them, ie:
        - update constraint type
        - add missing edge
        - remove no more used edge

        This method should be called if a block's '.bto' in nodes have been
        modified without notifying this instance to resynchronize edges.
        """
        self._build_label2block()
        for block in self._nodes:
            edges = []
            # Rebuild edges from bto
            for constraint in block.bto:
                dst = self._label2block.get(constraint.label,
                                            None)
                if dst is None:
                    # Missing destination, add to pendings
                    self._pendings.setdefault(constraint.label,
                                              set()).add(self.AsmCFGPending(block,
                                                                            constraint.c_t))
                    continue
                edge = (block, dst)
                edges.append(edge)
                if edge in self._edges:
                    # Already known edge, constraint may have changed
                    self.edges2constraint[edge] = constraint.c_t
                else:
                    # An edge is missing
                    self.add_edge(edge[0], edge[1], constraint.c_t)

            # Remove useless edges
            for succ in self.successors(block):
                edge = (block, succ)
                if edge not in edges:
                    self.del_edge(*edge)

    def get_bad_blocks(self):
        """Iterator on AsmBlockBad elements"""
        # A bad asm block is always a leaf
        for block in self.leaves():
            if isinstance(block, AsmBlockBad):
                yield block

    def get_bad_blocks_predecessors(self, strict=False):
        """Iterator on block with an AsmBlockBad destination
        @strict: (optional) if set, return block with only bad
        successors
        """
        # Avoid returning the same block
        done = set()
        for badblock in self.get_bad_blocks():
            for predecessor in self.predecessors_iter(badblock):
                if predecessor not in done:
                    if (strict and
                        not all(isinstance(block, AsmBlockBad)
                                for block in self.successors_iter(predecessor))):
                        continue
                    yield predecessor
                    done.add(predecessor)

    def sanity_check(self):
        """Do sanity checks on blocks' constraints:
        * no pendings
        * no multiple next constraint to same block
        * no next constraint to self
        """

        if len(self._pendings) != 0:
            raise RuntimeError("Some blocks are missing: %s" % map(str,
                                                                   self._pendings.keys()))

        next_edges = {edge: constraint
                      for edge, constraint in self.edges2constraint.iteritems()
                      if constraint == AsmConstraint.c_next}

        for block in self._nodes:
            # No next constraint to self
            if (block, block) in next_edges:
                raise RuntimeError('Bad constraint: self in next')

            # No multiple next constraint to same block
            pred_next = list(pblock
                             for (pblock, dblock) in next_edges
                             if dblock == block)

            if len(pred_next) > 1:
                raise RuntimeError("Too many next constraints for bloc %r"
                                   "(%s)" % (block.label,
                                             map(lambda x: x.label, pred_next)))

    def guess_blocks_size(self, mnemo):
        """Asm and compute max block size
        Add a 'size' and 'max_size' attribute on each block
        @mnemo: metamn instance"""
        for block in self._nodes:
            size = 0
            for instr in block.lines:
                if isinstance(instr, AsmRaw):
                    # for special AsmRaw, only extract len
                    if isinstance(instr.raw, list):
                        data = None
                        if len(instr.raw) == 0:
                            l = 0
                        else:
                            l = instr.raw[0].size / 8 * len(instr.raw)
                    elif isinstance(instr.raw, str):
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

    def apply_splitting(self, symbol_pool, dis_block_callback=None, **kwargs):
        """Consider @self' bto destinations and split block in @self if one of
        these destinations jumps in the middle of this block.
        In order to work, they must be only one block in @self per label in
        @symbol_pool (which is true if @self come from the same disasmEngine).

        @symbol_pool: AsmSymbolPool instance associated with @self'labels
        @dis_block_callback: (optional) if set, this callback will be called on
        new block destinations
        @kwargs: (optional) named arguments to pass to dis_block_callback
        """
        # Get all possible destinations not yet resolved, with a resolved
        # offset
        block_dst = [label.offset
                     for label in self.pendings
                     if label.offset is not None]

        todo = self.nodes().copy()
        rebuild_needed = False

        while todo:
            # Find a block with a destination inside another one
            cur_block = todo.pop()
            range_start, range_stop = cur_block.get_range()

            for off in block_dst:
                if not (off > range_start and off < range_stop):
                    continue

                # `cur_block` must be splitted at offset `off`
                label = symbol_pool.getby_offset_create(off)
                new_b = cur_block.split(off, label)
                log_asmblock.debug("Split block %x", off)
                if new_b is None:
                    log_asmblock.error("Cannot split %x!!", off)
                    continue

                # Remove pending from cur_block
                # Links from new_b will be generated in rebuild_edges
                for dst in new_b.bto:
                    if dst.label not in self.pendings:
                        continue
                    self.pendings[dst.label] = set(pending for pending in self.pendings[dst.label]
                                                   if pending.waiter != cur_block)

                # The new block destinations may need to be disassembled
                if dis_block_callback:
                    offsets_to_dis = set(constraint.label.offset
                                         for constraint in new_b.bto)
                    dis_block_callback(cur_bloc=new_b,
                                       offsets_to_dis=offsets_to_dis,
                                       symbol_pool=symbol_pool, **kwargs)

                # Update structure
                rebuild_needed = True
                self.add_node(new_b)

                # The new block must be considered
                todo.add(new_b)
                range_start, range_stop = cur_block.get_range()

        # Rebuild edges to match new blocks'bto
        if rebuild_needed:
            self.rebuild_edges()

    def __str__(self):
        out = []
        for node in self.nodes():
            out.append(str(node))
        for nodeA, nodeB in self.edges():
            out.append("%s -> %s" % (nodeA.label, nodeB.label))
        return '\n'.join(out)

    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, hex(id(self)))

# Out of _merge_blocks to be computed only once
_acceptable_block = lambda block: (not isinstance(block, AsmBlockBad) and
                                   len(block.lines) > 0)
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
        block, succ = match[_parent], match[_son]

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
        for nextb in graph.successors_iter(succ):
            graph.add_edge(block, nextb, graph.edges2constraint[(succ, nextb)])

        graph.del_node(succ)
        to_ignore.add(succ)


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
        if isinstance(e, m2_expr.ExprId):
            s = symbols._name2label[e.name]
            e = m2_expr.ExprInt(s.offset, e.size)
        return e
    result = expr.visit(expr_calc)
    result = expr_simp(result)
    if not isinstance(result, m2_expr.ExprInt):
        raise RuntimeError('Cannot resolve symbol %s' % expr)
    return result


def fix_label_offset(symbol_pool, label, offset, modified):
    """Fix the @label offset to @offset. If the @offset has changed, add @label
    to @modified
    @symbol_pool: current symbol_pool
    """
    if label.offset == offset:
        return
    symbol_pool.set_offset(label, offset)
    modified.add(label)


class BlockChain(object):

    """Manage blocks linked with an asm_constraint_next"""

    def __init__(self, symbol_pool, blocks):
        self.symbol_pool = symbol_pool
        self.blocks = blocks
        self.place()

    @property
    def pinned(self):
        """Return True iff at least one block is pinned"""
        return self.pinned_block_idx is not None

    def _set_pinned_block_idx(self):
        self.pinned_block_idx = None
        for i, block in enumerate(self.blocks):
            if is_int(block.label.offset):
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

        offset_base = self.blocks[self.pinned_block_idx].label.offset
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

    def fix_blocks(self, modified_labels):
        """Propagate a pinned to its blocks' neighbour
        @modified_labels: store new pinned labels"""

        if not self.pinned:
            raise ValueError('Trying to fix unpinned block')

        # Propagate offset to blocks before pinned block
        pinned_block = self.blocks[self.pinned_block_idx]
        offset = pinned_block.label.offset
        if offset % pinned_block.alignment != 0:
            raise RuntimeError('Bad alignment')

        for block in self.blocks[:self.pinned_block_idx - 1:-1]:
            new_offset = offset - block.size
            new_offset = new_offset - new_offset % pinned_block.alignment
            fix_label_offset(self.symbol_pool,
                             block.label,
                             new_offset,
                             modified_labels)

        # Propagate offset to blocks after pinned block
        offset = pinned_block.label.offset + pinned_block.size

        last_block = pinned_block
        for block in self.blocks[self.pinned_block_idx + 1:]:
            offset += (- offset) % last_block.alignment
            fix_label_offset(self.symbol_pool,
                             block.label,
                             offset,
                             modified_labels)
            offset += block.size
            last_block = block
        return modified_labels


class BlockChainWedge(object):

    """Stand for wedges between blocks"""

    def __init__(self, symbol_pool, offset, size):
        self.symbol_pool = symbol_pool
        self.offset = offset
        self.max_size = size
        self.offset_min = offset
        self.offset_max = offset + size

    def merge(self, chain):
        """Best effort merge two block chains
        Return the list of resulting blockchains"""
        self.symbol_pool.set_offset(chain.blocks[0].label, self.offset_max)
        chain.place()
        return [self, chain]


def group_constrained_blocks(symbol_pool, blocks):
    """
    Return the BlockChains list built from grouped asm blocks linked by
    asm_constraint_next
    @blocks: a list of asm block
    """
    log_asmblock.info('group_constrained_blocks')

    # Group adjacent blocks
    remaining_blocks = list(blocks)
    known_block_chains = {}
    lbl2block = {block.label: block for block in blocks}

    while remaining_blocks:
        # Create a new block chain
        block_list = [remaining_blocks.pop()]

        # Find sons in remainings blocks linked with a next constraint
        while True:
            # Get next block
            next_label = block_list[-1].get_next()
            if next_label is None or next_label not in lbl2block:
                break
            next_block = lbl2block[next_label]

            # Add the block at the end of the current chain
            if next_block not in remaining_blocks:
                break
            block_list.append(next_block)
            remaining_blocks.remove(next_block)

        # Check if son is in a known block group
        if next_label is not None and next_label in known_block_chains:
            block_list += known_block_chains[next_label]
            del known_block_chains[next_label]

        known_block_chains[block_list[0].label] = block_list

    out_block_chains = []
    for label in known_block_chains:
        chain = BlockChain(symbol_pool, known_block_chains[label])
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


def resolve_symbol(blockChains, symbol_pool, dst_interval=None):
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
            symbol_pool, offset=start, size=stop + 1 - start)
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
        for i in xrange(1, len(fixed_chains)):
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


def filter_exprid_label(exprs):
    """Extract labels from list of ExprId @exprs"""
    return set(expr.name for expr in exprs if isinstance(expr.name, AsmLabel))


def get_block_labels(block):
    """Extract labels used by @block"""
    symbols = set()
    for instr in block.lines:
        if isinstance(instr, AsmRaw):
            if isinstance(instr.raw, list):
                for expr in instr.raw:
                    symbols.update(m2_expr.get_expr_ids(expr))
        else:
            for arg in instr.args:
                symbols.update(m2_expr.get_expr_ids(arg))
    labels = filter_exprid_label(symbols)
    return labels


def assemble_block(mnemo, block, symbol_pool, conservative=False):
    """Assemble a @block using @symbol_pool
    @conservative: (optional) use original bytes when possible
    """
    offset_i = 0

    for instr in block.lines:
        if isinstance(instr, AsmRaw):
            if isinstance(instr.raw, list):
                # Fix special AsmRaw
                data = ""
                for expr in instr.raw:
                    expr_int = fix_expr_val(expr, symbol_pool)
                    data += pck[expr_int.size](expr_int.arg)
                instr.data = data

            instr.offset = offset_i
            offset_i += instr.l
            continue

        # Assemble an instruction
        saved_args = list(instr.args)
        instr.offset = block.label.offset + offset_i

        # Replace instruction's arguments by resolved ones
        instr.args = instr.resolve_args_with_symbols(symbol_pool)

        if instr.dstflow():
            instr.fixDstOffset()

        old_l = instr.l
        cached_candidate, _ = conservative_asm(mnemo, instr, symbol_pool,
                                               conservative)

        # Restore original arguments
        instr.args = saved_args

        # We need to update the block size
        block.size = block.size - old_l + len(cached_candidate)
        instr.data = cached_candidate
        instr.l = len(cached_candidate)

        offset_i += instr.l


def asmblock_final(mnemo, blocks, blockChains, symbol_pool, conservative=False):
    """Resolve and assemble @blockChains using @symbol_pool until fixed point is
    reached"""

    log_asmblock.debug("asmbloc_final")

    # Init structures
    lbl2block = {block.label: block for block in blocks}
    blocks_using_label = {}
    for block in blocks:
        labels = get_block_labels(block)
        for label in labels:
            blocks_using_label.setdefault(label, set()).add(block)

    block2chain = {}
    for chain in blockChains:
        for block in chain.blocks:
            block2chain[block] = chain

    # Init worklist
    blocks_to_rework = set(blocks)

    # Fix and re-assemble blocks until fixed point is reached
    while True:

        # Propagate pinned blocks into chains
        modified_labels = set()
        for chain in blockChains:
            chain.fix_blocks(modified_labels)

        for label in modified_labels:
            # Retrive block with modified reference
            if label in lbl2block:
                blocks_to_rework.add(lbl2block[label])

            # Enqueue blocks referencing a modified label
            if label not in blocks_using_label:
                continue
            for block in blocks_using_label[label]:
                blocks_to_rework.add(block)

        # No more work
        if not blocks_to_rework:
            break

        while blocks_to_rework:
            block = blocks_to_rework.pop()
            assemble_block(mnemo, block, symbol_pool, conservative)


def asmbloc_final(mnemo, blocks, blockChains, symbol_pool, conservative=False):
    """Resolve and assemble @blockChains using @symbol_pool until fixed point is
    reached"""

    warnings.warn('DEPRECATION WARNING: use "asmblock_final" instead of "asmbloc_final"')
    asmblock_final(mnemo, blocks, blockChains, symbol_pool, conservative)

def asm_resolve_final(mnemo, blocks, symbol_pool, dst_interval=None):
    """Resolve and assemble @blocks using @symbol_pool into interval
    @dst_interval"""

    blocks.sanity_check()

    blocks.guess_blocks_size(mnemo)
    blockChains = group_constrained_blocks(symbol_pool, blocks)
    resolved_blockChains = resolve_symbol(
        blockChains, symbol_pool, dst_interval)

    asmblock_final(mnemo, blocks, resolved_blockChains, symbol_pool)
    patches = {}
    output_interval = interval()

    for block in blocks:
        offset = block.label.offset
        for instr in block.lines:
            if not instr.data:
                # Empty line
                continue
            assert len(instr.data) == instr.l
            patches[offset] = instr.data
            instruction_interval = interval([(offset, offset + instr.l - 1)])
            if not (instruction_interval & output_interval).empty:
                raise RuntimeError("overlapping bytes %X" % int(offset))
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

    + callback(arch, attrib, pool_bin, cur_bloc, offsets_to_dis,
               symbol_pool)
     - dis_bloc_callback: callback after each new disassembled block

    The engine also tracks already handled block, for performance and to avoid
    infinite cycling.
    Addresses of disassembled block is in the attribute `job_done`.
    To force a new disassembly, the targeted offset must first be removed from
    this structure.
    """

    def __init__(self, arch, attrib, bin_stream, **kwargs):
        """Instanciate a new disassembly engine
        @arch: targeted architecture
        @attrib: architecture attribute
        @bin_stream: bytes source
        @kwargs: (optional) custom options
        """
        self.arch = arch
        self.attrib = attrib
        self.bin_stream = bin_stream
        self.symbol_pool = AsmSymbolPool()
        self.job_done = set()

        # Setup options
        self.dont_dis = []
        self.split_dis = []
        self.follow_call = False
        self.dontdis_retcall = False
        self.lines_wd = None
        self.blocs_wd = None
        self.dis_bloc_callback = None
        self.dont_dis_nulstart_bloc = False
        self.dont_dis_retcall_funcs = set()

        # Override options if needed
        self.__dict__.update(kwargs)

    def _dis_bloc(self, offset):
        """Disassemble the block at offset @offset
        Return the created AsmBlock and future offsets to disassemble
        """

        lines_cpt = 0
        in_delayslot = False
        delayslot_count = self.arch.delayslot
        offsets_to_dis = set()
        add_next_offset = False
        label = self.symbol_pool.getby_offset_create(offset)
        cur_block = AsmBlock(label)
        log_asmblock.debug("dis at %X", int(offset))
        while not in_delayslot or delayslot_count > 0:
            if in_delayslot:
                delayslot_count -= 1

            if offset in self.dont_dis:
                if not cur_block.lines:
                    self.job_done.add(offset)
                    # Block is empty -> bad block
                    cur_block = AsmBlockBad(label, errno=2)
                else:
                    # Block is not empty, stop the desassembly pass and add a
                    # constraint to the next block
                    cur_block.add_cst(offset, AsmConstraint.c_next,
                                      self.symbol_pool)
                break

            if lines_cpt > 0 and offset in self.split_dis:
                cur_block.add_cst(offset, AsmConstraint.c_next,
                                  self.symbol_pool)
                offsets_to_dis.add(offset)
                break

            lines_cpt += 1
            if self.lines_wd is not None and lines_cpt > self.lines_wd:
                log_asmblock.debug("lines watchdog reached at %X", int(offset))
                break

            if offset in self.job_done:
                cur_block.add_cst(offset, AsmConstraint.c_next,
                                  self.symbol_pool)
                break

            off_i = offset
            try:
                instr = self.arch.dis(self.bin_stream, self.attrib, offset)
            except (Disasm_Exception, IOError), e:
                log_asmblock.warning(e)
                instr = None

            if instr is None:
                log_asmblock.warning("cannot disasm at %X", int(off_i))
                if not cur_block.lines:
                    self.job_done.add(offset)
                    # Block is empty -> bad block
                    cur_block = AsmBlockBad(label, errno=0)
                else:
                    # Block is not empty, stop the desassembly pass and add a
                    # constraint to the next block
                    cur_block.add_cst(off_i, AsmConstraint.c_next,
                                      self.symbol_pool)
                break

            # XXX TODO nul start block option
            if self.dont_dis_nulstart_bloc and instr.b.count('\x00') == instr.l:
                log_asmblock.warning("reach nul instr at %X", int(off_i))
                if not cur_block.lines:
                    # Block is empty -> bad block
                    cur_block = AsmBlockBad(label, errno=1)
                else:
                    # Block is not empty, stop the desassembly pass and add a
                    # constraint to the next block
                    cur_block.add_cst(off_i, AsmConstraint.c_next,
                                      self.symbol_pool)
                break

            # special case: flow graph modificator in delayslot
            if in_delayslot and instr and (instr.splitflow() or instr.breakflow()):
                add_next_offset = True
                break

            self.job_done.add(offset)
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
                pass
            if instr.dstflow():
                instr.dstflow2label(self.symbol_pool)
                dst = instr.getdstflow(self.symbol_pool)
                dstn = []
                for d in dst:
                    if isinstance(d, m2_expr.ExprId) and \
                            isinstance(d.name, AsmLabel):
                        dstn.append(d.name)
                        if d.name.offset in self.dont_dis_retcall_funcs:
                            add_next_offset = False
                dst = dstn
                if (not instr.is_subcall()) or self.follow_call:
                    cur_block.bto.update(
                        [AsmConstraint(x, AsmConstraint.c_to) for x in dst])

            # get in delayslot mode
            in_delayslot = True
            delayslot_count = instr.delayslot

        for c in cur_block.bto:
            offsets_to_dis.add(c.label.offset)

        if add_next_offset:
            cur_block.add_cst(offset, AsmConstraint.c_next, self.symbol_pool)
            offsets_to_dis.add(offset)

        # Fix multiple constraints
        cur_block.fix_constraints()

        if self.dis_bloc_callback is not None:
            self.dis_bloc_callback(mn=self.arch, attrib=self.attrib,
                                   pool_bin=self.bin_stream, cur_bloc=cur_block,
                                   offsets_to_dis=offsets_to_dis,
                                   symbol_pool=self.symbol_pool)
        return cur_block, offsets_to_dis

    def dis_bloc(self, offset):
        """Disassemble the block at offset @offset and return the created
        AsmBlock
        @offset: targeted offset to disassemble
        """
        current_block, _ = self._dis_bloc(offset)
        return current_block

    def dis_multibloc(self, offset, blocs=None):
        """Disassemble every block reachable from @offset regarding
        specific disasmEngine conditions
        Return an AsmCFG instance containing disassembled blocks
        @offset: starting offset
        @blocs: (optional) AsmCFG instance of already disassembled blocks to
                merge with
        """
        log_asmblock.info("dis bloc all")
        if blocs is None:
            blocs = AsmCFG()
        todo = [offset]

        bloc_cpt = 0
        while len(todo):
            bloc_cpt += 1
            if self.blocs_wd is not None and bloc_cpt > self.blocs_wd:
                log_asmblock.debug("blocs watchdog reached at %X", int(offset))
                break

            target_offset = int(todo.pop(0))
            if (target_offset is None or
                    target_offset in self.job_done):
                continue
            cur_block, nexts = self._dis_bloc(target_offset)
            todo += nexts
            blocs.add_node(cur_block)

        blocs.apply_splitting(self.symbol_pool,
                              dis_block_callback=self.dis_bloc_callback,
                              mn=self.arch, attrib=self.attrib,
                              pool_bin=self.bin_stream)
        return blocs
