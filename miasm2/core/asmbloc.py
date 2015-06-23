#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging
import inspect


import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.expression.modint import moduint, modint
from miasm2.core.utils import Disasm_Exception, pck
from miasm2.core.graph import DiGraph
from miasm2.core.interval import interval

log_asmbloc = logging.getLogger("asmblock")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_asmbloc.addHandler(console_handler)
log_asmbloc.setLevel(logging.WARNING)

def is_int(a):
    return isinstance(a, int) or isinstance(a, long) or \
        isinstance(a, moduint) or isinstance(a, modint)


def expr_is_label(e):
    return isinstance(e, m2_expr.ExprId) and isinstance(e.name, asm_label)


def expr_is_int_or_label(e):
    return isinstance(e, m2_expr.ExprInt) or \
        (isinstance(e, m2_expr.ExprId) and isinstance(e.name, asm_label))


class asm_label:
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
        rep = '<asmlabel '
        if self.name:
            rep += repr(self.name) + ' '
        rep += '>'
        return rep

class asm_raw:
    def __init__(self, raw=""):
        self.raw = raw

    def __str__(self):
        return repr(self.raw)

class asm_constraint(object):
    c_to = "c_to"
    c_next = "c_next"
    c_bad = "c_bad"

    def __init__(self, label=None, c_t=c_to):
        self.label = label
        self.c_t = c_t

    def __str__(self):
        return "%s:%s" % (str(self.c_t), str(self.label))


class asm_constraint_next(asm_constraint):

    def __init__(self, label=None):
        super(asm_constraint_next, self).__init__(
            label, c_t=asm_constraint.c_next)


class asm_constraint_to(asm_constraint):

    def __init__(self, label=None):
        super(asm_constraint_to, self).__init__(
            label, c_t=asm_constraint.c_to)


class asm_constraint_bad(asm_constraint):

    def __init__(self, label=None):
        super(asm_constraint_bad, self).__init__(
            label, c_t=asm_constraint.c_bad)


class asm_bloc(object):

    def __init__(self, label=None, alignment=1):
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
        assert type(self.bto) is set
        self.bto.add(c)

    def split(self, offset, l):
        log_asmbloc.debug('split at %x', offset)
        i = -1
        offsets = [x.offset for x in self.lines]
        if not l.offset in offsets:
            log_asmbloc.warning(
                'cannot split bloc at %X ' % offset +
                'middle instruction? default middle')
            offsets.sort()
            return None
        new_bloc = asm_bloc(l)
        i = offsets.index(offset)

        self.lines, new_bloc.lines = self.lines[:i], self.lines[i:]
        flow_mod_instr = self.get_flow_instr()
        log_asmbloc.debug('flow mod %r', flow_mod_instr)
        c = asm_constraint(l, asm_constraint.c_next)
        # move dst if flowgraph modifier was in original bloc
        # (usecase: split delayslot bloc)
        if flow_mod_instr:
            for xx in self.bto:
                log_asmbloc.debug('lbl %s', xx)
            c_next = set(
                [x for x in self.bto if x.c_t == asm_constraint.c_next])
            c_to = [x for x in self.bto if x.c_t != asm_constraint.c_next]
            self.bto = set([c] + c_to)
            new_bloc.bto = c_next
        else:
            new_bloc.bto = self.bto
            self.bto = set([c])
        return new_bloc

    def get_range(self):
        if len(self.lines):
            return self.lines[0].offset, self.lines[-1].offset
        else:
            return 0, 0

    def get_offsets(self):
        return [x.offset for x in self.lines]

    def add_cst(self, offset, c_t, symbol_pool):
        if type(offset) in [int, long]:
            l = symbol_pool.getby_offset_create(offset)
        elif type(offset) is str:
            l = symbol_pool.getby_name_create(offset)
        elif isinstance(offset, asm_label):
            l = offset
        else:
            raise ValueError('unknown offset type %r' % offset)
        c = asm_constraint(l, c_t)
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
        for i in xrange(-1, -1 - self.lines[0].delayslot - 1, -1):
            l = self.lines[i]
            if l.is_subcall():
                return l

    def get_next(self):
        for x in self.bto:
            if x.c_t == asm_constraint.c_next:
                return x.label
        return None


class asm_symbol_pool:

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
        label = asm_label(name, offset)

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


def dis_bloc(mnemo, pool_bin, cur_bloc, offset, job_done, symbol_pool,
             dont_dis=[], split_dis=[
             ], follow_call=False, dontdis_retcall=False, lines_wd=None,
             dis_bloc_callback=None, dont_dis_nulstart_bloc=False,
             attrib={}):
    # pool_bin.offset = offset
    lines_cpt = 0
    in_delayslot = False
    delayslot_count = mnemo.delayslot
    offsets_to_dis = set()
    add_next_offset = False
    log_asmbloc.debug("dis at %X", int(offset))
    while not in_delayslot or delayslot_count > 0:
        if in_delayslot:
            delayslot_count -= 1

        if offset in dont_dis or (lines_cpt > 0 and offset in split_dis):
            cur_bloc.add_cst(offset, asm_constraint.c_next, symbol_pool)
            offsets_to_dis.add(offset)
            break

        lines_cpt += 1
        if lines_wd is not None and lines_cpt > lines_wd:
            # log_asmbloc.warning( "lines watchdog reached at %X"%int(offset))
            break

        if offset in job_done:
            cur_bloc.add_cst(offset, asm_constraint.c_next, symbol_pool)
            break

        off_i = offset
        try:
            # print repr(pool_bin.getbytes(offset, 4))
            instr = mnemo.dis(pool_bin, attrib, offset)
        except (Disasm_Exception, IOError), e:
            log_asmbloc.warning(e)
            instr = None

        if instr is None:
            log_asmbloc.warning("cannot disasm at %X", int(off_i))
            cur_bloc.add_cst(off_i, asm_constraint.c_bad, symbol_pool)
            break

        # XXX TODO nul start block option
        if dont_dis_nulstart_bloc and instr.b.count('\x00') == instr.l:
            log_asmbloc.warning("reach nul instr at %X", int(off_i))
            cur_bloc.add_cst(off_i, asm_constraint.c_bad, symbol_pool)
            break

        # special case: flow graph modificator in delayslot
        if in_delayslot and instr and (instr.splitflow() or instr.breakflow()):
            add_next_offset = True
            break

        job_done.add(offset)
        log_asmbloc.debug("dis at %X", int(offset))

        offset += instr.l
        log_asmbloc.debug(instr)
        log_asmbloc.debug(instr.args)

        cur_bloc.addline(instr)
        if not instr.breakflow():
            continue
        # test split
        if instr.splitflow() and not (instr.is_subcall() and dontdis_retcall):
            add_next_offset = True
            # cur_bloc.add_cst(n, asm_constraint.c_next, symbol_pool)
            pass
        if instr.dstflow():
            instr.dstflow2label(symbol_pool)
            dst = instr.getdstflow(symbol_pool)
            dstn = []
            for d in dst:
                if isinstance(d, m2_expr.ExprId) and \
                        isinstance(d.name, asm_label):
                    dstn.append(d.name)
            dst = dstn
            if (not instr.is_subcall()) or follow_call:
                cur_bloc.bto.update(
                    [asm_constraint(x, asm_constraint.c_to) for x in dst])

        # get in delayslot mode
        in_delayslot = True
        delayslot_count = instr.delayslot

    for c in cur_bloc.bto:
        if c.c_t == asm_constraint.c_bad:
            continue
        if isinstance(c.label, asm_label):
            offsets_to_dis.add(c.label.offset)

    if add_next_offset:
        cur_bloc.add_cst(offset, asm_constraint.c_next, symbol_pool)
        offsets_to_dis.add(offset)

    if dis_bloc_callback is not None:
        dis_bloc_callback(
            mnemo, attrib, pool_bin, cur_bloc, offsets_to_dis, symbol_pool)
    # print 'dst', [hex(x) for x in offsets_to_dis]
    return offsets_to_dis


def split_bloc(mnemo, attrib, pool_bin, blocs,
    symbol_pool, more_ref=None, dis_bloc_callback=None):
    if not more_ref:
        more_ref = []

    # get all possible dst
    bloc_dst = [symbol_pool._offset2label[x] for x in more_ref]
    for b in blocs:
        for c in b.bto:
            if not isinstance(c.label, asm_label):
                continue
            if c.c_t == asm_constraint.c_bad:
                continue
            bloc_dst.append(c.label)

    bloc_dst = [x.offset for x in bloc_dst if x.offset is not None]

    j = -1
    while j < len(blocs) - 1:
        j += 1
        cb = blocs[j]
        a, b = cb.get_range()

        for off in bloc_dst:
            if not (off > a and off <= b):
                continue
            l = symbol_pool.getby_offset_create(off)
            new_b = cb.split(off, l)
            log_asmbloc.debug("split bloc %x", off)
            if new_b is None:
                log_asmbloc.error("cannot split %x!!", off)
                continue
            if dis_bloc_callback:
                offsets_to_dis = set(
                    [x.label.offset for x in new_b.bto
                    if isinstance(x.label, asm_label)])
                dis_bloc_callback(
                    mnemo, attrib, pool_bin, new_b, offsets_to_dis,
                    symbol_pool)
            blocs.append(new_b)
            a, b = cb.get_range()

    return blocs

def dis_bloc_all(mnemo, pool_bin, offset, job_done, symbol_pool, dont_dis=[],
                 split_dis=[], follow_call=False, dontdis_retcall=False,
                 blocs_wd=None, lines_wd=None, blocs=None,
                 dis_bloc_callback=None, dont_dis_nulstart_bloc=False,
                 attrib={}):
    log_asmbloc.info("dis bloc all")
    if blocs is None:
        blocs = []
    todo = [offset]

    bloc_cpt = 0
    while len(todo):
        bloc_cpt += 1
        if blocs_wd is not None and bloc_cpt > blocs_wd:
            log_asmbloc.debug("blocs watchdog reached at %X", int(offset))
            break

        n = int(todo.pop(0))
        if n is None:
            continue
        if n in job_done:
            continue

        if n in dont_dis:
            continue
        dd_flag = False
        for dd in dont_dis:
            if not isinstance(dd, tuple):
                continue
            dd_a, dd_b = dd
            if dd_a <= n < dd_b:
                dd_flag = True
                break
        if dd_flag:
            continue
        l = symbol_pool.getby_offset_create(n)
        cur_bloc = asm_bloc(l)
        todo += dis_bloc(mnemo, pool_bin, cur_bloc, n, job_done, symbol_pool,
                         dont_dis, split_dis, follow_call, dontdis_retcall,
                         dis_bloc_callback=dis_bloc_callback,
                         lines_wd=lines_wd,
                         dont_dis_nulstart_bloc=dont_dis_nulstart_bloc,
                         attrib=attrib)
        blocs.append(cur_bloc)

    return split_bloc(mnemo, attrib, pool_bin, blocs,
    symbol_pool, dis_bloc_callback=dis_bloc_callback)


def bloc2graph(blocs, label=False, lines=True):
    # rankdir=LR;
    out = """
digraph asm_graph {
size="80,50";
node [
fontsize = "16",
shape = "box"
];
"""
    for b in blocs:
        out += '%s [\n' % b.label.name
        out += 'label = "'

        out += b.label.name + "\\l\\\n"
        if lines:
            for l in b.lines:
                if label:
                    out += "%.8X " % l.offset
                out += ("%s\\l\\\n" % l).replace('"', '\\"')
        out += '"\n];\n'

    for b in blocs:
        for n in b.bto:
            # print 'xxxx', n.label, n.label.__class__
            # if isinstance(n.label, ExprId):
            #    print n.label.name, n.label.name.__class__
            if isinstance(n.label, m2_expr.ExprId):
                dst, name, cst = b.label.name, n.label.name, n.c_t
                # out+='%s -> %s [ label = "%s" ];\n'%(b.label.name,
                # n.label.name, n.c_t)
            elif isinstance(n.label, asm_label):
                dst, name, cst = b.label.name, n.label.name, n.c_t
            else:
                continue
            out += '%s -> %s [ label = "%s" ];\n' % (dst, name, cst)

    out += "}"
    return out


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
            e = m2_expr.ExprInt_from(e, s.offset)
        return e
    result = expr.visit(expr_calc)
    result = expr_simp(result)
    if not isinstance(result, m2_expr.ExprInt):
        raise RuntimeError('Cannot resolve symbol %s' % expr)
    return result


def guess_blocks_size(mnemo, blocks):
    """Asm and compute max block size"""

    for block in blocks:
        size = 0
        for instr in block.lines:
            if isinstance(instr, asm_raw):
                # for special asm_raw, only extract len
                if isinstance(instr.raw, list):
                    data = None
                    if len(instr.raw) == 0:
                        l = 0
                    else:
                        l = instr.raw[0].size/8 * len(instr.raw)
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
        log_asmbloc.info("size: %d max: %d", block.size, block.max_size)

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
        for block in self.blocks[:self.pinned_block_idx-1:-1]:
            self.offset_min -= block.max_size + (block.alignment - block.max_size) % block.alignment

        self.offset_max = offset_base
        for block in self.blocks[self.pinned_block_idx:]:
            self.offset_max += block.max_size + (block.alignment - block.max_size) % block.alignment

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

        for block in self.blocks[:self.pinned_block_idx-1:-1]:
            new_offset = offset - block.size
            new_offset = new_offset - new_offset % pinned_block.alignment
            fix_label_offset(self.symbol_pool,
                             block.label,
                             new_offset,
                             modified_labels)

        # Propagate offset to blocks after pinned block
        offset = pinned_block.label.offset + pinned_block.size

        last_block = pinned_block
        for block in self.blocks[self.pinned_block_idx+1:]:
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
    log_asmbloc.info('group_constrained_blocks')

    # Group adjacent blocks
    remaining_blocks = list(blocks)
    known_block_chains = {}
    lbl2block = {block.label:block for block in blocks}

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
        chain_interval = interval([(chain.offset_min, chain.offset_max-1)])
        if chain_interval not in dst_interval:
            raise ValueError('Chain placed out of destination interval')
        allocated_interval += chain_interval
    return allocated_interval

def resolve_symbol(blockChains, symbol_pool, dst_interval=None):
    """Place @blockChains in the @dst_interval"""

    log_asmbloc.info('resolve_symbol')
    if dst_interval is None:
        dst_interval = interval([(0, 0xFFFFFFFFFFFFFFFF)])

    forbidden_interval = interval([(-1, 0xFFFFFFFFFFFFFFFF+1)]) - dst_interval
    allocated_interval = get_blockchains_address_interval(blockChains,
                                                          dst_interval)
    log_asmbloc.debug('allocated interval: %s', allocated_interval)

    pinned_chains = [chain for chain in blockChains if chain.pinned]

    # Add wedge in forbidden intervals
    for start, stop in forbidden_interval.intervals:
        wedge = BlockChainWedge(symbol_pool, offset=start, size=stop+1-start)
        pinned_chains.append(wedge)

    # Try to place bigger blockChains first
    pinned_chains.sort(key=lambda x:x.offset_min)
    blockChains.sort(key=lambda x:-x.max_size)

    fixed_chains = list(pinned_chains)

    log_asmbloc.debug("place chains")
    for chain in blockChains:
        if chain.pinned:
            continue
        fixed = False
        for i in xrange(1, len(fixed_chains)):
            prev_chain = fixed_chains[i-1]
            next_chain = fixed_chains[i]

            if prev_chain.offset_max + chain.max_size < next_chain.offset_min:
                new_chains = prev_chain.merge(chain)
                fixed_chains[i-1:i] = new_chains
                fixed = True
                break
        if not fixed:
            raise RuntimeError('Cannot find enough space to place blocks')

    return [chain for chain in fixed_chains if isinstance(chain, BlockChain)]

def filter_exprid_label(exprs):
    """Extract labels from list of ExprId @exprs"""
    return set(expr.name for expr in exprs if isinstance(expr.name, asm_label))

def get_block_labels(block):
    """Extract labels used by @block"""
    symbols = set()
    for instr in block.lines:
        if isinstance(instr, asm_raw):
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
        if isinstance(instr, asm_raw):
            if isinstance(instr.raw, list):
                # Fix special asm_raw
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
        cached_candidate, candidates = conservative_asm(
            mnemo, instr, symbol_pool, conservative)

        # Restore original arguments
        instr.args = saved_args

        # We need to update the block size
        block.size = block.size - old_l + len(cached_candidate)
        instr.data = cached_candidate
        instr.l = len(cached_candidate)

        offset_i += instr.l


def asmbloc_final(mnemo, blocks, blockChains, symbol_pool, conservative=False):
    """Resolve and assemble @blockChains using @symbol_pool until fixed point is
    reached"""

    log_asmbloc.debug("asmbloc_final")

    # Init structures
    lbl2block = {block.label:block for block in blocks}
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


def sanity_check_blocks(blocks):
    """Do sanity checks on blocks' constraints:
    * no multiple next constraint to same block
    * no next constraint to self"""

    blocks_graph = basicblocs(blocks)
    graph = blocks_graph.g
    for label in graph.nodes():
        if blocks_graph.blocs[label].get_next() == label:
            raise RuntimeError('Bad constraint: self in next')
        pred_next = set()
        for pred in graph.predecessors(label):
            if not pred in blocks_graph.blocs:
                continue
            if blocks_graph.blocs[pred].get_next() == label:
                pred_next.add(pred)
        if len(pred_next) > 1:
            raise RuntimeError("Too many next constraints for bloc %r"%label)

def asm_resolve_final(mnemo, blocks, symbol_pool, dst_interval=None):
    """Resolve and assemble @blocks using @symbol_pool into interval
    @dst_interval"""

    sanity_check_blocks(blocks)

    guess_blocks_size(mnemo, blocks)
    blockChains = group_constrained_blocks(symbol_pool, blocks)
    resolved_blockChains = resolve_symbol(blockChains, symbol_pool, dst_interval)

    asmbloc_final(mnemo, blocks, resolved_blockChains, symbol_pool)
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
            instruction_interval = interval([(offset, offset + instr.l-1)])
            if not (instruction_interval & output_interval).empty:
                raise RuntimeError("overlapping bytes %X" % int(offset))
            instr.offset = offset
            offset += instr.l
    return patches

def blist2graph(ab):
    """
    ab: list of asmbloc
    return: graph of asmbloc
    """
    g = DiGraph()
    g.lbl2bloc = {}
    for b in ab:
        g.lbl2bloc[b.label] = b
        g.add_node(b.label)
        for x in b.bto:
            g.add_edge(b.label, x.label)
    return g


class basicblocs:

    def __init__(self, ab=[]):
        self.blocs = {}
        self.g = DiGraph()
        self.add_blocs(ab)

    def add(self, b):
        self.blocs[b.label] = b
        self.g.add_node(b.label)
        for dst in b.bto:
            if isinstance(dst.label, asm_label):
                self.g.add_edge(b.label, dst.label)

    def add_blocs(self, ab):
        for b in ab:
            self.add(b)

    def get_bad_dst(self):
        o = set()
        for b in self.blocs.values():
            for c in b.bto:
                if c.c_t == asm_constraint.c_bad:
                    o.add(b)
        return o


def find_parents(blocs, l):
    p = set()
    for b in blocs:
        if l in [x.label for x in b.bto if isinstance(x.label, asm_label)]:
            p.add(b.label)
    return p


def bloc_blink(blocs):
    for b in blocs:
        b.parents = find_parents(blocs, b.label)


def getbloc_around(blocs, a, level=3, done=None, blocby_label=None):

    if not blocby_label:
        blocby_label = {}
        for b in blocs:
            blocby_label[b.label] = b
    if done is None:
        done = set()

    done.add(a)
    if not level:
        return done
    for b in a.parents:
        b = blocby_label[b]
        if b in done:
            continue
        done.update(getbloc_around(blocs, b, level - 1, done, blocby_label))
    for b in a.bto:
        b = blocby_label[b.label]
        if b in done:
            continue
        done.update(getbloc_around(blocs, b, level - 1, done, blocby_label))
    return done


def getbloc_parents(blocs, a, level=3, done=None, blocby_label=None):

    if not blocby_label:
        blocby_label = {}
        for b in blocs:
            blocby_label[b.label] = b
    if done is None:
        done = set()

    done.add(a)
    if not level:
        return done
    for b in a.parents:
        b = blocby_label[b]
        if b in done:
            continue
        done.update(getbloc_parents(blocs, b, level - 1, done, blocby_label))
    return done

# get ONLY level_X parents


def getbloc_parents_strict(
    blocs, a, level=3, rez=None, done=None, blocby_label=None):

    if not blocby_label:
        blocby_label = {}
        for b in blocs:
            blocby_label[b.label] = b
    if rez is None:
        rez = set()
    if done is None:
        done = set()

    done.add(a)
    if level == 0:
        rez.add(a)
    if not level:
        return rez
    for b in a.parents:
        b = blocby_label[b]
        if b in done:
            continue
        rez.update(getbloc_parents_strict(
            blocs, b, level - 1, rez, done, blocby_label))
    return rez


def bloc_find_path_next(blocs, blocby_label, a, b, path=None):
    if path == None:
        path = []
    if a == b:
        return [path]

    all_path = []
    for x in a.bto:
        if x.c_t != asm_constraint.c_next:
            continue
        if not x.label in blocby_label:
            log_asmbloc.error('XXX unknown label')
            continue
        x = blocby_label[x.label]
        all_path += bloc_find_path_next(blocs, blocby_label, x, b, path + [a])
        # stop if at least one path found
        if all_path:
            return all_path
    return all_path


def bloc_merge(blocs, dont_merge=[]):
    blocby_label = {}
    for b in blocs:
        blocby_label[b.label] = b
        b.parents = find_parents(blocs, b.label)

    i = -1
    while i < len(blocs) - 1:
        i += 1
        b = blocs[i]
        if b.label in dont_merge:
            continue
        p = set(b.parents)
        # if bloc dont self ref
        if b.label in p:
            continue
        # and bloc has only one parent
        if len(p) != 1:
            continue
        # may merge
        bpl = p.pop()
        # bp = getblocby_label(blocs, bpl)
        bp = blocby_label[bpl]
        # and parent has only one son
        if len(bp.bto) != 1:
            continue
        # and will not create next loop composed of constraint_next from son to
        # parent

        path = bloc_find_path_next(blocs, blocby_label, b, bp)
        if path:
            continue
        if bp.lines:
            l = bp.lines[-1]
            # jmp opt; jcc opt
            if l.is_subcall():
                continue
            if l.breakflow() and l.dstflow():
                bp.lines.pop()
        # merge
        # sons = b.bto[:]

        # update parents
        for s in b.bto:
            if not isinstance(s.label, asm_label):
                continue
            if s.label.name == None:
                continue
            if not s.label in blocby_label:
                log_asmbloc.error("unknown parent XXX")
                continue
            bs = blocby_label[s.label]
            for p in list(bs.parents):
                if p == b.label:
                    bs.parents.discard(p)
                    bs.parents.add(bp.label)
        bp.lines += b.lines
        bp.bto = b.bto

        del blocs[i]
        i = -1


class disasmEngine(object):

    def __init__(self, arch, attrib, bs=None, **kwargs):
        self.arch = arch
        self.attrib = attrib
        self.bs = bs
        self.symbol_pool = asm_symbol_pool()
        self.dont_dis = []
        self.split_dis = []
        self.follow_call = False
        self.dontdis_retcall = False
        self.lines_wd = None
        self.blocs_wd = None
        self.dis_bloc_callback = None
        self.dont_dis_nulstart_bloc = False
        self.job_done = set()
        self.__dict__.update(kwargs)

    def dis_bloc(self, offset):
        l = self.symbol_pool.getby_offset_create(offset)
        current_bloc = asm_bloc(l)
        dis_bloc(self.arch, self.bs, current_bloc, offset, self.job_done,
                 self.symbol_pool,
                 dont_dis=self.dont_dis, split_dis=self.split_dis,
                 follow_call=self.follow_call,
                 dontdis_retcall=self.dontdis_retcall,
                 lines_wd=self.lines_wd,
                 dis_bloc_callback=self.dis_bloc_callback,
                 dont_dis_nulstart_bloc=self.dont_dis_nulstart_bloc,
                 attrib=self.attrib)
        return current_bloc

    def dis_multibloc(self, offset, blocs=None):
        blocs = dis_bloc_all(self.arch, self.bs, offset, self.job_done,
                             self.symbol_pool,
                             dont_dis=self.dont_dis, split_dis=self.split_dis,
                             follow_call=self.follow_call,
                             dontdis_retcall=self.dontdis_retcall,
                             blocs_wd=self.blocs_wd,
                             lines_wd=self.lines_wd,
                             blocs=blocs,
                             dis_bloc_callback=self.dis_bloc_callback,
                             dont_dis_nulstart_bloc=self.dont_dis_nulstart_bloc,
                             attrib=self.attrib)
        return blocs

