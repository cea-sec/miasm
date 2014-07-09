#!/usr/bin/env python
#-*- coding:utf-8 -*-

import logging
import miasm2.expression.expression as m2_expr
from miasm2.expression.simplifications import expr_simp

from miasm2.expression.modint import moduint, modint
from miasm2.core.graph import DiGraph
from miasm2.core.utils import Disasm_Exception, pck
from miasm2.core.graph import DiGraph

import inspect

log_asmbloc = logging.getLogger("asmbloc")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_asmbloc.addHandler(console_handler)
log_asmbloc.setLevel(logging.WARNING)


def whoami():
    return inspect.stack()[2][3]


def is_int(a):
    return isinstance(a, int) or isinstance(a, long) or \
        isinstance(a, moduint) or isinstance(a, modint)


def expr_is_label(e):
    if isinstance(e, m2_expr.ExprId) and isinstance(e.name, asm_label):
        return True
    return False


def expr_is_int_or_label(e):
    if isinstance(e, m2_expr.ExprInt):
        return True
    if isinstance(e, m2_expr.ExprId) and isinstance(e.name, asm_label):
        return True
    return False


class asm_label:

    def __init__(self, name="", offset=None):
        # print whoami()
        self.fixedblocs = False
        if is_int(name):
            name = "loc_%.16X" % (int(name) & 0xFFFFFFFFFFFFFFFF)
        self.name = name
        self.attrib = None
        if offset is None:
            self.offset = offset
        else:
            self.offset = int(offset)
        self._hash = hash((self.name, self.offset))

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

    def __hash__(self):
        return self._hash

    def __eq__(self, a):
        if isinstance(a, asm_label):
            return self._hash == a._hash
        else:
            return False


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
        self._hash = hash((self.label, self.c_t))

    def __str__(self):
        return "%s:%s" % (str(self.c_t), str(self.label))

    def __hash__(self):
        return self._hash

    def __eq__(self, a):
        if isinstance(a, asm_constraint):
            return self._hash == a._hash
        else:
            return False


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


class asm_bloc:

    def __init__(self, label=None):
        self.bto = set()
        self.lines = []
        self.label = label

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
        assert(type(self.bto) is set)
        self.bto.add(c)

    def split(self, offset, l):
        log_asmbloc.debug('split at %x' % offset)
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
        log_asmbloc.debug('flow mod %r' % flow_mod_instr)
        c = asm_constraint(l, asm_constraint.c_next)
        # move dst if flowgraph modifier was in original bloc
        # (usecase: split delayslot bloc)
        if flow_mod_instr:
            for xx in self.bto:
                log_asmbloc.debug('lbl %s' % xx)
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
                return l

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

    def __init__(self, no_collision=True):
        self.labels = []
        self.s = {}
        self.s_offset = {}
        self.no_collision = no_collision
        self.label_num = 0

    def add_label(self, name="", offset=None):
        """
        This should be the only method to create new asm_label objects
        """
        l = asm_label(name, offset)
        collision = None
        if l.offset in self.s_offset and l != self.s_offset[l.offset]:
            collision = 'offset'
        if l.name in self.s and l != self.s[l.name]:
            collision = 'name'
        if self.no_collision and collision == 'offset':
            raise ValueError('symbol %s has same offset as %s' %
                             (l, self.s_offset[l.offset]))
        if self.no_collision and collision == 'name':
            raise ValueError(
                'symbol %s has same name as %s' % (l, self.s[l.name]))
        self.labels.append(l)
        if l.offset is not None:
            self.s_offset[l.offset] = l
        if l.name != "":
            self.s[l.name] = l
        return l

    def remove(self, obj):
        """
        obj can be an asm_label or an offset
        """
        if isinstance(obj, asm_label):
            if obj.name in self.s:
                del(self.s[obj.name])
            if obj.offset is not None and obj.offset in self.s_offset:
                del(self.s_offset[obj.offset])
        else:
            offset = int(obj)
            if offset in self.s_offset:
                obj = self.s_offset[offset]
                del(self.s_offset[offset])
            if obj.name in self.s:
                del(self.s[obj.name])

    def del_offset(self, l=None):
        if l is not None:
            if l.offset in self.s_offset:
                del(self.s_offset[l.offset])
            l.offset = None
        else:
            self.s_offset = {}
            for l in self.s:
                self.s[l].offset = None

    def getby_offset(self, offset):
        return self.s_offset.get(offset, None)

    def getby_name(self, name):
        return self.s.get(name, None)

    def getby_name_create(self, name):
        l = self.getby_name(name)
        if l is None:
            l = self.add_label(name)
        return l

    def getby_offset_create(self, offset):
        l = self.getby_offset(offset)
        if l is None:
            l = self.add_label(offset, offset)
        return l

    def rename(self, s, newname):
        if not s.name in self.s:
            log_asmbloc.warn('unk symb')
            return
        del(self.s[s.name])
        s.name = newname
        self.s[s.name] = s

    def set_offset(self, label, offset):
        # Note that there is a special case when the offset is a list
        # it happens when offsets are recomputed in resolve_symbol*
        if not label.name in self.s:
            raise ValueError('label %s not in symbol pool' % label)
        if not isinstance(label.offset, list) and label.offset in self.s_offset:
            del(self.s_offset[label.offset])
        label.offset = offset
        if not isinstance(label.offset, list):
            self.s_offset[label.offset] = label

    def items(self):
        return self.labels[:]

    def __str__(self):
        return reduce(lambda x, y: x + str(y) + '\n', self.labels, "")

    def __in__(self, obj):
        if obj in self.s:
            return True
        if obj in self.s_offset:
            return True
        return False

    def __getitem__(self, item):
        if item in self.s:
            return self.s[item]
        if item in self.s_offset:
            return self.s_offset[item]
        raise KeyError('unknown symbol %r' % item)

    def __contains__(self, item):
        return item in self.s or item in self.s_offset

    def merge(self, symbol_pool):
        self.labels += symbol_pool.labels
        self.s.update(symbol_pool.s)
        self.s_offset.update(symbol_pool.s_offset)

    def gen_label(self):
        l = self.add_label("lbl_gen_%.8X" % (self.label_num))
        self.label_num += 1
        return l


def dis_bloc(mnemo, pool_bin, cur_bloc, offset, job_done, symbol_pool,
             dont_dis=[], split_dis=[
             ], follow_call=False, patch_instr_symb=True,
             dontdis_retcall=False, lines_wd=None,
             dis_bloc_callback=None, dont_dis_nulstart_bloc=False,
             attrib={}):
    # pool_bin.offset = offset
    lines_cpt = 0
    in_delayslot = False
    delayslot_count = mnemo.delayslot
    offsets_to_dis = set()
    add_next_offset = False
    log_asmbloc.debug("dis at %X" % int(offset))
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
            log_asmbloc.warning("cannot disasm at %X" % int(off_i))
            cur_bloc.add_cst(off_i, asm_constraint.c_bad, symbol_pool)
            break

        # XXX TODO nul start block option
        if dont_dis_nulstart_bloc and instr.b.count('\x00') == instr.l:
            log_asmbloc.warning("reach nul instr at %X" % int(off_i))
            cur_bloc.add_cst(off_i, asm_constraint.c_bad, symbol_pool)
            break

        # special case: flow graph modificator in delayslot
        if in_delayslot and instr and (instr.splitflow() or instr.breakflow()):
            add_next_offset = True
            break

        job_done.add(offset)
        log_asmbloc.debug("dis at %X" % int(offset))

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
                if isinstance(d, m2_expr.ExprId) and isinstance(d.name, asm_label):
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
    i = -1
    err = False
    if not more_ref:
        more_ref = []

    # get all possible dst
    bloc_dst = [symbol_pool.s_offset[x] for x in more_ref]
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
            log_asmbloc.debug("split bloc %x" % off)
            if new_b is None:
                log_asmbloc.error("cannot split %x!!" % off)
                err = True
                break
            if dis_bloc_callback:
                offsets_to_dis = set(
                    [x.label.offset for x in new_b.bto
                    if isinstance(x.label, asm_label)])
                dis_bloc_callback(
                    mnemo, attrib, pool_bin, new_b, offsets_to_dis,
                    symbol_pool)
            blocs.append(new_b)
            a, b = cb.get_range()

        """
        if err:
            break
        """
    return blocs


def dis_bloc_all(mnemo, pool_bin, offset, job_done, symbol_pool, dont_dis=[],
                 split_dis=[], follow_call=False, patch_instr_symb=True,
                 dontdis_retcall=False,
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
            log_asmbloc.debug("blocs watchdog reached at %X" % int(offset))
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
                         dont_dis, split_dis, follow_call, patch_instr_symb,
                         dontdis_retcall,
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
            elif isinstance(b.label, asm_label):
                dst, name, cst = b.label.name, n.label.name, n.c_t
            else:
                continue
            out += '%s -> %s [ label = "%s" ];\n' % (dst, name, cst)

    out += "}"
    return out


def conservative_asm(mnemo, mode, instr, symbols, conservative):
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

def fix_expr_val(e, symbols):
    def expr_calc(e):
        if isinstance(e, m2_expr.ExprId):
            s = symbols.s[e.name]
            e = m2_expr.ExprInt_from(e, s.offset)
        return e
    e = e.visit(expr_calc)
    e = expr_simp(e)
    return e


def guess_blocs_size(mnemo, mode, blocs, symbols):
    """
    Asm and compute max bloc length
    """
    for b in blocs:
        log_asmbloc.debug('---')
        blen = 0
        blen_max = 0
        for instr in b.lines:
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
                l = mnemo.max_instruction_len
                data = None
            instr.data = data
            instr.l = l
            blen += l

        b.blen = blen
        # bloc with max rel values encoded
        b.blen_max = blen + blen_max
        log_asmbloc.info("blen: %d max: %d" % (b.blen, b.blen_max))


def group_blocs(blocs):
    """
    this function group asm blocs with next constraints
    """
    log_asmbloc.info('group_blocs')
    # group adjacent blocs
    rest = blocs[:]
    groups_bloc = {}
    d = dict([(x.label, x) for x in rest])
    log_asmbloc.debug([str(x.label) for x in rest])

    while rest:
        b = [rest.pop()]
        # find recursive son
        fini = False
        while not fini:
            fini = True
            for c in b[-1].bto:
                if c.c_t != asm_constraint.c_next:
                    continue
                if c.label in d and d[c.label] in rest:
                    b.append(d[c.label])
                    rest.remove(d[c.label])
                    fini = False
                    break
        # check if son in group:
        found_in_group = False
        for c in b[-1].bto:
            if c.c_t != asm_constraint.c_next:
                continue
            if c.label in groups_bloc:
                b += groups_bloc[c.label]
                del(groups_bloc[c.label])
                groups_bloc[b[0].label] = b
                found_in_group = True
                break

        if not found_in_group:
            groups_bloc[b[0].label] = b

    # create max label range for bigbloc
    for l in groups_bloc:
        l.total_max_l = reduce(lambda x, y: x + y.blen_max, groups_bloc[l], 0)
        log_asmbloc.debug(("offset totalmax l", l.offset, l.total_max_l))
        if is_int(l.offset):
            hof = hex(int(l.offset))
        else:
            hof = l.name
        log_asmbloc.debug(("offset totalmax l", hof, l.total_max_l))
    return groups_bloc


def gen_free_space_intervals(f, max_offset=0xFFFFFFFF):
    interval = {}
    offset_label = dict([(x.offset_free, x) for x in f])
    offset_label_order = offset_label.keys()
    offset_label_order.sort()
    offset_label_order.append(max_offset)
    offset_label_order.reverse()

    unfree_stop = 0L
    while len(offset_label_order) > 1:
        offset = offset_label_order.pop()
        offset_end = offset + f[offset_label[offset]]
        prev = 0
        if unfree_stop > offset_end:
            space = 0
        else:
            space = offset_label_order[-1] - offset_end
            if space < 0:
                space = 0
            interval[offset_label[offset]] = space
            if offset_label_order[-1] in offset_label:
                prev = offset_label[offset_label_order[-1]]
                prev = f[prev]

        interval[offset_label[offset]] = space

        unfree_stop = max(
            unfree_stop, offset_end, offset_label_order[-1] + prev)
    return interval


def add_dont_erase(f, dont_erase=[]):
    tmp_symbol_pool = asm_symbol_pool()
    for a, b in dont_erase:
        l = tmp_symbol_pool.add_label(a, a)
        l.offset_free = a
        f[l] = b - a
    return


def gen_non_free_mapping(group_bloc, dont_erase=[]):
    non_free_mapping = {}
    # calculate free space for bloc placing
    for g in group_bloc:
        rest_len = 0
        g.fixedblocs = False
        # if a label in the group is fixed
        diff_offset = 0
        for b in group_bloc[g]:
            if not is_int(b.label.offset):
                diff_offset += b.blen_max
                continue
            g.fixedblocs = True
            g.offset_free = b.label.offset - diff_offset
            break
        if g.fixedblocs:
            non_free_mapping[g] = g.total_max_l

    log_asmbloc.debug("non free bloc:")
    log_asmbloc.debug(non_free_mapping)
    add_dont_erase(non_free_mapping, dont_erase)
    log_asmbloc.debug("non free more:")
    log_asmbloc.debug(non_free_mapping)
    return non_free_mapping


def resolve_symbol(
    group_bloc, symbol_pool, dont_erase=[], max_offset=0xFFFFFFFF):
    """
    place all asmblocs
    """
    log_asmbloc.info('resolve_symbol')
    log_asmbloc.info(str(dont_erase))
    bloc_list = []
    unr_bloc = reduce(lambda x, y: x + group_bloc[y], group_bloc, [])
    ending_ad = []

    non_free_mapping = gen_non_free_mapping(group_bloc, dont_erase)
    free_interval = gen_free_space_intervals(non_free_mapping, max_offset)
    log_asmbloc.debug(free_interval)

    # first big ones
    g_tab = [(x.total_max_l, x) for x in group_bloc]
    g_tab.sort()
    g_tab.reverse()
    g_tab = [x[1] for x in g_tab]

    # g_tab => label of grouped blov
    # group_bloc => dict of grouped bloc labeled-key

    # first, near callee placing algo
    for g in g_tab:
        if g.fixedblocs:
            continue
        finish = False
        for x in group_bloc:
            if not x in free_interval.keys():
                continue
            if free_interval[x] < g.total_max_l:
                continue

            for b in group_bloc[x]:
                for c in b.bto:
                    if c.label == g:
                        tmp = free_interval[x] - g.total_max_l
                        log_asmbloc.debug(
                            "consumed %d rest: %d" % (g.total_max_l, int(tmp)))
                        free_interval[g] = tmp
                        del(free_interval[x])
                        symbol_pool.set_offset(
                            g, [group_bloc[x][-1].label, group_bloc[x][-1], 1])
                        g.fixedblocs = True
                        finish = True
                        break
                if finish:
                    break
            if finish:
                break

    # second, bigger in smaller algo
    for g in g_tab:
        if g.fixedblocs:
            continue
        # chose smaller free_interval first
        k_tab = [(free_interval[x], x) for x in free_interval]
        k_tab.sort()
        k_tab = [x[1] for x in k_tab]
        # choose free_interval
        for k in k_tab:
            if g.total_max_l > free_interval[k]:
                continue
            symbol_pool.set_offset(
                g, [group_bloc[k][-1].label, group_bloc[k][-1], 1])
            tmp = free_interval[k] - g.total_max_l
            log_asmbloc.debug(
                "consumed %d rest: %d" % (g.total_max_l, int(tmp)))
            free_interval[g] = tmp
            del(free_interval[k])

            g.fixedblocs = True
            break

    while unr_bloc:
        # propagate know offset
        resolving = False
        i = 0
        while i < len(unr_bloc):
            if unr_bloc[i].label.offset is None:
                i += 1
                continue
            resolving = True
            log_asmbloc.info("bloc %s resolved" % unr_bloc[i].label)
            bloc_list.append((unr_bloc[i], 0))
            g_found = None
            for g in g_tab:
                if unr_bloc[i] in group_bloc[g]:
                    if g_found is not None:
                        raise ValueError('blocin multiple group!!!')
                    g_found = g
            my_group = group_bloc[g_found]

            index = my_group.index(unr_bloc[i])
            if index > 0 and my_group[index - 1] in unr_bloc:
                symbol_pool.set_offset(
                    my_group[index - 1].label,
                    [unr_bloc[i].label, unr_bloc[i - 1], -1])
            if index < len(my_group) - 1 and my_group[index + 1] in unr_bloc:
                symbol_pool.set_offset(
                    my_group[index + 1].label,
                    [unr_bloc[i].label, unr_bloc[i], 1])
            del unr_bloc[i]

        if not resolving:
            log_asmbloc.warn("cannot resolve symbol! (no symbol fix found)")
        else:
            continue

        for g in g_tab:
            print g
            if g.fixedblocs:
                print "fixed"
            else:
                print "not fixed"
        raise ValueError('enable to fix bloc')
    return bloc_list


def calc_symbol_offset(symbol_pool):
    s_to_use = set()

    s_dependent = {}

    for label in symbol_pool.items():
        if label.offset is None:
            # raise ValueError("symbol missing?", label)
            #print "symbol missing?? %s" % label
            label.offset_g = None
            continue
        if not is_int(label.offset):
            # construct dependant blocs tree
            s_d = label.offset[0]
            if not s_d in s_dependent:
                s_dependent[s_d] = set()
            s_dependent[s_d].add(label)
        else:
            s_to_use.add(label)
        label.offset_g = label.offset

    while s_to_use:
        label = s_to_use.pop()
        if not label in s_dependent:
            continue
        for l in s_dependent[label]:
            if label.offset_g is None:
                raise ValueError("unknown symbol: %s" % str(label.name))
            l.offset_g = label.offset_g + l.offset_g[1].blen * l.offset_g[2]
            s_to_use.add(l)


def asmbloc_final(mnemo, mode, blocs, symbol_pool, symb_reloc_off=None, conservative = False):
    log_asmbloc.info("asmbloc_final")
    if symb_reloc_off is None:
        symb_reloc_off = {}
    fini = False
    # asm with minimal instr len
    # check if dst label are ok to this encoded form
    # recompute if not
    # TODO XXXX: implement todo list to remove n^high complexity!
    while fini is not True:

        fini = True
        my_symb_reloc_off = {}

        calc_symbol_offset(symbol_pool)

        symbols = asm_symbol_pool()
        for s, v in symbol_pool.s.items():
            symbols.add_label(s, v.offset_g)
        # print symbols
        # test if bad encoded relative
        for b, t in blocs:

            offset_i = 0
            blen = 0
            my_symb_reloc_off[b.label] = []
            for instr in b.lines:
                if isinstance(instr, asm_raw):
                    if isinstance(instr.raw, list):
                        # fix special asm_raw
                        data = ""
                        for x in instr.raw:
                            e = fix_expr_val(x, symbols)
                            data+= pck[e.size](e.arg)
                        instr.data = data

                    offset_i += instr.l
                    continue
                sav_a = instr.args[:]
                instr.offset = b.label.offset_g + offset_i
                args_e = instr.resolve_args_with_symbols(symbols)
                for i, e in enumerate(args_e):
                    instr.args[i] = e

                if instr.dstflow():
                    instr.fixDstOffset()

                symbol_reloc_off = []
                old_l = instr.l
                c, candidates = conservative_asm(
                    mnemo, mode, instr, symbol_reloc_off, conservative)

                # print candidates
                for i, e in enumerate(sav_a):
                    instr.args[i] = e

                if len(c) != instr.l:
                    # good len, bad offset...XXX
                    b.blen = b.blen - old_l + len(c)
                    instr.data = c
                    instr.l = len(c)
                    fini = False
                    continue
                found = False
                for cpos, c in enumerate(candidates):
                    # if len(c) == len(instr.data):
                    if len(c) == instr.l:
                        # print 'UPDD', repr(instr.data), repr(c)
                        # b.blen = b.blen-old_l+len(c)
                        instr.data = c
                        instr.l = len(c)

                        found = True
                        break
                if not found:
                    raise ValueError('something wrong in instr.data')

                if cpos < len(symbol_reloc_off):
                    my_s = symbol_reloc_off[cpos]
                else:
                    my_s = None

                if my_s is not None:
                    my_symb_reloc_off[b.label].append(offset_i + my_s)
                offset_i += instr.l
                blen += instr.l
                assert(len(instr.data) == instr.l)
    # we have fixed all relative values
    # recompute good offsets
    for label in symbol_pool.items():
        # if label.offset_g is None:
        #    fdfd
        symbol_pool.set_offset(label, label.offset_g)

    for a, b in my_symb_reloc_off.items():
        symb_reloc_off[a] = b


def asm_resolve_final(mnemo, mode, blocs, symbol_pool, dont_erase=[],
                      max_offset=0xFFFFFFFF,
                      symb_reloc_off=None, constrain_pos=False):
    if symb_reloc_off is None:
        symb_reloc_off = {}
    # asmbloc(mnemo, mode, blocs, symbol_pool)
    guess_blocs_size(mnemo, mode, blocs, symbol_pool)
    bloc_g = group_blocs(blocs)

    resolved_b = resolve_symbol(bloc_g, symbol_pool, dont_erase=dont_erase,
                                max_offset=max_offset)

    asmbloc_final(mnemo, mode, resolved_b, symbol_pool, symb_reloc_off)
    written_bytes = {}
    patches = {}
    for b, t in resolved_b:
        offset = b.label.offset
        for i in b.lines:
            assert(i.data is not None)
            patches[offset] = i.data
            for c in range(i.l):
                if offset + c in written_bytes:
                    raise ValueError(
                        "overlapping bytes in asssembly %X" % int(offset))
                written_bytes[offset + c] = 1
            i.offset = offset
            i.l = i.l
            offset += i.l

    return resolved_b, patches


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
            print 'XXX unknown label'
            continue
        x = blocby_label[x.label]
        all_path += bloc_find_path_next(blocs, blocby_label, x, b, path + [a])
        # stop if at least one path found
        if all_path:
            return all_path
    return all_path


def bloc_merge(blocs, symbol_pool, dont_merge=[]):
    i = -1
    """
    # TODO XXXX implement find all path for digraph

    g = blist2graph(blocs)
    g.lbl2node = dict([(b.label, b) for b in blocs])

    while i<len(blocs)-1:
        i+=1
        b = blocs[i]
        if b.label in dont_merge:
            continue

        successors = [x for x in g.successors(b.label)]
        predecessors = [x for x in g.predecessors(b.label)]
        # if bloc doesn't self ref
        if b.label in successors:
            continue
        # and bloc has only one parent
        if len(predecessors) != 1:
            continue
        # may merge
        bpl = predecessors[0]

        # and parent has only one son
        p_s = [x for x in g.successors(bpl)]
        if len(p_s)!=1:
            continue

        bp = g.lbl2node[bpl]
        # and parent has not a next constraint yet
        found = False
        for gpl in g.predecessors(bpl):
            gp = g.lbl2node[gpl]
            for x in gp.bto:
                if x.c_t != asm_constraint.c_next:
                    continue
                if x.label == bpl:
                    found = True
                    break
            if found:
                break
        if found:
            continue
        if bp.lines:
            l = bp.lines[-1]
            #jmp opt; jcc opt
            if l.is_subcall():
                continue
            if l.breakflow() and l.dstflow():
                bp.lines.pop()
        #merge
        #sons = b.bto[:]

        # update parents
        for s in b.bto:
            if not isinstance(s.label, asm_label): continue
            if s.label.name == None:
                continue
            if not s.label in g.lbl2node:
                print "unknown parent XXX"
                continue
            bs = g.lbl2node[s.label]
            for p in g.predecessors(bs.label):
                if p == b.label:
                    bs.parents.discard(p)
                    bs.parents.add(bp.label)
        bp.lines+=b.lines
        bp.bto = b.bto
        #symbol_pool.remove(b.label)
        del(blocs[i])
        i = -1

    return
    """
    blocby_label = {}
    for b in blocs:
        blocby_label[b.label] = b
        b.parents = find_parents(blocs, b.label)

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
        """
        and will not create next loop composed of constraint_next from son to
        parent
        """
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
                print "unknown parent XXX"
                continue
            bs = blocby_label[s.label]
            for p in list(bs.parents):
                if p == b.label:
                    bs.parents.discard(p)
                    bs.parents.add(bp.label)
        bp.lines += b.lines
        bp.bto = b.bto
        # symbol_pool.remove(b.label)
        del(blocs[i])
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
        self.patch_instr_symb = True
        self.dontdis_retcall = False
        self.lines_wd = None
        self.blocs_wd = None
        self.dis_bloc_callback = None
        self.dont_dis_nulstart_bloc = False
        self.job_done = set()
        self.__dict__.update(kwargs)

    def dis_bloc(self, offset):
        job_done = set()
        l = self.symbol_pool.getby_offset_create(offset)
        current_bloc = asm_bloc(l)
        dis_bloc(self.arch, self.bs, current_bloc, offset, self.job_done,
                 self.symbol_pool,
                 dont_dis=self.dont_dis, split_dis=self.split_dis,
                 follow_call=self.follow_call,
                 patch_instr_symb=self.patch_instr_symb,
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
                             patch_instr_symb=self.patch_instr_symb,
                             dontdis_retcall=self.dontdis_retcall,
                             blocs_wd=self.blocs_wd,
                             lines_wd=self.lines_wd,
                             blocs=blocs,
                             dis_bloc_callback=self.dis_bloc_callback,
                             dont_dis_nulstart_bloc=self.dont_dis_nulstart_bloc,
                             attrib=self.attrib)
        return blocs

