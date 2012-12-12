#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
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
import re
import logging
import shlex
import struct
from miasm.tools.modint import uint1, uint8, uint16, uint32, uint64
from miasm.tools.modint import int8, int16, int32, int64
from collections import defaultdict
log_asmbloc = logging.getLogger("asmbloc")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log_asmbloc.addHandler(console_handler)
log_asmbloc.setLevel(logging.WARN)

tab_int_size = {int8:8,
                uint8:8,
                int16:16,
                uint16:16,
                int32:32,
                uint32:32,
                int64:64,
                uint64:64
                }


def is_int(a):
    t = [int, long,
         int8, int16, int32, int64,
         uint8, uint16, uint32, uint64]
    return any([isinstance(a, x) for x in t])

class asm_label:
    def __init__(self, name = "", offset = None):

        self.fixedblocs = False
        if is_int(name):
            name = "loc_%.16X"%(int(name)&0xFFFFFFFFFFFFFFFF)
        self.name = name
        self.attrib = None
        if offset == None:
            self.offset = offset
        else:
            self.offset = int(offset)

    def __str__(self):
        if isinstance(self.offset, (int, long)):
            return "%s: 0x%08x" % (self.name, self.offset)
        else:
            return "%s: %s" % (self.name, str(self.offset))
    def __repr__(self):
        rep = '<asmlabel '
        if self.name:
            rep+=repr(self.name)+' '
        rep+='>'
        return rep

class asm_raw:
    def __init__(self, raw = ""):
        self.raw = raw
    def __str__(self):
        return repr(self.raw)

class asm_constraint:
    c_to = "c_to"
    c_next = "c_next"

    def __init__(self, label = None, c_t = c_to):
        self.label = label
        self.c_t = c_t

    def __str__(self):
        return str(self.label)+'\t'+str(self.c_t)


class asm_bloc:
    def __init__(self, label=None):
        self.bto = []
        self.lines = []
        self.label = label
    def __str__(self):
        out = str(self.label)+"\n"
        for l in self.lines:
            out+=str(l)+'\n'
        out+="to ->"
        for l in self.bto:
            if l == None:
                out+="Unknown? "
            else:
                out+=str(l)+" "
        return out
    def addline(self, l):
        self.lines.append(l)
    def addto(self, l):
        self.bto.append(l)
    def split(self, offset, l):
        i = -1
        offsets = [x.offset for x in self.lines]
        if not l.offset in offsets:
            log_asmbloc.warning( 'cannot split bloc at %X  middle instruction? default middle'%offset)
            offsets.sort()
            return None
        new_bloc = asm_bloc(l)
        i = offsets.index(offset)
        self.lines, new_bloc.lines = self.lines[:i],self.lines[i:]
        new_bloc.bto = self.bto
        c = asm_constraint(l, asm_constraint.c_next)
        self.bto = [c]
        return new_bloc

    def get_range(self):
        if len(self.lines):
            return self.lines[0].offset, self.lines[-1].offset
        else:
            return 0,0
    def get_offsets(self):
        return [x.offset for x in self.lines]

class asm_symbol_pool:
    def __init__(self, no_collision = True):
        self.labels = []
        self.s = {}
        self.s_offset = {}
        self.no_collision = no_collision

    def add_label(self, name = "", offset = None):
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
            raise ValueError('symbol %s has same offset as %s'%(l, self.s_offset[l.offset]))
        if self.no_collision and collision == 'name':
            raise ValueError('symbol %s has same name as %s'%(l, self.s[l.name]))
        self.labels.append(l)
        if l.offset != None:
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
            if obj.offset != None and obj.offset in self.s_offset:
                del(self.s_offset[obj.offset])
        else:
            offset = int(obj)
            if offset in self.s_offset:
                obj = self.s_offset[offset]
                del(self.s_offset[offset])
            if obj.name in self.s:
                del(self.s[obj.name])

    def del_offset(self, l = None):
        if l:
            if l.offset in self.s_offset:
                del(self.s_offset[l.offset])
            l.offset = None
        else:
            self.s_offset = {}
            for l in self.s:
                self.s[l].offset = None

    def getby_offset(self, offset):
        l = asm_label(offset, offset)
        if l.offset in self.s_offset:
            return self.s_offset[l.offset]
        return None

    def getby_name(self, name):
        l = asm_label(name)
        if l.name in self.s:
            return self.s[l.name]
        return None

    def getby_name_create(self, name):
        l = self.getby_name(name)
        if l == None:
            l = self.add_label(name)
        return l

    def getby_offset_create(self, offset):
        l = self.getby_offset(offset)
        if l == None:
            l = self.add_label(offset, offset)
        return l

    def rename(self, s, newname):
        if not s.name in self.s:
            print 'unk symb'
            return
        del(self.s[s.name])
        s.name = newname
        self.s[s.name] = s

    def set_offset(self, label, offset):
        # Note that there is a special case when the offset is a list
        # it happens when offsets are recomputed in resolve_symbol*
        if not label in self.labels:
            raise ValueError('label %s not in symbol pool'%label)
        if not isinstance(label.offset, list) and label.offset in self.s_offset:
            del(self.s_offset[label.offset])
        label.offset = offset
        if not isinstance(label.offset, list):
            self.s_offset[label.offset] = label

    def items(self):
        return self.labels[:]

    def __str__(self):
        return reduce(lambda x,y: x+str(y)+'\n', self.labels, "")

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
        raise KeyError('unknown symbol %r'%item)


class interval():
    # addrs represent interval using the form:
    # [start_addr1, stop_addr1[ U [start_addr2, stop_addr2[ U ...
    def __init__(self, addrs):
        self.intervals = addrs
    def __contains__(self, ad):
        for start, stop in self.intervals:
            if start <= ad < stop:
                return True
        return False
    def __getitem__(self, s):
        return self.intervals.__getitem__(s)


def dis_bloc(mnemo, pool_bin, cur_bloc, offset, job_done, symbol_pool,
             dont_dis = [], follow_call = False, patch_instr_symb = True,
             dontdis_retcall = False, lines_wd = None,
             dis_bloc_callback = None, dont_dis_nulstart_bloc = False,
             attrib = {}):
    pool_bin.offset = offset
    lines_cpt = 0
    while True:
        lines_cpt+=1
        if lines_wd !=None and lines_cpt>lines_wd:
            #log_asmbloc.warning( "lines watchdog reached at %X"%int(offset))
            offsets_to_dis = []
            break

        if pool_bin.offset in dont_dis:
            l = symbol_pool.getby_offset_create(pool_bin.offset)
            c = asm_constraint(l, asm_constraint.c_next)
            cur_bloc.bto = [c]
            offsets_to_dis = [pool_bin.offset]
            break
        if pool_bin.offset in job_done:
            l = symbol_pool.getby_offset(pool_bin.offset)
            if l != None:
                c = asm_constraint(l, asm_constraint.c_next)
                cur_bloc.bto = [c]
                offsets_to_dis = [pool_bin.offset]
                break
        job_done.add(pool_bin.offset)
        log_asmbloc.debug("dis at %X"%int(pool_bin.offset))
        off_i = pool_bin.offset
        if lines_cpt <=1 and dont_dis_nulstart_bloc:
            c = pool_bin.readbs()
            pool_bin.offset = off_i
            if c == "\x00":
                offsets_to_dis = []
                log_asmbloc.warning( "bloc start with nul %X"%int(off_i))
                break

        try:
            instr = mnemo.dis(pool_bin, attrib)
        except StandardError, e:
            log_asmbloc.warning(e)
            instr = None

        if instr == None:
            log_asmbloc.warning( "cannot disasm at %X"%int(off_i))
            l = symbol_pool.getby_offset_create(off_i)
            c = asm_constraint(l, asm_constraint.c_next)
            #cur_bloc.bto = [c]
            offsets_to_dis = []#pool_bin.offset]
            break
        log_asmbloc.debug(instr)
        log_asmbloc.debug(instr.m)
        log_asmbloc.debug(instr.arg)

        cur_bloc.addline(instr)
        if not instr.breakflow():
            continue

        if instr.splitflow() and not (instr.is_subcall() and dontdis_retcall):
            n = instr.getnextflow()
            l = symbol_pool.getby_offset_create(n)
            c = asm_constraint(l, asm_constraint.c_next)
            cur_bloc.bto.append(c)

        if instr.dstflow():
            dst = instr.getdstflow()
            dstn = []
            for d in dst:
                if is_int(d):
                    d = symbol_pool.getby_offset_create(d)
                dstn.append(d)
            dst = dstn
            # XXX todo: remove this test
            if len(dst) >= 1:
                if isinstance(dst[0], asm_label):
                    instr.setdstflow(dst)
            if (not instr.is_subcall()) or follow_call:
                cur_bloc.bto+=[asm_constraint(x, asm_constraint.c_to) for x in dst]
        offsets_to_dis = [x.label.offset for x in cur_bloc.bto if isinstance(x.label, asm_label)]
        break

    if dis_bloc_callback != None:
        dis_bloc_callback(mnemo, cur_bloc, offsets_to_dis, symbol_pool)
    return offsets_to_dis



def dis_i(mnemo, pool_bin, offset):
    symbol_pool = asm_symbol_pool()
    dum_l = symbol_pool.getby_offset_create(offset)
    dum_b = asm_bloc(dum_l)
    dis_bloc(mnemo, pool_bin, dum_b, offset, set(), symbol_pool, lines_wd = 1)
    if not dum_b.lines:
        return None
    return dum_b.lines[0]

def split_bloc(mnemo, all_bloc, symbol_pool, more_ref = None, dis_bloc_callback = None):
    i = -1
    err = False
    if not more_ref:
        more_ref = []
    more_ref = [symbol_pool.s_offset[x] for x in more_ref]
    while i<len(all_bloc)-1:
        i+=1
        for n in [x.label for x in all_bloc[i].bto if isinstance(x.label, asm_label)]+ more_ref:
            if n == None:
                continue
            n = n.offset
            j = -1
            while j<len(all_bloc)-1:# and not err:
                j+=1
                a,b = all_bloc[j].get_range()
                if n >a and n <=b:
                    l = symbol_pool.getby_offset_create(n)
                    new_b = all_bloc[j].split(n,l)
                    log_asmbloc.debug("split bloc %x"%n)
                    if new_b== None:
                        log_asmbloc.error("cannot split %x!!"%n)
                        err = True
                        break
                    if dis_bloc_callback:
                        dis_bloc_callback(mnemo, new_b, [x.label.offset for x in new_b.bto if isinstance(x.label, asm_label)],
                                          symbol_pool)
                    all_bloc.append(new_b)
            """
            if err:
                break
            """
    return all_bloc

def dis_bloc_all(mnemo, pool_bin, offset, job_done, symbol_pool, dont_dis = [],
                 follow_call = False, patch_instr_symb = True, dontdis_retcall = False,
                 bloc_wd = None, lines_wd = None, all_bloc = None,
                 dis_bloc_callback = None, dont_dis_nulstart_bloc = False,
                 attrib = {}):
    log_asmbloc.info("dis bloc all")
    if all_bloc == None:
        all_bloc = []
    todo = [offset]

    bloc_cpt = 0
    while len(todo):
        bloc_cpt+=1
        if bloc_wd !=None and bloc_cpt>bloc_wd:
            log_asmbloc.debug( "blocs watchdog reached at %X"%int(offset))
            break

        n = int(todo.pop(0))
        if n in job_done:
            continue
        if n == None:
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
                         dont_dis, follow_call, patch_instr_symb,
                         dontdis_retcall,
                         dis_bloc_callback = dis_bloc_callback,
                         lines_wd = lines_wd,
                         dont_dis_nulstart_bloc = dont_dis_nulstart_bloc,
                         attrib = attrib)
        all_bloc.append(cur_bloc)


    return split_bloc(mnemo, all_bloc, symbol_pool, dis_bloc_callback = dis_bloc_callback)


def bloc2graph(blocs, label = False, lines = True):
    #rankdir=LR;
    out = """
digraph asm_graph {
size="80,50";
node [
fontsize = "16",
shape = "box"
];
"""
    for b in blocs:
        out+='%s [\n'%b.label.name
        out+='label = "'

        out+=b.label.name+"\\l\\\n"
        if lines:
            for l in b.lines:
                if label:
                    out+="%.8X "%l.offset
                out+="%s\\l\\\n"%l
        out+='"\n];\n'

    for b in blocs:
        for n in b.bto:
            if isinstance(n.label, asm_label):
                out+='%s -> %s [ label = "%s" ];\n'%(b.label.name, n.label.name, n.c_t)
    out+="}"
    return out

#this function group asm blocs with next constraints
def group_blocs(all_bloc):
    log_asmbloc.info('group_blocs')
    #group adjacent blocs
    rest = all_bloc[:]
    groups_bloc = {}
    d = dict([(x.label,x) for x in rest])
    log_asmbloc.debug([str(x.label) for x in rest])

    while rest:
        b = [rest.pop()]
        #find recursive son
        fini =False
        while not fini:
            fini=True
            for c in b[-1].bto:
                if c.c_t != asm_constraint.c_next:
                    continue
                if d[c.label] in rest:
                    b.append(d[c.label])
                    rest.remove(d[c.label])
                    fini =False
                    break
        #check if son in group:
        found_in_group = False
        for c in b[-1].bto:
            if c.c_t != asm_constraint.c_next:
                continue
            if c.label in groups_bloc:
                b+=groups_bloc[c.label]
                del(groups_bloc[c.label])
                groups_bloc[b[0].label] = b
                found_in_group = True
                break

        if not found_in_group:
            groups_bloc[b[0].label] = b

    #create max label range for bigbloc
    for l in groups_bloc:
        l.total_max_l = reduce(lambda x,y: x+y.blen_max, groups_bloc[l], 0)
        log_asmbloc.debug(("offset totalmax l", l.offset, l.total_max_l))
        if is_int(l.offset):
            hof = hex(int(l.offset))
        else:
            hof = l.name
        log_asmbloc.debug(("offset totalmax l", hof, l.total_max_l))
    return groups_bloc


def gen_free_space_intervals(f):
    interval = {}
    last_offset = 0xFFFFFFFF
    offset_label = dict([(x.offset_free,x) for x in f])
    offset_label_order = offset_label.keys()
    offset_label_order.sort()
    offset_label_order.append(last_offset)
    offset_label_order.reverse()


    unfree_stop= 0L
    while len(offset_label_order)>1:
        offset = offset_label_order.pop()
        offset_end = offset+f[offset_label[offset]]
        prev = 0
        if unfree_stop>offset_end:
            space = 0
        else:
            space = offset_label_order[-1]-offset_end
            if space <0:
                space = 0
            interval[offset_label[offset]] = space
            if offset_label_order[-1] in offset_label:
                prev = offset_label[offset_label_order[-1]]
                prev = f[prev]

        interval[offset_label[offset]] = space

        unfree_stop = max(unfree_stop, offset_end, offset_label_order[-1]+prev)

    return interval

def add_dont_erase(f, dont_erase = []):
    tmp_symbol_pool = asm_symbol_pool()
    for a,b in dont_erase:
        l = tmp_symbol_pool.add_label(a, a)
        l.offset_free = a
        f[l] = b-a
    return


def del_dis_offset(all_bloc, symbol_pool):
    for b in all_bloc:
        symbol_pool.s[b.label.name].offset = None



def gen_non_free_mapping(group_bloc, dont_erase = []):
    non_free_mapping = {}
    #calculate free space for bloc placing
    for g in group_bloc:
        rest_len = 0
        g.fixedblocs = False
        #if a label in the group is fixed
        diff_offset = 0
        for b in group_bloc[g]:
            if not is_int(b.label.offset):
                diff_offset+=b.blen_max
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



# if one bloc is fixed in the bloc list, this function
# will fix other blocs around this one.
def fix_bloc_around_anchored_bloc(unr_bloc, symbol_pool):

    l2b = {}
    for b in unr_bloc:
        l2b[b.label] = b

    b_done = set()
    b_todo = set()
    b_rest = set()
    for l in unr_bloc:
        if l.label.fixedblocs:
            b_todo.add(l.label)
        else:
            b_rest.add(l.label)
    print b_todo
    print b_rest

    while b_todo:
        b = b_todo.pop()
        print 'testing ', b
        b_done.add(b)
        i = unr_bloc.index(l2b[b])
        if i >0 and unr_bloc[i-1].label in b_rest:
            symbol_pool.set_offset(unr_bloc[i-1].label, [b, unr_bloc[i-1], -1])
            unr_bloc[i-1].fixedblocs = True
            b_todo.add(unr_bloc[i-1].label)
            b_rest.remove(unr_bloc[i-1].label)
        if i < len(unr_bloc)-1 and unr_bloc[i+1].label in b_rest:
            symbol_pool.set_offset(unr_bloc[i+1].label, [b, unr_bloc[i], 1])
            unr_bloc[i+1].fixedblocs = True
            b_todo.add(unr_bloc[i+1].label)
            b_rest.remove(unr_bloc[i+1].label)


# place all asmblocs, ordered
# XXX WARNING, doesn't use dont erase arg!!
def resolve_symbol_linear(bloc_list, group_bloc, symbol_pool, dont_erase = []):
    print bloc_list
    log_asmbloc.info('resolve_symbol')
    log_asmbloc.info(str(dont_erase))

    non_free_mapping = gen_non_free_mapping(group_bloc, dont_erase)




    unr_bloc = []

    for l in bloc_list:
        unr_bloc+=group_bloc[l]

    l2b = {}
    for b in unr_bloc:
        l2b[b.label] = b

    # first, link grouped bloc around fixed labels
    for g in group_bloc.values():
        fix_bloc_around_anchored_bloc(g, symbol_pool)




    b_done = set()
    b_todo = set()
    b_rest = set()
    for l in unr_bloc:
        if l.label in bloc_list and l.label.fixedblocs:
            b_todo.add(l.label)
        else:
            b_rest.add(l.label)
    print b_todo
    print b_rest

    while b_todo:
        b = b_todo.pop()
        print 'testing ', b
        b_done.add(b)
        i = unr_bloc.index(l2b[b])
        if i >0 and unr_bloc[i-1].label in b_rest:
            symbol_pool.set_offset(unr_bloc[i-1].label, [b, unr_bloc[i-1], -1])
            b_todo.add(unr_bloc[i-1].label)
            b_rest.remove(unr_bloc[i-1].label)
        if i < len(unr_bloc)-1 and unr_bloc[i+1].label in b_rest:
            symbol_pool.set_offset(unr_bloc[i+1].label, [b, unr_bloc[i], 1])
            b_todo.add(unr_bloc[i+1].label)
            b_rest.remove(unr_bloc[i+1].label)
    print b_todo
    print b_rest
    print b_done

    return [(x,0) for x in unr_bloc]

#place all asmblocs
def resolve_symbol(group_bloc, symbol_pool, dont_erase = []):
    log_asmbloc.info('resolve_symbol')
    log_asmbloc.info(str(dont_erase))
    bloc_list = []
    unr_bloc = reduce(lambda x,y: x+group_bloc[y], group_bloc, [])
    ending_ad = []

    non_free_mapping = gen_non_free_mapping(group_bloc, dont_erase)
    free_interval = gen_free_space_intervals(non_free_mapping)
    log_asmbloc.debug(free_interval)

    #first big ones
    g_tab = [(x.total_max_l,x) for x in group_bloc]
    g_tab.sort()
    g_tab.reverse()
    g_tab = [x[1] for x in g_tab]

    #g_tab => label of grouped blov
    #group_bloc => dict of grouped bloc labeled-key

    #first, near callee placing algo
    for g in g_tab:
        if g.fixedblocs:
            continue
        finish = False
        for x in group_bloc:
            if not x in free_interval.keys():
                continue
            if free_interval[x]<g.total_max_l:
                continue

            for b in group_bloc[x]:
                for c in b.bto:
                    if c.label == g:
                        tmp = free_interval[x]-g.total_max_l
                        log_asmbloc.debug("consumed %d rest: %d"%(g.total_max_l, int(tmp)))
                        free_interval[g] = tmp
                        del(free_interval[x])
                        symbol_pool.set_offset(g, [group_bloc[x][-1].label, group_bloc[x][-1], 1])
                        g.fixedblocs = True
                        finish = True
                        break
                if finish:
                    break
            if finish:
                break

    #second, bigger in smaller algo
    for g in g_tab:
        if g.fixedblocs:
            continue
        #chose smaller free_interval first
        k_tab = [(free_interval[x],x) for x in free_interval]
        k_tab.sort()
        k_tab = [x[1] for x in k_tab]
        #choose free_interval
        for k in k_tab:
            if g.total_max_l>free_interval[k]:
                continue
            symbol_pool.set_offset(g, [group_bloc[k][-1].label, group_bloc[k][-1], 1])
            tmp = free_interval[k]-g.total_max_l
            log_asmbloc.debug("consumed %d rest: %d"%(g.total_max_l, int(tmp)))
            free_interval[g] = tmp
            del(free_interval[k])

            g.fixedblocs = True
            break

    while unr_bloc:
        #propagate know offset
        resolving = False
        i = 0
        while i < len(unr_bloc):
            if unr_bloc[i].label.offset == None:
                i+=1
                continue
            resolving = True
            log_asmbloc.info("bloc %s resolved"%unr_bloc[i].label)
            bloc_list.append((unr_bloc[i],0))
            g_found =  None
            for g in g_tab:
                if unr_bloc[i] in group_bloc[g]:
                    if g_found!=None:
                        raise ValueError('blocin multiple group!!!')
                    g_found = g
            my_group = group_bloc[g_found]

            index = my_group.index(unr_bloc[i])
            if index>0 and my_group[index-1] in unr_bloc:
                symbol_pool.set_offset(my_group[index-1].label, [unr_bloc[i].label, unr_bloc[i-1], -1])
            if index <len(my_group)-1 and my_group[index+1] in unr_bloc:
                symbol_pool.set_offset(my_group[index+1].label, [unr_bloc[i].label, unr_bloc[i], 1])
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
        if label.offset == None:
            raise ValueError("symbol missing?", l)
        if not is_int(label.offset):
            #construct dependant blocs tree
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
            if label.offset_g== None:
                raise ValueError("unknown symbol: %s"%str(label.name))
            l.offset_g=label.offset_g+l.offset_g[1].blen*l.offset_g[2]
            s_to_use.add(l)


def asmbloc(mnemo, all_blocs):
    #compute max bloc len
    for b in all_blocs:
        log_asmbloc.debug('---')
        blen = 0
        blen_max = 0
        for instr in b.lines:
            if isinstance(instr, asm_raw):
                candidates = [instr.raw]
                c = instr.raw
            elif any([mnemo.has_symb(a) for a in instr.arg]):
                testing_arg = [mnemo.fix_symbol(a) for a in instr.arg]
                sav_a = instr.arg
                instr.arg = testing_arg
                candidates=mnemo.asm(str(instr))
                if not candidates:
                    raise ValueError('cannot asm:%s'%str(instr))
                instr.arg = sav_a

                c = candidates[0]
                blen_max+= len(candidates[-1])-len(candidates[0])
            else:
                candidates=mnemo.asm(str(instr))
                if not candidates:
                    raise ValueError('cannot asm:%s'%str(instr))
                c = candidates[0]
            log_asmbloc.debug(instr)
            log_asmbloc.debug(candidates)
            log_asmbloc.debug(repr(c))
            instr.data = c
            blen +=len(c)

        b.blen = blen
        #bloc with max rel values encoded
        b.blen_max = blen+blen_max
        log_asmbloc.info("blen: %d max: %d"%(b.blen, b.blen_max))

def asmbloc_final(mnemo, all_blocs, symbol_pool, symb_reloc_off = {}):
    log_asmbloc.info("asmbloc_final")
    fini =False
    #asm with minimal instr len
    #check if dst label are ok to this encoded form
    #recompute if not
    while not fini:
        fini =True
        my_symb_reloc_off = {}

        calc_symbol_offset(symbol_pool)
        #test if bad encoded relative
        for b,t in all_blocs:
            offset_i = 0
            my_symb_reloc_off[b.label] = []
            for instr in b.lines:
                if isinstance(instr, asm_raw):
                    offset_i+=len(instr.data)
                    continue
                if not [True for a in instr.arg if mnemo.has_symb(a)]:
                    offset_i+=len(instr.data)
                    continue

                sav_a = instr.arg

                if instr.dstflow():
                    lbls = {}
                    xxx = instr.getdstflow()
                    if len(xxx) !=1:
                        raise ValueError('multi dst ?!')
                    label = mnemo.get_label(xxx[0])
                    is_mem = mnemo.is_mem(xxx[0])
                    lbls[label.name] = label.offset_g
                    instr.fixdst(lbls, b.label.offset_g+b.blen, is_mem)
                else:
                    instr.arg = [mnemo.fix_symbol(a, symbol_pool) for a in instr.arg]
                symbol_reloc_off = []
                candidates=mnemo.asm(str(instr), symbol_reloc_off)
                if not candidates:
                    raise ValueError('cannot asm:%s'%str(instr))
                c = candidates[0]
                instr.arg = sav_a
                if len(c)>len(instr.data):
                    #good len, bad offset...XXX
                    b.blen = b.blen-len(instr.data)+len(c)
                    instr.data = c
                    fini=False
                    break
                found = False
                for cpos, c in enumerate(candidates):
                    if len(c) == len(instr.data):
                        instr.data = c
                        found = True
                        break
                if not found:
                    raise ValueError('something wrong in instr.data')

                if cpos < len(symbol_reloc_off):
                    my_s = symbol_reloc_off[cpos]
                else:
                    my_s = None

                if my_s!=None:
                    my_symb_reloc_off[b.label].append(offset_i+my_s)
                offset_i+=len(instr.data)
    #we have fixed all relative values
    #recompute good offsets
    for label in symbol_pool.items():
        if label.offset_g == None:
            fdfd
        symbol_pool.set_offset(label, label.offset_g)

    for a, b in my_symb_reloc_off.items():
        symb_reloc_off[a] = b

def asm_resolve_final(mnemo, all_bloc, symbol_pool, dont_erase = [], symb_reloc_off = {}, constrain_pos = False):
    asmbloc(mnemo, all_bloc)
    bloc_g = group_blocs(all_bloc)
    if constrain_pos:
        #XXX
        print bloc_g
        bloc_list = [(bcs[0].bloc_num, bcs[0].label) for bcs in bloc_g.values()]
        bloc_list.sort()
        bloc_list = [b[1] for b in bloc_list]
        resolved_b = resolve_symbol_linear(bloc_list, bloc_g, symbol_pool, dont_erase)
    else:
        resolved_b = resolve_symbol(bloc_g, symbol_pool, dont_erase)

    asmbloc_final(mnemo, resolved_b, symbol_pool, symb_reloc_off)

    written_bytes = {}
    patches = {}
    for b,t in resolved_b:
        offset = b.label.offset
        for i in b.lines:
            patches[offset] = i.data
            for c in range(len(i.data)):
                if offset+c in written_bytes:
                    raise ValueError("overlapping bytes in asssembly %X"%int(offset))
                written_bytes[offset+c] = 1
            offset+=len(i.data)

    return resolved_b, patches


def patch_binary(f, resolved_b):
    written_bytes = {}
    for b,t in resolved_b:
        offset = b.label.offset
        f.seek(offset, 0)
        for i in b.lines:
            log_asmbloc.debug("%.8X %-30s %s"%(offset, repr(i.data), str(i)))
            f.write(i.data)
            for c in range(len(i.data)):
                if offset+c in written_bytes:
                    log_asmbloc.error( "erase allready fixed bytes")
                written_bytes[offset+c] = 1
            offset+=len(i.data)
    return written_bytes


def blocs2str(b):
    out = b.label.name+':\n'
    for l in b.lines:
        out+=str(l)+'\n'
    return out


def find_parents(all_bloc, l):
    p = set()
    for b in all_bloc:
        if l in [x.label for x in b.bto if isinstance(x.label, asm_label)]:
            p.add(b.label)
    return p

def dead_bloc_rem(all_bloc, symbol_pool, keeped = []):
    finish = False
    while not finish:
        finish = True
        for b in all_bloc:
            l = b.label
            if l in keeped:
                continue
            p = find_parents(all_bloc, l)
            if l in p:
                p.remove(l)
            if not len(p):
                symbol_pool.remove(b.label)
                all_bloc.remove(b)
                finish = False
                print 'del bloc %s'%str(l)
                break

def getbloc_around(all_bloc, a, level = 3, done = None, blocby_label = None):

    if not blocby_label:
        blocby_label = {}
        for b in all_bloc:
            blocby_label[b.label] = b
    if done == None:
        done = set()

    done.add(a)
    if not level:
        return done
    for b in a.parents:
        b = blocby_label[b]
        if b in done:
            continue
        done.update(getbloc_around(all_bloc, b, level-1, done, blocby_label))
    for b in a.bto:
        b = blocby_label[b.label]
        if b in done:
            continue
        done.update(getbloc_around(all_bloc, b, level-1, done, blocby_label))
    return done


def getbloc_parents(all_bloc, a, level = 3, done = None, blocby_label = None):

    if not blocby_label:
        blocby_label = {}
        for b in all_bloc:
            blocby_label[b.label] = b
    if done == None:
        done = set()

    done.add(a)
    if not level:
        return done
    for b in a.parents:
        b = blocby_label[b]
        if b in done:
            continue
        done.update(getbloc_parents(all_bloc, b, level-1, done, blocby_label))
    return done

#get ONLY level_X parents
def getbloc_parents_strict(all_bloc, a, level = 3, rez = None, done = None, blocby_label = None):

    if not blocby_label:
        blocby_label = {}
        for b in all_bloc:
            blocby_label[b.label] = b
    if rez == None:
        rez = set()
    if done == None:
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
        rez.update(getbloc_parents_strict(all_bloc, b, level-1, rez, done, blocby_label))
    return rez

def bloc_find_path(all_bloc, blocby_label, a, b, path = None, done = None):
    if path == None:
        path = []
    if done == None:
        done = set()

    all_path = []
    for x in a.bto:
        if not isinstance(x.label, asm_label) or not x.label in blocby_label:
            continue
        x = blocby_label[x.label]

        if x == b:
            all_path += [path+[a]]
            continue

        if x in done:
            continue

        done.add(a)
        all_path+=bloc_find_path(all_bloc, blocby_label, x, b, path+[a], done)
    return all_path

def getblocby_offsetin(all_bloc, o):
    for b in all_bloc:
        for l in b.lines:
            if o == l.offset:
                return b
    return None

def getblocby_offsetinr(all_bloc, o):
    for b in all_bloc:
        min_ad = None
        max_ad = None
        for l in b.lines:
            if min_ad == None or l.offset < min_ad:
                min_ad = l.offset
            if max_ad == None or l.offset > max_ad:#XXX + len l
                max_ad = l.offset
        if min_ad <= o <= max_ad:
            return b
    return None

def getlineby_offset(all_bloc, o):
    for b in all_bloc:
        for l in b.lines:
            if l.offset == o:
                return l
    return None

def getblocby_offset(all_bloc, o):
    for b in all_bloc:
        if b.lines and b.lines[0].offset == o:
            return b
    return None

def getblocby_label(all_bloc, l):
    for b in all_bloc:
        if b.label == l:
            return b
    return None

def bloc_blink(all_bloc):
    for b in all_bloc:
        b.parents = find_parents(all_bloc, b.label)


def bloc_find_path_next(all_bloc, blocby_label, a, b, path = None):
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
        all_path+=bloc_find_path_next(all_bloc, blocby_label, x, b, path+[a])
        #stop if at least one path found
        if all_path:
            return all_path
    return all_path

def bloc_merge(all_bloc, symbol_pool, dont_merge = []):
    i = -1
    blocby_label = {}
    for b in all_bloc:
        blocby_label[b.label] = b
        b.parents = find_parents(all_bloc, b.label)

    while i<len(all_bloc)-1:
        i+=1
        b = all_bloc[i]
        if b.label in dont_merge:
            continue
        p = set(b.parents)
        #if bloc dont self ref
        if b.label in p:
            continue
        #and bloc has only one parent
        if len(p) !=1:
            continue
        #may merge
        bpl = p.pop()
        #bp = getblocby_label(all_bloc, bpl)
        bp = blocby_label[bpl]
        #and parent has only one son
        if len(bp.bto)!=1:
            continue
        #and will not create next loop constraint
        path = bloc_find_path_next(all_bloc, blocby_label, b, bp)
        if path:
            continue
        if bp.lines:
            l = bp.lines[-1]
            #jmp opt; jcc opt
            if l.is_subcall():
                continue
            if l.breakflow() and l.dstflow():
                bp.lines.pop()
        #merge
        sons = b.bto[:]

        #update parents
        for s in b.bto:
            if not isinstance(s.label, asm_label): continue
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
        bp.lines+=b.lines
        bp.bto = b.bto
        symbol_pool.remove(b.label)
        del(all_bloc[i])
        i = -1

def extract_sub_graph_of_bloc(all_bloc, b_o):
    blocby_label = {}
    for b in all_bloc:
        blocby_label[b.label] = b
        b.parents = find_parents(all_bloc, b.label)
    out = []
    todo = set([b_o])
    done = set()

    while todo:
        b = todo.pop()
        if b in done:
            continue
        done.add(b)
        out.append(b)
        for c in b.bto:
            if not isinstance(c.label, asm_label):
                continue
            bson = blocby_label[c.label]
            todo.add(bson)
    return out

def steal_bytes(in_str, arch_mn, ad, l):
    in_str.setoffset(ad)
    lines = []
    total_bytes = 0
    erased_asm = ""
    callx86len = l
    while total_bytes<callx86len:
        lines.append(arch_mn.dis(in_str))
        total_bytes+=lines[-1].l
        erased_asm+=str(lines[-1])+'\n'
    return lines, total_bytes

def dis_multi_func(in_str, mnemo, symbol_pool, ad, dont_dis = [], follow_call = False, dontdis_retcall = False, dis_bloc_callback  =None ):
    todo = ad[:]
    done = set()
    all_bloc = []
    job_done = set()

    call_ad = set(ad)
    while todo:
        ad = todo.pop()
        if ad in done:
            continue
        done.add(ad)
        all_bloc__ = dis_bloc_all(mnemo, in_str, ad, job_done, symbol_pool, dont_dis, follow_call, False, dontdis_retcall, all_bloc = all_bloc, dis_bloc_callback = dis_bloc_callback )
        for b in all_bloc:
            if not b.lines:
                #XXX not lines in bloc ???
                continue
            l = b.lines[-1]
            if not l.m.name.startswith('call'): continue
            dst = mnemo.get_label(l.args[0])
            if not dst: continue

            todo.append(dst)
            call_ad.add(dst)
    all_bloc = split_bloc(mnemo, all_bloc, symbol_pool, more_ref = call_ad)
    return all_bloc

def dis_one_bloc(in_str, mnemo, ad, **kargs):
    job_done = set()
    symbol_pool = asm_symbol_pool()
    all_bloc = dis_bloc_all(mnemo, in_str, ad, job_done, symbol_pool, bloc_wd = 1, **kargs)
    if len(all_bloc) != 1:
        return None
    return all_bloc[0]

def dis_bloc_simple(mnemo, in_str, ad, **kargs):
    job_done = set()
    symbol_pool = asm_symbol_pool()
    if not "job_done" in kargs:
        kargs["job_done"] = job_done
    if not "symbol_pool" in kargs:
        kargs["symbol_pool"] = symbol_pool
    all_bloc = dis_bloc_all(mnemo, in_str, ad,  **kargs)
    return all_bloc


def dis_bloc_ia32(in_str, ad, **kargs):
    from miasm.arch.ia32_arch import x86_mn

    job_done = set()
    symbol_pool = asm_symbol_pool()

    if not "job_done" in kargs:
        kargs["job_done"] = job_done
    if not "symbol_pool" in kargs:
        kargs["symbol_pool"] = symbol_pool
    all_bloc = dis_bloc_all(x86_mn, in_str, ad, **kargs)
    return all_bloc

nx = None
try:
    import networkx as nx
except:
    pass

if nx:
    def is_isomorph(all_bloc1, all_bloc2):
        G1=nx.DiGraph()
        G2=nx.DiGraph()

        for b in all_bloc1:
            G1.add_node(b.label)
            for t in b.bto:
                G1.add_edge(b.label, t.label)
        for b in all_bloc2:
            G2.add_node(b.label)
            for t in b.bto:
                G2.add_edge(b.label, t.label)

        GM = nx.GraphMatcher(G1,G2)
        is_isom = GM.is_isomorphic()
        return GM.is_isomorphic(), GM.mapping
