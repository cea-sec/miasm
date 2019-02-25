#-*- coding:utf-8 -*-

from __future__ import print_function

from future.utils import viewvalues

from miasm2.expression.expression import ExprInt, ExprId, ExprMem, match_expr
from miasm2.expression.simplifications import expr_simp
from miasm2.core.asmblock import AsmConstraintNext, AsmConstraintTo
from miasm2.core.locationdb import LocationDB
from miasm2.core.utils import upck32


def get_ira(mnemo, attrib):
    arch = mnemo.name, attrib
    if arch == ("arm", "arm"):
        from miasm2.arch.arm.ira import ir_a_arm_base as ira
    elif arch == ("x86", 32):
        from miasm2.arch.x86.ira import ir_a_x86_32 as ira
    elif arch == ("x86", 64):
        from miasm2.arch.x86.ira import ir_a_x86_64 as ira
    else:
        raise ValueError('unknown architecture: %s' % mnemo.name)
    return ira


def arm_guess_subcall(
    mnemo, attrib, pool_bin, cur_bloc, offsets_to_dis, loc_db):
    ira = get_ira(mnemo, attrib)

    sp = LocationDB()
    ir_arch = ira(sp)
    ircfg = ira.new_ircfg()
    print('###')
    print(cur_bloc)
    ir_arch.add_asmblock_to_ircfg(cur_bloc, ircfg)

    to_add = set()
    for irblock in viewvalues(ircfg.blocks):
        pc_val = None
        lr_val = None
        for exprs in irblock:
            for e in exprs:
                if e.dst == ir_arch.pc:
                    pc_val = e.src
                if e.dst == mnemo.regs.LR:
                    lr_val = e.src
        if pc_val is None or lr_val is None:
            continue
        if not isinstance(lr_val, ExprInt):
            continue

        l = cur_bloc.lines[-1]
        if lr_val.arg != l.offset + l.l:
            continue
        l = loc_db.get_or_create_offset_location(int(lr_val))
        c = AsmConstraintNext(l)

        to_add.add(c)
        offsets_to_dis.add(int(lr_val))

    for c in to_add:
        cur_bloc.addto(c)


def arm_guess_jump_table(
    mnemo, attrib, pool_bin, cur_bloc, offsets_to_dis, loc_db):
    ira = get_ira(mnemo, attrib)

    jra = ExprId('jra')
    jrb = ExprId('jrb')

    sp = LocationDB()
    ir_arch = ira(sp)
    ircfg = ira.new_ircfg()
    ir_arch.add_asmblock_to_ircfg(cur_bloc, ircfg)

    for irblock in viewvalues(ircfg.blocks):
        pc_val = None
        for exprs in irblock:
            for e in exprs:
                if e.dst == ir_arch.pc:
                    pc_val = e.src
        if pc_val is None:
            continue
        if not isinstance(pc_val, ExprMem):
            continue
        assert(pc_val.size == 32)
        print(pc_val)
        ad = pc_val.arg
        ad = expr_simp(ad)
        print(ad)
        res = match_expr(ad, jra + jrb, set([jra, jrb]))
        if res is False:
            raise NotImplementedError('not fully functional')
        print(res)
        if not isinstance(res[jrb], ExprInt):
            raise NotImplementedError('not fully functional')
        base_ad = int(res[jrb])
        print(base_ad)
        addrs = set()
        i = -1
        max_table_entry = 10000
        max_diff_addr = 0x100000  # heuristic
        while i < max_table_entry:
            i += 1
            try:
                ad = upck32(pool_bin.getbytes(base_ad + 4 * i, 4))
            except:
                break
            if abs(ad - base_ad) > max_diff_addr:
                break
            addrs.add(ad)
        print([hex(x) for x in addrs])

        for ad in addrs:
            offsets_to_dis.add(ad)
            l = loc_db.get_or_create_offset_location(ad)
            c = AsmConstraintTo(l)
            cur_bloc.addto(c)

guess_funcs = []


def guess_multi_cb(
    mnemo, attrib, pool_bin, cur_bloc, offsets_to_dis, loc_db):
    for f in guess_funcs:
        f(mnemo, attrib, pool_bin, cur_bloc, offsets_to_dis, loc_db)
