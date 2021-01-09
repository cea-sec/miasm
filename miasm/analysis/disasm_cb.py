#-*- coding:utf-8 -*-

from __future__ import print_function

from future.utils import viewvalues

from miasm.expression.expression import ExprInt, ExprId, ExprMem, match_expr
from miasm.expression.simplifications import expr_simp
from miasm.core.asmblock import AsmConstraintNext, AsmConstraintTo
from miasm.core.locationdb import LocationDB
from miasm.core.utils import upck32


def get_lifter_model_call(arch, attrib):
    arch = arch.name, attrib
    if arch == ("arm", "arm"):
        from miasm.arch.arm.lifter_model_call import LifterModelCallArmlBase as lifter_model_call
    elif arch == ("x86", 32):
        from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_32 as lifter_model_call
    elif arch == ("x86", 64):
        from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_64 as lifter_model_call
    else:
        raise ValueError('unknown architecture: %s' % arch.name)
    return lifter_model_call


def arm_guess_subcall(dis_engine, cur_block, offsets_to_dis):
    arch = dis_engine.arch
    loc_db = dis_engine.loc_db
    lifter_model_call = get_lifter_model_call(arch, dis_engine.attrib)

    lifter = lifter_model_call(loc_db)
    ircfg = lifter_model_call.new_ircfg()
    print('###')
    print(cur_block)
    lifter.add_asmblock_to_ircfg(cur_block, ircfg)

    to_add = set()
    for irblock in viewvalues(ircfg.blocks):
        pc_val = None
        lr_val = None
        for exprs in irblock:
            for e in exprs:
                if e.dst == lifter.pc:
                    pc_val = e.src
                if e.dst == arch.regs.LR:
                    lr_val = e.src
        if pc_val is None or lr_val is None:
            continue
        if not isinstance(lr_val, ExprInt):
            continue

        l = cur_block.lines[-1]
        if lr_val.arg != l.offset + l.l:
            continue
        l = loc_db.get_or_create_offset_location(int(lr_val))
        c = AsmConstraintNext(l)

        to_add.add(c)
        offsets_to_dis.add(int(lr_val))

    for c in to_add:
        cur_block.addto(c)


def arm_guess_jump_table(dis_engine, cur_block, offsets_to_dis):
    arch = dis_engine.arch
    loc_db = dis_engine.loc_db
    lifter_model_call = get_lifter_model_call(arch, dis_engine.attrib)

    jra = ExprId('jra')
    jrb = ExprId('jrb')

    lifter = lifter_model_call(loc_db)
    ircfg = lifter_model_call.new_ircfg()
    lifter.add_asmblock_to_ircfg(cur_block, ircfg)

    for irblock in viewvalues(ircfg.blocks):
        pc_val = None
        for exprs in irblock:
            for e in exprs:
                if e.dst == lifter.pc:
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
                ad = upck32(dis_engine.bin_stream.getbytes(base_ad + 4 * i, 4))
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
            cur_block.addto(c)

guess_funcs = []


def guess_multi_cb(dis_engine, cur_block, offsets_to_dis):
    for f in guess_funcs:
        f(dis_engine, cur_block, offsets_to_dis)
