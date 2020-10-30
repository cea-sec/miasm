from __future__ import print_function
from builtins import map
from builtins import range
import os
import tempfile

from future.utils import viewitems, viewvalues

import idautils
import idc
import ida_funcs
import ida_kernwin


from miasm.core.bin_stream_ida import bin_stream_ida
from miasm.core.asmblock import *
from miasm.expression import expression as m2_expr
from miasm.core.locationdb import LocationDB

from miasm.expression.simplifications import expr_simp
from miasm.analysis.depgraph import DependencyGraph
from miasm.ir.ir import AssignBlock, IRBlock

from utils import guess_machine


class depGraphSettingsForm(ida_kernwin.Form):

    def __init__(self, ira, ircfg, mn):

        self.ira = ira
        self.ircfg = ircfg
        self.mn = mn
        self.stk_args = {'ARG%d' % i:i for i in range(10)}
        self.stk_unalias_force = False

        self.address = idc.get_screen_ea()
        cur_block = None
        for loc_key in ircfg.getby_offset(self.address):
            block = ircfg.get_block(loc_key)
            offset = self.ircfg.loc_db.get_location_offset(block.loc_key)
            if offset is not None:
                # Only one block non-generated
                assert cur_block is None
                cur_block = block
        assert cur_block is not None
        line_nb = None
        for line_nb, assignblk in enumerate(cur_block):
            if assignblk.instr.offset == self.address:
                break
        assert line_nb is not None
        cur_loc_key = str(cur_block.loc_key)
        loc_keys = sorted(map(str, ircfg.blocks))
        regs = sorted(ira.arch.regs.all_regs_ids_byname)
        regs += list(self.stk_args)
        reg_default = regs[0]
        for i in range(10):
            opnd = idc.print_operand(self.address, i).upper()
            if opnd in regs:
                reg_default = opnd
                break

        ida_kernwin.Form.__init__(self,
r"""BUTTON YES* Launch
BUTTON CANCEL NONE
Dependency Graph Settings

Track the element:
<Before the line:{rBeforeLine}>
<After the line:{rAfterLine}>
<At the end of the basic block:{rEndBlock}>{cMode}>

<Target basic block:{cbBBL}>
<Register to track:{cbReg}>
<Line number:{iLineNb}>

INFO: To track stack argument number n, use "ARGn"

Method to use:
<Follow Memory:{rNoMem}>
<Follow Call:{rNoCall}>
<Implicit dependencies:{rImplicit}>
<Unalias stack:{rUnaliasStack}>{cMethod}>

<Highlight color:{cColor}>
""", {
            'cbReg': ida_kernwin.Form.DropdownListControl(
                    items=regs,
                    readonly=False,
                    selval=reg_default),
            'cMode': ida_kernwin.Form.RadGroupControl(
                ("rBeforeLine", "rAfterLine", "rEndBlock")),
            'cMethod': ida_kernwin.Form.ChkGroupControl(
                ("rNoMem", "rNoCall", "rImplicit", "rUnaliasStack")),
            'iLineNb': ida_kernwin.Form.NumericInput(
                tp=ida_kernwin.Form.FT_RAWHEX,
                value=line_nb),
            'cbBBL': ida_kernwin.Form.DropdownListControl(
                    items=loc_keys,
                    readonly=False,
                    selval=cur_loc_key),
            'cColor': ida_kernwin.Form.ColorInput(value=0xc0c020),
        })

        self.Compile()

    @property
    def loc_key(self):
        value = self.cbBBL.value
        for real_loc_key in self.ircfg.blocks:
            if str(real_loc_key) == value:
                return real_loc_key
        raise ValueError("Bad loc_key")

    @property
    def line_nb(self):
        value = self.iLineNb.value
        mode = self.cMode.value
        if mode == 0:
            return value
        elif mode == 1:
            return value + 1
        else:
            return len(self.ircfg.blocks[self.loc_key])

    @property
    def elements(self):
        value = self.cbReg.value
        if value in self.stk_args:
            line = self.ircfg.blocks[self.loc_key][self.line_nb].instr
            arg_num = self.stk_args[value]
            stk_high = m2_expr.ExprInt(idc.get_spd(line.offset), ir_arch.sp.size)
            stk_off = m2_expr.ExprInt(self.ira.sp.size // 8 * arg_num, ir_arch.sp.size)
            element =  m2_expr.ExprMem(self.mn.regs.regs_init[ir_arch.sp] + stk_high + stk_off, self.ira.sp.size)
            element = expr_simp(element)
            # Force stack unaliasing
            self.stk_unalias_force = True
        elif value:
            element = self.ira.arch.regs.all_regs_ids_byname.get(value, None)

        else:
            raise ValueError("Unknown element '%s'!" % value)
        return set([element])

    @property
    def depgraph(self):
        value = self.cMethod.value
        return DependencyGraph(self.ircfg,
                               implicit=value & 4,
                               follow_mem=value & 1,
                               follow_call=value & 2)

    @property
    def unalias_stack(self):
        return self.cMethod.value & 8 or self.stk_unalias_force

    @property
    def color(self):
        return self.cColor.value

def clean_lines():
    "Remove previous comments"
    global comments
    for offset in comments:
        idc.set_color(offset, idc.CIC_ITEM, 0xffffff)
        idc.set_cmt(offset, "", 0)
    comments = {}

def treat_element():
    "Display an element"
    global graphs, comments, sol_nb, settings, addr, ir_arch, ircfg

    try:
        graph = next(graphs)
    except StopIteration:
        comments = {}
        print("Done: %d solutions" % (sol_nb))
        return

    sol_nb += 1
    print("Get graph number %02d" % sol_nb)
    filename = os.path.join(tempfile.gettempdir(), "solution_0x%08x_%02d.dot" % (addr, sol_nb))
    print("Dump the graph to %s" % filename)
    open(filename, "w").write(graph.graph.dot())

    for node in graph.relevant_nodes:
        try:
            offset = ircfg.blocks[node.loc_key][node.line_nb].instr.offset
        except IndexError:
            print("Unable to highlight %s" % node)
            continue
        comments[offset] = comments.get(offset, []) + [node.element]
        idc.set_color(offset, idc.CIC_ITEM, settings.color)

    if graph.has_loop:
        print('Graph has dependency loop: symbolic execution is inexact')
    else:
        print("Possible value: %s" % next(iter(viewvalues(graph.emul(ir_arch)))))

    for offset, elements in viewitems(comments):
        idc.set_cmt(offset, ", ".join(map(str, elements)), 0)

def next_element():
    "Display the next element"
    clean_lines()
    treat_element()


def launch_depgraph():
    global graphs, comments, sol_nb, settings, addr, ir_arch, ircfg
    # Get the current function
    addr = idc.get_screen_ea()
    func = ida_funcs.get_func(addr)

    # Init
    machine = guess_machine(addr=func.start_ea)
    mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

    bs = bin_stream_ida()
    loc_db = LocationDB()

    mdis = dis_engine(bs, loc_db=loc_db, dont_dis_nulstart_bloc=True)
    ir_arch = ira(loc_db)

    # Populate symbols with ida names
    for ad, name in idautils.Names():
        if name is None:
            continue
        loc_db.add_location(name, ad)

    asmcfg = mdis.dis_multiblock(func.start_ea)

    # Generate IR
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

    # Get settings
    settings = depGraphSettingsForm(ir_arch, ircfg, mn)
    settings.Execute()

    loc_key, elements, line_nb = settings.loc_key, settings.elements, settings.line_nb
    # Simplify assignments
    for irb in list(viewvalues(ircfg.blocks)):
        irs = []
        offset = loc_db.get_location_offset(irb.loc_key)
        fix_stack = offset is not None and settings.unalias_stack
        for assignblk in irb:
            if fix_stack:
                stk_high = m2_expr.ExprInt(idc.get_spd(assignblk.instr.offset), ir_arch.sp.size)
                fix_dct = {ir_arch.sp: mn.regs.regs_init[ir_arch.sp] + stk_high}

            new_assignblk = {}
            for dst, src in viewitems(assignblk):
                if fix_stack:
                    src = src.replace_expr(fix_dct)
                    if dst != ir_arch.sp:
                        dst = dst.replace_expr(fix_dct)
                dst, src = expr_simp(dst), expr_simp(src)
                new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, instr=assignblk.instr))
        ircfg.blocks[irb.loc_key] = IRBlock(irb.loc_db, irb.loc_key, irs)

    # Get dependency graphs
    dg = settings.depgraph
    graphs = dg.get(loc_key, elements, line_nb,
                    set([loc_db.get_offset_location(func.start_ea)]))

    # Display the result
    comments = {}
    sol_nb = 0

    # Register and launch
    ida_kernwin.add_hotkey("Shift-N", next_element)
    treat_element()

if __name__ == "__main__":
    launch_depgraph()
