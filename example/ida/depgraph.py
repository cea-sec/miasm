import os
import tempfile

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmblock import *
from miasm2.expression import expression as m2_expr

from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.depgraph import DependencyGraph
from miasm2.ir.ir import AssignBlock, IRBlock

from utils import guess_machine



class depGraphSettingsForm(Form):

    def __init__(self, ira):

        self.ira = ira
        self.stk_args = {'ARG%d' % i:i for i in xrange(10)}
        self.stk_unalias_force = False

        self.address = ScreenEA()
        cur_block = None
        for block in ira.getby_offset(self.address):
            if block.label.offset is not None:
                # Only one block non-generated
                assert cur_block is None
                cur_block = block
        assert cur_block is not None
        line_nb = None
        for line_nb, assignblk in enumerate(cur_block.irs):
            if assignblk.instr.offset == self.address:
                break
        assert line_nb is not None
        cur_label = str(cur_block.label)
        labels = sorted(map(str, ira.blocks.keys()))
        regs = sorted(ir_arch.arch.regs.all_regs_ids_byname.keys())
        regs += self.stk_args.keys()
        reg_default = regs[0]
        for i in xrange(10):
            opnd = GetOpnd(self.address, i).upper()
            if opnd in regs:
                reg_default = opnd
                break

        Form.__init__(self,
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
            'cbReg': Form.DropdownListControl(
                    items=regs,
                    readonly=False,
                    selval=reg_default),
            'cMode': Form.RadGroupControl(("rBeforeLine", "rAfterLine",
                                           "rEndBlock")),
            'cMethod': Form.ChkGroupControl(("rNoMem", "rNoCall", "rImplicit",
                                             "rUnaliasStack")),
            'iLineNb': Form.NumericInput(tp=Form.FT_RAWHEX,
                                         value=line_nb),
            'cbBBL': Form.DropdownListControl(
                    items=labels,
                    readonly=False,
                    selval=cur_label),
            'cColor': Form.ColorInput(value=0xc0c020),
        })

        self.Compile()

    @property
    def label(self):
        value = self.cbBBL.value
        for real_label in self.ira.blocks:
            if str(real_label) == value:
                return real_label
        raise ValueError("Bad label")

    @property
    def line_nb(self):
        value = self.iLineNb.value
        mode = self.cMode.value
        if mode == 0:
            return value
        elif mode == 1:
            return value + 1
        else:
            return len(self.ira.blocks[self.label].irs)

    @property
    def elements(self):
        value = self.cbReg.value
        if value in self.stk_args:
            line = self.ira.blocks[self.label].irs[self.line_nb].instr
            arg_num = self.stk_args[value]
            stk_high = m2_expr.ExprInt(GetSpd(line.offset), ir_arch.sp.size)
            stk_off = m2_expr.ExprInt(self.ira.sp.size/8 * arg_num, ir_arch.sp.size)
            element =  m2_expr.ExprMem(mn.regs.regs_init[ir_arch.sp] + stk_high + stk_off, self.ira.sp.size)
            element = expr_simp(element)
            # Force stack unaliasing
            self.stk_unalias_force = True
        elif value:
            element = ir_arch.arch.regs.all_regs_ids_byname.get(value, None)

        else:
            raise ValueError("Unknown element '%s'!" % value)
        return set([element])

    @property
    def depgraph(self):
        value = self.cMethod.value
        return DependencyGraph(self.ira,
                               implicit=value & 4,
                               follow_mem=value & 1,
                               follow_call=value & 2)

    @property
    def unalias_stack(self):
        return self.cMethod.value & 8 or self.stk_unalias_force

    @property
    def color(self):
        return self.cColor.value


# Init
machine = guess_machine()
mn, dis_engine, ira = machine.mn, machine.dis_engine, machine.ira

bs = bin_stream_ida()
mdis = dis_engine(bs, dont_dis_nulstart_bloc=True)
ir_arch = ira(mdis.symbol_pool)

# Populate symbols with ida names
for ad, name in Names():
    if name is None:
        continue
    mdis.symbol_pool.add_label(name, ad)

# Get the current function
addr = ScreenEA()
func = idaapi.get_func(addr)
blocks = mdis.dis_multibloc(func.startEA)

# Generate IR
for block in blocks:
    ir_arch.add_bloc(block)

# Get settings
settings = depGraphSettingsForm(ir_arch)
settings.Execute()

label, elements, line_nb = settings.label, settings.elements, settings.line_nb
# Simplify affectations
for irb in ir_arch.blocks.values():
    irs = []
    fix_stack = irb.label.offset is not None and settings.unalias_stack
    for assignblk in irb.irs:
        if fix_stack:
            stk_high = m2_expr.ExprInt(GetSpd(assignblk.instr.offset), ir_arch.sp.size)
            fix_dct = {ir_arch.sp: mn.regs.regs_init[ir_arch.sp] + stk_high}

        new_assignblk = {}
        for dst, src in assignblk.iteritems():
            if fix_stack:
                src = src.replace_expr(fix_dct)
                if dst != ir_arch.sp:
                    dst = dst.replace_expr(fix_dct)
            dst, src = expr_simp(dst), expr_simp(src)
            new_assignblk[dst] = src
        irs.append(AssignBlock(new_assignblk, instr=assignblk.instr))
    ir_arch.blocks[irb.label] = IRBlock(irb.label, irs)

# Get dependency graphs
dg = settings.depgraph
graphs = dg.get(label, elements, line_nb,
                set([ir_arch.symbol_pool.getby_offset(func.startEA)]))

# Display the result
comments = {}
sol_nb = 0

def clean_lines():
    "Remove previous comments"
    global comments
    for offset in comments:
        SetColor(offset, CIC_ITEM, 0xffffff)
        MakeComm(offset, "")
    comments = {}

def treat_element():
    "Display an element"
    global graphs, comments, sol_nb, settings

    try:
        graph = graphs.next()
    except StopIteration:
        comments = {}
        print "Done: %d solutions" % (sol_nb)
        return

    sol_nb += 1
    print "Get graph number %02d" % sol_nb
    filename = os.path.join(tempfile.gettempdir(), "solution_0x%08x_%02d.dot" % (addr, sol_nb))
    print "Dump the graph to %s" % filename
    open(filename, "w").write(graph.graph.dot())

    for node in graph.relevant_nodes:
        try:
            offset = ir_arch.blocks[node.label].irs[node.line_nb].instr.offset
        except IndexError:
            print "Unable to highlight %s" % node
            continue
        comments[offset] = comments.get(offset, []) + [node.element]
        SetColor(offset, CIC_ITEM, settings.color)

    if graph.has_loop:
        print 'Graph has dependency loop: symbolic execution is inexact'
    else:
        print "Possible value: %s" % graph.emul().values()[0]

    for offset, elements in comments.iteritems():
        MakeComm(offset, ", ".join(map(str, elements)))

def next_element():
    "Display the next element"
    clean_lines()
    treat_element()

# Register and launch
idaapi.add_hotkey("Shift-N", next_element)
treat_element()
