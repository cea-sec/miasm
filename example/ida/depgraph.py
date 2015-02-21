import sys

from idaapi import GraphViewer
from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmbloc import *
from miasm2.expression import expression as m2_expr

from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.machine import Machine
from miasm2.analysis.depgraph import DependencyGraph, DependencyGraph_NoMemory

from utils import guess_machine


class depGraphSettingsForm(Form):

    def __init__(self, ira):

        self.ira = ira
        self.address = ScreenEA()
        cur_bloc = list(ira.getby_offset(self.address))[0]
        for line_nb, l in enumerate(cur_bloc.lines):
            if l.offset == self.address:
                break
        cur_label = str(cur_bloc.label)
        labels = sorted(map(str, ira.blocs.keys()))
        regs = sorted(ir_arch.arch.regs.all_regs_ids_byname.keys())
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

Method to use:
<Best effort:{rBest}>
<No memory (sound & complete):{rNoMem}>{cMethod}>

<Highlight color:{cColor}>
""", {
            'cbReg': Form.DropdownListControl(
                    items=regs,
                    readonly=False,
                    selval=reg_default),
            'cMode': Form.RadGroupControl(("rBeforeLine", "rAfterLine",
                                           "rEndBlock")),
            'cMethod': Form.RadGroupControl(("rBest", "rNoMem")),
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
        for real_label in self.ira.blocs:
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
            return len(self.ira.blocs[self.label].irs)

    @property
    def elements(self):
        value = self.cbReg.value
        return set([ir_arch.arch.regs.all_regs_ids_byname[value]])

    @property
    def method(self):
        value = self.cMethod.value
        if value == 0:
            return DependencyGraph
        elif value == 1:
            return DependencyGraph_NoMemory
        else:
            raise ValueError("Unknown method")

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
blocs = mdis.dis_multibloc(func.startEA)

# Generate IR
for bloc in blocs:
    ir_arch.add_bloc(bloc)

# Simplify affectations
for irb in ir_arch.blocs.values():
    for irs in irb.irs:
        for i, expr in enumerate(irs):
            irs[i] = m2_expr.ExprAff(expr_simp(expr.dst), expr_simp(expr.src))

# Build the IRA Graph
ir_arch.gen_graph()

# Get settings
settings = depGraphSettingsForm(ir_arch)
settings.Execute()

# Get dependency graphs
dg = (settings.method)(ir_arch)
graphs = dg.get(settings.label, settings.elements, settings.line_nb,
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
    filename = "/tmp/solution_0x%08x_%02d.dot" % (addr, sol_nb)
    print "Dump the graph to %s" % filename
    open(filename, "w").write(graph.graph.dot())

    for node in graph.relevant_nodes:
        try:
            offset = ir_arch.blocs[node.label].lines[node.line_nb].offset
        except IndexError:
            print "Unable to highlight %s" % node
            continue
        comments[offset] = comments.get(offset, []) + [node.element]
        SetColor(offset, CIC_ITEM, settings.color)

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
