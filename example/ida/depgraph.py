import os
import tempfile

from miasm2.core.bin_stream_ida import bin_stream_ida
from miasm2.core.asmbloc import *
from miasm2.expression import expression as m2_expr

from miasm2.expression.simplifications import expr_simp
from miasm2.analysis.depgraph import DependencyGraph

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
<Follow Memory:{rNoMem}>
<Follow Call:{rNoCall}>
<Implicit dependencies:{rImplicit}>{cMethod}>

<Highlight color:{cColor}>
""", {
            'cbReg': Form.DropdownListControl(
                    items=regs,
                    readonly=False,
                    selval=reg_default),
            'cMode': Form.RadGroupControl(("rBeforeLine", "rAfterLine",
                                           "rEndBlock")),
            'cMethod': Form.ChkGroupControl(("rNoMem", "rNoCall", "rImplicit")),
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
        reg = ir_arch.arch.regs.all_regs_ids_byname.get(value, None)
        if reg is None:
            raise ValueError("Unknown element '%s'!" % value)
        return set([reg])

    @property
    def depgraph(self):
        value = self.cMethod.value
        return DependencyGraph(self.ira,
                               implicit=value & 4,
                               follow_mem=value & 1,
                               follow_call=value & 2)

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
    for assignblk in irb.irs:
        for dst, src in assignblk.items():
            del(assignblk[dst])
            dst, src = expr_simp(dst), expr_simp(src)
            assignblk[dst] = src

# Get settings
settings = depGraphSettingsForm(ir_arch)
settings.Execute()

# Get dependency graphs
dg = settings.depgraph
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
    filename = os.path.join(tempfile.gettempdir(), "solution_0x%08x_%02d.dot" % (addr, sol_nb))
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
