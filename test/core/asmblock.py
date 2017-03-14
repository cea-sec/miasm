from pdb import pm

from miasm2.arch.x86.disasm import dis_x86_32
from miasm2.analysis.binary import Container
from miasm2.core.asmblock import AsmCFG, AsmConstraint, AsmBlock, \
    AsmLabel, AsmBlockBad, AsmConstraintTo, AsmConstraintNext, \
    bbl_simplifier
from miasm2.core.graph import DiGraphSimplifier, MatchGraphJoker
from miasm2.expression.expression import ExprId

# Initial data: from 'samples/simple_test.bin'
data = "5589e583ec10837d08007509c745fc01100000eb73837d08017709c745fc02100000eb64837d08057709c745fc03100000eb55837d080774138b450801c083f80e7509c745fc04100000eb3c8b450801c083f80e7509c745fc05100000eb298b450883e03085c07409c745fc06100000eb16837d08427509c745fc07100000eb07c745fc081000008b45fcc9c3".decode("hex")
cont = Container.from_string(data)

# Test Disasm engine
mdis = dis_x86_32(cont.bin_stream)
## Disassembly of one block
first_block = mdis.dis_bloc(0)
assert len(first_block.lines) == 5
print first_block

## Disassembly of several block, with cache
blocks = mdis.dis_multibloc(0)
assert len(blocks) == 0

## Test cache
mdis.job_done.clear()
blocks = mdis.dis_multibloc(0)
assert len(blocks) == 17
## Equality between assembly lines is not yet implemented
assert len(blocks.heads()) == 1
assert len(blocks.heads()[0].lines) == len(first_block.lines)

# Test AsmCFG
assert isinstance(blocks, AsmCFG)
assert len(blocks.pendings) == 0
assert len(blocks.nodes()) == 17
assert len(blocks.edges2constraint) == len(blocks.edges())
assert len(blocks.edges()) == 24

## Convert to dot
open("graph.dot", "w").write(blocks.dot())

## Modify the structure: link the first and the last block
leaves = blocks.leaves()
assert len(leaves) == 1
last_block = leaves.pop()

### Remove first_block for the rest of the graph
first_block = blocks.heads()[0]
assert len(first_block.bto) == 2
for succ in blocks.successors(first_block):
    blocks.del_edge(first_block, succ)

### Modification must be reported from the graph
assert len(first_block.bto) == 0
assert last_block in blocks

### Remove predecessors of last block
for pred in blocks.predecessors(last_block):
    blocks.del_edge(pred, last_block)
### Link first and last block
blocks.add_edge(first_block, last_block, AsmConstraint.c_next)
### Only one link between two blocks
try:
    blocks.add_edge(first_block, last_block, AsmConstraint.c_to)
    good = False
except AssertionError:
    good = True
assert good

### Check final state
assert len(first_block.bto) == 1
assert list(first_block.bto)[0].c_t == AsmConstraint.c_next

## Simplify the obtained graph to keep only blocks which reach a block
## finnishing with RET

def remove_useless_blocks(d_g, graph):
    """Remove leaves without a RET"""
    for block in graph.leaves():
        if block.lines[-1].name != "RET":
            graph.del_node(block)

### Use a graph simplifier to recursively apply the simplification pass
dg = DiGraphSimplifier()
dg.enable_passes([remove_useless_blocks])
blocks = dg(blocks)

### Only two blocks should remain
assert len(blocks) == 2
assert first_block in blocks
assert last_block in blocks

## Graph the final output
open("graph2.dot", "w").write(blocks.dot())

# Test helper methods
## Label2block should always be updated
assert blocks.label2block(first_block.label) == first_block
my_block = AsmBlock(AsmLabel("testlabel"))
blocks.add_node(my_block)
assert len(blocks) == 3
assert blocks.label2block(first_block.label) == first_block
assert blocks.label2block(my_block.label) == my_block

## Bad blocks
assert len(list(blocks.get_bad_blocks())) == 0
assert len(list(blocks.get_bad_blocks_predecessors())) == 0
### Add a bad block, not linked
my_bad_block = AsmBlockBad(AsmLabel("testlabel_bad"))
blocks.add_node(my_bad_block)
assert list(blocks.get_bad_blocks()) == [my_bad_block]
assert len(list(blocks.get_bad_blocks_predecessors())) == 0
### Link the bad block and update edges
### Indeed, a sub-element has been modified (bto from a block from blocks)
my_block.bto.add(AsmConstraintTo(my_bad_block.label))
blocks.rebuild_edges()
assert list(blocks.get_bad_blocks_predecessors()) == [my_block]
### Test strict option
my_block.bto.add(AsmConstraintTo(my_block.label))
blocks.rebuild_edges()
assert list(blocks.get_bad_blocks_predecessors(strict=False)) == [my_block]
assert len(list(blocks.get_bad_blocks_predecessors(strict=True))) == 0

## Sanity check
blocks.sanity_check()
### Next on itself
my_block_ni = AsmBlock(AsmLabel("testlabel_nextitself"))
my_block_ni.bto.add(AsmConstraintNext(my_block_ni.label))
blocks.add_node(my_block_ni)
error_raised = False
try:
    blocks.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
### Back to a normal state
blocks.del_node(my_block_ni)
blocks.sanity_check()
### Multiple next on the same node
my_block_target = AsmBlock(AsmLabel("testlabel_target"))
blocks.add_node(my_block_target)
my_block_src1 = AsmBlock(AsmLabel("testlabel_src1"))
my_block_src2 = AsmBlock(AsmLabel("testlabel_src2"))
my_block_src1.bto.add(AsmConstraintNext(my_block_target.label))
blocks.add_node(my_block_src1)
### OK for now
blocks.sanity_check()
### Add a second next from src2 to target (already src1 -> target)
my_block_src2.bto.add(AsmConstraintNext(my_block_target.label))
blocks.add_node(my_block_src2)
error_raised = False
try:
    blocks.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
blocks.del_node(my_block_src2)
blocks.sanity_check()

## Guess block size
### Initial state
assert not hasattr(first_block, 'size')
assert not hasattr(first_block, 'max_size')
blocks.guess_blocks_size(mdis.arch)
assert first_block.size == 39
assert blocks.label2block(my_block_src1.label).size == 0
assert first_block.max_size == 39
assert blocks.label2block(my_block_src1.label).max_size == 0

## Check pendings
### Create a pending element
my_block_src = AsmBlock(AsmLabel("testlabel_pend_src"))
my_block_dst = AsmBlock(AsmLabel("testlabel_pend_dst"))
my_block_src.bto.add(AsmConstraintTo(my_block_dst.label))
blocks.add_node(my_block_src)
### Check resulting state
assert len(blocks) == 7
assert len(blocks.pendings) == 1
assert my_block_dst.label in blocks.pendings
assert len(blocks.pendings[my_block_dst.label]) == 1
pending = list(blocks.pendings[my_block_dst.label])[0]
assert isinstance(pending, blocks.AsmCFGPending)
assert pending.waiter == my_block_src
assert pending.constraint == AsmConstraint.c_to
### Sanity check must fail
error_raised = False
try:
    blocks.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
### Pending must disappeared when adding expected block
blocks.add_node(my_block_dst)
assert len(blocks) == 8
assert len(blocks.pendings) == 0
blocks.sanity_check()

# Test block_merge
data2 = "31c0eb0c31c9750c31d2eb0c31ffebf831dbebf031edebfc31f6ebf031e4c3".decode("hex")
cont2 = Container.from_string(data2)
mdis = dis_x86_32(cont2.bin_stream)
## Elements to merge
blocks = mdis.dis_multibloc(0)
## Block alone
blocks.add_node(mdis.dis_bloc(0x1c))
## Bad block
blocks.add_node(mdis.dis_bloc(len(data2)))
## Dump the graph before merging
open("graph3.dot", "w").write(blocks.dot())
## Apply merging
blocks = bbl_simplifier(blocks)
## Dump the graph after merging
open("graph4.dot", "w").write(blocks.dot())
## Check the final state
assert len(blocks) == 5
assert len(list(blocks.get_bad_blocks())) == 1
### Check "special" blocks
entry_blocks = blocks.heads()
bad_block = (block for block in entry_blocks
             if isinstance(block, AsmBlockBad)).next()
entry_blocks.remove(bad_block)
alone_block = (block for block in entry_blocks
               if len(blocks.successors(block)) == 0).next()
entry_blocks.remove(alone_block)
assert alone_block.lines[-1].name == "RET"
assert len(alone_block.lines) == 2
### Check resulting function
entry_block = entry_blocks.pop()
assert len(entry_block.lines) == 4
assert map(str, entry_block.lines) == ['XOR        EAX, EAX',
                                       'XOR        EBX, EBX',
                                       'XOR        ECX, ECX',
                                       'JNZ        loc_0000000000000014:0x00000014']
assert len(blocks.successors(entry_block)) == 2
assert len(entry_block.bto) == 2
nextb = blocks.label2block((cons.label for cons in entry_block.bto
                            if cons.c_t == AsmConstraint.c_next).next())
tob = blocks.label2block((cons.label for cons in entry_block.bto
                          if cons.c_t == AsmConstraint.c_to).next())
assert len(nextb.lines) == 4
assert map(str, nextb.lines) == ['XOR        EDX, EDX',
                                 'XOR        ESI, ESI',
                                 'XOR        EDI, EDI',
                                 'JMP        loc_0000000000000008:0x00000008']
assert blocks.successors(nextb) == [nextb]
assert len(tob.lines) == 2
assert map(str, tob.lines) == ['XOR        EBP, EBP',
                               'JMP        loc_0000000000000014:0x00000014']
assert blocks.successors(tob) == [tob]

# Check split_block
## Without condition for a split, no change
blocks_bef = blocks.copy()
blocks.apply_splitting(mdis.symbol_pool)
assert blocks_bef == blocks
## Create conditions for a block split
inside_firstbbl = mdis.symbol_pool.getby_offset(4)
tob.bto.add(AsmConstraintTo(inside_firstbbl))
blocks.rebuild_edges()
assert len(blocks.pendings) == 1
assert inside_firstbbl in blocks.pendings
blocks.apply_splitting(mdis.symbol_pool)
## Check result
assert len(blocks) == 6
assert len(blocks.pendings) == 0
assert len(entry_block.lines) == 2
assert map(str, entry_block.lines) == ['XOR        EAX, EAX',
                                       'XOR        EBX, EBX']
assert len(blocks.successors(entry_block)) == 1
newb = blocks.successors(entry_block)[0]
assert len(newb.lines) == 2
assert map(str, newb.lines) == ['XOR        ECX, ECX',
                                'JNZ        loc_0000000000000014:0x00000014']
preds = blocks.predecessors(newb)
assert len(preds) == 2
assert entry_block in preds
assert tob in preds
assert blocks.edges2constraint[(entry_block, newb)] == AsmConstraint.c_next
assert blocks.edges2constraint[(tob, newb)] == AsmConstraint.c_to


# Check double block split
data = "74097405b8020000007405b803000000b804000000c3".decode('hex')
cont = Container.from_string(data)
mdis = dis_x86_32(cont.bin_stream)
blocks = mdis.dis_multibloc(0)
## Check resulting disasm
assert len(blocks.nodes()) == 6
blocks.sanity_check()
## Check graph structure
bbl0 = MatchGraphJoker(name="0")
bbl2 = MatchGraphJoker(name="2")
bbl4 = MatchGraphJoker(name="4")
bbl9 = MatchGraphJoker(name="9")
bblB = MatchGraphJoker(name="B")
bbl10 = MatchGraphJoker(name="10")

matcher = bbl0 >> bbl2 >> bbl4 >> bbl9 >> bblB >> bbl10
matcher += bbl2 >> bbl9 >> bbl10
matcher += bbl0 >> bblB

solutions = list(matcher.match(blocks))
assert len(solutions) == 1
solution = solutions.pop()
for jbbl, block in solution.iteritems():
    assert block.label.offset == int(jbbl._name, 16)
