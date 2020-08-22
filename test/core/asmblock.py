from __future__ import print_function
from builtins import map
from pdb import pm

from future.utils import viewitems

from miasm.core.utils import decode_hex
from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.asmblock import AsmCFG, AsmConstraint, AsmBlock, \
    AsmBlockBad, AsmConstraintTo, AsmConstraintNext, \
    bbl_simplifier
from miasm.core.graph import DiGraphSimplifier, MatchGraphJoker
from miasm.expression.expression import ExprId
from miasm.core.locationdb import LocationDB

# Initial data: from 'samples/simple_test.bin'
data = decode_hex("5589e583ec10837d08007509c745fc01100000eb73837d08017709c745fc02100000eb64837d08057709c745fc03100000eb55837d080774138b450801c083f80e7509c745fc04100000eb3c8b450801c083f80e7509c745fc05100000eb298b450883e03085c07409c745fc06100000eb16837d08427509c745fc07100000eb07c745fc081000008b45fcc9c3")
loc_db = LocationDB()
cont = Container.from_string(data, loc_db)

# Test Disasm engine
machine = Machine("x86_32")
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
## Disassembly of one block
first_block = mdis.dis_block(0)
assert len(first_block.lines) == 5
print(first_block)

## Test redisassemble asmcfg
first_block_bis = mdis.dis_block(0)
assert len(first_block.lines) == len(first_block_bis.lines)
print(first_block_bis)

## Disassembly of several block, with cache
asmcfg = mdis.dis_multiblock(0)
assert len(asmcfg) == 17

## Test redisassemble asmcfg
asmcfg = mdis.dis_multiblock(0)
assert len(asmcfg) == 17
## Equality between assembly lines is not yet implemented
assert len(asmcfg.heads()) == 1
assert len(asmcfg.loc_key_to_block(asmcfg.heads()[0]).lines) == len(first_block.lines)

# Test AsmCFG
assert isinstance(asmcfg, AsmCFG)
assert len(asmcfg.pendings) == 0
assert len(asmcfg.nodes()) == 17
assert len(asmcfg.edges2constraint) == len(asmcfg.edges())
assert len(asmcfg.edges()) == 24
assert asmcfg.getby_offset(0x63).lines[0].offset == 0x5f
assert asmcfg.getby_offset(0x69).lines[0].offset == 0x69

## Convert to dot
open("graph.dot", "w").write(asmcfg.dot())

## Modify the structure: link the first and the last block
leaves = asmcfg.leaves()
assert len(leaves) == 1
last_block_loc_key = leaves.pop()

### Remove first_block for the rest of the graph
first_block = asmcfg.loc_key_to_block(asmcfg.heads()[0])
assert len(first_block.bto) == 2
for succ in asmcfg.successors(first_block.loc_key):
    asmcfg.del_edge(first_block.loc_key, succ)

### Modification must be reported from the graph
assert len(first_block.bto) == 0
assert last_block_loc_key in asmcfg.nodes()

### Remove predecessors of last block
for pred in asmcfg.predecessors(last_block_loc_key):
    asmcfg.del_edge(pred, last_block_loc_key)
### Link first and last block
asmcfg.add_edge(first_block.loc_key, last_block_loc_key, AsmConstraint.c_next)
### Only one link between two asmcfg
try:
    asmcfg.add_edge(first_block, last_block_loc_key, AsmConstraint.c_to)
    good = False
except AssertionError:
    good = True
assert good

### Check final state
assert len(first_block.bto) == 1
assert list(first_block.bto)[0].c_t == AsmConstraint.c_next

## Simplify the obtained graph to keep only asmcfg which reach a block
## finishing with RET

def remove_useless_blocks(d_g, graph):
    """Remove leaves without a RET"""
    for leaf_label in graph.leaves():
        block = graph.loc_key_to_block(leaf_label)
        if block.lines[-1].name != "RET":
            graph.del_block(graph.loc_key_to_block(leaf_label))

### Use a graph simplifier to recursively apply the simplification pass
dg = DiGraphSimplifier()
dg.enable_passes([remove_useless_blocks])
asmcfg = dg(asmcfg)

### Only two asmcfg should remain
assert len(asmcfg) == 2
assert first_block.loc_key in asmcfg.nodes()
assert last_block_loc_key in asmcfg.nodes()

## Graph the final output
open("graph2.dot", "w").write(asmcfg.dot())

# Test helper methods
## loc_key_to_block should always be updated
assert asmcfg.loc_key_to_block(first_block.loc_key) == first_block
testlabel = loc_db.get_or_create_name_location("testlabel")
my_block = AsmBlock(loc_db, testlabel)
asmcfg.add_block(my_block)
assert len(asmcfg) == 3
assert asmcfg.loc_key_to_block(first_block.loc_key) == first_block
assert asmcfg.loc_key_to_block(my_block.loc_key) == my_block

## Bad asmcfg
assert len(list(asmcfg.get_bad_blocks())) == 0
assert len(list(asmcfg.get_bad_blocks_predecessors())) == 0
### Add a bad block, not linked
testlabel_bad = loc_db.get_or_create_name_location("testlabel_bad")
my_bad_block = AsmBlockBad(loc_db, testlabel_bad)
asmcfg.add_block(my_bad_block)
assert list(asmcfg.get_bad_blocks()) == [my_bad_block]
assert len(list(asmcfg.get_bad_blocks_predecessors())) == 0
### Link the bad block and update edges
### Indeed, a sub-element has been modified (bto from a block from asmcfg)
my_block.bto.add(AsmConstraintTo(my_bad_block.loc_key))
asmcfg.rebuild_edges()
assert list(asmcfg.get_bad_blocks_predecessors()) == [my_block.loc_key]
### Test strict option
my_block.bto.add(AsmConstraintTo(my_block.loc_key))
asmcfg.rebuild_edges()
assert list(asmcfg.get_bad_blocks_predecessors(strict=False)) == [my_block.loc_key]
assert len(list(asmcfg.get_bad_blocks_predecessors(strict=True))) == 0

## Sanity check
asmcfg.sanity_check()
### Next on itself
testlabel_nextitself = loc_db.get_or_create_name_location("testlabel_nextitself")
my_block_ni = AsmBlock(loc_db, testlabel_nextitself)
my_block_ni.bto.add(AsmConstraintNext(my_block_ni.loc_key))
asmcfg.add_block(my_block_ni)
error_raised = False
try:
    asmcfg.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
### Back to a normal state
asmcfg.del_block(my_block_ni)
asmcfg.sanity_check()
### Multiple next on the same node
testlabel_target = loc_db.get_or_create_name_location("testlabel_target")
my_block_target = AsmBlock(loc_db, testlabel_target)
asmcfg.add_block(my_block_target)
testlabel_src1 = loc_db.get_or_create_name_location("testlabel_src1")
testlabel_src2 = loc_db.get_or_create_name_location("testlabel_src2")
my_block_src1 = AsmBlock(loc_db, testlabel_src1)
my_block_src2 = AsmBlock(loc_db, testlabel_src2)
my_block_src1.bto.add(AsmConstraintNext(my_block_target.loc_key))
asmcfg.add_block(my_block_src1)
### OK for now
asmcfg.sanity_check()
### Add a second next from src2 to target (already src1 -> target)
my_block_src2.bto.add(AsmConstraintNext(my_block_target.loc_key))
asmcfg.add_block(my_block_src2)
error_raised = False
try:
    asmcfg.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
asmcfg.del_block(my_block_src2)
asmcfg.sanity_check()

## Guess block size
### Initial state
assert not hasattr(first_block, 'size')
assert not hasattr(first_block, 'max_size')
asmcfg.guess_blocks_size(mdis.arch)
assert first_block.size == 39
assert asmcfg.loc_key_to_block(my_block_src1.loc_key).size == 0
assert first_block.max_size == 39
assert asmcfg.loc_key_to_block(my_block_src1.loc_key).max_size == 0

## Check pendings
### Create a pending element
testlabel_pend_src = loc_db.get_or_create_name_location("testlabel_pend_src")
testlabel_pend_dst = loc_db.get_or_create_name_location("testlabel_pend_dst")
my_block_src = AsmBlock(loc_db, testlabel_pend_src)
my_block_dst = AsmBlock(loc_db, testlabel_pend_dst)
my_block_src.bto.add(AsmConstraintTo(my_block_dst.loc_key))
asmcfg.add_block(my_block_src)
### Check resulting state
assert len(asmcfg) == 7
assert len(asmcfg.pendings) == 1
assert my_block_dst.loc_key in asmcfg.pendings
assert len(asmcfg.pendings[my_block_dst.loc_key]) == 1
pending = list(asmcfg.pendings[my_block_dst.loc_key])[0]
assert isinstance(pending, asmcfg.AsmCFGPending)
assert pending.waiter == my_block_src
assert pending.constraint == AsmConstraint.c_to
### Sanity check must fail
error_raised = False
try:
    asmcfg.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
### Pending must disappeared when adding expected block
asmcfg.add_block(my_block_dst)
assert len(asmcfg) == 8
assert len(asmcfg.pendings) == 0
asmcfg.sanity_check()

# Test block_merge
data2 = decode_hex("31c0eb0c31c9750c31d2eb0c31ffebf831dbebf031edebfc31f6ebf031e4c3")
cont2 = Container.from_string(data2, loc_db)
mdis = machine.dis_engine(cont2.bin_stream, loc_db=loc_db)
## Elements to merge
asmcfg = mdis.dis_multiblock(0)
## Block alone
asmcfg.add_block(mdis.dis_block(0x1c))
## Bad block
asmcfg.add_block(mdis.dis_block(len(data2)))
## Dump the graph before merging
open("graph3.dot", "w").write(asmcfg.dot())
## Apply merging
asmcfg = bbl_simplifier(asmcfg)
## Dump the graph after merging
open("graph4.dot", "w").write(asmcfg.dot())
## Check the final state
assert len(asmcfg) == 5
assert len(list(asmcfg.get_bad_blocks())) == 1
### Check "special" asmcfg
entry_asmcfg = asmcfg.heads()
bad_block_lbl = next((lbl for lbl in entry_asmcfg
                 if isinstance(asmcfg.loc_key_to_block(lbl), AsmBlockBad)))
entry_asmcfg.remove(bad_block_lbl)
alone_block = next((asmcfg.loc_key_to_block(lbl) for lbl in entry_asmcfg
               if len(asmcfg.successors(lbl)) == 0))
entry_asmcfg.remove(alone_block.loc_key)
assert alone_block.lines[-1].name == "RET"
assert len(alone_block.lines) == 2
### Check resulting function
entry_block = asmcfg.loc_key_to_block(entry_asmcfg.pop())
assert len(entry_block.lines) == 4
assert list(map(str, entry_block.lines)) == ['XOR        EAX, EAX',
                                       'XOR        EBX, EBX',
                                       'XOR        ECX, ECX',
                                       'JNZ        loc_key_27']
assert len(asmcfg.successors(entry_block.loc_key)) == 2
assert len(entry_block.bto) == 2
nextb = asmcfg.loc_key_to_block(next((cons.loc_key for cons in entry_block.bto
                              if cons.c_t == AsmConstraint.c_next)))
tob = asmcfg.loc_key_to_block(next((cons.loc_key for cons in entry_block.bto
                            if cons.c_t == AsmConstraint.c_to)))
assert len(nextb.lines) == 4
assert list(map(str, nextb.lines)) == ['XOR        EDX, EDX',
                                 'XOR        ESI, ESI',
                                 'XOR        EDI, EDI',
                                 'JMP        loc_key_28']
assert asmcfg.successors(nextb.loc_key) == [nextb.loc_key]
assert len(tob.lines) == 2
assert list(map(str, tob.lines)) == ['XOR        EBP, EBP',
                               'JMP        loc_key_27']
assert asmcfg.successors(tob.loc_key) == [tob.loc_key]

# Check split_block
## Without condition for a split, no change
asmcfg_bef = asmcfg.copy()
mdis.apply_splitting(asmcfg)
assert asmcfg_bef == asmcfg
open("graph5.dot", "w").write(asmcfg.dot())
## Create conditions for a block split
inside_firstbbl = loc_db.get_offset_location(4)
tob.bto.add(AsmConstraintTo(inside_firstbbl))
asmcfg.rebuild_edges()
assert len(asmcfg.pendings) == 1
assert inside_firstbbl in asmcfg.pendings
mdis.apply_splitting(asmcfg)
## Check result
assert len(asmcfg) == 6
assert len(asmcfg.pendings) == 0
assert len(entry_block.lines) == 2
assert list(map(str, entry_block.lines)) == ['XOR        EAX, EAX',
                                       'XOR        EBX, EBX']
assert len(asmcfg.successors(entry_block.loc_key)) == 1
lbl_newb = asmcfg.successors(entry_block.loc_key)[0]
newb = asmcfg.loc_key_to_block(lbl_newb)
assert len(newb.lines) == 2
assert list(map(str, newb.lines)) == ['XOR        ECX, ECX',
                                'JNZ        loc_key_27']
preds = asmcfg.predecessors(lbl_newb)
assert len(preds) == 2
assert entry_block.loc_key in preds
assert tob.loc_key in preds
assert asmcfg.edges2constraint[(entry_block.loc_key, lbl_newb)] == AsmConstraint.c_next
assert asmcfg.edges2constraint[(tob.loc_key, lbl_newb)] == AsmConstraint.c_to


# Check double block split
data = decode_hex("74097405b8020000007405b803000000b804000000c3")
cont = Container.from_string(data, loc_db)
mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
asmcfg = mdis.dis_multiblock(0)
## Check resulting disasm
assert len(asmcfg.nodes()) == 6
asmcfg.sanity_check()
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

solutions = list(matcher.match(asmcfg))
assert len(solutions) == 1
solution = solutions.pop()
for jbbl, label in viewitems(solution):
    offset = loc_db.get_location_offset(label)
    assert offset == int(jbbl._name, 16)

loc_key_dum = loc_db.get_or_create_name_location("dummy_loc")
asmcfg.add_node(loc_key_dum)
error_raised = False
try:
    asmcfg.sanity_check()
except RuntimeError:
    error_raised = True
assert error_raised
