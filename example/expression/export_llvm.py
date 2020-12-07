from future.utils import viewitems, viewvalues

from argparse import ArgumentParser
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.jitter.llvmconvert import LLVMType, LLVMContext_IRCompilation, LLVMFunction_IRCompilation
from llvmlite import ir as llvm_ir
from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.core.locationdb import LocationDB

parser = ArgumentParser("LLVM export example")
parser.add_argument("target", help="Target binary")
parser.add_argument("addr", help="Target address")
parser.add_argument("--architecture", "-a", help="Force architecture")
args = parser.parse_args()
loc_db = LocationDB()
# This part focus on obtaining an IRCFG to transform #
cont = Container.from_stream(open(args.target, 'rb'), loc_db)
machine = Machine(args.architecture if args.architecture else cont.arch)
lifter = machine.lifter(loc_db)
dis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)
asmcfg = dis.dis_multiblock(int(args.addr, 0))
ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
ircfg.simplify(expr_simp_high_to_explicit)
######################################################

# Instantiate a context and the function to fill
context = LLVMContext_IRCompilation()
context.lifter = lifter

func = LLVMFunction_IRCompilation(context, name="test")
func.ret_type = llvm_ir.VoidType()
func.init_fc()

# Here, as an example, we arbitrarily represent registers with global
# variables. Locals allocas are used for the computation during the function,
# and is finally saved in the aforementioned global variable.

# In other words, for each registers:
# entry:
#     ...
#     %reg_val_in = load i32 @REG
#     %REG = alloca i32
#     store i32 %reg_val_in, i32* %REG
#     ...
# exit:
#     ...
#     %reg_val_out = load i32 %REG
#     store i32 %reg_val_out, i32* @REG
#     ...

all_regs = set()
for block in viewvalues(ircfg.blocks):
    for irs in block.assignblks:
        for dst, src in viewitems(irs.get_rw(mem_read=True)):
            elem = src.union(set([dst]))
            all_regs.update(
                x for x in elem
                if x.is_id()
            )

reg2glob = {}
for var in all_regs:
    # alloca reg = global reg
    data = context.mod.globals.get(str(var), None)
    if data is None:
        data = llvm_ir.GlobalVariable(context.mod,  LLVMType.IntType(var.size), name=str(var))
    data.initializer = LLVMType.IntType(var.size)(0)
    value = func.builder.load(data)
    func.local_vars_pointers[var.name] = func.builder.alloca(llvm_ir.IntType(var.size), name=var.name)
    func.builder.store(value, func.local_vars_pointers[var.name])
    reg2glob[var] = data

# IRCFG is imported, without the final "ret void"
func.from_ircfg(ircfg, append_ret=False)

# Finish the saving of registers (temporary version to global)
for reg, glob in viewitems(reg2glob):
    value = func.builder.load(func.local_vars_pointers[reg.name])
    func.builder.store(value, glob)

# Finish the function
func.builder.ret_void()

# Get it back
open("out.ll", "w").write(str(func))
# The optimized CFG can be seen with:
# $ opt -O2 -dot-cfg -S out.ll && xdot cfg.test.dot
