import os
import tempfile

import miasm.jitter.csts as csts
from miasm.core.interval import interval
from miasm.analysis.taint_codegen import makeTaintGen, bits2bytes
from miasm.expression.expression import ExprSlice
from miasm.expression.simplifications import ExpressionSimplifier
from miasm.expression.simplifications_common import simp_slice

def init_registers_index(jitter):
    """Associate register names with an index (needed during JiT)"""

    regs_index = dict()
    regs_name = dict()
    index = 0
    regs = list(jitter.arch.regs.all_regs_ids_byname.keys())
    regs.sort()
    for reg in regs:
        regs_index[reg] = index
        regs_name[index] = reg
        index += 1
    jitter.jit.codegen.regs_index = regs_index
    jitter.jit.codegen.regs_name = regs_name
    return len(regs_index)

def enable_taint_analysis(jitter, nb_colors=1):
    """Init all component of the taint analysis engine"""

    # Enable generation of C code analysing taint
    jitter.jit.codegen = makeTaintGen(jitter.C_Gen, jitter.ir_arch)
    nb_regs = init_registers_index(jitter)
    # Allocate taint structures
    jitter.taint.init_taint_analysis(nb_colors, nb_regs)
    jitter.nb_colors = nb_colors
    # Switch to taint cache
    jitter.jit.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache_taint")

def disable_taint_analysis(jitter):
    jitter.jit.codegen = jitter.C_Gen(jitter.ir_arch)
    jitter.jit.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")

# API usage examples

def taint(jitter, to_taint, color):
    """
    @to_taint can be either an ExprMem or an ExprId (or ExprSlice of ExprId).
    """

    if to_taint.is_mem():
        taint_memory(jitter, to_taint, color)
    elif to_taint.is_id() or (to_taint.is_slice() and to_taint.arg.is_id()):
        taint_register(jitter, to_taint, color)
    else:
        raise TypeError("Unsupported type for parameter to_taint: %s" %
                        type(to_taint))

def untaint(jitter, to_untaint, color):
    """
    @to_untaint can be either an ExprMem or an ExprId (or ExprSlice of ExprId).
    """

    if to_untaint.is_mem():
        untaint_memory(jitter, to_untaint, color)
    elif to_untaint.is_id() or (to_untaint.is_slice() and to_untaint.arg.is_id()):
        untaint_register(jitter, to_untaint, color)
    else:
        raise TypeError("Unsupported type for parameter to_utaint: %s" %
                        type(to_untaint))

def eval_reg_alias(jitter, register):
    if register.is_slice():
        new_register = jitter.ir_arch.expr_fix_regs_for_mode(register.arg)
        register = ExprSlice(new_register, register.start, register.stop)
        simplifier = ExpressionSimplifier()
        simplifier.enable_passes({ExprSlice: [simp_slice]})
        return simplifier.apply_simp(register)
    return jitter.ir_arch.expr_fix_regs_for_mode(register)

def taint_register(jitter, register, color):
    """
    @register can be either an ExprId or ExprSlice of ExprId.
    """

    register = eval_reg_alias(jitter, register)

    if register.is_slice():
        jitter.taint.taint_register(color,
                                    jitter.jit.codegen.regs_index[str(register.arg)],
                                    bits2bytes(register.start),
                                    bits2bytes(register.stop) - 1)
    else:
        jitter.taint.taint_register(color,
                                    jitter.jit.codegen.regs_index[str(register)],
                                    0,
                                    bits2bytes(register.size)-1)

def untaint_register(jitter, register, color):
    """
    @register can be either an ExprId or ExprSlice of ExprId.
    """

    register = eval_reg_alias(jitter, register)

    if register.is_slice():
        jitter.taint.untaint_register(color,
                                      jitter.jit.codegen.regs_index[str(register.arg)],
                                      bits2bytes(register.start),
                                      bits2bytes(register.stop) - 1)
    else:
        jitter.taint.untaint_register(color,
                                      jitter.jit.codegen.regs_index[str(register)],
                                      0,
                                      bits2bytes(register.size)-1)

def taint_memory(jitter, memory, color):
    jitter.taint.taint_memory(int(memory.ptr),
                              bits2bytes(memory.size),
                              color)

def untaint_memory(jitter, memory, color):
    jitter.taint.untaint_memory(int(memory.ptr),
                                bits2bytes(memory.size),
                                color)

# TODO: add helpers to get current taint and last tainted elements as
# ExprSlice(ExprId)/ExprMem

def on_taint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.taint.last_tainted_registers(color)
        if last_regs:
            print("[Color:%s] Taint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t+ %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
    return True

def on_untaint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.taint.last_untainted_registers(color)
        if last_regs:
            print("[Color:%s] Untaint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t- %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_REG))
    is_taint_vanished(jitter)
    return True

def on_taint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.taint.last_tainted_memory(color)
        if last_mem:
            print("[Color:%s] Taint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_MEM))
    return True

def on_untaint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.taint.last_untainted_memory(color)
        if last_mem:
            print("[Color%s] Untaint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_MEM))
    is_taint_vanished(jitter)
    return True

def display_all_taint(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.taint.get_all_taint(color)
        print("\n","_"*20)
        print("Color: %s" % (color))
        print("_"*20)
        print("Registers:")
        for reg_id, intervals in regs:
            print("\t* %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
        print("-"*20)
        print("Memory:")
        print(interval(mems))
        print("_"*20,"\n")

def is_taint_vanished(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.taint.get_all_taint(color)
        if regs or mems:
            return # There is still some taint
    print("\n\n/!\\ All taint is gone ! /!\\\n\n")
