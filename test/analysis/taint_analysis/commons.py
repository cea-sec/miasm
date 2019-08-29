from miasm.loader.strpatchwork import StrPatchwork
from miasm.arch.x86.arch import mn_x86
from miasm.core import parse_asm
from miasm.core.asmblock import asm_resolve_final
from miasm.analysis.machine import Machine
import miasm.jitter.csts as csts
import miasm.analysis.taint_analysis as taint

## CSTS
# Color csts
nb_colors = 2
red = 0
blue = 1
# Addr csts
data_addr = 0x80000000
code_addr = 0x40000000
# Indexes
reg_index = 0
reg_start_byte = 1
reg_end_byte = 2
mem_addr = 0
mem_size = 1

machine = Machine('x86_32')

def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

def create_jitter():
    jitter = machine.jitter(jit_type='gcc', taint=True)
    jitter.init_stack()
    jitter.vm.add_memory_page(data_addr, csts.PAGE_READ | csts.PAGE_WRITE, '0'*200)
    jitter.add_breakpoint(0x1337beef, code_sentinelle)
    jitter.push_uint32_t(0x1337beef)
    taint.enable_taint_analysis(jitter, nb_colors)
    return jitter

def assemble_code(code_str):
    # Assemble code to test
    blocks, symbol_pool = parse_asm.parse_txt(mn_x86, 32, code_str)

    # Set 'main' label's offset
    symbol_pool.set_location_offset(symbol_pool.get_name_location("main"), 0x0)

    # Spread information and resolve instructions offset
    patches = asm_resolve_final(mn_x86, blocks, symbol_pool)

    output = StrPatchwork()
    for offset, raw in patches.items():
        output[offset] = raw
    return str(output)

def nothing_tainted(jitter, color):
    no_reg_tainted(jitter, color)
    no_mem_tainted(jitter, color)

def no_reg_tainted(jitter, color):
    last_regs = jitter.cpu.last_tainted_registers(color)
    assert not last_regs
    last_regs = jitter.cpu.last_untainted_registers(color)
    assert not last_regs

def no_mem_tainted(jitter, color):
    last_mem = jitter.cpu.last_tainted_memory(color)
    assert not last_mem
    last_mem = jitter.cpu.last_untainted_memory(color)
    assert not last_mem

def no_more_taint(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.cpu.get_all_taint(color)
        assert not regs
        assert not mems
    return True

def check_reg(reg, jitter, register, start, end):
    assert reg[reg_index] == jitter.jit.codegen.regs_index[register]
    assert reg[reg_start_byte] == start
    assert reg[reg_end_byte] == end

def check_mem(mem, addr, size):
    assert mem[mem_addr] == addr
    assert mem[mem_size] == size

def taint_register(jitter, color, register, start=0, end=7):
    jitter.cpu.taint_register(color, jitter.jit.codegen.regs_index[register], start, end)
    return True

def taint_EAX(jitter):
    taint_register(jitter, red, "RAX", 0, 3)
    return True

def taint_AX(jitter):
    taint_register(jitter, red, "RAX", 0, 1)
    return True

def taint_EBX(jitter):
    taint_register(jitter, red, "RBX", 0, 3)
    return True

def taint_ECX(jitter):
    taint_register(jitter, red, "RCX", 0, 3)
    return True

def taint_ECX_blue(jitter):
    taint_register(jitter, blue, "RCX", 0, 3)
    return True

def taint_EDX_blue(jitter):
    taint_register(jitter, blue, "RDX", 0, 3)
    return True

def taint_mem_0x123FFE8(jitter):
    jitter.cpu.taint_memory(0x123FFe8,4,red)
    return True

def taint_mem_RAX(jitter):
    jitter.cpu.taint_memory(jitter.cpu.RAX,4,red)
    return True

def taint_mem_RBX(jitter):
    jitter.cpu.taint_memory(jitter.cpu.RBX,4,red)
    return True

