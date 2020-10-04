#from builtins import range
from miasm.expression.expression import *
#from miasm.core.cpu import reg_info

WASM_ADDR_SIZE = 32

PC = ExprId('PC', WASM_ADDR_SIZE)
SP = ExprId('SP', WASM_ADDR_SIZE)

# Call pointer
# A pointer on a parallel stack storing
# Local variables of functions and return addresses
CP = ExprId('CP', WASM_ADDR_SIZE)

PC_init = ExprId("PC_init", WASM_ADDR_SIZE)
SP_init = ExprId("SP_init", WASM_ADDR_SIZE)
CP_init = ExprId("CP_init", WASM_ADDR_SIZE)


regs_init = {
    PC: PC_init,
    SP: SP_init,
    CP: CP_init,
}
