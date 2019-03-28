#-*- coding:utf-8 -*-

from miasm.expression.expression import *
from miasm.arch.wasm.regs import *
from miasm.arch.wasm.arch import mn_wasm
from miasm.ir.ir import IntermediateRepresentation, IRBlock, AssignBlock


##### Utility functions #####

def i2expr(i, size):
    if isinstance(i, int):
        if i >= 0:
            return ExprInt(i, size)
        return ExprOp('-', ExprInt(-i, size))
    return i

##### Functions that make operations on stack #####
##### or depend on the stack implementation #####
'''
These functions return some IR that must be
executed to make some operations on the stack.
Only use these functions when you operate the stack,
so it's easier to change the way the stack work
The returned IR depends on the status of the stack,
use them carefully !
'''

# Sizes of types
VT_SIZE = {
    'i32': 32,
    'i64': 64,
    'f32': 32,
    'i64': 64,
}

# Representation of value types on stack
VT_REPR = {
    'i32': 0,
    'i64': 1,
    'f32': 2,
    'i64': 3,
}

def size_on_stack(vt):
   # Assumes vt is a correct calue type
    if vt[1:] == '64':
        return 9
    return 5

def overwrite_at(ir, ofs, val):
    '''
    Returns an ExprAssign that writes the value @val
    on the stack at sp+@ofs
    '''
    ofs = i2expr(ofs, ir.sp.size)
    return ExprAssign(ExprMem(ExprOp('+', ir.sp, ofs), val.size), val)

def get_at(ir, ofs, vt):
    '''
    Returns an Expr which holds the value contained
    on the stack at sp+@ofs
    '''
    ofs = i2expr(ofs, ir.sp.size)
    return ExprMem(ExprOp('+', ir.sp, ofs), VT_SIZE[vt])

def add_sp(ir, n_bytes):
    '''
    Returns an ExprAssign to add a shift to the SP
    '''
    shf = i2expr(n_bytes, ir.sp.size)
    return ExprAssign(ir.sp, ExprOp('+', ir.sp, shf))

def push(ir, val, vt, ofs=0):
    '''
    "Pushes" a value on the stack.
    Returns a list of ExprAssign that:
    - Moves the SP accordingly
    - Write the value on the stack
    The parameter @ofs enables to move the SP
    before pushing
    '''
    ofs = i2expr(ofs, ir.sp.size)
    shf = i2expr(-size_on_stack(vt), ir.sp.size)
    target = ExprOp('+', ofs, shf)
    mv_sp = add_sp(ir, target)
    w_val = overwrite_at(ir, ExprOp('+', ExprInt(1, ir.sp.size), target), val)
    w_vt = overwrite_at(ir, target, i2expr(VT_REPR[vt], 8))
    return [mv_sp, w_val, w_vt]

def get_last_value_size(ir):
    return ExprCond(ExprOp('&', ExprMem(ir.sp, 8), ExprInt(1, 8)),
                    ExprInt(9, ir.sp.size),
                    ExprInt(5, ir.sp.size))

def pop(ir, vt=None, n=1):
    '''
    "Pops" a value (or @n values) from the operand stack.
    If @vt is None, @n is ignored and only one value is poped
    Returns a tuple (shf, val) where:
    - shf is an Expr holding the value to add to the stack
    - ofs_vals is a list of Expr holding offsets to get the poped values
    Note that if @vt is None, val is None too
    '''
    if vt is None:
        return get_last_value_size(ir), None

    size_per_item = size_on_stack(vt)
    size_to_pop = ExprInt(size_per_item * n, ir.sp.size)

    is_64 = VT_REPR[vt] & 1 == 1
    # get poped values ordered with the one the furthest from the SP first
    ofs_vals = [i2expr(1 + (i*size_per_item), ir.sp.size) for i in range(n)][::-1]
    return i2expr(size_per_item * n, ir.sp.size), ofs_vals

##### Mnemonics functions #####

def nop(ir, instr):
    return [],[]

def const(ir, instr, arg):
    e = push(ir, arg, instr.name.split('.')[0])
    return e, []

def drop(ir, instr):
    a = pop(ir)[0]
    return [add_sp(ir, a)], []


## Control flow (block, loop, end, calls...

def block(ir, instr, *args):
    return nop(ir, instr)

def loop(ir, instr, *args):
    return nop(ir, instr)

def call(ir, instr, *args):
    info = ir.func_info[args[0]]
    adjust_cp_size = ExprAssign(
        ir.cp,
        ExprOp('+',
               ir.cp,
               ExprOp('-',
                      ExprInt(info[locsize],
                              ir.addrsize))))
    fds #TODO#

def if_(ir, instr, *args):
    # #TODO# (outside block) :
    # Pop value and branch on correct LocKey
    return nop(ir, instr)
    

def else_(ir, instr, *args):
    return br(ir, instr, *args)

def end(ir, instr, *args):
    if isinstance(args[0], int):
         return return_(ir, instr, *args)
    return nop(ir, instr)

def return_(ir, instr, *args):
    idx = args[0]
    

## Branch instructions

def br(ir, instr, dest):
    return [ExprAssign(ir.IRDst, dest)], []

def br_if(ir, instr, dest):
    shf, ofs = pop(ir, 'i32')
    test = ExprMem(ofs[0], 32)
    cond_dst = ExprAssign(ir.IRDst, ExprCond(test, dest, ir.IRDst))
    fds #TODO# c'est pas bon
    return [shf, cond_dst], []


def br_table(ir, instr, *args):
    shf, ofs = pop(ir, 'i32')
    index = ExprMem(ofs[0], 32)
    oob = ExprOp('<u', vals[0], vals[1]).zeroExtend(32)
    # #TODO#
    # check if index too big
    # if yes: default branch
    # else: indexed branch
    fds

## Operations on integers

IUNOPS = {
    'clz'   : lambda vals: ExprOp('cntleadzeros', vals[0]),
    'ctz'   : lambda vals: ExprOp('cnttrailzeros', vals[0]),
    'popcnt': lambda vals: ExprOp('cntones', vals[0]),
}

def iunop(ir, instr):
    '''
    Unary operation on integer:
    Consumes 1 operand on stack
    Produces 1 operand of same type
    '''
    vt, op = instr.name.split('.')
    # get operands
    _, ofs_vals = pop(ir, vt, 1)
    res = IUNOPS[op]([get_at(ir, ofs_vals[0], vt)])
    # Overwrite the value that has not been poped
    aff_res = overwrite_at(ir, ofs_vals[0], res)
    return [aff_res], []


IBINOPS = {
    'add'  : lambda vals: ExprOp('+', vals[0], vals[1]),
    'sub'  : lambda vals: ExprOp('+', vals[0], ExprOp('-', vals[1])),
    'mul'  : lambda vals: ExprOp('*', vals[0], vals[1]),
    'and'  : lambda vals: ExprOp('&', vals[0], vals[1]),
    'or'   : lambda vals: ExprOp('|', vals[0], vals[1]),
    'xor'  : lambda vals: ExprOp('^', vals[0], vals[1]),
    'shl'  : lambda vals: ExprOp('<<', vals[0], vals[1]),
    'rotl' : lambda vals: ExprOp('<<<', vals[0], vals[1]),
    'rotr' : lambda vals: ExprOp('>>>', vals[0], vals[1]),
    'div_u': lambda vals: ExprOp('udiv', vals[0], vals[1]),
    'rem_u': lambda vals: ExprOp('umod', vals[0], vals[1]),
    'shr_u': lambda vals: ExprOp('>>', vals[0], vals[1]),
    'div_s': lambda vals: ExprOp('sdiv', vals[0], vals[1]),
    'rem_s': lambda vals: ExprOp('smod', vals[0], vals[1]),
    'shr_s': lambda vals: ExprOp('a>>', vals[0], vals[1]),
}

def ibinop(ir, instr):
    '''
    Binary operation on integer:
    Consumes 2 operands on stack
    Produces 1 operand of same type
    '''
    vt, op = instr.name.split('.')
    # get operands and make operation
    _, ofs_vals = pop(ir, vt, 2)
    res = IBINOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    aff_res = overwrite_at(ir, ofs_vals[1], res)

    # Move the stack
    mv_sp = add_sp(ir, size_on_stack(vt))
    return [mv_sp, aff_res], []


ITESTOPS = {
    'eqz': lambda vals: ExprCond(vals[0], ExprInt(0x0, 32), ExprInt(0x1, 32)),
}

def itestop(ir, instr):
    '''
    Test operation on integer:
    Consumes 1 operand on stack
    Produces 1 boolean (i32) operand
    '''
    vt, op = instr.name.split('.')
    # get operands
    pp, ofs_vals = pop(ir, vt, 1)
    res = ITESTOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    # Push result of operation on the previous value
    push_res = push(ir, res, 'i32', pp)

    return push_res, []

IRELOPS = {
    'eq'  : lambda vals: ExprOp('==', vals[0], vals[1]).zeroExtend(32),
    # 'FLAG_EQ' operator acts like a 'not'
    'ne'  : lambda vals: ExprOp('FLAG_EQ', ExprOp('==', vals[0], vals[1])).zeroExtend(32),
    'lt_s': lambda vals: ExprOp('<s', vals[0], vals[1]).zeroExtend(32),
    'lt_u': lambda vals: ExprOp('<u', vals[0], vals[1]).zeroExtend(32),
    'gt_s': lambda vals: ExprOp('FLAG_EQ', ExprOp('<=s', vals[0], vals[1])).zeroExtend(32),
    'gt_u': lambda vals: ExprOp('FLAG_EQ', ExprOp('<=u', vals[0], vals[1])).zeroExtend(32),
    'le_s': lambda vals: ExprOp('<=s', vals[0], vals[1]).zeroExtend(32),
    'le_u': lambda vals: ExprOp('<=u', vals[0], vals[1]).zeroExtend(32),
    'ge_s': lambda vals: ExprOp('FLAG_EQ', ExprOp('<s', vals[0], vals[1])).zeroExtend(32),
    'ge_u': lambda vals: ExprOp('FLAG_EQ', ExprOp('<u', vals[0], vals[1])).zeroExtend(32),
}

def irelop(ir, instr):
    '''
    Comparison operation on integer:
    Consumes 2 operand on stack
    Produces 1 boolean (i32) operand
    '''
    vt, op = instr.name.split('.')
    # get operands
    pp, ofs_vals = pop(ir, vt, 2)
    res = IRELOPS[op]([get_at(ir, ofs, vt) for ofs in ofs_vals])
    # Push result of operation on the previous value
    push_res = push(ir, res, 'i32', pp)

    return push_res, []


I2I = {
    'wrap_i64': lambda vals: ExprSlice(vals[0], 0, 32),
    'extend_i32_u': lambda vals: vals[0].zeroExtend(64),
    'extend_i32_s': lambda vals: vals[0].signExtend(64),
}

def i2i(ir, instr):
    '''
    Conversion of integers (i32 <-> i64)
    '''
    vt_dst, op = instr.name.split('.')
    if vt_dst == 'i32':
        vt_src = 'i64'
    elif vt_dst == 'i64':
        vt_src = 'i32'
    pp, ofs_vals = pop(ir, vt_src, 1)
    res = I2I[op]([get_at(ir, ofs, vt_src) for ofs in ofs_vals])

    push_res = push(ir, res, vt_dst, pp)
    return push_res, []

##### Mnemonics indexing #####

''' #TODO#
if / loop / block / else...
calls
memories
branches
select
floats
locals
globals
'''

mnemo_func = {
    'i32.const'        : const,
    'i64.const'        : const,
    'f32.const'        : const,
    'f64.const'        : const,
    'nop'              : nop,
    'block'            : block,
    'loop'             : loop,
    'else'             : else_,
    'end'              : end,
    'if'               : if_,
    'return'           : return_,
    'drop'             : drop,
    'i32.clz'          : iunop,
    'i32.ctz'          : iunop,
    'i32.popcnt'       : iunop,
    'i64.clz'          : iunop,
    'i64.ctz'          : iunop,
    'i64.popcnt'       : iunop,
    'i32.add'          : ibinop,
    'i32.sub'          : ibinop,
    'i32.mul'          : ibinop,
    'i32.and'          : ibinop,
    'i32.or'           : ibinop,
    'i32.xor'          : ibinop,
    'i32.shl'          : ibinop,
    'i32.rotl'         : ibinop,
    'i32.rotr'         : ibinop,
    'i32.div_u'        : ibinop,
    'i32.rem_u'        : ibinop,
    'i32.shr_u'        : ibinop,
    'i32.div_s'        : ibinop,
    'i32.rem_s'        : ibinop,
    'i32.shr_s'        : ibinop,
    'i64.add'          : ibinop,
    'i64.sub'          : ibinop,
    'i64.mul'          : ibinop,
    'i64.and'          : ibinop,
    'i64.or'           : ibinop,
    'i64.xor'          : ibinop,
    'i64.shl'          : ibinop,
    'i64.rotl'         : ibinop,
    'i64.rotr'         : ibinop,
    'i64.div_u'        : ibinop,
    'i64.rem_u'        : ibinop,
    'i64.shr_u'        : ibinop,
    'i64.div_s'        : ibinop,
    'i64.rem_s'        : ibinop,
    'i64.shr_s'        : ibinop,
    'i32.eqz'          : itestop,
    'i64.eqz'          : itestop,
    'i32.eq'           : irelop,
    'i32.ne'           : irelop,
    'i32.lt_s'         : irelop,
    'i32.lt_u'         : irelop,
    'i32.gt_s'         : irelop,
    'i32.gt_u'         : irelop,
    'i32.le_s'         : irelop,
    'i32.le_u'         : irelop,
    'i32.ge_s'         : irelop,
    'i32.ge_u'         : irelop,
    'i64.eq'           : irelop,
    'i64.ne'           : irelop,
    'i64.lt_s'         : irelop,
    'i64.lt_u'         : irelop,
    'i64.gt_s'         : irelop,
    'i64.gt_u'         : irelop,
    'i64.le_s'         : irelop,
    'i64.le_u'         : irelop,
    'i64.ge_s'         : irelop,
    'i64.ge_u'         : irelop,
    'i32.wrap_i64'     : i2i,
    'i64.extend_i32_u' : i2i,
    'i64.extend_i32_s' : i2i,
}

class ir_wasm(IntermediateRepresentation):

    def __init__(self, loc_db=None, cont=None):
        IntermediateRepresentation.__init__(self, mn_wasm, None, loc_db)

        if cont is None:
            raise Exception("Container object is needed")

        # Init registers and basic information
        self.pc = PC # Does it make sense ?
        self.sp = SP
        self.cp = CP
        self.IRDst = ExprId('IRDst', WASM_ADDR_SIZE)
        self.addrsize = WASM_ADDR_SIZE

        # Init function information
        self.func_info = []
        for f in cont.executable.functions:
            locs = []
            if not f.is_imported:
                locs = f.code.locs
            locsize = 0
            for vt in f.signature.params + locs:
                locsize += VT_SIZE[vt.name]
            self.func_info.append({
                'params' : f.signature.params,
                'results': f.signature.results,
                'locals' : locs,
                'locsize': locsize,
            })
        #TODO# init globals, memories, tables (with elements)

    def get_ir(self, instr):
        args = instr.args
        instr_ir, extra_ir = mnemo_func[instr.name](self, instr, *args)
        return instr_ir, extra_ir

    def get_loc_key_for_instr(self, instr):
        '''
        Only called when instruction is not at beginning of block,
        so @instr has no loc_key already
        '''
        return self.loc_db.add_location()

    def get_next_loc_key(self, instr):
        raise NotImplementedError("Cannot be used")

    def add_instr_to_ircfg(self, instr, ircfg, loc_key=None, gen_pc_updt=False):
        raise NotImplementedError("Cannot be used")
