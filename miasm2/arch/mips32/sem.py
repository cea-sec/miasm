from miasm2.expression.expression import *
from miasm2.ir.ir import ir, irbloc
from miasm2.arch.mips32.arch import mn_mips32
from miasm2.arch.mips32.regs import *

def addiu(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b+c))
    return None, e, []

def lw(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return None, e, []

def sw(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return None, e, []

def jalr(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(b, n))
    return a, e, []

def bal(ir, instr, a):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    e.append(ExprAff(PC, a))
    e.append(ExprAff(RA, n))
    return a, e, []

def l_b(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    return a, e, []

def lbu(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 8)
    e.append(ExprAff(a, b.zeroExtend(32)))
    return None, e, []

def lhu(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 16)
    e.append(ExprAff(a, b.zeroExtend(32)))
    return None, e, []

def beq(ir, instr, a, b, c):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a-b, c, n)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def bgez(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a.msb(), n, b)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def bne(ir, instr, a, b, c):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a-b, n, c)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def lui(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, ExprCompose([(ExprInt16(0), 0, 16),
                                     (b[:16], 16, 32)])))
    return None, e, []

def nop(ir, instr):
    return None, [], []

def j(ir, instr, a):
    e = []
    e.append(ExprAff(PC, a))
    return a, e, []

def l_or(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b|c))
    return None, e, []

def nor(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, (b|c)^ExprInt32(0xFFFFFFFF)))
    return None, e, []

def l_and(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b&c))
    return None, e, []

def ext(ir, instr, a, b, c, d):
    e = []
    pos = int(c.arg)
    size = int(d.arg)
    e.append(ExprAff(a, b[pos:pos+size].zeroExtend(32)))
    return None, e, []

def mul(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('imul', b, c)))
    return None, e, []

def sltu(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, (b-c).msb().zeroExtend(32)))
    return None, e, []

def slt(ir, instr, a, b, c):
    e = []
    #nf - of
    # TODO CHECK
    f = (b-c).msb() ^ (((a ^ c) & (~(a ^ b)))).msb()
    e.append(ExprAff(a, f.zeroExtend(32)))
    return None, e, []

def l_sub(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b-c))
    return None, e, []

def sb(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 8)
    e.append(ExprAff(b, a[:8]))
    return None, e, []

def sh(ir, instr, a, b):
    e = []
    b = ExprMem(b.arg, 16)
    e.append(ExprAff(b, a[:16]))
    return None, e, []

def movn(ir, instr, a, b, c):
    lbl_do = ExprId(ir.gen_label(), instr.mode)
    lbl_skip = ExprId(ir.get_next_label(instr), instr.mode)
    e_do = []
    e_do.append(ExprAff(a, b))

    return ExprCond(c, lbl_do, lbl_skip), [], [irbloc(lbl_do.name, lbl_skip, [e_do])]

def srl(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b >> c))
    return None, e, []

def sra(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('a>>', b, c)))
    return None, e, []

def srav(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('a>>', b, c&ExprInt32(0x1F))))
    return None, e, []

def sll(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b<<c))
    return None, e, []

def srlv(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b >> (c & ExprInt32(0x1F))))
    return None, e, []

def sllv(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b << (c & ExprInt32(0x1F))))
    return None, e, []

def l_xor(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, b^c))
    return None, e, []

def seb(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b[:8].signExtend(32)))
    return None, e, []

def bltz(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a.msb(), b, n)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def blez(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    cond = ExprCond(a, ExprInt1(1), ExprInt1(0)) | a.msb()
    dst_o = ExprCond(cond, b, n)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def bgtz(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    cond = ExprCond(a, ExprInt1(1), ExprInt1(0)) | a.msb()
    dst_o = ExprCond(cond, n, b)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def wsbh(ir, instr, a, b):
    e = [ExprAff(a, ExprCompose([(b[8:16],  0, 8)   ,
                                 (b[0:8]  , 8, 16)  ,
                                 (b[24:32], 16, 24),
                                 (b[16:24], 24, 32)]))]
    return None, e, []

def rotr(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('>>>', b, c)))
    return None, e, []

def add_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fadd', b, c)))
    return None, e, []

def sub_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fsub', b, c)))
    return None, e, []

def div_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fdiv', b, c)))
    return None, e, []

def mul_d(ir, instr, a, b, c):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, ExprOp('fmul', b, c)))
    return None, e, []

def mov_d(ir, instr, a, b):
    # XXX TODO check
    e = []
    e.append(ExprAff(a, b))
    return None, e, []

def mfc0(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return None, e, []

def mfc1(ir, instr, a, b):
    e = []
    e.append(ExprAff(a, b))
    return None, e, []

def mtc0(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return None, e, []

def mtc1(ir, instr, a, b):
    e = []
    e.append(ExprAff(b, a))
    return None, e, []

def tlbwi(ir, instr):
    # TODO XXX
    e = []
    return None, e, []

def tlbp(ir, instr):
    # TODO XXX
    e = []
    return None, e, []

def ins(ir, instr, a, b, c, d):
    e = []
    pos = int(c.arg)
    l = int(d.arg)

    my_slices = []
    if pos != 0:
        my_slices.append((a[:pos], 0, pos))
    if l != 0:
        my_slices.append((b[:l], pos, pos+l))
    if pos + l != 32:
        my_slices.append((a[pos+l:], pos+l, 32))
    r = ExprCompose(my_slices)
    e.append(ExprAff(a, r))
    return None, e, []


def lwc1(ir, instr, a, b):
    e = []
    src = ExprOp('mem_%.2d_to_single' % b.size, b)
    e.append(ExprAff(a, src))
    return None, e, []

def swc1(ir, instr, a, b):
    e = []
    src = ExprOp('single_to_mem_%.2d' % a.size, a)
    e.append(ExprAff(b, src))
    return None, e, []

def c_lt_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_lt', b, c)))
    return None, e, []

def c_eq_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_eq', b, c)))
    return None, e, []

def c_le_d(ir, instr, a, b, c):
    e = []
    e.append(ExprAff(a, ExprOp('fcomp_le', b, c)))
    return None, e, []

def bc1t(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a, b, n)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def bc1f(ir, instr, a, b):
    e = []
    n = ExprId(ir.get_next_break_label(instr))
    dst_o = ExprCond(a, n, b)
    e = [ExprAff(PC, dst_o)]
    return dst_o, e, []

def cvt_d_w(ir, instr, a, b):
    e = []
    # TODO XXX
    e.append(ExprAff(a, ExprOp('flt_d_w', b)))
    return None, e, []

def mult(ir, instr, a, b):
    e = []
    size = a.size
    r = a.signExtend(size * 2) * b.signExtend(size * 2)

    e.append(ExprAff(R_LO, r[:32]))
    e.append(ExprAff(R_HI, r[32:]))
    return None, e, []

def mfhi(ir, instr, a):
    e = []
    e.append(ExprAff(a, R_HI))
    return None, e, []

def mflo(ir, instr, a):
    e = []
    e.append(ExprAff(a, R_LO))
    return None, e, []


mnemo_func = {
    "addiu": addiu,
    "addu": addiu,
    "lw" : lw,
    "sw" : sw,
    "sh" : sh,
    "sb" : sb,
    "jalr" : jalr,
    "bal" : bal,
    "b" : l_b,
    "lbu" : lbu,
    "lhu" : lhu,
    "beq" : beq,
    "bgez" : bgez,
    "bltz" : bltz,
    "bgtz" : bgtz,
    "bne" : bne,
    "lui" : lui,
    "nop" : nop,
    "j" : j,
    "jr" : j,
    "ori" : l_or,
    "or" : l_or,
    "nor" : nor,
    "and" : l_and,
    "andi" : l_and,
    "ext" : ext,
    "mul" : mul,
    "sltu" : sltu,
    "slt" : slt,
    "slti" : slt,
    "sltiu" : sltu,
    "subu" : l_sub,
    "movn" : movn,
    "srl" : srl,
    "sra" : sra,
    "srav" : srav,
    "sll" : sll,
    "srlv" : srlv,
    "sllv" : sllv,
    "xori" : l_xor,
    "xor" : l_xor,
    "seb" : seb,
    "bltz" : bltz,
    "blez" : blez,
    "wsbh" : wsbh,
    "rotr" : rotr,
    "mfc0" : mfc0,
    "mfc1" : mfc1,
    "mtc0" : mtc0,
    "mtc1" : mtc1,
    "tlbwi" : tlbwi,
    "tlbp" : tlbp,
    "ins" : ins,

    "add.d" : add_d,
    "sub.d" : sub_d,
    "div.d" : div_d,
    "mul.d" : mul_d,
    "mov.d" : mov_d,
    "lwc1" : lwc1,
    "swc1" : swc1,
    "c.lt.d" : c_lt_d,
    "c.eq.d" : c_eq_d,
    "c.le.d" : c_le_d,
    "bc1t" : bc1t,
    "bc1f" : bc1f,
    "cvt.d.w":cvt_d_w,
    "mult" : mult,

    "mfhi" : mfhi,
    "mflo" : mflo,

    }

def get_mnemo_expr(ir, instr, *args):
    dst, instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return dst, instr, extra_ir

class ir_mips32(ir):

    def __init__(self, symbol_pool=None):
        ir.__init__(self, mn_mips32, None, symbol_pool)
        self.pc = mn_mips32.getpc()
        self.sp = mn_mips32.getsp()

    def get_ir(self, instr):
        args = instr.args
        dst, instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)

        for i, x in enumerate(instr_ir):
            x = ExprAff(x.dst, x.src.replace_expr(
                {self.pc: ExprInt32(instr.offset + 4)}))
            instr_ir[i] = x
        for b in extra_ir:
            for irs in b.irs:
                for i, x in enumerate(irs):
                    x = ExprAff(x.dst, x.src.replace_expr(
                        {self.pc: ExprInt32(instr.offset + 4)}))
                    irs[i] = x
        return dst, instr_ir, extra_ir
