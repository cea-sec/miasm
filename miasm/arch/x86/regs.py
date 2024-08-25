from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import reg_info


IP = ExprId('IP', 16)
EIP = ExprId('EIP', 32)
RIP = ExprId('RIP', 64)
exception_flags = ExprId('exception_flags', 32)
interrupt_num = ExprId('interrupt_num', 8)

# GP


regs08_str = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"] + \
    ["R%dB" % (i + 8) for i in range(8)]
regs08_expr = [ExprId(x, 8) for x in regs08_str]

regs08_64_str = ["AL", "CL", "DL", "BL", "SPL", "BPL", "SIL", "DIL"] + \
    ["R%dB" % (i + 8) for i in range(8)]
regs08_64_expr = [ExprId(x, 8) for x in regs08_64_str]


regs16_str = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"] + \
    ["R%dW" % (i + 8) for i in range(8)]
regs16_expr = [ExprId(x, 16) for x in regs16_str]

regs32_str = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"] + \
    ["R%dD" % (i + 8) for i in range(8)] + ["EIP"]
regs32_expr = [ExprId(x, 32) for x in regs32_str]

regs64_str = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
              "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
              "RIP"]
regs64_expr = [ExprId(x, 64) for x in regs64_str]


regs_xmm_str = ["XMM%d" % i for i in range(16)]
regs_xmm_expr = [ExprId(x, 128) for x in regs_xmm_str]

regs_mm_str = ["MM%d" % i for i in range(16)]
regs_mm_expr = [ExprId(x, 64) for x in regs_mm_str]

regs_bnd_str = ["BND%d" % i for i in range(4)]
regs_bnd_expr = [ExprId(x, 128) for x in regs_bnd_str]

gpregs08 = reg_info(regs08_str, regs08_expr)
gpregs08_64 = reg_info(regs08_64_str, regs08_64_expr)
gpregs16 = reg_info(regs16_str, regs16_expr)
gpregs32 = reg_info(regs32_str, regs32_expr)
gpregs64 = reg_info(regs64_str, regs64_expr)

gpregs_xmm = reg_info(regs_xmm_str, regs_xmm_expr)
gpregs_mm = reg_info(regs_mm_str, regs_mm_expr)
gpregs_bnd = reg_info(regs_bnd_str, regs_bnd_expr)

r08_eax = reg_info([regs08_str[0]], [regs08_expr[0]])
r16_eax = reg_info([regs16_str[0]], [regs16_expr[0]])
r32_eax = reg_info([regs32_str[0]], [regs32_expr[0]])
r64_eax = reg_info([regs64_str[0]], [regs64_expr[0]])

r08_ecx = reg_info([regs08_str[1]], [regs08_expr[1]])

r_eax_all = reg_info(
    [regs08_str[0], regs16_str[0], regs32_str[0], regs64_str[0]],
    [regs08_expr[0], regs16_expr[0], regs32_expr[0], regs64_expr[0]])
r_edx_all = reg_info(
    [regs08_str[2], regs16_str[2], regs32_str[2], regs64_str[2]],
    [regs08_expr[2], regs16_expr[2], regs32_expr[2], regs64_expr[2]])

r16_edx = reg_info([regs16_str[2]], [regs16_expr[2]])


selectr_str = ["ES", "CS", "SS", "DS", "FS", "GS"]
selectr_expr = [ExprId(x, 16) for x in selectr_str]
segmreg = reg_info(selectr_str, selectr_expr)

crregs32_str = ["CR%d" % i for i in range(8)]
crregs32_expr = [ExprId(x, 32) for x in crregs32_str]
crregs = reg_info(crregs32_str, crregs32_expr)


drregs32_str = ["DR%d" % i for i in range(8)]
drregs32_expr = [ExprId(x, 32) for x in drregs32_str]
drregs = reg_info(drregs32_str, drregs32_expr)


fltregs32_str = ["ST(%d)" % i for i in range(8)]
fltregs32_expr = [ExprId(x, 64) for x in fltregs32_str]
fltregs = reg_info(fltregs32_str, fltregs32_expr)

r_st_all = reg_info(['ST'],
                    [ExprId('ST', 64)])

r_cs_all = reg_info(['CS'],
                    [ExprId('CS', 16)])
r_ds_all = reg_info(['DS'],
                    [ExprId('DS', 16)])
r_es_all = reg_info(['ES'],
                    [ExprId('ES', 16)])
r_ss_all = reg_info(['SS'],
                    [ExprId('SS', 16)])
r_fs_all = reg_info(['FS'],
                    [ExprId('FS', 16)])
r_gs_all = reg_info(['GS'],
                    [ExprId('GS', 16)])


AL = regs08_expr[0]
CL = regs08_expr[1]
DL = regs08_expr[2]
BL = regs08_expr[3]
AH = regs08_expr[4]
CH = regs08_expr[5]
DH = regs08_expr[6]
BH = regs08_expr[7]
R8B = regs08_expr[8]
R9B = regs08_expr[9]
R10B = regs08_expr[10]
R11B = regs08_expr[11]
R12B = regs08_expr[12]
R13B = regs08_expr[13]
R14B = regs08_expr[14]
R15B = regs08_expr[15]

SPL = regs08_64_expr[4]
BPL = regs08_64_expr[5]
SIL = regs08_64_expr[6]
DIL = regs08_64_expr[7]


AX = regs16_expr[0]
CX = regs16_expr[1]
DX = regs16_expr[2]
BX = regs16_expr[3]
SP = regs16_expr[4]
BP = regs16_expr[5]
SI = regs16_expr[6]
DI = regs16_expr[7]
R8W = regs16_expr[8]
R9W = regs16_expr[9]
R10W = regs16_expr[10]
R11W = regs16_expr[11]
R12W = regs16_expr[12]
R13W = regs16_expr[13]
R14W = regs16_expr[14]
R15W = regs16_expr[15]


EAX = regs32_expr[0]
ECX = regs32_expr[1]
EDX = regs32_expr[2]
EBX = regs32_expr[3]
ESP = regs32_expr[4]
EBP = regs32_expr[5]
ESI = regs32_expr[6]
EDI = regs32_expr[7]
R8D = regs32_expr[8]
R9D = regs32_expr[9]
R10D = regs32_expr[10]
R11D = regs32_expr[11]
R12D = regs32_expr[12]
R13D = regs32_expr[13]
R14D = regs32_expr[14]
R15D = regs32_expr[15]


RAX = regs64_expr[0]
RCX = regs64_expr[1]
RDX = regs64_expr[2]
RBX = regs64_expr[3]
RSP = regs64_expr[4]
RBP = regs64_expr[5]
RSI = regs64_expr[6]
RDI = regs64_expr[7]
R8 = regs64_expr[8]
R9 = regs64_expr[9]
R10 = regs64_expr[10]
R11 = regs64_expr[11]
R12 = regs64_expr[12]
R13 = regs64_expr[13]
R14 = regs64_expr[14]
R15 = regs64_expr[15]


reg_zf = 'zf'
reg_nf = 'nf'
reg_pf = 'pf'
reg_of = 'of'
reg_cf = 'cf'
reg_tf = 'tf'
reg_if = 'i_f'
reg_df = 'df'
reg_af = 'af'
reg_iopl = 'iopl_f'
reg_nt = 'nt'
reg_rf = 'rf'
reg_vm = 'vm'
reg_ac = 'ac'
reg_vif = 'vif'
reg_vip = 'vip'
reg_id = 'i_d'


reg_es = "ES"
reg_cs = "CS"
reg_ss = "SS"
reg_ds = "DS"
reg_fs = "FS"
reg_gs = "GS"

reg_dr0 = 'DR0'
reg_dr1 = 'DR1'
reg_dr2 = 'DR2'
reg_dr3 = 'DR3'
reg_dr4 = 'DR4'
reg_dr5 = 'DR5'
reg_dr6 = 'DR6'
reg_dr7 = 'DR7'

reg_cr0 = 'CR0'
reg_cr1 = 'CR1'
reg_cr2 = 'CR2'
reg_cr3 = 'CR3'
reg_cr4 = 'CR4'
reg_cr5 = 'CR5'
reg_cr6 = 'CR6'
reg_cr7 = 'CR7'

reg_mm0 = 'MM0'
reg_mm1 = 'MM1'
reg_mm2 = 'MM2'
reg_mm3 = 'MM3'
reg_mm4 = 'MM4'
reg_mm5 = 'MM5'
reg_mm6 = 'MM6'
reg_mm7 = 'MM7'

reg_tsc = "tsc"

reg_float_c0 = 'float_c0'
reg_float_c1 = 'float_c1'
reg_float_c2 = 'float_c2'
reg_float_c3 = 'float_c3'
reg_float_stack_ptr = "float_stack_ptr"
reg_float_control = 'reg_float_control'
reg_float_eip = 'reg_float_eip'
reg_float_cs = 'reg_float_cs'
reg_float_address = 'reg_float_address'
reg_float_ds = 'reg_float_ds'


dr0 = ExprId(reg_dr0, 32)
dr1 = ExprId(reg_dr1, 32)
dr2 = ExprId(reg_dr2, 32)
dr3 = ExprId(reg_dr3, 32)
dr4 = ExprId(reg_dr4, 32)
dr5 = ExprId(reg_dr5, 32)
dr6 = ExprId(reg_dr6, 32)
dr7 = ExprId(reg_dr7, 32)

cr0 = ExprId(reg_cr0, 32)
cr1 = ExprId(reg_cr1, 32)
cr2 = ExprId(reg_cr2, 32)
cr3 = ExprId(reg_cr3, 32)
cr4 = ExprId(reg_cr4, 32)
cr5 = ExprId(reg_cr5, 32)
cr6 = ExprId(reg_cr6, 32)
cr7 = ExprId(reg_cr7, 32)

mm0 = ExprId(reg_mm0, 64)
mm1 = ExprId(reg_mm1, 64)
mm2 = ExprId(reg_mm2, 64)
mm3 = ExprId(reg_mm3, 64)
mm4 = ExprId(reg_mm4, 64)
mm5 = ExprId(reg_mm5, 64)
mm6 = ExprId(reg_mm6, 64)
mm7 = ExprId(reg_mm7, 64)

XMM0 = regs_xmm_expr[0]
XMM1 = regs_xmm_expr[1]
XMM2 = regs_xmm_expr[2]
XMM3 = regs_xmm_expr[3]
XMM4 = regs_xmm_expr[4]
XMM5 = regs_xmm_expr[5]
XMM6 = regs_xmm_expr[6]
XMM7 = regs_xmm_expr[7]
XMM8 = regs_xmm_expr[8]
XMM9 = regs_xmm_expr[9]
XMM10 = regs_xmm_expr[10]
XMM11 = regs_xmm_expr[11]
XMM12 = regs_xmm_expr[12]
XMM13 = regs_xmm_expr[13]
XMM14 = regs_xmm_expr[14]
XMM15 = regs_xmm_expr[15]

# tmp1= ExprId(reg_tmp1)
zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
pf = ExprId(reg_pf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)
tf = ExprId(reg_tf, size=1)
i_f = ExprId(reg_if, size=1)
df = ExprId(reg_df, size=1)
af = ExprId(reg_af, size=1)
iopl = ExprId(reg_iopl, size=2)
nt = ExprId(reg_nt, size=1)
rf = ExprId(reg_rf, size=1)
vm = ExprId(reg_vm, size=1)
ac = ExprId(reg_ac, size=1)
vif = ExprId(reg_vif, size=1)
vip = ExprId(reg_vip, size=1)
i_d = ExprId(reg_id, size=1)

ES = ExprId(reg_es, size=16)
CS = ExprId(reg_cs, size=16)
SS = ExprId(reg_ss, size=16)
DS = ExprId(reg_ds, size=16)
FS = ExprId(reg_fs, size=16)
GS = ExprId(reg_gs, size=16)

tsc = ExprId(reg_tsc, size=64)

float_c0 = ExprId(reg_float_c0, size=1)
float_c1 = ExprId(reg_float_c1, size=1)
float_c2 = ExprId(reg_float_c2, size=1)
float_c3 = ExprId(reg_float_c3, size=1)
float_stack_ptr = ExprId(reg_float_stack_ptr, size=3)
float_control = ExprId(reg_float_control, 16)
float_eip = ExprId(reg_float_eip, 32)
float_cs = ExprId(reg_float_cs, size=16)
float_address = ExprId(reg_float_address, 32)
float_ds = ExprId(reg_float_ds, size=16)

float_st0 = ExprId("float_st0", 64)
float_st1 = ExprId("float_st1", 64)
float_st2 = ExprId("float_st2", 64)
float_st3 = ExprId("float_st3", 64)
float_st4 = ExprId("float_st4", 64)
float_st5 = ExprId("float_st5", 64)
float_st6 = ExprId("float_st6", 64)
float_st7 = ExprId("float_st7", 64)


float_list = [float_st0, float_st1, float_st2, float_st3,
              float_st4, float_st5, float_st6, float_st7]

float_replace = {fltregs32_expr[i]: float_list[i] for i in range(8)}
float_replace[r_st_all.expr[0]] = float_st0


EAX_init = ExprId('EAX_init', 32)
EBX_init = ExprId('EBX_init', 32)
ECX_init = ExprId('ECX_init', 32)
EDX_init = ExprId('EDX_init', 32)
ESI_init = ExprId('ESI_init', 32)
EDI_init = ExprId('EDI_init', 32)
ESP_init = ExprId('ESP_init', 32)
EBP_init = ExprId('EBP_init', 32)


RAX_init = ExprId('RAX_init', 64)
RBX_init = ExprId('RBX_init', 64)
RCX_init = ExprId('RCX_init', 64)
RDX_init = ExprId('RDX_init', 64)
RSI_init = ExprId('RSI_init', 64)
RDI_init = ExprId('RDI_init', 64)
RSP_init = ExprId('RSP_init', 64)
RBP_init = ExprId('RBP_init', 64)


all_regs_ids = [
    AL, CL, DL, BL, AH, CH, DH, BH,
    R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B,
    SPL, BPL, SIL, DIL,
    AX, CX, DX, BX, SP, BP, SI, DI,
    R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W,
    IP,
    EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
    R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D,
    EIP,

    RAX, RBX, RCX, RDX, RSP, RBP, RIP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    zf, nf, pf, of, cf, af, df,
    tf, i_f, iopl, nt, rf, vm, ac, vif, vip, i_d,
    float_control, float_eip, float_cs, float_address, float_ds,
    tsc,
    ES, CS, SS, DS, FS, GS,
    float_st0, float_st1, float_st2, float_st3,
    float_st4, float_st5, float_st6, float_st7,
    float_c0, float_c1, float_c2, float_c3,
    cr0, cr3,
    dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7,
    float_stack_ptr,
    mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7,

    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,


    exception_flags, interrupt_num,
] + fltregs32_expr

all_regs_ids_no_alias = [
    RAX, RBX, RCX, RDX, RSP, RBP, RIP, RSI, RDI,
    R8, R9, R10, R11, R12, R13, R14, R15,
    zf, nf, pf, of, cf, af, df,
    tf, i_f, iopl, nt, rf, vm, ac, vif, vip, i_d,
    float_control, float_eip, float_cs, float_address, float_ds,
    tsc,
    ES, CS, SS, DS, FS, GS,
    float_st0, float_st1, float_st2, float_st3,
    float_st4, float_st5, float_st6, float_st7,
    float_c0, float_c1, float_c2, float_c3,
    cr0, cr3,
    dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7,
    float_stack_ptr,
    mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,


    exception_flags, interrupt_num,
] + fltregs32_expr

attrib_to_regs = {
    16: regs16_expr + all_regs_ids_no_alias[all_regs_ids_no_alias.index(zf):] + [IP],
    32: regs32_expr + all_regs_ids_no_alias[all_regs_ids_no_alias.index(zf):] + [EIP],
    64: all_regs_ids_no_alias,
}

all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [ExprId("%s_init" % x.name, x.size) for x in all_regs_ids]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

regs_flt_expr = [float_st0, float_st1, float_st2, float_st3,
                 float_st4, float_st5, float_st6, float_st7,
                 ]

mRAX = {16: AX, 32: EAX, 64: RAX}
mRBX = {16: BX, 32: EBX, 64: RBX}
mRCX = {16: CX, 32: ECX, 64: RCX}
mRDX = {16: DX, 32: EDX, 64: RDX}
mRSI = {16: SI, 32: ESI, 64: RSI}
mRDI = {16: DI, 32: EDI, 64: RDI}
mRBP = {16: BP, 32: EBP, 64: RBP}
mRSP = {16: SP, 32: ESP, 64: RSP}
mRIP = {16: IP, 32: EIP, 64: RIP}
