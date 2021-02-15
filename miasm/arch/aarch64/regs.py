#-*- coding:utf-8 -*-

from builtins import range
from miasm.expression.expression import ExprId
from miasm.core.cpu import gen_reg, gen_regs, reg_info

exception_flags = ExprId('exception_flags', 32)
interrupt_num = ExprId('interrupt_num', 32)


gpregs32_str = ["W%d" % i for i in range(0x1f)] + ["WSP"]
gpregs32_expr, gpregs32_init, gpregs32_info = gen_regs(
    gpregs32_str, globals(), 32)

gpregs64_str = ["X%d" % i for i in range(0x1E)] + ["LR", "SP"]
gpregs64_expr, gpregs64_init, gpregs64_info = gen_regs(
    gpregs64_str, globals(), 64)


gpregsz32_str = ["W%d" % i for i in range(0x1f)] + ["WZR"]
gpregsz32_expr, gpregsz32_init, gpregsz32_info = gen_regs(
    gpregsz32_str, globals(), 32)

gpregsz64_str = ["X%d" % i for i in range(0x1e)] + ["LR", "XZR"]
gpregsz64_expr, gpregsz64_init, gpregsz64_info = gen_regs(
    gpregsz64_str, globals(), 64)

gpregs32_nosp, _, gpregs32_nosp_info = gen_regs(gpregs32_str[:-1], globals(), 32)
gpregs64_nosp, _, gpregs64_nosp_info = gen_regs(gpregs64_str[:-1], globals(), 64)


cr_str = ["c%d" % i for i in range(0x10)]
cr_expr, cr_init, cr_info = gen_regs(cr_str, globals(), 32)


simd08_str = ["B%d" % i for i in range(0x20)]
simd08_expr, simd08_init, simd08_info = gen_regs(simd08_str, globals(), 8)

simd16_str = ["H%d" % i for i in range(0x20)]
simd16_expr, simd16_init, simd16_info = gen_regs(simd16_str, globals(), 16)

simd32_str = ["S%d" % i for i in range(0x20)]
simd32_expr, simd32_init, simd32_info = gen_regs(simd32_str, globals(), 32)

simd64_str = ["D%d" % i for i in range(0x20)]
simd64_expr, simd64_init, simd64_info = gen_regs(simd64_str, globals(), 64)

simd128_str = ["Q%d" % i for i in range(0x20)]
simd128_expr, simd128_init, simd128_info = gen_regs(
    simd128_str, globals(), 128)

sysregs_str = ['ACTLR_EL1', 'ACTLR_EL2', 'ACTLR_EL3', 'AFSR0_EL1',
    'AFSR0_EL2', 'AFSR0_EL3', 'AFSR1_EL1', 'AFSR1_EL2', 'AFSR1_EL3',
    'AIDR_EL1', 'AMAIR_EL1', 'AMAIR_EL2', 'AMAIR_EL3', 'AMCFGR_EL0',
    'AMCG1IDR_EL0', 'AMCGCR_EL0', 'AMCNTENCLR0_EL0', 'AMCNTENCLR1_EL0',
    'AMCNTENSET0_EL0', 'AMCNTENSET1_EL0', 'AMCR_EL0'] + \
    ['AMEVCNTR%d%d_EL0' % (i, j)     for i in range(2) for j in range(16)] + \
    ['AMEVCNTVOFF%d%d_EL2' % (i, j)  for i in range(2) for j in range(16)] + \
    ['AMEVTYPER%d%d_EL0' % (i, j)    for i in range(2) for j in range(16)] + \
    ['AMUSERENR_EL0', 'APDAKeyHi_EL1', 'APDAKeyLo_EL1', 'APDBKeyHi_EL1',
    'APDBKeyLo_EL1', 'APGAKeyHi_EL1', 'APGAKeyLo_EL1', 'APIAKeyHi_EL1',
    'APIAKeyLo_EL1', 'APIBKeyHi_EL1', 'APIBKeyLo_EL1', 'CCSIDR2_EL1',
    'CCSIDR_EL1', 'CLIDR_EL1', 'CNTFRQ_EL0', 'CNTHCTL_EL2',
    'CNTHPS_CTL_EL2', 'CNTHPS_CVAL_EL2', 'CNTHPS_TVAL_EL2', 'CNTHP_CTL_EL2',
    'CNTHP_CVAL_EL2', 'CNTHP_TVAL_EL2', 'CNTHVS_CTL_EL2', 'CNTHVS_CVAL_EL2',
    'CNTHVS_TVAL_EL2', 'CNTHV_CTL_EL2', 'CNTHV_CVAL_EL2', 'CNTHV_TVAL_EL2',
    'CNTKCTL_EL1', 'CNTPCTSS_EL0', 'CNTPCT_EL0', 'CNTPOFF_EL2',
    'CNTPS_CTL_EL1', 'CNTPS_CVAL_EL1', 'CNTPS_TVAL_EL1', 'CNTP_CTL_EL0',
    'CNTP_CVAL_EL0', 'CNTP_TVAL_EL0', 'CNTVCTSS_EL0', 'CNTVCT_EL0',
    'CNTVOFF_EL2', 'CNTV_CTL_EL0', 'CNTV_CVAL_EL0', 'CNTV_TVAL_EL0',
    'CONTEXTIDR_EL1', 'CONTEXTIDR_EL2', 'CPACR_EL1', 'CPTR_EL2',
    'CPTR_EL3', 'CSSELR_EL1', 'CTR_EL0', 'DACR32_EL2', 'DBGAUTHSTATUS_EL1'] + \
    ['DBGBCR%d_EL1' % i for i in range(16)] + \
    ['DBGBVR%d_EL1' % i for i in range(16)] + \
    ['DBGCLAIMCLR_EL1', 'DBGCLAIMSET_EL1', 'DBGDTRRX_EL0', 'DBGDTRTX_EL0',
    'DBGDTR_EL0', 'DBGPRCR_EL1', 'DBGVCR32_EL2'] + \
    ['DBGWCR%d_EL1' % i for i in range(16)] + \
    ['DBGWVR%d_EL1' % i for i in range(16)] + \
    ['DCZID_EL0', 'DISR_EL1', 'ELR_EL1', 'ERRIDR_EL1',
    'ERRSELR_EL1','ERXADDR_EL1', 'ERXCTLR_EL1', 'ERXFR_EL1',
    'ERXMISC0_EL1', 'ERXMISC1_EL1', 'ERXMISC2_EL1', 'ERXMISC3_EL1',
    'ERXPFGCDN_EL1', 'ERXPFGCTL_EL1', 'ERXPFGF_EL1', 'ERXSTATUS_EL1',
    'ESR_EL1', 'ESR_EL2', 'ESR_EL3', 'FAR_EL1',
    'FAR_EL2', 'FAR_EL3', 'FPEXC32_EL2', 'HACR_EL2',
    'HAFGRTR_EL2', 'HCR_EL2', 'HDFGRTR_EL2', 'HDFGWTR_EL2',
    'HFGITR_EL2', 'HFGRTR_EL2', 'HFGWTR_EL2', 'HPFAR_EL2',
    'HSTR_EL2', 'ICC_AP0R0_EL1', 'ICC_AP0R1_EL1', 'ICC_AP0R2_EL1', 
    'ICC_AP0R3_EL1', 'ICC_AP1R0_EL1', 'ICC_AP1R1_EL1', 'ICC_AP1R2_EL1',
    'ICC_AP1R3_EL1', 'ICC_ASGI1R_EL1', 'ICC_BPR0_EL1', 'ICC_BPR1_EL1',
    'ICC_CTLR_EL1', 'ICC_CTLR_EL3', 'ICC_DIR_EL1', 'ICC_EOIR0_EL1',
    'ICC_EOIR1_EL1', 'ICC_HPPIR0_EL1', 'ICC_HPPIR1_EL1', 'ICC_IAR0_EL1',
    'ICC_IAR1_EL1', 'ICC_IGRPEN0_EL1', 'ICC_IGRPEN1_EL1', 'ICC_IGRPEN1_EL3',
    'ICC_PMR_EL1', 'ICC_RPR_EL1', 'ICC_SGI0R_EL1', 'ICC_SGI1R_EL1',
    'ICC_SRE_EL1', 'ICC_SRE_EL2', 'ICC_SRE_EL3', 'ICH_AP0R0_EL2',
    'ICH_AP0R1_EL2', 'ICH_AP0R2_EL2', 'ICH_AP0R3_EL2', 'ICH_AP1R0_EL2',
    'ICH_AP1R1_EL2', 'ICH_AP1R2_EL2', 'ICH_AP1R3_EL2', 'ICH_EISR_EL2',
    'ICH_ELRSR_EL2', 'ICH_HCR_EL2'] + \
    ['ICH_LR%d_EL2' % i for i in range(16)] + \
    ['ICH_MISR_EL2', 'ICH_VMCR_EL2', 'ICH_VTR_EL2', 'ID_AA64AFR0_EL1',
    'ID_AA64AFR1_EL1', 'ID_AA64DFR0_EL1', 'ID_AA64DFR1_EL1', 'ID_AA64ISAR0_EL1',
    'ID_AA64ISAR1_EL1', 'ID_AA64MMFR0_EL1','ID_AA64MMFR1_EL1', 'ID_AA64MMFR2_EL1',
    'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1', 'ID_AA64ZFR0_EL1', 'ID_AFR0_EL1',
    'ID_DFR0_EL1', 'ID_ISAR0_EL1', 'ID_ISAR1_EL1', 'ID_ISAR2_EL1',
    'ID_ISAR3_EL1', 'ID_ISAR4_EL1', 'ID_ISAR5_EL1', 'ID_MMFR0_EL1',
    'ID_MMFR1_EL1', 'ID_MMFR2_EL1', 'ID_MMFR3_EL1', 'ID_MMFR4_EL1',
    'ID_MMFR5_EL1', 'ID_PFR0_EL1', 'ID_PFR1_EL1', 'ID_PFR2_EL1',
    'IFSR32_EL2', 'ISR_EL1', 'LORC_EL1', 'LOREA_EL1',
    'LORID_EL1', 'LORN_EL1', 'LORSA_EL1', 'MAIR_EL1',
    'MAIR_EL2', 'MAIR_EL3', 'MDCCINT_EL1', 'MDCCSR_EL0',
    'MDCR_EL2', 'MDCR_EL3', 'MDRAR_EL1', 'MDSCR_EL1',
    'MIDR_EL1', 'MPIDR_EL1', 'MVFR0_EL1', 'MVFR1_EL1',
    'MVFR2_EL1', 'OSDLR_EL1', 'OSDTRRX_EL1', 'OSDTRTX_EL1',
    'OSECCR_EL1', 'OSLAR_EL1', 'OSLSR_EL1', 'PAR_EL1',
    'PMBIDR_EL1', 'PMBLIMITR_EL1', 'PMBPTR_EL1', 'PMBSR_EL1',
    'PMCCFILTR_EL0', 'PMCCNTR_EL0', 'PMCEID0_EL0', 'PMCEID1_EL0',
    'PMCNTENCLR_EL0', 'PMCNTENSET_EL0', 'PMCR_EL0'] + \
    ['PMEVCNTR%d_EL0' % i for i in range(32)] + \
    ['PMEVTYPER%d_EL0' % i for i in range(32)] + \
    ['PMINTENCLR_EL1', 'PMINTENSET_EL1', 'PMMIR_EL1', 'PMOVSCLR_EL0',
    'PMOVSSET_EL0', 'PMSCR_EL1', 'PMSCR_EL2', 'PMSELR_EL0',
    'PMSEVFR_EL1', 'PMSFCR_EL1', 'PMSICR_EL1', 'PMSIDR_EL1',
    'PMSIRR_EL1', 'PMSLATFR_EL1', 'PMSWINC_EL0', 'PMUSERENR_EL0',
    'PMXEVCNTR_EL0', 'PMXEVTYPER_EL0', 'REVIDR_EL1', 'RMR_EL1',
    'RMR_EL2', 'RMR_EL3', 'RVBAR_EL1', 'RVBAR_EL2',
    'RVBAR_EL3', 'SCRLR_EL1', 'SCR_EL3', 'SCTLR_EL1',
    'SCTLR_EL2', 'SCTLR_EL3', 'SDER32_EL2', 'SDER32_EL3',
    'SPSR_EL1', 'TCR_EL1', 'TCR_EL2', 'TCR_EL3',
    'TPIDRRO_EL0', 'TPIDR_EL0', 'TPIDR_EL1', 'TPIDR_EL2',
    'TPIDR_EL3', 'TRFCR_EL1', 'TRFCR_EL2', 'TTBR0_EL1',
    'TTBR0_EL2', 'TTBR0_EL3', 'TTBR1_EL1', 'VBAR_EL1',
    'VBAR_EL2', 'VBAR_EL3', 'VDISR_EL2', 'VMPIDR_EL2',
    'VNCR_EL2', 'VPIDR_EL2', 'VSESR_EL2', 'VSTCR_EL2',
    'VSTTBR_EL2', 'VTCR_EL2', 'VTTBR_EL2', 'ZCR_EL1',
    'ZCR_EL2', 'ZCR_EL3', 'ELR_EL2', 'ELR_EL3', 
    'FPCR', 'FPSR', 'SP_EL0', 'SP_EL1', 
    'SP_EL2', 'SPSR_abt', 'SPSR_EL2',
    'SPSR_EL3', 'SPSR_fiq', 'SPSR_irq', 'SPSR_und',
    'DLR_EL0', 'DSPSR_EL0']
sysregs_expr, sysregs_init, sysregs_info = gen_regs(sysregs_str, globals(), 64)

PC, _ = gen_reg("PC", 64)
WZR, _ = gen_reg("WZR", 32)
XZR, _ = gen_reg("XZR", 64)

PC_init = ExprId("PC_init", 64)
WZR_init = ExprId("WZR_init", 32)
XZR_init = ExprId("XZR_init", 64)

reg_zf = 'zf'
reg_nf = 'nf'
reg_of = 'of'
reg_cf = 'cf'

reg_df = 'df'
reg_af = 'af'
reg_iff = 'if'
reg_ff = 'ff'

reg_cur_el = 'cur_el'
reg_dit = 'dit'
reg_pan = 'pan'
reg_spsel = 'spsel'
reg_ssbs = 'ssbs'
reg_tco = 'tco'
reg_uao = 'uao'

zf = ExprId(reg_zf, size=1)
nf = ExprId(reg_nf, size=1)
of = ExprId(reg_of, size=1)
cf = ExprId(reg_cf, size=1)

df = ExprId(reg_df, size=1)
af = ExprId(reg_af, size=1)
iff = ExprId(reg_iff, size=1)
ff = ExprId(reg_ff, size=1)

cur_el = ExprId(reg_cur_el, size=2)
dit = ExprId(reg_dit, size=1)
pan = ExprId(reg_pan, size=1)
spsel = ExprId(reg_spsel, size=1)
ssbs = ExprId(reg_ssbs, size=1)
tco = ExprId(reg_tco, size=1)
uao = ExprId(reg_uao, size=1)


zf_init = ExprId("zf_init", size=1)
nf_init = ExprId("nf_init", size=1)
of_init = ExprId("of_init", size=1)
cf_init = ExprId("cf_init", size=1)
df_init = ExprId("df_init", size=1)
af_init = ExprId("af_init", size=1)
iff_init = ExprId("if_init", size=1)
ff_init = ExprId("ff_init", size=1)
cur_el_init = ExprId("cur_el_init", size=2)
dit_init = ExprId("dit_init", size=1)
pan_init = ExprId("pan_init", size=1)
spsel_init = ExprId("spsel_init", size=1)
ssbs_init = ExprId("ssbs_init", size=1)
tco_init = ExprId("tco_init", size=1)
uao_init = ExprId("uao_init", size=1)


all_regs_ids = [
    B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16,
    B17, B18, B19, B20, B21, B22, B23, B24, B25, B26, B27, B28, B29, B30, B31,

    H0, H1, H2, H3, H4, H5, H6, H7, H8, H9, H10, H11, H12, H13, H14, H15, H16,
    H17, H18, H19, H20, H21, H22, H23, H24, H25, H26, H27, H28, H29, H30, H31,

    S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15, S16,
    S17, S18, S19, S20, S21, S22, S23, S24, S25, S26, S27, S28, S29, S30, S31,

    D0, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12, D13, D14, D15, D16,
    D17, D18, D19, D20, D21, D22, D23, D24, D25, D26, D27, D28, D29, D30, D31,

    Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16,
    Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,

    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16,
    W17, W18, W19, W20, W21, W22, W23, W24, W25, W26, W27, W28, W29, W30, WSP,

    X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16,
    X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, LR, SP,

    exception_flags,
    interrupt_num,
    PC,
    WZR,
    XZR,
    zf, nf, of, cf,
    df, af, iff, ff,
    cur_el, dit, pan, spsel, ssbs, tco, uao,
] + sysregs_expr 


all_regs_ids_no_alias = all_regs_ids

attrib_to_regs = {
    'l': all_regs_ids_no_alias,
    'b': all_regs_ids_no_alias,
}

all_regs_ids_byname = dict([(x.name, x) for x in all_regs_ids])

all_regs_ids_init = [ExprId("%s_init" % x.name, x.size) for x in all_regs_ids]

regs_init = {}
for i, r in enumerate(all_regs_ids):
    regs_init[r] = all_regs_ids_init[i]

regs_flt_expr = []
