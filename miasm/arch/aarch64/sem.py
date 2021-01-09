from builtins import range
from future.utils import viewitems

from miasm.expression.expression import ExprId, ExprInt, ExprLoc, ExprMem, \
    ExprCond, ExprCompose, ExprOp, ExprAssign
from miasm.ir.ir import Lifter, IRBlock, AssignBlock
from miasm.arch.aarch64.arch import mn_aarch64, conds_expr, replace_regs
from miasm.arch.aarch64.regs import *
from miasm.core.sembuilder import SemBuilder
from miasm.jitter.csts import EXCEPT_DIV_BY_ZERO, EXCEPT_INT_XX

# System register for ARM64-A 8.6
system_regs = {
    # op0 op1 crn crm op2
    (2, 0, 0, 0, 2): OSDTRRX_EL1,

    (2, 0, 0, 2, 0): MDCCINT_EL1,
    (2, 0, 0, 2, 2): MDSCR_EL1,

    (2, 0, 0, 3, 2): OSDTRTX_EL1,

    (2, 0, 0, 6, 2): OSECCR_EL1,

    (2, 0, 0, 0, 4): DBGBVR0_EL1,
    (2, 0, 0, 1, 4): DBGBVR1_EL1,
    (2, 0, 0, 2, 4): DBGBVR2_EL1,
    (2, 0, 0, 3, 4): DBGBVR3_EL1,
    (2, 0, 0, 4, 4): DBGBVR4_EL1,
    (2, 0, 0, 5, 4): DBGBVR5_EL1,
    (2, 0, 0, 6, 4): DBGBVR6_EL1,
    (2, 0, 0, 7, 4): DBGBVR7_EL1,
    (2, 0, 0, 8, 4): DBGBVR8_EL1,
    (2, 0, 0, 9, 4): DBGBVR9_EL1,
    (2, 0, 0, 10, 4): DBGBVR10_EL1,
    (2, 0, 0, 11, 4): DBGBVR11_EL1,
    (2, 0, 0, 12, 4): DBGBVR12_EL1,
    (2, 0, 0, 13, 4): DBGBVR13_EL1,
    (2, 0, 0, 14, 4): DBGBVR14_EL1,
    (2, 0, 0, 15, 4): DBGBVR15_EL1,

    (2, 0, 0, 0, 5): DBGBCR0_EL1,
    (2, 0, 0, 1, 5): DBGBCR1_EL1,
    (2, 0, 0, 2, 5): DBGBCR2_EL1,
    (2, 0, 0, 3, 5): DBGBCR3_EL1,
    (2, 0, 0, 4, 5): DBGBCR4_EL1,
    (2, 0, 0, 5, 5): DBGBCR5_EL1,
    (2, 0, 0, 6, 5): DBGBCR6_EL1,
    (2, 0, 0, 7, 5): DBGBCR7_EL1,
    (2, 0, 0, 8, 5): DBGBCR8_EL1,
    (2, 0, 0, 9, 5): DBGBCR9_EL1,
    (2, 0, 0, 10, 5): DBGBCR10_EL1,
    (2, 0, 0, 11, 5): DBGBCR11_EL1,
    (2, 0, 0, 12, 5): DBGBCR12_EL1,
    (2, 0, 0, 13, 5): DBGBCR13_EL1,
    (2, 0, 0, 14, 5): DBGBCR14_EL1,
    (2, 0, 0, 15, 5): DBGBCR15_EL1,

    (2, 0, 0, 0, 6): DBGWVR0_EL1,
    (2, 0, 0, 1, 6): DBGWVR1_EL1,
    (2, 0, 0, 2, 6): DBGWVR2_EL1,
    (2, 0, 0, 3, 6): DBGWVR3_EL1,
    (2, 0, 0, 4, 6): DBGWVR4_EL1,
    (2, 0, 0, 5, 6): DBGWVR5_EL1,
    (2, 0, 0, 6, 6): DBGWVR6_EL1,
    (2, 0, 0, 7, 6): DBGWVR7_EL1,
    (2, 0, 0, 8, 6): DBGWVR8_EL1,
    (2, 0, 0, 9, 6): DBGWVR9_EL1,
    (2, 0, 0, 10, 6): DBGWVR10_EL1,
    (2, 0, 0, 11, 6): DBGWVR11_EL1,
    (2, 0, 0, 12, 6): DBGWVR12_EL1,
    (2, 0, 0, 13, 6): DBGWVR13_EL1,
    (2, 0, 0, 14, 6): DBGWVR14_EL1,
    (2, 0, 0, 15, 6): DBGWVR15_EL1,

    (2, 0, 0, 0, 7): DBGWCR0_EL1,
    (2, 0, 0, 1, 7): DBGWCR1_EL1,
    (2, 0, 0, 2, 7): DBGWCR2_EL1,
    (2, 0, 0, 3, 7): DBGWCR3_EL1,
    (2, 0, 0, 4, 7): DBGWCR4_EL1,
    (2, 0, 0, 5, 7): DBGWCR5_EL1,
    (2, 0, 0, 6, 7): DBGWCR6_EL1,
    (2, 0, 0, 7, 7): DBGWCR7_EL1,
    (2, 0, 0, 8, 7): DBGWCR8_EL1,
    (2, 0, 0, 9, 7): DBGWCR9_EL1,
    (2, 0, 0, 10, 7): DBGWCR10_EL1,
    (2, 0, 0, 11, 7): DBGWCR11_EL1,
    (2, 0, 0, 12, 7): DBGWCR12_EL1,
    (2, 0, 0, 13, 7): DBGWCR13_EL1,
    (2, 0, 0, 14, 7): DBGWCR14_EL1,
    (2, 0, 0, 15, 7): DBGWCR15_EL1,

    (2, 0, 1, 0, 0): MDRAR_EL1,
    (2, 0, 1, 0, 4): OSLAR_EL1,

    (2, 0, 1, 1, 4): OSLSR_EL1,

    (2, 0, 1, 3, 4): OSDLR_EL1,

    (2, 0, 1, 4, 4): DBGPRCR_EL1,

    (2, 0, 7, 8, 6): DBGCLAIMSET_EL1,

    (2, 0, 7, 9, 6): DBGCLAIMCLR_EL1,

    (2, 0, 7, 14, 6): DBGAUTHSTATUS_EL1,

    (2, 3, 0, 1, 0): MDCCSR_EL0,

    (2, 3, 0, 4, 0): DBGDTR_EL0,

    (2, 3, 0, 5, 0): DBGDTRRX_EL0,
    (2, 3, 0, 5, 1): DBGDTRTX_EL0,

    (2, 4, 0, 7, 0): DBGVCR32_EL2,

    (3, 0, 0, 0, 0): MIDR_EL1,
    (3, 0, 0, 0, 5): MPIDR_EL1,
    (3, 0, 0, 0, 6): REVIDR_EL1,

    (3, 0, 0, 1, 0): ID_PFR0_EL1,
    (3, 0, 0, 1, 1): ID_PFR1_EL1,
    (3, 0, 0, 1, 2): ID_DFR0_EL1,
    (3, 0, 0, 1, 3): ID_AFR0_EL1,
    (3, 0, 0, 1, 4): ID_MMFR0_EL1,
    (3, 0, 0, 1, 5): ID_MMFR1_EL1,
    (3, 0, 0, 1, 6): ID_MMFR2_EL1,
    (3, 0, 0, 1, 7): ID_MMFR3_EL1,

    (3, 0, 0, 2, 0): ID_ISAR0_EL1,
    (3, 0, 0, 2, 1): ID_ISAR1_EL1,
    (3, 0, 0, 2, 2): ID_ISAR2_EL1,
    (3, 0, 0, 2, 3): ID_ISAR3_EL1,
    (3, 0, 0, 2, 4): ID_ISAR4_EL1,
    (3, 0, 0, 2, 5): ID_ISAR5_EL1,
    (3, 0, 0, 2, 6): ID_MMFR4_EL1,

    (3, 0, 0, 3, 0): MVFR0_EL1,
    (3, 0, 0, 3, 1): MVFR1_EL1,
    (3, 0, 0, 3, 2): MVFR2_EL1,
    (3, 0, 0, 3, 4): ID_PFR2_EL1,
    (3, 0, 0, 3, 6): ID_MMFR5_EL1,

    (3, 0, 0, 4, 0): ID_AA64PFR0_EL1,
    (3, 0, 0, 4, 1): ID_AA64PFR1_EL1,
    (3, 0, 0, 4, 4): ID_AA64ZFR0_EL1,

    (3, 0, 0, 5, 0): ID_AA64DFR0_EL1,
    (3, 0, 0, 5, 1): ID_AA64DFR1_EL1,
    (3, 0, 0, 5, 4): ID_AA64AFR0_EL1,
    (3, 0, 0, 5, 5): ID_AA64AFR1_EL1,

    (3, 0, 0, 6, 0): ID_AA64ISAR0_EL1,
    (3, 0, 0, 6, 1): ID_AA64ISAR1_EL1,

    (3, 0, 0, 7, 0): ID_AA64MMFR0_EL1,
    (3, 0, 0, 7, 1): ID_AA64MMFR1_EL1,
    (3, 0, 0, 7, 2): ID_AA64MMFR2_EL1,

    (3, 0, 1, 0, 0): SCRLR_EL1,
    (3, 0, 1, 0, 1): ACTLR_EL1,
    (3, 0, 1, 0, 2): CPACR_EL1,

    (3, 0, 1, 2, 0): ZCR_EL1,
    (3, 0, 1, 2, 1): TRFCR_EL1,

    (3, 0, 2, 0, 0): TTBR0_EL1,
    (3, 0, 2, 0, 1): TTBR1_EL1,
    (3, 0, 2, 0, 2): TCR_EL1,

    (3, 0, 2, 1, 0): APIAKeyLo_EL1,
    (3, 0, 2, 1, 1): APIAKeyHi_EL1,
    (3, 0, 2, 1, 2): APIBKeyLo_EL1,
    (3, 0, 2, 1, 3): APIBKeyHi_EL1,

    (3, 0, 2, 2, 0): APDAKeyLo_EL1,
    (3, 0, 2, 2, 1): APDAKeyHi_EL1,
    (3, 0, 2, 2, 2): APDBKeyLo_EL1,
    (3, 0, 2, 2, 3): APDBKeyHi_EL1,

    (3, 0, 2, 3, 0): APGAKeyLo_EL1,
    (3, 0, 2, 3, 1): APGAKeyHi_EL1,
    
    (3, 0, 4, 1, 0): SP_EL0,
    (3, 0, 4, 6, 0): ICC_PMR_EL1, # Alias ICV_PMR_EL1

    (3, 0, 5, 1, 0): AFSR0_EL1,
    (3, 0, 5, 1, 1): AFSR1_EL1,

    (3, 0, 5, 2, 0): ESR_EL1,

    (3, 0, 5, 3, 0): ERRIDR_EL1,
    (3, 0, 5, 3, 1): ERRSELR_EL1,

    (3, 0, 5, 4, 0): ERXFR_EL1,
    (3, 0, 5, 4, 1): ERXCTLR_EL1,
    (3, 0, 5, 4, 2): ERXSTATUS_EL1,
    (3, 0, 5, 4, 3): ERXADDR_EL1,
    (3, 0, 5, 4, 4): ERXPFGF_EL1,
    (3, 0, 5, 4, 5): ERXPFGCTL_EL1,
    (3, 0, 5, 4, 6): ERXPFGCDN_EL1,

    (3, 0, 5, 5, 0): ERXMISC0_EL1,
    (3, 0, 5, 5, 1): ERXMISC1_EL1,
    (3, 0, 5, 5, 2): ERXMISC2_EL1,
    (3, 0, 5, 5, 3): ERXMISC3_EL1,

    (3, 0, 6, 0, 0): FAR_EL1,

    (3, 0, 7, 4, 0): PAR_EL1,

    (3, 0, 9, 9, 0): PMSCR_EL1,
    (3, 0, 9, 9, 2): PMSICR_EL1,
    (3, 0, 9, 9, 3): PMSIRR_EL1,
    (3, 0, 9, 9, 4): PMSFCR_EL1,
    (3, 0, 9, 9, 5): PMSEVFR_EL1,
    (3, 0, 9, 9, 6): PMSLATFR_EL1,
    (3, 0, 9, 9, 7): PMSIDR_EL1,

    (3, 0, 9, 10, 0): PMBLIMITR_EL1,
    (3, 0, 9, 10, 1): PMBPTR_EL1,
    (3, 0, 9, 10, 3): PMBSR_EL1,
    (3, 0, 9, 10, 7): PMBIDR_EL1,

    (3, 0, 9, 14, 1): PMINTENSET_EL1,
    (3, 0, 9, 14, 2): PMINTENCLR_EL1,
    (3, 0, 9, 14, 6): PMMIR_EL1,

    (3, 0, 10, 2, 0): MAIR_EL1,

    (3, 0, 10, 3, 0): AMAIR_EL1,

    (3, 0, 10, 4, 0): LORSA_EL1,
    (3, 0, 10, 4, 1): LOREA_EL1,
    (3, 0, 10, 4, 2): LORN_EL1,
    (3, 0, 10, 4, 3): LORC_EL1,
    (3, 0, 10, 4, 7): LORID_EL1,

    (3, 0, 12, 0, 0): VBAR_EL1,
    (3, 0, 12, 0, 1): RVBAR_EL1,
    (3, 0, 12, 0, 2): RMR_EL1,

    (3, 0, 12, 1, 0): ISR_EL1,
    (3, 0, 12, 1, 1): DISR_EL1,

    (3, 0, 12, 8, 0): ICC_IAR0_EL1,   # Alias ICV_IAR0_EL1
    (3, 0, 12, 8, 1): ICC_EOIR0_EL1,  # Alias ICV_EOIR0_EL1
    (3, 0, 12, 8, 2): ICC_HPPIR0_EL1, # Alias ICV_HPPIR0_EL1
    (3, 0, 12, 8, 3): ICC_BPR0_EL1,   # Alias ICV_BPR0_EL1
    (3, 0, 12, 8, 4): ICC_AP0R0_EL1,  # Alias ICV_AP0R0_EL1
    (3, 0, 12, 8, 5): ICC_AP0R1_EL1,  # Alias ICV_AP0R1_EL1
    (3, 0, 12, 8, 6): ICC_AP0R2_EL1,  # Alias ICV_AP0R2_EL1
    (3, 0, 12, 8, 7): ICC_AP0R3_EL1,  # Alias ICV_AP0R3_EL1

    (3, 0, 12, 9, 0): ICC_AP1R0_EL1,  # Alias ICV_AP1R0_EL1
    (3, 0, 12, 9, 1): ICC_AP1R1_EL1,  # Alias ICV_AP1R1_EL1
    (3, 0, 12, 9, 2): ICC_AP1R2_EL1,  # Alias ICV_AP1R2_EL1
    (3, 0, 12, 9, 3): ICC_AP1R3_EL1,  # Alias ICV_AP1R3_EL1

    (3, 0, 12, 11, 1): ICC_DIR_EL1,  # Alias ICV_DIR_EL1
    (3, 0, 12, 11, 3): ICC_RPR_EL1,  # Alias ICV_RPR_EL1
    (3, 0, 12, 11, 5): ICC_SGI1R_EL1,
    (3, 0, 12, 11, 6): ICC_ASGI1R_EL1,
    (3, 0, 12, 11, 7): ICC_SGI0R_EL1,

    (3, 0, 12, 12, 0): ICC_IAR1_EL1,   # Alias ICV_IAR1_EL1
    (3, 0, 12, 12, 1): ICC_EOIR1_EL1,  # Alias ICV_EOIR1_EL1
    (3, 0, 12, 12, 2): ICC_HPPIR1_EL1, # Alias ICV_HPPIR1_EL1
    (3, 0, 12, 12, 3): ICC_BPR1_EL1,   # Alias ICV_BPR1_EL1
    (3, 0, 12, 12, 4): ICC_CTLR_EL1,   # Alias ICV_CTLR_EL1
    (3, 0, 12, 12, 5): ICC_SRE_EL1,
    (3, 0, 12, 12, 6): ICC_IGRPEN0_EL1,  # Alias ICV_IGRPEN0_EL1
    (3, 0, 12, 12, 7): ICC_IGRPEN1_EL1,  # Alias ICV_IGRPEN1_EL1

    (3, 0, 13, 0, 1): CONTEXTIDR_EL1,
    (3, 0, 13, 0, 4): TPIDR_EL1,

    (3, 0, 14, 1, 0): CNTKCTL_EL1,

    (3, 1, 0, 0, 0): CCSIDR_EL1,
    (3, 1, 0, 0, 1): CLIDR_EL1,
    (3, 1, 0, 0, 2): CCSIDR2_EL1,
    (3, 1, 0, 0, 7): AIDR_EL1,

    (3, 2, 0, 0, 0): CSSELR_EL1,
    (3, 0, 0, 0, 1): CTR_EL0,

    (3, 3, 0, 0, 7): DCZID_EL0,
    
    (3, 3, 4, 4, 0): FPCR,
    (3, 3, 4, 4, 1): FPSR,

    (3, 3, 4, 5, 0): DSPSR_EL0,
    (3, 3, 4, 5, 1): DLR_EL0,

    (3, 4, 4, 0, 0): SPSR_EL2,
    (3, 4 ,4, 0, 1): ELR_EL2,

    (3, 4, 4, 1, 0): SP_EL1,

    (3, 4, 4, 3, 0): SPSR_irq,
    (3, 4, 4, 3, 1): SPSR_abt,
    (3, 4, 4, 3, 2): SPSR_und,
    (3, 4, 4, 3, 3): SPSR_fiq,

    (3, 3, 9, 12, 0): PMCR_EL0,
    (3, 3, 9, 12, 1): PMCNTENSET_EL0,
    (3, 3, 9, 12, 2): PMCNTENCLR_EL0,
    (3, 3, 9, 12, 3): PMOVSCLR_EL0,
    (3, 3, 9, 12, 4): PMSWINC_EL0,
    (3, 3, 9, 12, 5): PMSELR_EL0,
    (3, 3, 9, 12, 6): PMCEID0_EL0,
    (3, 3, 9, 12, 7): PMCEID1_EL0,

    (3, 3, 9, 13, 0): PMCCNTR_EL0,
    (3, 3, 9, 13, 1): PMXEVTYPER_EL0,
    (3, 3, 9, 13, 2): PMXEVCNTR_EL0,

    (3, 3, 9, 14, 0): PMUSERENR_EL0,
    (3, 3, 9, 14, 3): PMOVSSET_EL0,

    (3, 3, 13, 0, 2): TPIDR_EL0,
    (3, 3, 13, 0, 3): TPIDRRO_EL0,

    (3, 3, 13, 2, 0): AMCR_EL0,
    (3, 3, 13, 2, 1): AMCFGR_EL0,
    (3, 3, 13, 2, 2): AMCGCR_EL0,
    (3, 3, 13, 2, 3): AMUSERENR_EL0,
    (3, 3, 13, 2, 4): AMCNTENCLR0_EL0,
    (3, 3, 13, 2, 5): AMCNTENSET0_EL0,
    (3, 3, 13, 2, 6): AMCG1IDR_EL0,

    (3, 3, 13, 3, 0): AMCNTENCLR1_EL0,
    (3, 3, 13, 3, 1): AMCNTENSET1_EL0,

    (3, 3, 13, 4, 0): AMEVCNTR00_EL0,
    (3, 3, 13, 4, 1): AMEVCNTR01_EL0,
    (3, 3, 13, 4, 2): AMEVCNTR02_EL0,
    (3, 3, 13, 4, 3): AMEVCNTR03_EL0,
    (3, 3, 13, 4, 4): AMEVCNTR04_EL0,
    (3, 3, 13, 4, 5): AMEVCNTR05_EL0,
    (3, 3, 13, 4, 6): AMEVCNTR06_EL0,
    (3, 3, 13, 4, 7): AMEVCNTR07_EL0,

    (3, 3, 13, 5, 0): AMEVCNTR08_EL0,
    (3, 3, 13, 5, 1): AMEVCNTR09_EL0,
    (3, 3, 13, 5, 2): AMEVCNTR010_EL0,
    (3, 3, 13, 5, 3): AMEVCNTR011_EL0,
    (3, 3, 13, 5, 4): AMEVCNTR012_EL0,
    (3, 3, 13, 5, 5): AMEVCNTR013_EL0,
    (3, 3, 13, 5, 6): AMEVCNTR014_EL0,
    (3, 3, 13, 5, 7): AMEVCNTR015_EL0,

    (3, 3, 13, 6, 0): AMEVTYPER00_EL0,
    (3, 3, 13, 6, 1): AMEVTYPER01_EL0,
    (3, 3, 13, 6, 2): AMEVTYPER02_EL0,
    (3, 3, 13, 6, 3): AMEVTYPER03_EL0,
    (3, 3, 13, 6, 4): AMEVTYPER04_EL0,
    (3, 3, 13, 6, 5): AMEVTYPER05_EL0,
    (3, 3, 13, 6, 6): AMEVTYPER06_EL0,
    (3, 3, 13, 6, 7): AMEVTYPER07_EL0,

    (3, 3, 13, 7, 0): AMEVTYPER08_EL0,
    (3, 3, 13, 7, 1): AMEVTYPER09_EL0,
    (3, 3, 13, 7, 2): AMEVTYPER010_EL0,
    (3, 3, 13, 7, 3): AMEVTYPER011_EL0,
    (3, 3, 13, 7, 4): AMEVTYPER012_EL0,
    (3, 3, 13, 7, 5): AMEVTYPER013_EL0,
    (3, 3, 13, 7, 6): AMEVTYPER014_EL0,
    (3, 3, 13, 7, 7): AMEVTYPER015_EL0,

    (3, 3, 13, 12, 0): AMEVCNTR10_EL0,
    (3, 3, 13, 12, 1): AMEVCNTR11_EL0,
    (3, 3, 13, 12, 2): AMEVCNTR12_EL0,
    (3, 3, 13, 12, 3): AMEVCNTR13_EL0,
    (3, 3, 13, 12, 4): AMEVCNTR14_EL0,
    (3, 3, 13, 12, 5): AMEVCNTR15_EL0,
    (3, 3, 13, 12, 6): AMEVCNTR16_EL0,
    (3, 3, 13, 12, 7): AMEVCNTR17_EL0,

    (3, 3, 13, 13, 0): AMEVCNTR18_EL0,
    (3, 3, 13, 13, 1): AMEVCNTR19_EL0,
    (3, 3, 13, 13, 2): AMEVCNTR110_EL0,
    (3, 3, 13, 13, 3): AMEVCNTR111_EL0,
    (3, 3, 13, 13, 4): AMEVCNTR112_EL0,
    (3, 3, 13, 13, 5): AMEVCNTR113_EL0,
    (3, 3, 13, 13, 6): AMEVCNTR114_EL0,
    (3, 3, 13, 13, 7): AMEVCNTR115_EL0,

    (3, 3, 13, 14, 0): AMEVTYPER10_EL0,
    (3, 3, 13, 14, 1): AMEVTYPER11_EL0,
    (3, 3, 13, 14, 2): AMEVTYPER12_EL0,
    (3, 3, 13, 14, 3): AMEVTYPER13_EL0,
    (3, 3, 13, 14, 4): AMEVTYPER14_EL0,
    (3, 3, 13, 14, 5): AMEVTYPER15_EL0,
    (3, 3, 13, 14, 6): AMEVTYPER16_EL0,
    (3, 3, 13, 14, 7): AMEVTYPER17_EL0,

    (3, 3, 13, 15, 0): AMEVTYPER18_EL0,
    (3, 3, 13, 15, 1): AMEVTYPER19_EL0,
    (3, 3, 13, 15, 2): AMEVTYPER110_EL0,
    (3, 3, 13, 15, 3): AMEVTYPER111_EL0,
    (3, 3, 13, 15, 4): AMEVTYPER112_EL0,
    (3, 3, 13, 15, 5): AMEVTYPER113_EL0,
    (3, 3, 13, 15, 6): AMEVTYPER114_EL0,
    (3, 3, 13, 15, 7): AMEVTYPER115_EL0,

    (3, 3, 14, 0, 0): CNTFRQ_EL0,
    (3, 3, 14, 0, 1): CNTPCT_EL0,
    (3, 3, 14, 0, 2): CNTVCT_EL0,
    (3, 3, 14, 0, 5): CNTPCTSS_EL0,
    (3, 3, 14, 0, 6): CNTVCTSS_EL0,

    (3, 3, 14, 2, 0): CNTP_TVAL_EL0,
    (3, 3, 14, 2, 1): CNTP_CTL_EL0,
    (3, 3, 14, 2, 2): CNTP_CVAL_EL0,

    (3, 3, 14, 3, 0): CNTV_TVAL_EL0,
    (3, 3, 14, 3, 1): CNTV_CTL_EL0,
    (3, 3, 14, 3, 2): CNTV_CVAL_EL0,

    (3, 3, 14, 8, 0): PMEVCNTR0_EL0,
    (3, 3, 14, 8, 1): PMEVCNTR1_EL0,
    (3, 3, 14, 8, 2): PMEVCNTR2_EL0,
    (3, 3, 14, 8, 3): PMEVCNTR3_EL0,
    (3, 3, 14, 8, 4): PMEVCNTR4_EL0,
    (3, 3, 14, 8, 5): PMEVCNTR5_EL0,
    (3, 3, 14, 8, 6): PMEVCNTR6_EL0,
    (3, 3, 14, 8, 7): PMEVCNTR7_EL0,

    (3, 3, 14, 9, 0): PMEVCNTR8_EL0,
    (3, 3, 14, 9, 1): PMEVCNTR9_EL0,
    (3, 3, 14, 9, 2): PMEVCNTR10_EL0,
    (3, 3, 14, 9, 3): PMEVCNTR11_EL0,
    (3, 3, 14, 9, 4): PMEVCNTR12_EL0,
    (3, 3, 14, 9, 5): PMEVCNTR13_EL0,
    (3, 3, 14, 9, 6): PMEVCNTR14_EL0,
    (3, 3, 14, 9, 7): PMEVCNTR15_EL0,

    (3, 3, 14, 10, 0): PMEVCNTR16_EL0,
    (3, 3, 14, 10, 1): PMEVCNTR17_EL0,
    (3, 3, 14, 10, 2): PMEVCNTR18_EL0,
    (3, 3, 14, 10, 3): PMEVCNTR19_EL0,
    (3, 3, 14, 10, 4): PMEVCNTR20_EL0,
    (3, 3, 14, 10, 5): PMEVCNTR21_EL0,
    (3, 3, 14, 10, 6): PMEVCNTR22_EL0,
    (3, 3, 14, 10, 7): PMEVCNTR23_EL0,

    (3, 3, 14, 11, 0): PMEVCNTR24_EL0,
    (3, 3, 14, 11, 1): PMEVCNTR25_EL0,
    (3, 3, 14, 11, 2): PMEVCNTR26_EL0,
    (3, 3, 14, 11, 3): PMEVCNTR27_EL0,
    (3, 3, 14, 11, 4): PMEVCNTR28_EL0,
    (3, 3, 14, 11, 5): PMEVCNTR29_EL0,
    (3, 3, 14, 11, 6): PMEVCNTR30_EL0,

    (3, 3, 14, 12, 0): PMEVTYPER0_EL0,
    (3, 3, 14, 12, 1): PMEVTYPER1_EL0,
    (3, 3, 14, 12, 2): PMEVTYPER2_EL0,
    (3, 3, 14, 12, 3): PMEVTYPER3_EL0,
    (3, 3, 14, 12, 4): PMEVTYPER4_EL0,
    (3, 3, 14, 12, 5): PMEVTYPER5_EL0,
    (3, 3, 14, 12, 6): PMEVTYPER6_EL0,
    (3, 3, 14, 12, 7): PMEVTYPER7_EL0,

    (3, 3, 14, 13, 0): PMEVTYPER8_EL0,
    (3, 3, 14, 13, 1): PMEVTYPER9_EL0,
    (3, 3, 14, 13, 2): PMEVTYPER10_EL0,
    (3, 3, 14, 13, 3): PMEVTYPER11_EL0,
    (3, 3, 14, 13, 4): PMEVTYPER12_EL0,
    (3, 3, 14, 13, 5): PMEVTYPER13_EL0,
    (3, 3, 14, 13, 6): PMEVTYPER14_EL0,
    (3, 3, 14, 13, 7): PMEVTYPER15_EL0,

    (3, 3, 14, 14, 0): PMEVTYPER16_EL0,
    (3, 3, 14, 14, 1): PMEVTYPER17_EL0,
    (3, 3, 14, 14, 2): PMEVTYPER18_EL0,
    (3, 3, 14, 14, 3): PMEVTYPER19_EL0,
    (3, 3, 14, 14, 4): PMEVTYPER20_EL0,
    (3, 3, 14, 14, 5): PMEVTYPER21_EL0,
    (3, 3, 14, 14, 6): PMEVTYPER22_EL0,
    (3, 3, 14, 14, 7): PMEVTYPER23_EL0,

    (3, 3, 14, 15, 0): PMEVTYPER24_EL0,
    (3, 3, 14, 15, 1): PMEVTYPER25_EL0,
    (3, 3, 14, 15, 2): PMEVTYPER26_EL0,
    (3, 3, 14, 15, 3): PMEVTYPER27_EL0,
    (3, 3, 14, 15, 4): PMEVTYPER28_EL0,
    (3, 3, 14, 15, 5): PMEVTYPER29_EL0,
    (3, 3, 14, 15, 6): PMEVTYPER30_EL0,
    (3, 3, 14, 15, 7): PMCCFILTR_EL0,

    (3, 4, 0, 0, 0): VPIDR_EL2,
    (3, 4, 0, 0, 5): VMPIDR_EL2,

    (3, 4, 1, 0, 0): SCTLR_EL2,
    (3, 4, 1, 0, 5): ACTLR_EL2,

    (3, 4, 1, 1, 0): HCR_EL2,
    (3, 4, 1, 1, 1): MDCR_EL2,
    (3, 4, 1, 1, 2): CPTR_EL2,
    (3, 4, 1, 1, 3): HSTR_EL2,
    (3, 4, 1, 1, 4): HFGRTR_EL2,
    (3, 4, 1, 1, 5): HFGWTR_EL2,
    (3, 4, 1, 1, 6): HFGITR_EL2,
    (3, 4, 1, 1, 7): HACR_EL2,

    (3, 4, 1, 2, 0): ZCR_EL2,

    (3, 4, 1, 2, 1): TRFCR_EL2,

    (3, 4, 1, 3, 1): SDER32_EL2,

    (3, 4, 2, 0, 0): TTBR0_EL2,
    (3, 4, 2, 0, 2): TCR_EL2,

    (3, 4, 2, 1, 0): VTTBR_EL2,
    (3, 4, 2, 1, 2): VTCR_EL2,

    (3, 4, 2, 2, 0): VNCR_EL2,

    (3, 4, 2, 6, 0): VSTTBR_EL2,
    (3, 4, 2, 6, 2): VSTCR_EL2,

    (3, 4, 3, 0, 0): DACR32_EL2,

    (3, 4, 3, 1, 4): HDFGRTR_EL2,
    (3, 4, 3, 1, 5): HDFGWTR_EL2,
    (3, 4, 3, 1, 6): HAFGRTR_EL2,

    (3, 4, 5, 0, 1): IFSR32_EL2,

    (3, 4, 5, 1, 0): AFSR0_EL2,
    (3, 4, 5, 1, 1): AFSR1_EL2,

    (3, 4, 5, 2, 0): ESR_EL2,
    (3, 4, 5, 2, 3): VSESR_EL2,

    (3, 4, 5, 3, 0): FPEXC32_EL2,

    (3, 4, 6, 0, 0): FAR_EL2,
    (3, 4, 6, 0, 4): HPFAR_EL2,

    (3, 4, 9, 9, 0): PMSCR_EL2,

    (3, 4, 10, 2, 0): MAIR_EL2,

    (3, 4, 10, 3, 0): AMAIR_EL2,

    (3, 4, 12, 0, 0): VBAR_EL2,
    (3, 4, 12, 0, 1): RVBAR_EL2,
    (3, 4, 12, 0, 2): RMR_EL2,

    (3, 4, 12, 1, 1): VDISR_EL2,

    (3, 4, 12, 8, 0): ICH_AP0R0_EL2,
    (3, 4, 12, 8, 1): ICH_AP0R1_EL2,
    (3, 4, 12, 8, 2): ICH_AP0R2_EL2,
    (3, 4, 12, 8, 3): ICH_AP0R3_EL2,

    (3, 4, 12, 9, 0): ICH_AP1R0_EL2,
    (3, 4, 12, 9, 1): ICH_AP1R1_EL2,
    (3, 4, 12, 9, 2): ICH_AP1R2_EL2,
    (3, 4, 12, 9, 3): ICH_AP1R3_EL2,
    (3, 4, 12, 9, 5): ICC_SRE_EL2,

    (3, 4, 12, 11, 0): ICH_HCR_EL2,
    (3, 4, 12, 11, 1): ICH_VTR_EL2,
    (3, 4, 12, 11, 2): ICH_MISR_EL2,
    (3, 4, 12, 11, 3): ICH_EISR_EL2,
    (3, 4, 12, 11, 5): ICH_ELRSR_EL2,
    (3, 4, 12, 11, 7): ICH_VMCR_EL2,

    (3, 4, 12, 12, 0): ICH_LR0_EL2,
    (3, 4, 12, 12, 1): ICH_LR1_EL2,
    (3, 4, 12, 12, 2): ICH_LR2_EL2,
    (3, 4, 12, 12, 3): ICH_LR3_EL2,
    (3, 4, 12, 12, 4): ICH_LR4_EL2,
    (3, 4, 12, 12, 5): ICH_LR5_EL2,
    (3, 4, 12, 12, 6): ICH_LR6_EL2,
    (3, 4, 12, 12, 7): ICH_LR7_EL2,

    (3, 4, 12, 13, 0): ICH_LR8_EL2,
    (3, 4, 12, 13, 1): ICH_LR9_EL2,
    (3, 4, 12, 13, 2): ICH_LR10_EL2,
    (3, 4, 12, 13, 3): ICH_LR11_EL2,
    (3, 4, 12, 13, 4): ICH_LR12_EL2,
    (3, 4, 12, 13, 5): ICH_LR13_EL2,
    (3, 4, 12, 13, 6): ICH_LR14_EL2,
    (3, 4, 12, 13, 7): ICH_LR15_EL2,

    (3, 4, 13, 0, 1): CONTEXTIDR_EL2,
    (3, 4, 13, 0, 2): TPIDR_EL2,

    (3, 4, 13, 8, 0): AMEVCNTVOFF00_EL2,
    (3, 4, 13, 8, 1): AMEVCNTVOFF01_EL2,
    (3, 4, 13, 8, 2): AMEVCNTVOFF02_EL2,
    (3, 4, 13, 8, 3): AMEVCNTVOFF03_EL2,
    (3, 4, 13, 8, 4): AMEVCNTVOFF04_EL2,
    (3, 4, 13, 8, 5): AMEVCNTVOFF05_EL2,
    (3, 4, 13, 8, 6): AMEVCNTVOFF06_EL2,
    (3, 4, 13, 8, 7): AMEVCNTVOFF07_EL2,

    (3, 4, 13, 9, 0): AMEVCNTVOFF08_EL2,
    (3, 4, 13, 9, 1): AMEVCNTVOFF09_EL2,
    (3, 4, 13, 9, 2): AMEVCNTVOFF010_EL2,
    (3, 4, 13, 9, 3): AMEVCNTVOFF011_EL2,
    (3, 4, 13, 9, 4): AMEVCNTVOFF012_EL2,
    (3, 4, 13, 9, 5): AMEVCNTVOFF013_EL2,
    (3, 4, 13, 9, 6): AMEVCNTVOFF014_EL2,
    (3, 4, 13, 9, 7): AMEVCNTVOFF015_EL2,

    (3, 4, 13, 10, 0): AMEVCNTVOFF10_EL2,
    (3, 4, 13, 10, 1): AMEVCNTVOFF11_EL2,
    (3, 4, 13, 10, 2): AMEVCNTVOFF12_EL2,
    (3, 4, 13, 10, 3): AMEVCNTVOFF13_EL2,
    (3, 4, 13, 10, 4): AMEVCNTVOFF14_EL2,
    (3, 4, 13, 10, 5): AMEVCNTVOFF15_EL2,
    (3, 4, 13, 10, 6): AMEVCNTVOFF16_EL2,
    (3, 4, 13, 10, 7): AMEVCNTVOFF17_EL2,

    (3, 4, 13, 11, 0): AMEVCNTVOFF18_EL2,
    (3, 4, 13, 11, 1): AMEVCNTVOFF19_EL2,
    (3, 4, 13, 11, 2): AMEVCNTVOFF110_EL2,
    (3, 4, 13, 11, 3): AMEVCNTVOFF111_EL2,
    (3, 4, 13, 11, 4): AMEVCNTVOFF112_EL2,
    (3, 4, 13, 11, 5): AMEVCNTVOFF113_EL2,
    (3, 4, 13, 11, 6): AMEVCNTVOFF114_EL2,
    (3, 4, 13, 11, 7): AMEVCNTVOFF115_EL2,

    (3, 4, 14, 0, 3): CNTVOFF_EL2,
    (3, 4, 14, 0, 6): CNTPOFF_EL2,

    (3, 4, 14, 1, 0): CNTHCTL_EL2,

    (3, 4, 14, 2, 0): CNTHP_TVAL_EL2,
    (3, 4, 14, 2, 1): CNTHP_CTL_EL2,
    (3, 4, 14, 2, 2): CNTHP_CVAL_EL2,

    (3, 4, 14, 3, 0): CNTHV_TVAL_EL2,
    (3, 4, 14, 3, 1): CNTHV_CTL_EL2,
    (3, 4, 14, 3, 2): CNTHV_CVAL_EL2,

    (3, 4, 14, 4, 0): CNTHVS_TVAL_EL2,
    (3, 4, 14, 4, 1): CNTHVS_CTL_EL2,
    (3, 4, 14, 4, 2): CNTHVS_CVAL_EL2,

    (3, 4, 14, 5, 0): CNTHPS_TVAL_EL2,
    (3, 4, 14, 5, 1): CNTHPS_CTL_EL2,
    (3, 4, 14, 5, 2): CNTHPS_CVAL_EL2,

    # Aliases for *_EL02 *_EL12
    # see page 2864 of "Arm Architecture Reference Manual Armv8,
    # for Armv8-A architecture profile" Release 31 March 2020
    (3, 5, 1, 0, 0): SCTLR_EL1,
    (3, 5, 1, 0, 2): CPACR_EL1,

    (3, 5, 1, 2, 0): ZCR_EL1,
    (3, 5, 1, 2, 1): TRFCR_EL1,

    (3, 5, 2, 0, 0): TTBR0_EL1,
    (3, 5, 2, 0, 1): TTBR1_EL1,
    (3, 5, 2, 0, 2): TCR_EL1,

    (3, 5, 4, 0, 0): SPSR_EL1,
    (3, 5, 4, 0, 1): ELR_EL1,

    (3, 5, 5, 1, 0): AFSR0_EL1,
    (3, 5, 5, 1, 1): AFSR1_EL1,

    (3, 5, 5, 2, 0): ESR_EL1,

    (3, 5, 6, 0, 0): FAR_EL1,

    (3, 5, 9, 9, 0): PMSCR_EL1,

    (3, 5, 10, 2, 0): MAIR_EL1,

    (3, 5, 10, 3, 0): AMAIR_EL1,

    (3, 5, 12, 0, 0): VBAR_EL1,

    (3, 5, 13, 0, 0): CONTEXTIDR_EL1,

    (3, 5, 14, 1, 0): CNTKCTL_EL1,

    (3, 5, 14, 2, 0): CNTP_TVAL_EL0,
    (3, 5, 14, 2, 1): CNTP_CTL_EL0,
    (3, 5, 14, 2, 2): CNTP_CVAL_EL0,

    (3, 5, 14, 3, 0): CNTV_TVAL_EL0,
    (3, 5, 14, 3, 1): CNTV_CTL_EL0,
    (3, 5, 14, 3, 2): CNTV_CVAL_EL0,
    # End of aliases

    (3, 6, 1, 0, 0): SCTLR_EL3,
    (3, 6, 1, 0, 1): ACTLR_EL3,

    (3, 6, 1, 1, 0): SCR_EL3,
    (3, 6, 1, 1, 1): SDER32_EL3,
    (3, 6, 1, 1, 2): CPTR_EL3,

    (3, 6, 1, 2, 0): ZCR_EL3,

    (3, 6, 1, 3, 1): MDCR_EL3,

    (3, 6, 2, 0, 0): TTBR0_EL3,
    (3, 6, 2, 0, 2): TCR_EL3,

    (3, 6, 4, 0, 0): SPSR_EL3,
    (3, 6, 4, 0, 1): ELR_EL3,

    (3, 6, 4, 1, 0): SP_EL2,

    (3, 6, 5, 1, 0): AFSR0_EL3,
    (3, 6, 5, 1, 1): AFSR1_EL3,

    (3, 6, 5, 2, 0): ESR_EL3,

    (3, 6, 6, 0, 0): FAR_EL3,

    (3, 6, 10, 2, 0): MAIR_EL3,

    (3, 6, 10, 3, 0): AMAIR_EL3,

    (3, 6, 12, 0, 0): VBAR_EL3,
    (3, 6, 12, 0, 1): RVBAR_EL3,
    (3, 6, 12, 0, 2): RMR_EL3,

    (3, 6, 12, 12, 4): ICC_CTLR_EL3,
    (3, 6, 12, 12, 5): ICC_SRE_EL3,
    (3, 6, 12, 12, 7): ICC_IGRPEN1_EL3,

    (3, 6, 13, 0, 2): TPIDR_EL3,

    (3, 7, 14, 2, 0): CNTPS_TVAL_EL1,
    (3, 7, 14, 2, 1): CNTPS_CTL_EL1,
    (3, 7, 14, 2, 2): CNTPS_CVAL_EL1,
}

# CPSR: N Z C V


def update_flag_zf(a):
    return [ExprAssign(zf, ExprOp("FLAG_EQ", a))]


def update_flag_zf_eq(a, b):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_CMP", a, b))]


def update_flag_nf(arg):
    return [
        ExprAssign(
            nf,
            ExprOp("FLAG_SIGN_SUB", arg, ExprInt(0, arg.size))
        )
    ]


def update_flag_zn(a):
    e = []
    e += update_flag_zf(a)
    e += update_flag_nf(a)
    return e


def check_ops_msb(a, b, c):
    if not a or not b or not c or a != b or a != c:
        raise ValueError('bad ops size %s %s %s' % (a, b, c))


def update_flag_add_cf(op1, op2):
    "Compute cf in @op1 + @op2"
    return [ExprAssign(cf, ExprOp("FLAG_ADD_CF", op1, op2))]


def update_flag_add_of(op1, op2):
    "Compute of in @op1 + @op2"
    return [ExprAssign(of, ExprOp("FLAG_ADD_OF", op1, op2))]


def update_flag_sub_cf(op1, op2):
    "Compote CF in @op1 - @op2"
    return [ExprAssign(cf, ExprOp("FLAG_SUB_CF", op1, op2) ^ ExprInt(1, 1))]


def update_flag_sub_of(op1, op2):
    "Compote OF in @op1 - @op2"
    return [ExprAssign(of, ExprOp("FLAG_SUB_OF", op1, op2))]


def update_flag_arith_add_co(arg1, arg2):
    e = []
    e += update_flag_add_cf(arg1, arg2)
    e += update_flag_add_of(arg1, arg2)
    return e


def update_flag_arith_add_zn(arg1, arg2):
    """
    Compute zf and nf flags for (arg1 + arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, -arg2)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUB", arg1, -arg2))]
    return e


def update_flag_arith_sub_co(arg1, arg2):
    """
    Compute cf and of flags for (arg1 - arg2)
    """
    e = []
    e += update_flag_sub_cf(arg1, arg2)
    e += update_flag_sub_of(arg1, arg2)
    return e


def update_flag_arith_sub_zn(arg1, arg2):
    """
    Compute zf and nf flags for (arg1 - arg2)
    """
    e = []
    e += update_flag_zf_eq(arg1, arg2)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUB", arg1, arg2))]
    return e




def update_flag_zfaddwc_eq(arg1, arg2, arg3):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_ADDWC", arg1, arg2, arg3))]

def update_flag_zfsubwc_eq(arg1, arg2, arg3):
    return [ExprAssign(zf, ExprOp("FLAG_EQ_SUBWC", arg1, arg2, arg3))]


def update_flag_arith_addwc_zn(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 + arg2 + cf)
    """
    e = []
    e += update_flag_zfaddwc_eq(arg1, arg2, arg3)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_ADDWC", arg1, arg2, arg3))]
    return e


def update_flag_arith_subwc_zn(arg1, arg2, arg3):
    """
    Compute znp flags for (arg1 - (arg2 + cf))
    """
    e = []
    e += update_flag_zfsubwc_eq(arg1, arg2, arg3)
    e += [ExprAssign(nf, ExprOp("FLAG_SIGN_SUBWC", arg1, arg2, arg3))]
    return e


def update_flag_addwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [ExprAssign(cf, ExprOp("FLAG_ADDWC_CF", op1, op2, op3))]


def update_flag_addwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [ExprAssign(of, ExprOp("FLAG_ADDWC_OF", op1, op2, op3))]


def update_flag_arith_addwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_addwc_cf(arg1, arg2, arg3)
    e += update_flag_addwc_of(arg1, arg2, arg3)
    return e



def update_flag_subwc_cf(op1, op2, op3):
    "Compute cf in @res = @op1 + @op2 + @op3"
    return [ExprAssign(cf, ExprOp("FLAG_SUBWC_CF", op1, op2, op3) ^ ExprInt(1, 1))]


def update_flag_subwc_of(op1, op2, op3):
    "Compute of in @res = @op1 + @op2 + @op3"
    return [ExprAssign(of, ExprOp("FLAG_SUBWC_OF", op1, op2, op3))]


def update_flag_arith_subwc_co(arg1, arg2, arg3):
    e = []
    e += update_flag_subwc_cf(arg1, arg2, arg3)
    e += update_flag_subwc_of(arg1, arg2, arg3)
    return e


cond2expr = {'EQ': ExprOp("CC_EQ", zf),
             'NE': ExprOp("CC_NE", zf),
             'CS': ExprOp("CC_U>=", cf ^ ExprInt(1, 1)), # inv cf
             'CC': ExprOp("CC_U<", cf ^ ExprInt(1, 1)), # inv cf
             'MI': ExprOp("CC_NEG", nf),
             'PL': ExprOp("CC_POS", nf),
             'VS': ExprOp("CC_sOVR", of),
             'VC': ExprOp("CC_sNOOVR", of),
             'HI': ExprOp("CC_U>", cf ^ ExprInt(1, 1), zf), # inv cf
             'LS': ExprOp("CC_U<=", cf ^ ExprInt(1, 1), zf), # inv cf
             'GE': ExprOp("CC_S>=", nf, of),
             'LT': ExprOp("CC_S<", nf, of),
             'GT': ExprOp("CC_S>", nf, of, zf),
             'LE': ExprOp("CC_S<=", nf, of, zf),
             'AL': ExprInt(1, 1),
             'NV': ExprInt(0, 1)
             }


def extend_arg(dst, arg):
    if not isinstance(arg, ExprOp):
        return arg

    op, (reg, shift) = arg.op, arg.args
    if op == "SXTB":
        base = reg[:8].signExtend(dst.size)
        op = "<<"
    elif op == "SXTH":
        base = reg[:16].signExtend(dst.size)
        op = "<<"
    elif op == 'SXTW':
        base = reg[:32].signExtend(dst.size)
        op = "<<"
    elif op == "SXTX":
        base = reg.signExtend(dst.size)
        op = "<<"

    elif op == "UXTB":
        base = reg[:8].zeroExtend(dst.size)
        op = "<<"
    elif op == "UXTH":
        base = reg[:16].zeroExtend(dst.size)
        op = "<<"
    elif op == 'UXTW':
        base = reg[:32].zeroExtend(dst.size)
        op = "<<"
    elif op == "UXTX":
        base = reg.zeroExtend(dst.size)
        op = "<<"

    elif op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>']:
        base = reg.zeroExtend(dst.size)
    else:
        raise NotImplementedError('Unknown shifter operator')

    out = ExprOp(op, base, (shift.zeroExtend(dst.size)
                            & ExprInt(dst.size - 1, dst.size)))
    return out


# SemBuilder context
ctx = {"PC": PC,
       "LR": LR,
       "nf": nf,
       "zf": zf,
       "cf": cf,
       "of": of,
       "cond2expr": cond2expr,
       "extend_arg": extend_arg,
       "ExprId":ExprId,
       "exception_flags": exception_flags,
       "interrupt_num": interrupt_num,
       "EXCEPT_DIV_BY_ZERO": EXCEPT_DIV_BY_ZERO,
       "EXCEPT_INT_XX": EXCEPT_INT_XX,
       }

sbuild = SemBuilder(ctx)


# instruction definition ##############

@sbuild.parse
def add(arg1, arg2, arg3):
    arg1 = arg2 + extend_arg(arg2, arg3)


@sbuild.parse
def sub(arg1, arg2, arg3):
    arg1 = arg2 - extend_arg(arg2, arg3)


@sbuild.parse
def neg(arg1, arg2):
    arg1 = - arg2


@sbuild.parse
def and_l(arg1, arg2, arg3):
    arg1 = arg2 & extend_arg(arg2, arg3)


@sbuild.parse
def eor(arg1, arg2, arg3):
    arg1 = arg2 ^ extend_arg(arg2, arg3)


@sbuild.parse
def eon(arg1, arg2, arg3):
    arg1 = arg2 ^ (~extend_arg(arg2, arg3))


@sbuild.parse
def orr(arg1, arg2, arg3):
    arg1 = arg2 | extend_arg(arg2, arg3)


@sbuild.parse
def orn(arg1, arg2, arg3):
    arg1 = arg2 | (~extend_arg(arg2, arg3))


@sbuild.parse
def bic(arg1, arg2, arg3):
    arg1 = arg2 & (~extend_arg(arg2, arg3))


def bics(ir, instr, arg1, arg2, arg3):
    e = []
    tmp1, tmp2 = arg2, (~extend_arg(arg2, arg3))
    res = tmp1 & tmp2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', tmp1, tmp2))]
    e += update_flag_nf(res)

    e.append(ExprAssign(arg1, res))
    return e, []


@sbuild.parse
def mvn(arg1, arg2):
    arg1 = (~extend_arg(arg1, arg2))


def adds(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 + arg3

    e += update_flag_arith_add_zn(arg2, arg3)
    e += update_flag_arith_add_co(arg2, arg3)

    e.append(ExprAssign(arg1, res))

    return e, []


def subs(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 - arg3


    e += update_flag_arith_sub_zn(arg2, arg3)
    e += update_flag_arith_sub_co(arg2, arg3)

    e.append(ExprAssign(arg1, res))
    return e, []


def cmp(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)

    e += update_flag_arith_sub_zn(arg1, arg2)
    e += update_flag_arith_sub_co(arg1, arg2)

    return e, []


def cmn(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)

    e += update_flag_arith_add_zn(arg1, arg2)
    e += update_flag_arith_add_co(arg1, arg2)

    return e, []


def ands(ir, instr, arg1, arg2, arg3):
    e = []
    arg3 = extend_arg(arg2, arg3)
    res = arg2 & arg3

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', arg2, arg3))]
    e += update_flag_nf(res)

    e.append(ExprAssign(arg1, res))
    return e, []

def tst(ir, instr, arg1, arg2):
    e = []
    arg2 = extend_arg(arg1, arg2)
    res = arg1 & arg2

    e += [ExprAssign(zf, ExprOp('FLAG_EQ_AND', arg1, arg2))]
    e += update_flag_nf(res)

    return e, []


@sbuild.parse
def lsl(arg1, arg2, arg3):
    arg1 = arg2 << (arg3 & ExprInt(arg3.size - 1, arg3.size))


@sbuild.parse
def lsr(arg1, arg2, arg3):
    arg1 = arg2 >> (arg3 & ExprInt(arg3.size - 1, arg3.size))


@sbuild.parse
def asr(arg1, arg2, arg3):
    arg1 = ExprOp(
        'a>>', arg2, (arg3 & ExprInt(arg3.size - 1, arg3.size)))


@sbuild.parse
def mov(arg1, arg2):
    arg1 = arg2


def movk(ir, instr, arg1, arg2):
    e = []
    if isinstance(arg2, ExprOp):
        assert(arg2.op == 'slice_at' and
               isinstance(arg2.args[0], ExprInt) and
               isinstance(arg2.args[1], ExprInt))
        value, shift = int(arg2.args[0]), int(arg2.args[1])
        e.append(
            ExprAssign(arg1[shift:shift + 16], ExprInt(value, 16)))
    else:
        e.append(ExprAssign(arg1[:16], ExprInt(int(arg2), 16)))

    return e, []


@sbuild.parse
def movz(arg1, arg2):
    arg1 = arg2


@sbuild.parse
def movn(arg1, arg2):
    arg1 = ~arg2


@sbuild.parse
def bl(arg1):
    PC = arg1
    ir.IRDst = arg1
    LR = ExprInt(instr.offset + instr.l, 64)

@sbuild.parse
def csel(arg1, arg2, arg3, arg4):
    cond_expr = cond2expr[arg4.name]
    arg1 = arg2 if cond_expr else arg3

def ccmp(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    if(arg2.is_int()):
        arg2=ExprInt(int(arg2),arg1.size)
    default_nf = arg3[0:1]
    default_zf = arg3[1:2]
    default_cf = arg3[2:3]
    default_of = arg3[3:4]
    cond_expr = cond2expr[arg4.name]
    res = arg1 - arg2
    new_nf = nf
    new_zf = update_flag_zf(res)[0].src
    new_cf = update_flag_sub_cf(arg1, arg2)[0].src
    new_of = update_flag_sub_of(arg1, arg2)[0].src

    e.append(ExprAssign(nf, ExprCond(cond_expr,
                                                    new_nf,
                                                    default_nf)))
    e.append(ExprAssign(zf, ExprCond(cond_expr,
                                                    new_zf,
                                                    default_zf)))
    e.append(ExprAssign(cf, ExprCond(cond_expr,
                                                    new_cf,
                                                    default_cf)))
    e.append(ExprAssign(of, ExprCond(cond_expr,
                                                    new_of,
                                                    default_of)))
    return e, []


def csinc(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                arg3 + ExprInt(1, arg3.size)
            )
        )
    )
    return e, []


def csinv(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                ~arg3)
        )
    )
    return e, []


def csneg(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    cond_expr = cond2expr[arg4.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                arg2,
                -arg3)
        )
    )
    return e, []


def cset(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                ExprInt(1, arg1.size),
                ExprInt(0, arg1.size)
            )
        )
    )
    return e, []


def csetm(ir, instr, arg1, arg2):
    e = []
    cond_expr = cond2expr[arg2.name]
    e.append(
        ExprAssign(
            arg1,
            ExprCond(
                cond_expr,
                ExprInt(-1, arg1.size),
                ExprInt(0, arg1.size)
            )
        )
    )
    return e, []


def get_mem_access(mem):
    updt = None
    if isinstance(mem, ExprOp):
        if mem.op == 'preinc':
            if len(mem.args) == 1:
                addr = mem.args[0]
            else:
                addr = mem.args[0] + mem.args[1]
        elif mem.op == 'segm':
            base = mem.args[0]
            op, (reg, shift) = mem.args[1].op, mem.args[1].args
            if op == 'SXTW':
                off = reg.signExtend(base.size) << shift.zeroExtend(base.size)
                addr = base + off
            elif op == 'UXTW':
                off = reg.zeroExtend(base.size) << shift.zeroExtend(base.size)
                addr = base + off
            elif op == 'LSL':
                if isinstance(shift, ExprInt) and int(shift) == 0:
                    addr = base + reg.zeroExtend(base.size)
                else:
                    addr = base + \
                        (reg.zeroExtend(base.size)
                         << shift.zeroExtend(base.size))
            else:
                raise NotImplementedError('bad op')
        elif mem.op == "postinc":
            addr, off = mem.args
            updt = ExprAssign(addr, addr + off)
        elif mem.op == "preinc_wb":
            base, off = mem.args
            addr = base + off
            updt = ExprAssign(base, base + off)
        else:
            raise NotImplementedError('bad op')
    else:
        raise NotImplementedError('bad op')
    return addr, updt



def ldr(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(arg1, ExprMem(addr, arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldr_size(ir, instr, arg1, arg2, size):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        ExprAssign(arg1, ExprMem(addr, size).zeroExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrb(ir, instr, arg1, arg2):
    return ldr_size(ir, instr, arg1, arg2, 8)


def ldrh(ir, instr, arg1, arg2):
    return ldr_size(ir, instr, arg1, arg2, 16)


def ldrs_size(ir, instr, arg1, arg2, size):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(
        ExprAssign(arg1, ExprMem(addr, size).signExtend(arg1.size)))
    if updt:
        e.append(updt)
    return e, []


def ldrsb(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 8)


def ldrsh(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 16)


def ldrsw(ir, instr, arg1, arg2):
    return ldrs_size(ir, instr, arg1, arg2, 32)

def ldaxrb(ir, instr, arg1, arg2):
    # TODO XXX no memory lock implemented
    assert arg2.is_op('preinc')
    assert len(arg2.args) == 1
    ptr = arg2.args[0]
    e = []
    e.append(ExprAssign(arg1, ExprMem(ptr, 8).zeroExtend(arg1.size)))
    return e, []

def ldxr(ir, instr, arg1, arg2):
    # TODO XXX no memory lock implemented
    assert arg2.is_op('preinc')
    assert len(arg2.args) == 1
    ptr = arg2.args[0]
    e = []
    e.append(ExprAssign(arg1, ExprMem(ptr, arg1.size).zeroExtend(arg1.size)))
    return e, []

def stlxr(ir, instr, arg1, arg2, arg3):
    assert arg3.is_op('preinc')
    assert len(arg3.args) == 1
    ptr = arg3.args[0]
    e = []
    e.append(ExprAssign(ExprMem(ptr, arg2.size), arg2))
    # TODO XXX here, force update success
    e.append(ExprAssign(arg1, ExprInt(0, arg1.size)))
    return e, []

def stlxrb(ir, instr, arg1, arg2, arg3):
    assert arg3.is_op('preinc')
    assert len(arg3.args) == 1
    ptr = arg3.args[0]
    e = []
    e.append(ExprAssign(ExprMem(ptr, 8), arg2[:8]))
    # TODO XXX here, force update success
    e.append(ExprAssign(arg1, ExprInt(0, arg1.size)))
    return e, []

def stlrb(ir, instr, arg1, arg2):
    ptr = arg2.args[0]
    e = []
    e.append(ExprAssign(ExprMem(ptr, 8), arg1[:8]))
    return e, []

def l_str(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, arg1.size), arg1))
    if updt:
        e.append(updt)
    return e, []


def strb(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, 8), arg1[:8]))
    if updt:
        e.append(updt)
    return e, []


def strh(ir, instr, arg1, arg2):
    e = []
    addr, updt = get_mem_access(arg2)
    e.append(ExprAssign(ExprMem(addr, 16), arg1[:16]))
    if updt:
        e.append(updt)
    return e, []


def stp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(ExprAssign(ExprMem(addr, arg1.size), arg1))
    e.append(
        ExprAssign(ExprMem(addr + ExprInt(arg1.size // 8, addr.size), arg2.size), arg2))
    if updt:
        e.append(updt)
    return e, []


def ldp(ir, instr, arg1, arg2, arg3):
    e = []
    addr, updt = get_mem_access(arg3)
    e.append(ExprAssign(arg1, ExprMem(addr, arg1.size)))
    e.append(
        ExprAssign(arg2, ExprMem(addr + ExprInt(arg1.size // 8, addr.size), arg2.size)))
    if updt:
        e.append(updt)
    return e, []


def sbfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3), int(arg4) + 1
    if sim > rim:
        res = arg2[rim:sim].signExtend(arg1.size)
    else:
        shift = ExprInt(arg2.size - rim, arg2.size)
        res = (arg2[:sim].signExtend(arg1.size) << shift)
    e.append(ExprAssign(arg1, res))
    return e, []


def ubfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3), int(arg4) + 1
    if sim != arg1.size - 1 and rim == sim:
        # Simple case: lsl
        value = int(rim)
        assert value < arg1.size
        e.append(ExprAssign(arg1, arg2 << (ExprInt(arg1.size - value, arg2.size))))
        return e, []
    if sim == arg1.size:
        # Simple case: lsr
        value = int(rim)
        assert value < arg1.size
        e.append(ExprAssign(arg1, arg2 >> (ExprInt(value, arg2.size))))
        return e, []

    if sim > rim:
        res = arg2[rim:sim].zeroExtend(arg1.size)
    else:
        shift = ExprInt(arg2.size - rim, arg2.size)
        res = (arg2[:sim].zeroExtend(arg1.size) << shift)
    e.append(ExprAssign(arg1, res))
    return e, []

def bfm(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    rim, sim = int(arg3), int(arg4) + 1
    if sim > rim:
        res = arg2[rim:sim]
        e.append(ExprAssign(arg1[:sim-rim], res))
    else:
        shift_i = arg2.size - rim
        shift = ExprInt(shift_i, arg2.size)
        res = arg2[:sim]
        e.append(ExprAssign(arg1[shift_i:shift_i+sim], res))
    return e, []



def mrs(ir, insr, arg1, arg2, arg3, arg4, arg5, arg6):
    e = []
    if arg2.is_int(3) and arg3.is_int(3) and arg4.is_id("c4") and arg5.is_id("c2") and arg6.is_int(0):
        out = []
        out.append(ExprInt(0x0, 28))
        out.append(of)
        out.append(cf)
        out.append(zf)
        out.append(nf)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(7):
        out = []
        out.append(ExprInt(0x0, 38))
        out.append(tco)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        out = []
        out.append(ExprInt(0x0, 39))
        out.append(dit)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(4):
        out = []
        out.append(ExprInt(0x0, 40))
        out.append(uao)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(3):
        out = []
        out.append(ExprInt(0x0, 41))
        out.append(pan)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(6):
        out = []
        out.append(ExprInt(0x0, 51))
        out.append(ssbs)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(1):
        out = []
        out.append(ExprInt(0x0, 54))
        out.append(df)
        out.append(af)
        out.append(iff)
        out.append(ff)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(2):
        out = []
        out.append(ExprInt(0x0, 60))
        out.append(cur_el)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        out = []
        out.append(ExprInt(0x0, 63))
        out.append(spsel)
        e.append(ExprAssign(arg1, ExprCompose(*out).zeroExtend(arg1.size)))

    else:
        sreg = (int(arg2), int(arg3), int(str(arg4)[1:]), int(str(arg5)[1:]), int(arg6))
        if sreg in system_regs:
            e.append(ExprAssign(arg1, system_regs[sreg]))
        else:
            raise NotImplementedError("Unknown system register: %d %d %s %s %d" % (int(arg2), int(arg3), str(arg4), str(arg5), int(arg6)))

    return e, []

def msr(ir, instr, arg1, arg2, arg3, arg4, arg5, arg6):

    e = []
    if arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        e.append(ExprAssign(nf, arg6[31:32]))
        e.append(ExprAssign(zf, arg6[30:31]))
        e.append(ExprAssign(cf, arg6[29:30]))
        e.append(ExprAssign(of, arg6[28:29]))
    
    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(7):
        e.append(ExprAssign(tco, arg6[25:26]))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        e.append(ExprAssign(dit, arg6[24:25]))
    
    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(4):
        e.append(ExprAssign(uao, arg6[23:24]))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(3):
        e.append(ExprAssign(pan, arg6[22:23]))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(6):
        e.append(ExprAssign(ssbs, arg6[12:13]))

    elif arg1.is_int(3) and arg2.is_int(3) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(1):
        e.append(ExprAssign(df, arg6[9:10]))
        e.append(ExprAssign(af, arg6[8:9]))
        e.append(ExprAssign(iff, arg6[7:8]))
        e.append(ExprAssign(ff, arg6[6:7]))
    
    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(2):
        e.append(ExprAssign(cur_el, arg6[2:4]))

    elif arg1.is_int(3) and arg2.is_int(0) and arg3.is_id("c4") and arg4.is_id("c2") and arg5.is_int(0):
        e.append(ExprAssign(spsel, arg6[0:1]))

    else:
        sreg = (int(arg1), int(arg2), int(str(arg3)[1:]), int(str(arg4)[1:]), int(arg5))
        if sreg in system_regs:
            e.append(ExprAssign(system_regs[sreg], arg6))
        else:
            raise NotImplementedError("Unknown system register: %d %d %s %s %d" % (int(arg1), int(arg2), str(arg3), str(arg4), int(arg5)))

    return e, []



def adc(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 + arg3 + cf.zeroExtend(arg3.size)
    e.append(ExprAssign(arg1, r))
    return e, []


def adcs(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 + arg3 + cf.zeroExtend(arg3.size)
    e.append(ExprAssign(arg1, r))
    e += update_flag_arith_addwc_zn(arg2, arg3, cf)
    e += update_flag_arith_addwc_co(arg2, arg3, cf)
    return e, []


def sbc(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 - (arg3 + (~cf).zeroExtend(arg3.size))
    e.append(ExprAssign(arg1, r))
    return e, []


def sbcs(ir, instr, arg1, arg2, arg3):
    arg3 = extend_arg(arg2, arg3)
    e = []
    r = arg2 - (arg3 + (~cf).zeroExtend(arg3.size))
    e.append(ExprAssign(arg1, r))
    e += update_flag_arith_subwc_zn(arg2, arg3, ~cf)
    e += update_flag_arith_subwc_co(arg2, arg3, ~cf)
    return e, []


@sbuild.parse
def madd(arg1, arg2, arg3, arg4):
    arg1 = arg2 * arg3 + arg4


@sbuild.parse
def msub(arg1, arg2, arg3, arg4):
    arg1 = arg4 - (arg2 * arg3)


@sbuild.parse
def udiv(arg1, arg2, arg3):
    if arg3:
        arg1 = ExprOp('udiv', arg2, arg3)
    else:
        exception_flags = ExprInt(EXCEPT_DIV_BY_ZERO,
                                          exception_flags.size)

@sbuild.parse
def sdiv(arg1, arg2, arg3):
    if arg3:
        arg1 = ExprOp('sdiv', arg2, arg3)
    else:
        exception_flags = ExprInt(EXCEPT_DIV_BY_ZERO,
                                          exception_flags.size)



@sbuild.parse
def smaddl(arg1, arg2, arg3, arg4):
    arg1 = arg2.signExtend(arg1.size) * arg3.signExtend(arg1.size) + arg4


@sbuild.parse
def cbz(arg1, arg2):
    dst = ExprLoc(ir.get_next_loc_key(instr), 64) if arg1 else arg2
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def cbnz(arg1, arg2):
    dst = arg2 if arg1 else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbz(arg1, arg2, arg3):
    bitmask = ExprInt(1, arg1.size) << arg2
    dst = ExprLoc(
        ir.get_next_loc_key(instr),
        64
    ) if arg1 & bitmask else arg3
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def tbnz(arg1, arg2, arg3):
    bitmask = ExprInt(1, arg1.size) << arg2
    dst = arg3 if arg1 & bitmask else ExprLoc(
        ir.get_next_loc_key(instr),
        64
    )
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ne(arg1):
    cond = cond2expr['NE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_eq(arg1):
    cond = cond2expr['EQ']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ge(arg1):
    cond = cond2expr['GE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_mi(arg1):
    cond = cond2expr['MI']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_pl(arg1):
    cond = cond2expr['PL']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_gt(arg1):
    cond = cond2expr['GT']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cc(arg1):
    cond = cond2expr['CC']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_cs(arg1):
    cond = cond2expr['CS']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_hi(arg1):
    cond = cond2expr['HI']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_le(arg1):
    cond = cond2expr['LE']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_ls(arg1):
    cond = cond2expr['LS']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def b_lt(arg1):
    cond = cond2expr['LT']
    dst = arg1 if cond else ExprLoc(ir.get_next_loc_key(instr), 64)
    PC = dst
    ir.IRDst = dst


@sbuild.parse
def ret(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def adrp(arg1, arg2):
    arg1 = (PC & ExprInt(0xfffffffffffff000, 64)) + arg2


@sbuild.parse
def adr(arg1, arg2):
    arg1 = PC + arg2


@sbuild.parse
def b(arg1):
    PC = arg1
    ir.IRDst = arg1


@sbuild.parse
def br(arg1):
    PC = arg1
    ir.IRDst = arg1

@sbuild.parse
def blr(arg1):
    PC = arg1
    ir.IRDst = arg1
    LR = ExprLoc(ir.get_next_loc_key(instr), 64)

@sbuild.parse
def nop():
    """Do nothing"""


@sbuild.parse
def dsb(arg1):
    """Data Synchronization Barrier"""

@sbuild.parse
def isb(arg1):
    """Instruction Synchronization Barrier"""

@sbuild.parse
def dmb(arg1):
    """Data Memory Barrier"""

@sbuild.parse
def tlbi(arg1, arg2, arg3, arg4):
    """TLB invalidate operation"""

@sbuild.parse
def clrex(arg1):
    """Clear the local monitor of the executing PE"""

@sbuild.parse
def ic(arg1, arg2, arg3, arg4):
    """Instruction/Data cache operation"""


def rev(ir, instr, arg1, arg2):
    out = []
    for i in range(0, arg2.size, 8):
        out.append(arg2[i:i+8])
    out.reverse()
    e = []
    result = ExprCompose(*out)
    e.append(ExprAssign(arg1, result))
    return e, []


def rev16(ir, instr, arg1, arg2):
    out = []
    for i in range(0, arg2.size // 8):
        index = (i & ~1) + (1 - (i & 1))
        out.append(arg2[index * 8:(index + 1) * 8])
    e = []
    result = ExprCompose(*out)
    e.append(ExprAssign(arg1, result))
    return e, []


@sbuild.parse
def extr(arg1, arg2, arg3, arg4):
    compose = ExprCompose(arg2, arg3)
    arg1 = compose[int(arg4):int(arg4)+arg1.size]


@sbuild.parse
def svc(arg1):
    exception_flags = ExprInt(EXCEPT_INT_XX, exception_flags.size)
    interrupt_num = ExprInt(int(arg1), interrupt_num.size)


def fmov(ir, instr, arg1, arg2):
    if arg2.is_int():
        # Transform int to signed floating-point constant with 3-bit exponent
        # and normalized 4 bits of precision
        # VFPExpandImm() of ARM Architecture Reference Manual
        imm8 = int(arg2)
        N = arg1.size
        assert N in [32, 64]
        E = 8 if N == 32 else 11
        F = N - E - 1;
        # sign = imm8<7>;
        sign = (imm8 >> 7) & 1;
        # exp = NOT(imm8<6>):Replicate(imm8<6>,E-3):imm8<5:4>;
        exp = (((imm8 >> 6) & 1) ^ 1) << (E - 3 + 2)
        if (imm8 >> 6) & 1:
            tmp = (1 << (E - 3)) - 1
        else:
            tmp = 0
        exp |= tmp << 2
        exp |= (imm8 >> 4) & 3
        # frac = imm8<3:0>:Zeros(F-4);
        frac = (imm8 & 0xf) << (F - 4)
        value = frac
        value |= exp << (4 + F - 4)
        value |= sign << (4 + F - 4  + 1 + E - 3 + 2)
        arg2 = ExprInt(value, N)
    e = [ExprAssign(arg1, arg2)]
    return e, []


def fadd(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fadd', arg2, arg3)))
    return e, []


def fsub(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fsub', arg2, arg3)))
    return e, []


def fmul(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fmul', arg2, arg3)))
    return e, []


def fdiv(ir, instr, arg1, arg2, arg3):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fdiv', arg2, arg3)))
    return e, []


def fabs(ir, instr, arg1, arg2):
    e = []
    e.append(ExprAssign(arg1, ExprOp('fabs', arg2)))
    return e, []


def fmadd(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp(
                'fadd',
                arg4,
                ExprOp('fmul', arg2, arg3)
            )
        )
    )
    return e, []


def fmsub(ir, instr, arg1, arg2, arg3, arg4):
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp(
                'fsub',
                arg4,
                ExprOp('fmul', arg2, arg3)
            )
        )
    )
    return e, []


def fcvt(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('fpconvert_fp%d' % arg1.size, arg2)
    e.append(ExprAssign(arg1, src))
    return e, []


def scvtf(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('sint_to_fp', arg2)
    if arg1.size != src.size:
        src = ExprOp('fpconvert_fp%d' % arg1.size, src)
    e.append(ExprAssign(arg1, src))
    return e, []


def ucvtf(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    src = ExprOp('uint_to_fp', arg2)
    if arg1.size != src.size:
        src = ExprOp('fpconvert_fp%d' % arg1.size, src)
    e.append(ExprAssign(arg1, src))
    return e, []


def fcvtzs(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp('fp_to_sint%d' % arg1.size,
                   ExprOp('fpround_towardszero', arg2)
            )
        )
    )
    return e, []


def fcvtzu(ir, instr, arg1, arg2):
    # XXX TODO: rounding
    e = []
    e.append(
        ExprAssign(
            arg1,
            ExprOp('fp_to_uint%d' % arg1.size,
                   ExprOp('fpround_towardszero', arg2)
            )
        )
    )
    return e, []


def fcmpe(ir, instr, arg1, arg2):
    e = []
    e.append(
        ExprAssign(
            nf,
            ExprOp('fcom_c0', arg1, arg2)
        )
    )
    e.append(
        ExprAssign(
            cf,
            ~ExprOp('fcom_c0', arg1, arg2)
        )
    )
    e.append(
        ExprAssign(
            zf,
            ExprOp('fcom_c3', arg1, arg2)
        )
    )
    e.append(ExprAssign(of, ExprInt(0, 1)))
    return e, []


def clz(ir, instr, arg1, arg2):
    e = []
    e.append(ExprAssign(arg1, ExprOp('cntleadzeros', arg2)))
    return e, []

def casp(ir, instr, arg1, arg2, arg3):
    # XXX TODO: memory barrier
    e = []
    if arg1.size == 32:
        regs = gpregs32_expr
    else:
        regs = gpregs64_expr
    index1 = regs.index(arg1)
    index2 = regs.index(arg2)

    # TODO endianness
    comp_value = ExprCompose(regs[index1], regs[index1 + 1])
    new_value = ExprCompose(regs[index2], regs[index2 + 1])
    assert arg3.is_op('preinc')
    ptr = arg3.args[0]
    data = ExprMem(ptr, comp_value.size)

    loc_store = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_do = ExprLoc(ir.loc_db.add_location(), ir.IRDst.size)
    loc_next = ExprLoc(ir.get_next_loc_key(instr), ir.IRDst.size)

    e.append(ExprAssign(ir.IRDst, ExprCond(ExprOp("FLAG_EQ_CMP", data, comp_value), loc_do, loc_store)))

    e_store = []
    e_store.append(ExprAssign(data, new_value))
    e_store.append(ExprAssign(ir.IRDst, loc_do))
    blk_store = IRBlock(ir.loc_db, loc_store.loc_key, [AssignBlock(e_store, instr)])

    e_do = []
    e_do.append(ExprAssign(regs[index1], data[:data.size // 2]))
    e_do.append(ExprAssign(regs[index1 + 1], data[data.size // 2:]))
    e_do.append(ExprAssign(ir.IRDst, loc_next))
    blk_do = IRBlock(ir.loc_db, loc_do.loc_key, [AssignBlock(e_do, instr)])

    return e, [blk_store, blk_do]


@sbuild.parse
def umaddl(arg1, arg2, arg3, arg4):
    arg1 = arg2.zeroExtend(arg1.size) * arg3.zeroExtend(arg1.size) + arg4


@sbuild.parse
def umsubbl(arg1, arg2, arg3, arg4):
    arg1 = arg2.zeroExtend(arg1.size) * arg3.zeroExtend(arg1.size) + arg4


@sbuild.parse
def umull(arg1, arg2, arg3):
    arg1 = (arg2.zeroExtend(64) * arg3.zeroExtend(64))


@sbuild.parse
def umulh(arg1, arg2, arg3):
    arg1 = (arg2.zeroExtend(128) * arg3.zeroExtend(128))[64:]


@sbuild.parse
def smulh(arg1, arg2, arg3):
    arg1 = (arg2.signExtend(128) * arg3.signExtend(128))[64:]


@sbuild.parse
def smull(arg1, arg2, arg3):
    arg1 = (arg2.signExtend(64) * arg3.signExtend(64))[64:]



mnemo_func = sbuild.functions
mnemo_func.update({
    'and': and_l,
    'adds': adds,
    'ands': ands,
    'tst': tst,
    'subs': subs,
    'cmp': cmp,
    'cmn': cmn,
    'movk': movk,
    'ccmp': ccmp,
    'csinc': csinc,
    'csinv': csinv,
    'csneg': csneg,
    'cset': cset,
    'csetm': csetm,

    'b.ne': b_ne,
    'b.eq': b_eq,
    'b.ge': b_ge,
    'b.mi': b_mi,
    'b.pl': b_pl,
    'b.gt': b_gt,
    'b.cc': b_cc,
    'b.cs': b_cs,
    'b.hi': b_hi,
    'b.le': b_le,
    'b.ls': b_ls,
    'b.lt': b_lt,

    'bics': bics,

    'ret': ret,
    'stp': stp,
    'ldp': ldp,

    'ldr': ldr,
    'ldrb': ldrb,
    'ldrh': ldrh,

    'ldur': ldr,
    'ldurb': ldrb,
    'ldursb': ldrsb,
    'ldurh': ldrh,
    'ldursh': ldrsh,
    'ldursw': ldrsw,

    'ldrsb': ldrsb,
    'ldrsh': ldrsh,
    'ldrsw': ldrsw,

    'ldar': ldr, # TODO memory barrier
    'ldarb': ldrb,

    'ldaxrb': ldaxrb,
    'stlxrb': stlxrb,

    'stlr': l_str, # TODO memory barrier
    'stlrb': stlrb,

    'stlxr': stlxr,
    'ldxr': ldxr,

    'str': l_str,
    'strb': strb,
    'strh': strh,

    'stur': l_str,
    'sturb': strb,
    'sturh': strh,


    'bfm': bfm,
    'sbfm': sbfm,
    'ubfm': ubfm,

    'extr': extr,
    'rev': rev,
    'rev16': rev16,

    'msr': msr,
    'mrs': mrs,

    'adc': adc,
    'adcs': adcs,
    'sbc': sbc,
    'sbcs': sbcs,

    'fmov': fmov,
    'fadd': fadd,
    'fsub': fsub,
    'fmul': fmul,
    'fdiv': fdiv,
    'fabs': fabs,
    'fmadd': fmadd,
    'fmsub': fmsub,
    'fcvt': fcvt,
    'scvtf': scvtf,
    'ucvtf': ucvtf,
    'fcvtzs': fcvtzs,
    'fcvtzu': fcvtzu,
    'fcmpe': fcmpe,
    'clz': clz,

    # XXX TODO: memory barrier
    'casp':casp,
    'caspl':casp,
    'caspa':casp,
    'caspal':casp,

    'yield': nop,
    'isb': isb,
    'dsb': dsb,
    'dmb': dmb,
    'tlbi': tlbi,
    'clrex': clrex,
    'ic': ic
})


def get_mnemo_expr(ir, instr, *args):
    if not instr.name.lower() in mnemo_func:
        raise NotImplementedError('unknown mnemo %s' % instr)
    instr, extra_ir = mnemo_func[instr.name.lower()](ir, instr, *args)
    return instr, extra_ir


class aarch64info(object):
    mode = "aarch64"
    # offset


class Lifter_Aarch64l(Lifter):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_aarch64, "l", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 64)
        self.addrsize = 64

    def get_ir(self, instr):
        args = instr.args
        if len(args) and isinstance(args[-1], ExprOp):
            if (args[-1].op in ['<<', '>>', '<<a', 'a>>', '<<<', '>>>'] and
               isinstance(args[-1].args[-1], ExprId)):
                args[-1] = ExprOp(args[-1].op,
                                          args[-1].args[0],
                                          args[-1].args[-1][:8].zeroExtend(32))
        instr_ir, extra_ir = get_mnemo_expr(self, instr, *args)
        self.mod_pc(instr, instr_ir, extra_ir)
        instr_ir, extra_ir = self.del_dst_zr(instr, instr_ir, extra_ir)
        return instr_ir, extra_ir

    def expr_fix_regs_for_mode(self, e):
        return e.replace_expr(replace_regs)

    def expraff_fix_regs_for_mode(self, e):
        dst = self.expr_fix_regs_for_mode(e.dst)
        src = self.expr_fix_regs_for_mode(e.src)
        return ExprAssign(dst, src)

    def irbloc_fix_regs_for_mode(self, irblock, mode=64):
        irs = []
        for assignblk in irblock:
            new_assignblk = dict(assignblk)
            for dst, src in viewitems(assignblk):
                del(new_assignblk[dst])
                # Special case for 64 bits:
                # If destination is a 32 bit reg, zero extend the 64 bit reg
                if (isinstance(dst, ExprId) and
                    dst.size == 32 and
                    dst in replace_regs):
                    src = src.zeroExtend(64)
                    dst = replace_regs[dst].arg

                dst = self.expr_fix_regs_for_mode(dst)
                src = self.expr_fix_regs_for_mode(src)
                new_assignblk[dst] = src
            irs.append(AssignBlock(new_assignblk, assignblk.instr))
        return IRBlock(self.loc_db, irblock.loc_key, irs)

    def mod_pc(self, instr, instr_ir, extra_ir):
        "Replace PC by the instruction's offset"
        cur_offset = ExprInt(instr.offset, 64)
        pc_fixed = {self.pc: cur_offset}
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = ExprAssign(dst, src)

        for idx, irblock in enumerate(extra_ir):
            extra_ir[idx] = irblock.modify_exprs(lambda expr: expr.replace_expr(pc_fixed) \
                                                 if expr != self.pc else expr,
                                                 lambda expr: expr.replace_expr(pc_fixed))


    def del_dst_zr(self, instr, instr_ir, extra_ir):
        "Writes to zero register are discarded"
        regs_to_fix = [WZR, XZR]
        instr_ir = [expr for expr in instr_ir if expr.dst not in regs_to_fix]

        new_irblocks = []
        for irblock in extra_ir:
            irs = []
            for assignblk in irblock:
                new_dsts = {
                    dst:src for dst, src in viewitems(assignblk)
                    if dst not in regs_to_fix
                }
                irs.append(AssignBlock(new_dsts, assignblk.instr))
            new_irblocks.append(IRBlock(self.loc_db, irblock.loc_key, irs))

        return instr_ir, new_irblocks


class Lifter_Aarch64b(Lifter_Aarch64l):

    def __init__(self, loc_db):
        Lifter.__init__(self, mn_aarch64, "b", loc_db)
        self.pc = PC
        self.sp = SP
        self.IRDst = ExprId('IRDst', 64)
        self.addrsize = 64
