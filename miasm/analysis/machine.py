#-*- coding:utf-8 -*-
import warnings


class Machine(object):
    """Abstract machine architecture to restrict architecture dependent code"""

    __dis_engine = None   # Disassembly engine
    __mn = None           # Machine instance
    __lifter_model_call = None          # IR analyser
    __jitter = None       # Jit engine
    __gdbserver = None    # GdbServer handler

    __available = ["arml", "armb", "armtl", "armtb", "sh4", "x86_16", "x86_32",
                   "x86_64", "msp430", "mips32b", "mips32l",
                   "aarch64l", "aarch64b", "ppc32b", "mepl", "mepb"]


    def __init__(self, machine_name):

        dis_engine = None
        mn = None
        lifter_model_call = None
        ir = None
        jitter = None
        gdbserver = None
        jit = None
        log_jit = None
        log_arch = None

        # Import on runtime for performance issue
        if machine_name == "arml":
            from miasm.arch.arm.disasm import dis_arml as dis_engine
            from miasm.arch.arm import arch
            try:
                from miasm.arch.arm import jit
                jitter = jit.jitter_arml
            except ImportError:
                pass
            mn = arch.mn_arm
            from miasm.arch.arm.lifter_model_call import LifterModelCallArml as lifter_model_call
            from miasm.arch.arm.sem import Lifter_Arml as lifter
        elif machine_name == "armb":
            from miasm.arch.arm.disasm import dis_armb as dis_engine
            from miasm.arch.arm import arch
            try:
                from miasm.arch.arm import jit
                jitter = jit.jitter_armb
            except ImportError:
                pass
            mn = arch.mn_arm
            from miasm.arch.arm.lifter_model_call import LifterModelCallArmb as lifter_model_call
            from miasm.arch.arm.sem import Lifter_Armb as lifter
        elif machine_name == "aarch64l":
            from miasm.arch.aarch64.disasm import dis_aarch64l as dis_engine
            from miasm.arch.aarch64 import arch
            try:
                from miasm.arch.aarch64 import jit
                jitter = jit.jitter_aarch64l
            except ImportError:
                pass
            mn = arch.mn_aarch64
            from miasm.arch.aarch64.lifter_model_call import LifterModelCallAarch64l as lifter_model_call
            from miasm.arch.aarch64.sem import Lifter_Aarch64l as lifter
        elif machine_name == "aarch64b":
            from miasm.arch.aarch64.disasm import dis_aarch64b as dis_engine
            from miasm.arch.aarch64 import arch
            try:
                from miasm.arch.aarch64 import jit
                jitter = jit.jitter_aarch64b
            except ImportError:
                pass
            mn = arch.mn_aarch64
            from miasm.arch.aarch64.lifter_model_call import LifterModelCallAarch64b as lifter_model_call
            from miasm.arch.aarch64.sem import Lifter_Aarch64b as lifter
        elif machine_name == "armtl":
            from miasm.arch.arm.disasm import dis_armtl as dis_engine
            from miasm.arch.arm import arch
            mn = arch.mn_armt
            from miasm.arch.arm.lifter_model_call import LifterModelCallArmtl as lifter_model_call
            from miasm.arch.arm.sem import Lifter_Armtl as lifter
            try:
                from miasm.arch.arm import jit
                jitter = jit.jitter_armtl
            except ImportError:
                pass
        elif machine_name == "armtb":
            from miasm.arch.arm.disasm import dis_armtb as dis_engine
            from miasm.arch.arm import arch
            mn = arch.mn_armt
            from miasm.arch.arm.lifter_model_call import LifterModelCallArmtb as lifter_model_call
            from miasm.arch.arm.sem import Lifter_Armtb as lifter
        elif machine_name == "sh4":
            from miasm.arch.sh4 import arch
            mn = arch.mn_sh4
        elif machine_name == "x86_16":
            from miasm.arch.x86.disasm import dis_x86_16 as dis_engine
            from miasm.arch.x86 import arch
            try:
                from miasm.arch.x86 import jit
                jitter = jit.jitter_x86_16
            except ImportError:
                pass
            mn = arch.mn_x86
            from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_16 as lifter_model_call
            from miasm.arch.x86.sem import Lifter_X86_16 as lifter
        elif machine_name == "x86_32":
            from miasm.arch.x86.disasm import dis_x86_32 as dis_engine
            from miasm.arch.x86 import arch
            try:
                from miasm.arch.x86 import jit
                jitter = jit.jitter_x86_32
            except ImportError:
                pass
            mn = arch.mn_x86
            from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_32 as lifter_model_call
            from miasm.arch.x86.sem import Lifter_X86_32 as lifter
            try:
                from miasm.analysis.gdbserver import GdbServer_x86_32 as gdbserver
            except ImportError:
                pass
        elif machine_name == "x86_64":
            from miasm.arch.x86.disasm import dis_x86_64 as dis_engine
            from miasm.arch.x86 import arch
            try:
                from miasm.arch.x86 import jit
                jitter = jit.jitter_x86_64
            except ImportError:
                pass
            mn = arch.mn_x86
            from miasm.arch.x86.lifter_model_call import LifterModelCall_x86_64 as lifter_model_call
            from miasm.arch.x86.sem import Lifter_X86_64 as lifter
        elif machine_name == "msp430":
            from miasm.arch.msp430.disasm import dis_msp430 as dis_engine
            from miasm.arch.msp430 import arch
            try:
                from miasm.arch.msp430 import jit
                jitter = jit.jitter_msp430
            except ImportError:
                pass
            mn = arch.mn_msp430
            from miasm.arch.msp430.lifter_model_call import LifterModelCallMsp430 as lifter_model_call
            from miasm.arch.msp430.sem import Lifter_MSP430 as lifter
            try:
                from miasm.analysis.gdbserver import GdbServer_msp430 as gdbserver
            except ImportError:
                pass
        elif machine_name == "mips32b":
            from miasm.arch.mips32.disasm import dis_mips32b as dis_engine
            from miasm.arch.mips32 import arch
            try:
                from miasm.arch.mips32 import jit
                jitter = jit.jitter_mips32b
            except ImportError:
                pass
            mn = arch.mn_mips32
            from miasm.arch.mips32.lifter_model_call import LifterModelCallMips32b as lifter_model_call
            from miasm.arch.mips32.sem import Lifter_Mips32b as lifter
        elif machine_name == "mips32l":
            from miasm.arch.mips32.disasm import dis_mips32l as dis_engine
            from miasm.arch.mips32 import arch
            try:
                from miasm.arch.mips32 import jit
                jitter = jit.jitter_mips32l
            except ImportError:
                pass
            mn = arch.mn_mips32
            from miasm.arch.mips32.lifter_model_call import LifterModelCallMips32l as lifter_model_call
            from miasm.arch.mips32.sem import Lifter_Mips32l as lifter
        elif machine_name == "ppc32b":
            from miasm.arch.ppc.disasm import dis_ppc32b as dis_engine
            from miasm.arch.ppc import arch
            try:
                from miasm.arch.ppc import jit
                jitter = jit.jitter_ppc32b
            except ImportError:
                pass
            mn = arch.mn_ppc
            from miasm.arch.ppc.lifter_model_call import LifterModelCallPpc32b as lifter_model_call
            from miasm.arch.ppc.sem import Lifter_PPC32b as lifter
        elif machine_name == "mepb":
            from miasm.arch.mep.disasm import dis_mepb as dis_engine
            from miasm.arch.mep import arch
            try:
                from miasm.arch.mep import jit
                jitter = jit.jitter_mepb
            except ImportError:
                pass
            mn = arch.mn_mep
            from miasm.arch.mep.lifter_model_call import LifterModelCallMepb as lifter_model_call
            from miasm.arch.mep.sem import Lifter_MEPb as lifter
        elif machine_name == "mepl":
            from miasm.arch.mep.disasm import dis_mepl as dis_engine
            from miasm.arch.mep import arch
            try:
                from miasm.arch.mep import jit
                jitter = jit.jitter_mepl
            except ImportError:
                pass
            mn = arch.mn_mep
            from miasm.arch.mep.lifter_model_call import LifterModelCallMepl as lifter_model_call
            from miasm.arch.mep.sem import Lifter_MEPl as lifter
        else:
            raise ValueError('Unknown machine: %s' % machine_name)

        # Loggers
        if jit is not None:
            log_jit = jit.log
        log_arch = arch.log

        self.__dis_engine = dis_engine
        self.__mn = mn
        self.__lifter_model_call = lifter_model_call
        self.__jitter = jitter
        self.__gdbserver = gdbserver
        self.__log_jit = log_jit
        self.__log_arch = log_arch
        self.__base_expr = arch.base_expr
        self.__lifter = lifter
        self.__name = machine_name

    @property
    def dis_engine(self):
        return self.__dis_engine

    @property
    def mn(self):
        return self.__mn

    @property
    def lifter(self):
        return self.__lifter

    @property
    def lifter_model_call(self):
        return self.__lifter_model_call

    @property
    def ir(self):
        return self.__ir

    @property
    def jitter(self):
        return self.__jitter

    @property
    def gdbserver(self):
        return self.__gdbserver

    @property
    def log_jit(self):
        return self.__log_jit

    @property
    def log_arch(self):
        return self.__log_arch

    @property
    def base_expr(self):
        return self.__base_expr

    @property
    def name(self):
        return self.__name

    @classmethod
    def available_machine(cls):
        "Return a list of supported machines"
        return cls.__available

    @property
    def ira(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter_model_call" instead of ".ira"')
        return self.lifter_model_call

    @property
    def ir(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir"')
        return self.lifter
