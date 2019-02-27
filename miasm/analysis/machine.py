#-*- coding:utf-8 -*-


class Machine(object):
    """Abstract machine architecture to restrict architecture dependent code"""

    __dis_engine = None   # Disassembly engine
    __mn = None           # Machine instance
    __ira = None          # IR analyser
    __jitter = None       # Jit engine
    __gdbserver = None    # GdbServer handler

    __available = ["arml", "armb", "armtl", "armtb", "sh4", "x86_16", "x86_32",
                   "x86_64", "msp430", "mips32b", "mips32l",
                   "aarch64l", "aarch64b", "ppc32b", "mepl", "mepb"]


    def __init__(self, machine_name):

        dis_engine = None
        mn = None
        ira = None
        ir = None
        jitter = None
        gdbserver = None
        jit = None
        jitter = None
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
            from miasm.arch.arm.ira import ir_a_arml as ira
            from miasm.arch.arm.sem import ir_arml as ir
        elif machine_name == "armb":
            from miasm.arch.arm.disasm import dis_armb as dis_engine
            from miasm.arch.arm import arch
            try:
                from miasm.arch.arm import jit
                jitter = jit.jitter_armb
            except ImportError:
                pass
            mn = arch.mn_arm
            from miasm.arch.arm.ira import ir_a_armb as ira
            from miasm.arch.arm.sem import ir_armb as ir
        elif machine_name == "aarch64l":
            from miasm.arch.aarch64.disasm import dis_aarch64l as dis_engine
            from miasm.arch.aarch64 import arch
            try:
                from miasm.arch.aarch64 import jit
                jitter = jit.jitter_aarch64l
            except ImportError:
                pass
            mn = arch.mn_aarch64
            from miasm.arch.aarch64.ira import ir_a_aarch64l as ira
            from miasm.arch.aarch64.sem import ir_aarch64l as ir
        elif machine_name == "aarch64b":
            from miasm.arch.aarch64.disasm import dis_aarch64b as dis_engine
            from miasm.arch.aarch64 import arch
            try:
                from miasm.arch.aarch64 import jit
                jitter = jit.jitter_aarch64b
            except ImportError:
                pass
            mn = arch.mn_aarch64
            from miasm.arch.aarch64.ira import ir_a_aarch64b as ira
            from miasm.arch.aarch64.sem import ir_aarch64b as ir
        elif machine_name == "armtl":
            from miasm.arch.arm.disasm import dis_armtl as dis_engine
            from miasm.arch.arm import arch
            mn = arch.mn_armt
            from miasm.arch.arm.ira import ir_a_armtl as ira
            from miasm.arch.arm.sem import ir_armtl as ir
            try:
                from miasm.arch.arm import jit
                jitter = jit.jitter_armtl
            except ImportError:
                pass
        elif machine_name == "armtb":
            from miasm.arch.arm.disasm import dis_armtb as dis_engine
            from miasm.arch.arm import arch
            mn = arch.mn_armt
            from miasm.arch.arm.ira import ir_a_armtb as ira
            from miasm.arch.arm.sem import ir_armtb as ir
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
            from miasm.arch.x86.ira import ir_a_x86_16 as ira
            from miasm.arch.x86.sem import ir_x86_16 as ir
        elif machine_name == "x86_32":
            from miasm.arch.x86.disasm import dis_x86_32 as dis_engine
            from miasm.arch.x86 import arch
            try:
                from miasm.arch.x86 import jit
                jitter = jit.jitter_x86_32
            except ImportError:
                pass
            mn = arch.mn_x86
            from miasm.arch.x86.ira import ir_a_x86_32 as ira
            from miasm.arch.x86.sem import ir_x86_32 as ir
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
            from miasm.arch.x86.ira import ir_a_x86_64 as ira
            from miasm.arch.x86.sem import ir_x86_64 as ir
        elif machine_name == "msp430":
            from miasm.arch.msp430.disasm import dis_msp430 as dis_engine
            from miasm.arch.msp430 import arch
            try:
                from miasm.arch.msp430 import jit
                jitter = jit.jitter_msp430
            except ImportError:
                pass
            mn = arch.mn_msp430
            from miasm.arch.msp430.ira import ir_a_msp430 as ira
            from miasm.arch.msp430.sem import ir_msp430 as ir
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
            from miasm.arch.mips32.ira import ir_a_mips32b as ira
            from miasm.arch.mips32.sem import ir_mips32b as ir
        elif machine_name == "mips32l":
            from miasm.arch.mips32.disasm import dis_mips32l as dis_engine
            from miasm.arch.mips32 import arch
            try:
                from miasm.arch.mips32 import jit
                jitter = jit.jitter_mips32l
            except ImportError:
                pass
            mn = arch.mn_mips32
            from miasm.arch.mips32.ira import ir_a_mips32l as ira
            from miasm.arch.mips32.sem import ir_mips32l as ir
        elif machine_name == "ppc32b":
            from miasm.arch.ppc.disasm import dis_ppc32b as dis_engine
            from miasm.arch.ppc import arch
            try:
                from miasm.arch.ppc import jit
                jitter = jit.jitter_ppc32b
            except ImportError:
                pass
            mn = arch.mn_ppc
            from miasm.arch.ppc.ira import ir_a_ppc32b as ira
            from miasm.arch.ppc.sem import ir_ppc32b as ir
        elif machine_name == "mepb":
            from miasm.arch.mep.disasm import dis_mepb as dis_engine
            from miasm.arch.mep import arch
            try:
                from miasm.arch.mep import jit
                jitter = jit.jitter_mepb
            except ImportError:
                pass
            mn = arch.mn_mep
            from miasm.arch.mep.ira import ir_a_mepb as ira
            from miasm.arch.mep.sem import ir_mepb as ir
        elif machine_name == "mepl":
            from miasm.arch.mep.disasm import dis_mepl as dis_engine
            from miasm.arch.mep import arch
            try:
                from miasm.arch.mep import jit
                jitter = jit.jitter_mepl
            except ImportError:
                pass
            mn = arch.mn_mep
            from miasm.arch.mep.ira import ir_a_mepl as ira
            from miasm.arch.mep.sem import ir_mepl as ir
        else:
            raise ValueError('Unknown machine: %s' % machine_name)

        # Loggers
        if jit is not None:
            log_jit = jit.log
        log_arch = arch.log

        self.__dis_engine = dis_engine
        self.__mn = mn
        self.__ira = ira
        self.__jitter = jitter
        self.__gdbserver = gdbserver
        self.__log_jit = log_jit
        self.__log_arch = log_arch
        self.__base_expr = arch.base_expr
        self.__ir = ir
        self.__name = machine_name

    @property
    def dis_engine(self):
        return self.__dis_engine

    @property
    def mn(self):
        return self.__mn

    @property
    def ira(self):
        return self.__ira

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
