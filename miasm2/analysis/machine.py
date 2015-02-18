#!/usr/bin/env python
#-*- coding:utf-8 -*-


class Machine(object):
    """Abstract machine architecture to restrict architecture dependant code"""

    __dis_engine = None   # Disassembly engine
    __mn = None           # Machine instance
    __ira = None          # IR analyser
    __jitter = None       # Jit engine
    __gdbserver = None    # GdbServer handler

    __available = ["arml", "armb", "armtl", "armtb", "sh4", "x86_16", "x86_32",
                   "x86_64", "msp430", "mips32b", "mips32l"]


    def __init__(self, machine_name):

        dis_engine = None
        mn = None
        ira = None
        jitter = None
        gdbserver = None
        jit = None
        jitter = None
        log_jit = None
        log_arch = None

        # Import on runtime for performance issue
        if machine_name == "arml":
            from miasm2.arch.arm.disasm import dis_arml as dis_engine
            from miasm2.arch.arm import arch, jit
            mn = arch.mn_arm
            jitter = jit.jitter_arml
            from miasm2.arch.arm.ira import ir_a_arml as ira
        elif machine_name == "armb":
            from miasm2.arch.arm.disasm import dis_armb as dis_engine
            from miasm2.arch.arm import arch, jit
            mn = arch.mn_arm
            jitter = jit.jitter_armb
            from miasm2.arch.arm.ira import ir_a_armb as ira
        elif machine_name == "armtl":
            from miasm2.arch.arm.disasm import dis_armtl as dis_engine
            from miasm2.arch.arm import arch
            mn = arch.mn_armt
            from miasm2.arch.arm.ira import ir_a_armtl as ira
        elif machine_name == "armtb":
            from miasm2.arch.arm.disasm import dis_armtb as dis_engine
            from miasm2.arch.arm import arch
            mn = arch.mn_armt
            from miasm2.arch.arm.ira import ir_a_armtb as ira
        elif machine_name == "sh4":
            from miasm2.arch.sh4 import arch
            mn = arch.mn_sh4
        elif machine_name == "x86_16":
            from miasm2.arch.x86.disasm import dis_x86_16 as dis_engine
            from miasm2.arch.x86 import arch, jit
            mn = arch.mn_x86
            jitter = jit.jitter_x86_16
            from miasm2.arch.x86.ira import ir_a_x86_16 as ira
        elif machine_name == "x86_32":
            from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine
            from miasm2.arch.x86 import arch, jit
            mn = arch.mn_x86
            jitter = jit.jitter_x86_32
            from miasm2.arch.x86.ira import ir_a_x86_32 as ira
            from miasm2.analysis.gdbserver import GdbServer_x86_32 as gdbserver
        elif machine_name == "x86_64":
            from miasm2.arch.x86.disasm import dis_x86_64 as dis_engine
            from miasm2.arch.x86 import arch, jit
            mn = arch.mn_x86
            jitter = jit.jitter_x86_64
            from miasm2.arch.x86.ira import ir_a_x86_64 as ira
        elif machine_name == "msp430":
            from miasm2.arch.msp430.disasm import dis_msp430 as dis_engine
            from miasm2.arch.msp430 import arch, jit
            mn = arch.mn_msp430
            jitter = jit.jitter_msp430
            from miasm2.arch.msp430.ira import ir_a_msp430 as ira
            from miasm2.analysis.gdbserver import GdbServer_msp430 as gdbserver
        elif machine_name == "mips32b":
            from miasm2.arch.mips32.disasm import dis_mips32b as dis_engine
            from miasm2.arch.mips32 import arch, jit
            mn = arch.mn_mips32
            jitter = jit.jitter_mips32b
            from miasm2.arch.mips32.ira import ir_a_mips32b as ira
        elif machine_name == "mips32l":
            from miasm2.arch.mips32.disasm import dis_mips32l as dis_engine
            from miasm2.arch.mips32 import arch, jit
            mn = arch.mn_mips32
            jitter = jit.jitter_mips32l
            from miasm2.arch.mips32.ira import ir_a_mips32l as ira
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

    @classmethod
    def available_machine(cls):
        "Return a list of supported machines"
        return cls.__available
