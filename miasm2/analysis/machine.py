#!/usr/bin/env python
#-*- coding:utf-8 -*-


class Machine(object):
    """Abstract machine architecture to restrict architecture dependant code"""

    __dis_engine = None   # Disassembly engine
    __mn = None           # Machine instance
    __ira = None          # IR analyser
    __jitter = None       # Jit engine
    __gdbserver = None    # GdbServer handler

    __available = ["arm", "armt", "sh4", "x86_16", "x86_32", "x86_64", "msp430",
                   "mips32b", "mips32l"]


    def __init__(self, machine_name):

        dis_engine = None
        mn = None
        ira = None
        jitter = None
        gdbserver = None

        # Import on runtime for performance issue
        if machine_name == "arml":
            from miasm2.arch.arm.disasm import dis_arml as dis_engine
            from miasm2.arch.arm.arch import mn_arm as mn
            from miasm2.arch.arm.ira import ir_a_arml as ira
            from miasm2.arch.arm.jit import jitter_arml as jitter
        elif machine_name == "armb":
            from miasm2.arch.arm.disasm import dis_armb as dis_engine
            from miasm2.arch.arm.arch import mn_arm as mn
            from miasm2.arch.arm.ira import ir_a_armb as ira
            from miasm2.arch.arm.jit import jitter_armb as jitter
        elif machine_name == "armtl":
            from miasm2.arch.arm.disasm import dis_armtl as dis_engine
            from miasm2.arch.arm.arch import mn_armt as mn
            from miasm2.arch.arm.ira import ir_a_armtl as ira
        elif machine_name == "armtb":
            from miasm2.arch.arm.disasm import dis_armtb as dis_engine
            from miasm2.arch.arm.arch import mn_armt as mn
            from miasm2.arch.arm.ira import ir_a_armtb as ira
        elif machine_name == "sh4":
            from miasm2.arch.sh4.disasm import dis_sha4 as dis_engine
            from miasm2.arch.sh4.arch import mn_sh4 as mn
            from miasm2.arch.sh4.ira import ir_a_sh4 as ira
        elif machine_name == "x86_16":
            from miasm2.arch.x86.disasm import dis_x86_16 as dis_engine
            from miasm2.arch.x86.arch import mn_x86 as mn
            from miasm2.arch.x86.ira import ir_a_x86_16 as ira
            from miasm2.arch.x86.jit import jitter_x86_16 as jitter
        elif machine_name == "x86_32":
            from miasm2.arch.x86.disasm import dis_x86_32 as dis_engine
            from miasm2.arch.x86.arch import mn_x86 as mn
            from miasm2.arch.x86.ira import ir_a_x86_32 as ira
            from miasm2.arch.x86.jit import jitter_x86_32 as jitter
            from miasm2.analysis.gdbserver import GdbServer_x86_32 as gdbserver
        elif machine_name == "x86_64":
            from miasm2.arch.x86.disasm import dis_x86_64 as dis_engine
            from miasm2.arch.x86.arch import mn_x86 as mn
            from miasm2.arch.x86.ira import ir_a_x86_64 as ira
            from miasm2.arch.x86.jit import jitter_x86_64 as jitter
        elif machine_name == "msp430":
            from miasm2.arch.msp430.disasm import dis_msp430 as dis_engine
            from miasm2.arch.msp430.arch import mn_msp430 as mn
            from miasm2.arch.msp430.ira import ir_a_msp430 as ira
            from miasm2.arch.msp430.jit import jitter_msp430 as jitter
            from miasm2.analysis.gdbserver import GdbServer_msp430 as gdbserver
        elif machine_name == "mips32b":
            from miasm2.arch.mips32.disasm import dis_mips32b as dis_engine
            from miasm2.arch.mips32.arch import mn_mips32 as mn
            from miasm2.arch.mips32.ira import ir_a_mips32b as ira
            from miasm2.arch.mips32.jit import jitter_mips32b as jitter
        elif machine_name == "mips32l":
            from miasm2.arch.mips32.disasm import dis_mips32l as dis_engine
            from miasm2.arch.mips32.arch import mn_mips32 as mn
            from miasm2.arch.mips32.ira import ir_a_mips32l as ira
            from miasm2.arch.mips32.jit import jitter_mips32l as jitter
        else:
            raise ValueError('Unknown machine: %s' % machine_name)

        self.__dis_engine = dis_engine
        self.__mn = mn
        self.__ira = ira
        self.__jitter = jitter
        self.__gdbserver = gdbserver

    def get_dis_engine(self):
        return self.__dis_engine
    dis_engine = property(get_dis_engine)

    def get_mn(self):
        return self.__mn
    mn = property(get_mn)

    def get_ira(self):
        return self.__ira
    ira = property(get_ira)

    def get_jitter(self):
        return self.__jitter
    jitter = property(get_jitter)

    def get_gdbserver(self):
        return self.__gdbserver
    gdbserver = property(get_gdbserver)

    @classmethod
    def available_machine(cls):
        "Return a list of supported machines"
        return cls.__available
