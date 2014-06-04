#!/usr/bin/env python
#-*- coding:utf-8 -*-

import socket
import struct
import time
import logging
from StringIO import StringIO
import miasm2.analysis.debugging as debugging
from miasm2.jitter.jitload import ExceptionHandle


class GdbServer(object):

    "Debugguer binding for GDBServer protocol"

    general_registers_order = []
    general_registers_size = {}  # RegName : Size in octet
    status = "S05"

    def __init__(self, dbg, port=4455):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', port))
        server.listen(1)
        self.server = server
        self.dbg = dbg

    # Communication methods

    def compute_checksum(self, data):
        return chr(sum(map(ord, data)) % 256).encode("hex")

    def get_messages(self):
        all_data = ""
        data = self.sock.recv(4096)
        all_data += data
        while (len(data) == 4096 or data == ""):
            if data == "":
                # Avoid consuming CPU
                time.sleep(0.001)
                continue
            data = self.sock.recv(4096)
            all_data += data

        logging.debug("<- %r" % all_data)
        self.recv_queue += self.parse_messages(all_data)

    def parse_messages(self, data):
        buf = StringIO(data)

        msgs = []

        while (buf.tell() < buf.len):
            token = buf.read(1)
            if token == "+":
                continue
            if token == "-":
                raise NotImplementedError("Resend packet")
            if token == "$":
                packet_data = ""
                c = buf.read(1)
                while c != "#":
                    packet_data += c
                    c = buf.read(1)
                checksum = buf.read(2)
                if checksum != self.compute_checksum(packet_data):
                    raise ValueError("Incorrect checksum")

                msgs.append(packet_data)

        return msgs

    def send_string(self, s):
        self.send_queue.append("O" + s.encode("hex"))

    def process_messages(self):

        while self.recv_queue:
            msg = self.recv_queue.pop(0)
            buf = StringIO(msg)
            msg_type = buf.read(1)

            self.send_queue.append("+")

            if msg_type == "q":
                if msg.startswith("qSupported"):
                    self.send_queue.append("PacketSize=3fff")
                elif msg.startswith("qC"):
                    # Current thread
                    self.send_queue.append("")
                elif msg.startswith("qAttached"):
                    # Not supported
                    self.send_queue.append("")
                elif msg.startswith("qTStatus"):
                    # Not supported
                    self.send_queue.append("")
                elif msg.startswith("qfThreadInfo"):
                    # Not supported
                    self.send_queue.append("")
                else:
                    raise NotImplementedError()

            elif msg_type == "H":
                # Set current thread
                self.send_queue.append("OK")

            elif msg_type == "?":
                # Report why the target halted
                self.send_queue.append(self.status)  # TRAP signal

            elif msg_type == "g":
                # Report all general register values
                self.send_queue.append(self.report_general_register_values())

            elif msg_type == "p":
                # Read a specific register
                reg_num = int(buf.read(), 16)
                self.send_queue.append(self.read_register(reg_num))

            elif msg_type == "P":
                # Set a specific register
                reg_num, value = buf.read().split("=")
                reg_num = int(reg_num, 16)
                value = int(value.decode("hex")[::-1].encode("hex"), 16)
                self.set_register(reg_num, value)
                self.send_queue.append("OK")

            elif msg_type == "m":
                # Read memory
                addr, size = map(lambda x: int(x, 16), buf.read().split(","))
                self.send_queue.append(self.read_memory(addr, size))

            elif msg_type == "k":
                # Kill
                self.sock.close()
                exit(1)

            elif msg_type == "!":
                # Extending debugging will be used
                self.send_queue.append("OK")

            elif msg_type == "v":
                if msg == "vCont?":
                    # Is vCont supported ?
                    self.send_queue.append("")

            elif msg_type == "s":
                # Step
                self.dbg.step()
                self.send_queue.append("S05")  # TRAP signal

            elif msg_type == "Z":
                # Add breakpoint or watchpoint
                bp_type = buf.read(1)
                if bp_type == "0":
                    # Exec breakpoint
                    assert(buf.read(1) == ",")
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))

                    if size != 1:
                        raise NotImplementedError("Bigger size")
                    self.dbg.add_breakpoint(addr)
                    self.send_queue.append("OK")

                elif bp_type == "1":
                    # Hardware BP
                    assert(buf.read(1) == ",")
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))

                    self.dbg.add_memory_breakpoint(addr, size,
                                                   read=True,
                                                   write=True)
                    self.send_queue.append("OK")

                elif bp_type in ["2", "3", "4"]:
                    # Memory breakpoint
                    assert(buf.read(1) == ",")
                    read = bp_type in ["3", "4"]
                    write = bp_type in ["2", "4"]
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))

                    self.dbg.add_memory_breakpoint(addr, size,
                                                   read=read,
                                                   write=write)
                    self.send_queue.append("OK")

                else:
                    raise ValueError("Impossible value")

            elif msg_type == "z":
                # Remove breakpoint or watchpoint
                bp_type = buf.read(1)
                if bp_type == "0":
                    # Exec breakpoint
                    assert(buf.read(1) == ",")
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))

                    if size != 1:
                        raise NotImplementedError("Bigger size")
                    dbgsoft = self.dbg.get_breakpoint_by_addr(addr)
                    assert(len(dbgsoft) == 1)
                    self.dbg.remove_breakpoint(dbgsoft[0])
                    self.send_queue.append("OK")

                elif bp_type == "1":
                    # Hardware BP
                    assert(buf.read(1) == ",")
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))
                    self.dbg.remove_memory_breakpoint_by_addr_access(
                        addr, read=True, write=True)
                    self.send_queue.append("OK")

                elif bp_type in ["2", "3", "4"]:
                    # Memory breakpoint
                    assert(buf.read(1) == ",")
                    read = bp_type in ["3", "4"]
                    write = bp_type in ["2", "4"]
                    addr, size = map(
                        lambda x: int(x, 16), buf.read().split(","))

                    self.dbg.remove_memory_breakpoint_by_addr_access(
                        addr, read=read, write=write)
                    self.send_queue.append("OK")

                else:
                    raise ValueError("Impossible value")

            elif msg_type == "c":
                # Continue
                self.status = ""
                self.send_messages()
                ret = self.dbg.run()
                if isinstance(ret, debugging.DebugBreakpointSoft):
                    self.status = "S05"
                    self.send_queue.append("S05")  # TRAP signal
                elif isinstance(ret, ExceptionHandle):
                    if ret == ExceptionHandle.memoryBreakpoint():
                        self.status = "S05"
                        self.send_queue.append("S05")
                    else:
                        raise NotImplementedError("Unknown Except")
                else:
                    raise NotImplementedError()

            else:
                raise NotImplementedError(
                    "Not implemented: message type '%s'" % msg_type)

    def send_messages(self):
        for msg in self.send_queue:
            if msg == "+":
                data = "+"
            else:
                data = "$%s#%s" % (msg, self.compute_checksum(msg))
            logging.debug("-> %r" % data)
            self.sock.send(data)
        self.send_queue = []

    def main_loop(self):
        self.recv_queue = []
        self.send_queue = []

        self.send_string("Test\n")

        while (self.sock):
            self.get_messages()
            self.process_messages()
            self.send_messages()

    def run(self):
        self.sock, self.address = self.server.accept()
        self.main_loop()

    # Debugguer processing methods
    def report_general_register_values(self):
        s = ""
        for i in xrange(len(self.general_registers_order)):
            s += self.read_register(i)
        return s

    def read_register(self, reg_num):
        reg_name = self.general_registers_order[reg_num]
        reg_value = self.read_register_by_name(reg_name)
        size = self.general_registers_size[reg_name]

        pack_token = ""
        if size == 1:
            pack_token = "<B"
        elif size == 2:
            pack_token = "<H"
        elif size == 4:
            pack_token = "<I"
        elif size == 8:
            pack_token = "<Q"
        else:
            raise NotImplementedError("Unknown size")

        return struct.pack(pack_token, reg_value).encode("hex")

    def set_register(self, reg_num, value):
        reg_name = self.general_registers_order[reg_num]
        self.dbg.set_reg_value(reg_name, value)

    def read_register_by_name(self, reg_name):
        return self.dbg.get_reg_value(reg_name)

    def read_memory(self, addr, size):
        except_flag_vm = self.dbg.myjit.vm.vm_get_exception()
        try:
            return self.dbg.get_mem_raw(addr, size).encode("hex")
        except RuntimeError:
            self.dbg.myjit.vm.vm_set_exception(except_flag_vm)
            return "00" * size


class GdbServer_x86_32(GdbServer):

    "Extend GdbServer for x86 32bits purposes"

    general_registers_order = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI",
                               "EDI", "EIP", "EFLAGS", "CS", "SS", "DS", "ES",
                               "FS", "GS"]

    general_registers_size = {"EAX": 4,
                              "ECX": 4,
                              "EDX": 4,
                              "EBX": 4,
                              "ESP": 4,
                              "EBP": 4,
                              "ESI": 4,
                              "EDI": 4,
                              "EIP": 4,
                              "EFLAGS": 2,
                              "CS": 2,
                              "SS": 2,
                              "DS": 2,
                              "ES": 2,
                              "FS": 2,
                              "GS": 2}

    register_ignore = [
        "tf", "i_f", "nt", "rf", "vm", "ac", "vif", "vip", "i_d"]

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_x86_32, self).read_register_by_name

        # Assert EIP on pc jitter
        if reg_name == "EIP":
            return self.dbg.myjit.pc

        # EFLAGS case
        if reg_name == "EFLAGS":
            val = 0
            eflags_args = [
                "cf", 1, "pf", 0, "af", 0, "zf", "nf", "tf", "i_f", "df", "of"]
            eflags_args += ["nt", 0, "rf", "vm", "ac", "vif", "vip", "i_d"]
            eflags_args += [0] * 10

            for i, arg in enumerate(eflags_args):
                if isinstance(arg, str):
                    if arg not in self.register_ignore:
                        to_add = sup_func(arg)
                    else:
                        to_add = 0
                else:
                    to_add = arg

                val |= (to_add << i)
            return val
        else:
            return sup_func(reg_name)


class GdbServer_msp430(GdbServer):

    "Extend GdbServer for msp430 purposes"

    general_registers_order = ["PC", "SP", "SR", "R3", "R4", "R5", "R6", "R7",
                               "R8", "R9", "R10", "R11", "R12", "R13", "R14",
                               "R15"]

    general_registers_size = {"PC": 2,
                              "SP": 2,
                              "SR": 2,
                              "R3": 2,
                              "R2": 2,
                              "R5": 2,
                              "R6": 2,
                              "R7": 2,
                              "R8": 2,
                              "R9": 2,
                              "R10": 2,
                              "R11": 2,
                              "R12": 2,
                              "R13": 2,
                              "R12": 2,
                              "R15": 2}

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_msp430, self).read_register_by_name
        if reg_name == "SR":
            o = sup_func('res')
            o <<= 1
            o |= sup_func('of')
            o <<= 1
            o |= sup_func('scg1')
            o <<= 1
            o |= sup_func('scg0')
            o <<= 1
            o |= sup_func('osc')
            o <<= 1
            o |= sup_func('cpuoff')
            o <<= 1
            o |= sup_func('gie')
            o <<= 1
            o |= sup_func('nf')
            o <<= 1
            o |= sup_func('zf')
            o <<= 1
            o |= sup_func('cf')

            return o
        else:
            return sup_func(reg_name)

