from __future__ import print_function
#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
from hashlib import md5
import warnings

from future.utils import viewvalues

from miasm.core.asmblock import disasmEngine, AsmBlockBad
from miasm.core.interval import interval
from miasm.core.utils import BoundedDict
from miasm.expression.expression import LocKey
from miasm.jitter.csts import *

class JitCore(object):

    "JiT management. This is an abstract class"

    # Jitted function's name
    FUNCNAME = "block_entry"

    jitted_block_delete_cb = None
    jitted_block_max_size = 10000

    def __init__(self, lifter, bin_stream):
        """Initialise a JitCore instance.
        @lifter: Lifter instance for current architecture
        @bin_stream: bin_stream instance
        """
        # Arch related
        self.lifter = lifter
        self.ircfg = self.lifter.new_ircfg()
        self.arch_name = "%s%s" % (self.lifter.arch.name, self.lifter.attrib)

        # Structures for block tracking
        self.offset_to_jitted_func = BoundedDict(self.jitted_block_max_size,
                                       delete_cb=self.jitted_block_delete_cb)
        self.loc_key_to_block = {}
        self.blocks_mem_interval = interval()

        # Logging & options
        self.log_mn = False
        self.log_regs = False
        self.log_newbloc = False
        self.options = {"jit_maxline": 50,  # Maximum number of line jitted
                        "max_exec_per_call": 0 # 0 means no limit
                        }

        # Disassembly Engine
        self.split_dis = set()
        self.mdis = disasmEngine(
            lifter.arch, lifter.attrib, bin_stream,
            lines_wd=self.options["jit_maxline"],
            loc_db=lifter.loc_db,
            follow_call=False,
            dontdis_retcall=False,
            split_dis=self.split_dis,
        )

    @property
    def ir_arch(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir_arch"')
        return self.lifter


    def set_options(self, **kwargs):
        "Set options relative to the backend"
        self.options.update(kwargs)

    def clear_jitted_blocks(self):
        "Reset all jitted blocks"
        self.offset_to_jitted_func.clear()
        self.loc_key_to_block.clear()
        self.blocks_mem_interval = interval()

    def add_disassembly_splits(self, *args):
        """The disassembly engine will stop on address in args if they
        are not at the block beginning"""
        self.split_dis.update(set(args))

    def remove_disassembly_splits(self, *args):
        """The disassembly engine will no longer stop on address in args"""
        self.split_dis.difference_update(set(args))

    def load(self):
        "Initialise the Jitter"
        raise NotImplementedError("Abstract class")

    def set_block_min_max(self, cur_block):
        "Update cur_block to set min/max address"

        if cur_block.lines:
            cur_block.ad_min = cur_block.lines[0].offset
            cur_block.ad_max = cur_block.lines[-1].offset + cur_block.lines[-1].l
        else:
            # 1 byte block for unknown mnemonic
            offset = self.lifter.loc_db.get_location_offset(cur_block.loc_key)
            cur_block.ad_min = offset
            cur_block.ad_max = offset+1


    def add_block_to_mem_interval(self, vm, block):
        "Update vm to include block addresses in its memory range"
        self.blocks_mem_interval += interval([(block.ad_min, block.ad_max - 1)])

        vm.reset_code_bloc_pool()
        for a, b in self.blocks_mem_interval:
            vm.add_code_bloc(a, b + 1)

    def add_block(self, block):
        """Add a block to JiT and JiT it.
        @block: asm_bloc to add
        """
        raise NotImplementedError("Abstract class")

    def disasm_and_jit_block(self, addr, vm):
        """Disassemble a new block and JiT it
        @addr: address of the block to disassemble (LocKey or int)
        @vm: VmMngr instance
        """

        # Get the block
        if isinstance(addr, LocKey):
            addr = self.lifter.loc_db.get_location_offset(addr)
            if addr is None:
                raise RuntimeError("Unknown offset for LocKey")

        # Prepare disassembler
        self.mdis.lines_wd = self.options["jit_maxline"]

        # Disassemble it
        cur_block = self.mdis.dis_block(addr)
        if isinstance(cur_block, AsmBlockBad):
            return cur_block
        # Logging
        if self.log_newbloc:
            print(cur_block)

        # Update label -> block
        self.loc_key_to_block[cur_block.loc_key] = cur_block

        # Store min/max block address needed in jit automod code
        self.set_block_min_max(cur_block)

        # JiT it
        self.add_block(cur_block)

        # Update jitcode mem range
        self.add_block_to_mem_interval(vm, cur_block)
        return cur_block

    def run_at(self, cpu, offset, stop_offsets):
        """Run from the starting address @offset.
        Execution will stop if:
        - max_exec_per_call option is reached
        - a new, yet unknown, block is reached after the execution of block at
          address @offset
        - an address in @stop_offsets is reached
        @cpu: JitCpu instance
        @offset: starting address (int)
        @stop_offsets: set of address on which the jitter must stop
        """

        if offset is None:
            offset = getattr(cpu, self.lifter.pc.name)

        if offset not in self.offset_to_jitted_func:
            # Need to JiT the block
            cur_block = self.disasm_and_jit_block(offset, cpu.vmmngr)
            if isinstance(cur_block, AsmBlockBad):
                errno = cur_block.errno
                if errno == AsmBlockBad.ERROR_IO:
                    cpu.vmmngr.set_exception(EXCEPT_ACCESS_VIOL)
                elif errno == AsmBlockBad.ERROR_CANNOT_DISASM:
                    cpu.set_exception(EXCEPT_UNK_MNEMO)
                else:
                    raise RuntimeError("Unhandled disasm result %r" % errno)
                return offset

        # Run the block and update cpu/vmmngr state
        return self.exec_wrapper(offset, cpu, self.offset_to_jitted_func.data,
                                 stop_offsets,
                                 self.options["max_exec_per_call"])

    def blocks_to_memrange(self, blocks):
        """Return an interval instance standing for blocks addresses
        @blocks: list of AsmBlock instances
        """

        mem_range = interval()
        mem_range = interval([(block.ad_min, block.ad_max - 1) for block in blocks])
        return mem_range

    def __updt_jitcode_mem_range(self, vm):
        """Rebuild the VM blocks address memory range
        @vm: VmMngr instance
        """

        # Reset the current pool
        vm.reset_code_bloc_pool()

        # Add blocks in the pool
        for start, stop in self.blocks_mem_interval:
            vm.add_code_bloc(start, stop + 1)

    def del_block_in_range(self, ad1, ad2):
        """Find and remove jitted block in range [ad1, ad2].
        Return the list of block removed.
        @ad1: First address
        @ad2: Last address
        """

        # Find concerned blocks
        modified_blocks = set()
        for block in viewvalues(self.loc_key_to_block):
            if not block.lines:
                continue
            if block.ad_max <= ad1 or block.ad_min >= ad2:
                # Block not modified
                pass
            else:
                # Modified blocks
                modified_blocks.add(block)

        # Remove modified blocks
        for block in modified_blocks:
            try:
                for irblock in block.blocks:
                    # Remove offset -> jitted block link
                    offset = self.lifter.loc_db.get_location_offset(irblock.loc_key)
                    if offset in self.offset_to_jitted_func:
                        del(self.offset_to_jitted_func[offset])

            except AttributeError:
                # The block has never been translated in IR
                offset = self.lifter.loc_db.get_location_offset(block.loc_key)
                if offset in self.offset_to_jitted_func:
                    del(self.offset_to_jitted_func[offset])

            # Remove label -> block link
            del(self.loc_key_to_block[block.loc_key])

        # Re generate blocks intervals
        self.blocks_mem_interval = self.blocks_to_memrange(self.loc_key_to_block.values())

        return modified_blocks

    def updt_automod_code_range(self, vm, mem_range):
        """Remove jitted code in range @mem_range
        @vm: VmMngr instance
        @mem_range: list of start/stop addresses
        """
        for addr_start, addr_stop in mem_range:
            self.del_block_in_range(addr_start, addr_stop)
        self.__updt_jitcode_mem_range(vm)
        vm.reset_memory_access()

    def updt_automod_code(self, vm):
        """Remove jitted code updated by memory write
        @vm: VmMngr instance
        """
        mem_range = []
        for addr_start, addr_stop in vm.get_memory_write():
            mem_range.append((addr_start, addr_stop))
        self.updt_automod_code_range(vm, mem_range)

    def hash_block(self, block):
        """
        Build a hash of the block @block
        @block: asmblock
        """
        block_raw = b"".join(line.b for line in block.lines)
        offset = self.lifter.loc_db.get_location_offset(block.loc_key)
        block_hash = md5(
            b"%X_%s_%s_%s_%s" % (
                offset,
                self.arch_name.encode(),
                b'\x01' if self.log_mn else b'\x00',
                b'\x01' if self.log_regs else b'\x00',
                block_raw
            )
        ).hexdigest()
        return block_hash

    @property
    def disasm_cb(self):
        warnings.warn("Deprecated API: use .mdis.dis_block_callback")
        return self.mdis.dis_block_callback

    @disasm_cb.setter
    def disasm_cb(self, value):
        warnings.warn("Deprecated API: use .mdis.dis_block_callback")
        self.mdis.dis_block_callback = value
