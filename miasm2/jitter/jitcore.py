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

from miasm2.core import asmblock
from miasm2.core.interval import interval
from miasm2.core.utils import BoundedDict
from miasm2.jitter.csts import *


class JitCore(object):

    "JiT management. This is an abstract class"

    jitted_block_delete_cb = None
    jitted_block_max_size = 10000

    def __init__(self, ir_arch, bs=None):
        """Initialise a JitCore instance.
        @ir_arch: ir instance for current architecture
        @bs: bitstream
        """

        self.ir_arch = ir_arch
        self.arch_name = "%s%s" % (self.ir_arch.arch.name, self.ir_arch.attrib)
        self.bs = bs
        self.known_blocs = {}
        self.lbl2jitbloc = BoundedDict(self.jitted_block_max_size,
                                       delete_cb=self.jitted_block_delete_cb)
        self.lbl2bloc = {}
        self.log_mn = False
        self.log_regs = False
        self.log_newbloc = False
        self.segm_to_do = set()
        self.jitcount = 0
        self.addr2obj = {}
        self.addr2objref = {}
        self.blocs_mem_interval = interval()
        self.disasm_cb = None
        self.split_dis = set()
        self.options = {"jit_maxline": 50,  # Maximum number of line jitted
                        "max_exec_per_call": 0 # 0 means no limit
                        }

        self.mdis = asmblock.disasmEngine(ir_arch.arch, ir_arch.attrib, bs,
                                          lines_wd=self.options["jit_maxline"],
                                          symbol_pool=ir_arch.symbol_pool,
                                          follow_call=False,
                                          dontdis_retcall=False,
                                          split_dis=self.split_dis,
                                          dis_block_callback=self.disasm_cb)


    def set_options(self, **kwargs):
        "Set options relative to the backend"

        self.options.update(kwargs)

    def clear_jitted_blocks(self):
        "Reset all jitted blocks"
        self.lbl2jitbloc.clear()
        self.lbl2bloc.clear()
        self.blocs_mem_interval = interval()

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

    def get_bloc_min_max(self, cur_block):
        "Update cur_block to set min/max address"

        if cur_block.lines:
            cur_block.ad_min = cur_block.lines[0].offset
            cur_block.ad_max = cur_block.lines[-1].offset + cur_block.lines[-1].l
        else:
            # 1 byte block for unknown mnemonic
            cur_block.ad_min = cur_block.label.offset
            cur_block.ad_max = cur_block.label.offset+1


    def add_bloc_to_mem_interval(self, vm, block):
        "Update vm to include block addresses in its memory range"

        self.blocs_mem_interval += interval([(block.ad_min, block.ad_max - 1)])

        vm.reset_code_bloc_pool()
        for a, b in self.blocs_mem_interval:
            vm.add_code_bloc(a, b + 1)

    def jitirblocs(self, label, irblocks):
        """JiT a group of irblocks.
        @label: the label of the irblocks
        @irblocks: a gorup of irblocks
        """

        raise NotImplementedError("Abstract class")

    def add_bloc(self, block):
        """Add a block to JiT and JiT it.
        @block: asm_bloc to add
        """

        irblocks = self.ir_arch.add_block(block, gen_pc_updt = True)
        block.blocks = irblocks
        self.jitirblocs(block.label, irblocks)

    def disbloc(self, addr, vm):
        """Disassemble a new block and JiT it
        @addr: address of the block to disassemble (AsmLabel or int)
        @vm: VmMngr instance
        """

        # Get the block
        if isinstance(addr, asmblock.AsmLabel):
            addr = addr.offset

        # Prepare disassembler
        self.mdis.lines_wd = self.options["jit_maxline"]
        self.mdis.dis_block_callback = self.disasm_cb

        # Disassemble it
        try:
            cur_block = self.mdis.dis_block(addr)
        except IOError:
            # vm_exception_flag is set
            label = self.ir_arch.symbol_pool.getby_offset_create(addr)
            cur_block = asmblock.AsmBlockBad(label)

        # Logging
        if self.log_newbloc:
            print cur_block

        # Update label -> block
        self.lbl2bloc[cur_block.label] = cur_block

        # Store min/max block address needed in jit automod code
        self.get_bloc_min_max(cur_block)

        # JiT it
        self.add_bloc(cur_block)

        # Update jitcode mem range
        self.add_bloc_to_mem_interval(vm, cur_block)

    def runbloc(self, cpu, lbl, breakpoints):
        """Run the block starting at lbl.
        @cpu: JitCpu instance
        @lbl: target label
        """

        if lbl is None:
            lbl = getattr(cpu, self.ir_arch.pc.name)

        if not lbl in self.lbl2jitbloc:
            # Need to JiT the block
            self.disbloc(lbl, cpu.vmmngr)

        # Run the block and update cpu/vmmngr state
        return self.exec_wrapper(lbl, cpu, self.lbl2jitbloc.data, breakpoints,
                                 self.options["max_exec_per_call"])

    def blocs2memrange(self, blocks):
        """Return an interval instance standing for blocks addresses
        @blocks: list of asm_bloc instances
        """

        mem_range = interval()

        for block in blocks:
            mem_range += interval([(block.ad_min, block.ad_max - 1)])

        return mem_range

    def __updt_jitcode_mem_range(self, vm):
        """Rebuild the VM blocks address memory range
        @vm: VmMngr instance
        """

        # Reset the current pool
        vm.reset_code_bloc_pool()

        # Add blocks in the pool
        for start, stop in self.blocs_mem_interval:
            vm.add_code_bloc(start, stop + 1)

    def del_bloc_in_range(self, ad1, ad2):
        """Find and remove jitted block in range [ad1, ad2].
        Return the list of block removed.
        @ad1: First address
        @ad2: Last address
        """

        # Find concerned blocks
        modified_blocks = set()
        for block in self.lbl2bloc.values():
            if not block.lines:
                continue
            if block.ad_max <= ad1 or block.ad_min >= ad2:
                # Block not modified
                pass
            else:
                # Modified blocks
                modified_blocks.add(block)

        # Generate interval to delete
        del_interval = self.blocs2memrange(modified_blocks)

        # Remove interval from monitored interval list
        self.blocs_mem_interval -= del_interval

        # Remove modified blocks
        for block in modified_blocks:
            try:
                for irblock in block.blocks:
                    # Remove offset -> jitted block link
                    if irblock.label.offset in self.lbl2jitbloc:
                        del(self.lbl2jitbloc[irblock.label.offset])

            except AttributeError:
                # The block has never been translated in IR
                if block.label.offset in self.lbl2jitbloc:
                    del(self.lbl2jitbloc[block.label.offset])

            # Remove label -> block link
            del(self.lbl2bloc[block.label])

        return modified_blocks

    def updt_automod_code_range(self, vm, mem_range):
        """Remove jitted code in range @mem_range
        @vm: VmMngr instance
        @mem_range: list of start/stop addresses
        """
        for addr_start, addr_stop in mem_range:
            self.del_bloc_in_range(addr_start, addr_stop)
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
        block_raw = "".join(line.b for line in block.lines)
        block_hash = md5("%X_%s_%s_%s_%s" % (block.label.offset,
                                             self.arch_name,
                                             self.log_mn,
                                             self.log_regs,
                                             block_raw)).hexdigest()
        return block_hash
