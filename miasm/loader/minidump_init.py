"""
High-level abstraction of Minidump file
"""
from builtins import range
import struct

from miasm.loader.strpatchwork import StrPatchwork
from miasm.loader import minidump as mp


class MemorySegment(object):
    """Stand for a segment in memory with additional information"""

    def __init__(self, offset, memory_desc, module=None, memory_info=None):
        self.offset = offset
        self.memory_desc = memory_desc
        self.module = module
        self.memory_info = memory_info
        self.minidump = self.memory_desc.parent_head

    @property
    def address(self):
        return self.memory_desc.StartOfMemoryRange

    @property
    def size(self):
        if isinstance(self.memory_desc, mp.MemoryDescriptor64):
            return self.memory_desc.DataSize
        elif isinstance(self.memory_desc, mp.MemoryDescriptor):
            return self.memory_desc.Memory.DataSize
        raise TypeError

    @property
    def name(self):
        if not self.module:
            return ""
        name = mp.MinidumpString.unpack(self.minidump._content,
                                        self.module.ModuleNameRva.rva,
                                        self.minidump)
        return b"".join(
            struct.pack("B", x) for x in name.Buffer
        ).decode("utf-16")

    @property
    def content(self):
        return self.minidump._content[self.offset:self.offset + self.size]

    @property
    def protect(self):
        if self.memory_info:
            return self.memory_info.Protect
        return None

    @property
    def pretty_protect(self):
        if self.protect is None:
            return "UNKNOWN"
        return mp.memProtect[self.protect]


class Minidump(object):
    """Stand for a Minidump file

    Here is a few limitation:
     - only < 4GB Minidump are supported (LocationDescriptor handling)
     - only Stream relative to memory mapping are implemented

    Official description is available on MSDN:
    https://msdn.microsoft.com/en-us/library/ms680378(VS.85).aspx
    """

    _sex = 0
    _wsize = 32

    def __init__(self, minidump_str):
        self._content = StrPatchwork(minidump_str)

        # Specific streams
        self.modulelist = None
        self.memory64list = None
        self.memorylist = None
        self.memoryinfolist = None
        self.systeminfo = None

        # Get information
        self.streams = []
        self.threads = None
        self.parse_content()

        # Memory information
        self.memory = {} # base address (virtual) -> Memory information
        self.build_memory()

    def parse_content(self):
        """Build structures corresponding to current content"""

        # Header
        offset = 0
        self.minidumpHDR = mp.MinidumpHDR.unpack(self._content, offset, self)
        assert self.minidumpHDR.Magic == 0x504d444d

        # Streams
        base_offset = self.minidumpHDR.StreamDirectoryRva.rva
        empty_stream = mp.StreamDirectory(
            StreamType=0,
            Location=mp.LocationDescriptor(
                DataSize=0,
                Rva=mp.Rva(rva=0)
            )
        )
        streamdir_size = len(empty_stream)
        for i in range(self.minidumpHDR.NumberOfStreams):
            stream_offset = base_offset + i * streamdir_size
            stream = mp.StreamDirectory.unpack(self._content, stream_offset, self)
            self.streams.append(stream)

            # Launch specific action depending on the stream
            datasize = stream.Location.DataSize
            offset = stream.Location.Rva.rva
            if stream.StreamType == mp.streamType.ModuleListStream:
                self.modulelist = mp.ModuleList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.MemoryListStream:
                self.memorylist = mp.MemoryList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.Memory64ListStream:
                self.memory64list = mp.Memory64List.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.MemoryInfoListStream:
                self.memoryinfolist = mp.MemoryInfoList.unpack(self._content, offset, self)
            elif stream.StreamType == mp.streamType.SystemInfoStream:
                self.systeminfo = mp.SystemInfo.unpack(self._content, offset, self)

        # Some streams need the SystemInfo stream to work
        for stream in self.streams:
            datasize = stream.Location.DataSize
            offset = stream.Location.Rva.rva
            if (self.systeminfo is not None and
                stream.StreamType == mp.streamType.ThreadListStream):
                self.threads = mp.ThreadList.unpack(self._content, offset, self)


    def build_memory(self):
        """Build an easier to use memory view based on ModuleList and
        Memory64List streams"""

        addr2module = dict((module.BaseOfImage, module)
                           for module in (self.modulelist.Modules if
                                          self.modulelist else []))
        addr2meminfo = dict((memory.BaseAddress, memory)
                            for memory in (self.memoryinfolist.MemoryInfos if
                                           self.memoryinfolist else []))

        mode64 = self.minidumpHDR.Flags & mp.minidumpType.MiniDumpWithFullMemory

        if mode64:
            offset = self.memory64list.BaseRva
            memranges = self.memory64list.MemoryRanges
        else:
            memranges = self.memorylist.MemoryRanges

        for memory in memranges:
            if not mode64:
                offset = memory.Memory.Rva.rva

            # Create a MemorySegment with augmented information
            base_address = memory.StartOfMemoryRange
            module = addr2module.get(base_address, None)
            meminfo = addr2meminfo.get(base_address, None)
            self.memory[base_address] = MemorySegment(offset, memory,
                                                      module, meminfo)

            if mode64:
                offset += memory.DataSize

        # Sanity check
        if mode64:
            assert all(addr in self.memory for addr in addr2module)

    def get(self, virt_start, virt_stop):
        """Return the content at the (virtual addresses)
        [virt_start:virt_stop]"""

        # Find the corresponding memory segment
        for addr in self.memory:
            if virt_start <= addr <= virt_stop:
                break
        else:
            return b""

        memory = self.memory[addr]
        shift = addr - virt_start
        last = virt_stop - addr
        if last > memory.size:
            raise RuntimeError("Multi-page not implemented")

        return self._content[memory.offset + shift:memory.offset + last]
