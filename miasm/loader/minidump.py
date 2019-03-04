"""Constants and structures associated to Minidump format
Based on: http://amnesia.gtisc.gatech.edu/~moyix/minidump.py
"""
from future.utils import viewitems

from future.builtins import int as int_types
from miasm.loader.new_cstruct import CStruct

class Enumeration(object):
    """Stand for an enumeration type"""

    def __init__(self, enum_info):
        """enum_info: {name: value}"""
        self._enum_info = enum_info
        self._inv_info = dict((v, k) for k, v in viewitems(enum_info))

    def __getitem__(self, key):
        """Helper: assume that string is for key, integer is for value"""
        if isinstance(key, int_types):
            return self._inv_info[key]
        return self._enum_info[key]

    def __getattr__(self, key):
        if key in self._enum_info:
            return self._enum_info[key]
        raise AttributeError

    def from_value(self, value):
        return self._inv_info[value]


class Rva(CStruct):
    """Relative Virtual Address
    Note: RVA in Minidump means "file offset"
    """
    _fields = [("rva", "u32"),
    ]


minidumpType = Enumeration({
    # MINIDUMP_TYPE
    # https://msdn.microsoft.com/en-us/library/ms680519(v=vs.85).aspx
    "MiniDumpNormal"                          : 0x00000000,
    "MiniDumpWithDataSegs"                    : 0x00000001,
    "MiniDumpWithFullMemory"                  : 0x00000002,
    "MiniDumpWithHandleData"                  : 0x00000004,
    "MiniDumpFilterMemory"                    : 0x00000008,
    "MiniDumpScanMemory"                      : 0x00000010,
    "MiniDumpWithUnloadedModules"             : 0x00000020,
    "MiniDumpWithIndirectlyReferencedMemory"  : 0x00000040,
    "MiniDumpFilterModulePaths"               : 0x00000080,
    "MiniDumpWithProcessThreadData"           : 0x00000100,
    "MiniDumpWithPrivateReadWriteMemory"      : 0x00000200,
    "MiniDumpWithoutOptionalData"             : 0x00000400,
    "MiniDumpWithFullMemoryInfo"              : 0x00000800,
    "MiniDumpWithThreadInfo"                  : 0x00001000,
    "MiniDumpWithCodeSegs"                    : 0x00002000,
    "MiniDumpWithoutAuxiliaryState"           : 0x00004000,
    "MiniDumpWithFullAuxiliaryState"          : 0x00008000,
    "MiniDumpWithPrivateWriteCopyMemory"      : 0x00010000,
    "MiniDumpIgnoreInaccessibleMemory"        : 0x00020000,
    "MiniDumpWithTokenInformation"            : 0x00040000,
    "MiniDumpWithModuleHeaders"               : 0x00080000,
    "MiniDumpFilterTriage"                    : 0x00100000,
    "MiniDumpValidTypeFlags"                  : 0x001fffff,
})

class MinidumpHDR(CStruct):
    """MINIDUMP_HEADER
    https://msdn.microsoft.com/en-us/library/ms680378(VS.85).aspx
    """
    _fields = [("Magic", "u32"), # MDMP
               ("Version", "u16"),
               ("ImplementationVersion", "u16"),
               ("NumberOfStreams", "u32"),
               ("StreamDirectoryRva", "Rva"),
               ("Checksum", "u32"),
               ("TimeDateStamp", "u32"),
               ("Flags", "u32")
    ]

class LocationDescriptor(CStruct):
    """MINIDUMP_LOCATION_DESCRIPTOR
    https://msdn.microsoft.com/en-us/library/ms680383(v=vs.85).aspx
    """
    _fields = [("DataSize", "u32"),
               ("Rva", "Rva"),
    ]


streamType = Enumeration({
    # MINIDUMP_STREAM_TYPE
    # https://msdn.microsoft.com/en-us/library/ms680394(v=vs.85).aspx
    "UnusedStream"               : 0,
    "ReservedStream0"            : 1,
    "ReservedStream1"            : 2,
    "ThreadListStream"           : 3,
    "ModuleListStream"           : 4,
    "MemoryListStream"           : 5,
    "ExceptionStream"            : 6,
    "SystemInfoStream"           : 7,
    "ThreadExListStream"         : 8,
    "Memory64ListStream"         : 9,
    "CommentStreamA"             : 10,
    "CommentStreamW"             : 11,
    "HandleDataStream"           : 12,
    "FunctionTableStream"        : 13,
    "UnloadedModuleListStream"   : 14,
    "MiscInfoStream"             : 15,
    "MemoryInfoListStream"       : 16,
    "ThreadInfoListStream"       : 17,
    "HandleOperationListStream"  : 18,
    "LastReservedStream"         : 0xffff,
})

class StreamDirectory(CStruct):
    """MINIDUMP_DIRECTORY
    https://msdn.microsoft.com/en-us/library/ms680365(VS.85).aspx
    """
    _fields = [("StreamType", "u32"),
               ("Location", "LocationDescriptor"),
    ]

    @property
    def pretty_name(self):
        return streamType[self.StreamType]


class FixedFileInfo(CStruct):
    """VS_FIXEDFILEINFO
    https://msdn.microsoft.com/en-us/library/ms646997(v=vs.85).aspx
    """
    _fields = [("dwSignature", "u32"),
               ("dwStrucVersion", "u32"),
               ("dwFileVersionMS", "u32"),
               ("dwFileVersionLS", "u32"),
               ("dwProductVersionMS", "u32"),
               ("dwProductVersionLS", "u32"),
               ("dwFileFlagsMask", "u32"),
               ("dwFileFlags", "u32"),
               ("dwFileOS", "u32"),
               ("dwFileType", "u32"),
               ("dwFileSubtype", "u32"),
               ("dwFileDateMS", "u32"),
               ("dwFileDateLS", "u32"),
    ]

class MinidumpString(CStruct):
    """MINIDUMP_STRING
    https://msdn.microsoft.com/en-us/library/ms680395(v=vs.85).aspx
    """
    _fields = [("Length", "u32"),
               ("Buffer", "u08", lambda string:string.Length),
    ]

class Module(CStruct):
    """MINIDUMP_MODULE
    https://msdn.microsoft.com/en-us/library/ms680392(v=vs.85).aspx
    """
    _fields = [("BaseOfImage", "u64"),
               ("SizeOfImage", "u32"),
               ("CheckSum", "u32"),
               ("TimeDateStamp", "u32"),
               ("ModuleNameRva", "Rva"),
               ("VersionInfo", "FixedFileInfo"),
               ("CvRecord", "LocationDescriptor"),
               ("MiscRecord", "LocationDescriptor"),
               ("Reserved0", "u64"),
               ("Reserved1", "u64"),
    ]


class ModuleList(CStruct):
    """MINIDUMP_MODULE_LIST
    https://msdn.microsoft.com/en-us/library/ms680391(v=vs.85).aspx
    """
    _fields = [("NumberOfModules", "u32"),
               ("Modules", "Module", lambda mlist:mlist.NumberOfModules),
    ]


class MemoryDescriptor64(CStruct):
    """MINIDUMP_MEMORY_DESCRIPTOR64
    https://msdn.microsoft.com/en-us/library/ms680384(v=vs.85).aspx
    """
    _fields = [("StartOfMemoryRange", "u64"),
               ("DataSize", "u64")
    ]


class Memory64List(CStruct):
    """MINIDUMP_MEMORY64_LIST
    https://msdn.microsoft.com/en-us/library/ms680387(v=vs.85).aspx
    """
    _fields = [("NumberOfMemoryRanges", "u64"),
               ("BaseRva", "u64"),
               ("MemoryRanges", "MemoryDescriptor64",
                lambda mlist:mlist.NumberOfMemoryRanges),
    ]

class MemoryDescriptor(CStruct):
    """MINIDUMP_MEMORY_DESCRIPTOR
    https://msdn.microsoft.com/en-us/library/ms680384(v=vs.85).aspx
    """
    _fields = [("StartOfMemoryRange", "u64"),
               ("Memory", "LocationDescriptor"),
    ]

class MemoryList(CStruct):
    """MINIDUMP_MEMORY_LIST
    https://msdn.microsoft.com/en-us/library/ms680387(v=vs.85).aspx
    """
    _fields = [("NumberOfMemoryRanges", "u32"),
               ("MemoryRanges", "MemoryDescriptor",
                lambda mlist:mlist.NumberOfMemoryRanges),
    ]

memProtect = Enumeration({
    # MEM PROTECT
    # https://msdn.microsoft.com/en-us/library/aa366786(v=vs.85).aspx
    "PAGE_NOACCESS"          : 0x0001,
    "PAGE_READONLY"          : 0x0002,
    "PAGE_READWRITE"         : 0x0004,
    "PAGE_WRITECOPY"         : 0x0008,
    "PAGE_EXECUTE"           : 0x0010,
    "PAGE_EXECUTE_READ"      : 0x0020,
    "PAGE_EXECUTE_READWRITE" : 0x0040,
    "PAGE_EXECUTE_WRITECOPY" : 0x0080,
    "PAGE_GUARD"             : 0x0100,
    "PAGE_NOCACHE"           : 0x0200,
    "PAGE_WRITECOMBINE"      : 0x0400,
})

class MemoryInfo(CStruct):
    """MINIDUMP_MEMORY_INFO
    https://msdn.microsoft.com/en-us/library/ms680386(v=vs.85).aspx
    """
    _fields = [("BaseAddress", "u64"),
               ("AllocationBase", "u64"),
               ("AllocationProtect", "u32"),
               ("__alignment1", "u32"),
               ("RegionSize", "u64"),
               ("State", "u32"),
               ("Protect", "u32"),
               ("Type", "u32"),
               ("__alignment2", "u32"),
    ]

class MemoryInfoList(CStruct):
    """MINIDUMP_MEMORY_INFO_LIST
    https://msdn.microsoft.com/en-us/library/ms680385(v=vs.85).aspx
    """
    _fields = [("SizeOfHeader", "u32"),
               ("SizeOfEntry", "u32"),
               ("NumberOfEntries", "u64"),
                # Fake field, for easy access to MemoryInfo elements
               ("MemoryInfos", "MemoryInfo",
                lambda mlist: mlist.NumberOfEntries),
    ]


contextFlags_x86 = Enumeration({
    "CONTEXT_i386"                : 0x00010000,
    "CONTEXT_CONTROL"             : 0x00010001,
    "CONTEXT_INTEGER"             : 0x00010002,
    "CONTEXT_SEGMENTS"            : 0x00010004,
    "CONTEXT_FLOATING_POINT"      : 0x00010008,
    "CONTEXT_DEBUG_REGISTERS"     : 0x00010010,
    "CONTEXT_EXTENDED_REGISTERS"  : 0x00010020,
})

class FloatingSaveArea(CStruct):
    """FLOATING_SAVE_AREA
    http://terminus.rewolf.pl/terminus/structures/ntdll/_FLOATING_SAVE_AREA_x86.html
    """
    _fields = [("ControlWord", "u32"),
               ("StatusWord", "u32"),
               ("TagWord", "u32"),
               ("ErrorOffset", "u32"),
               ("ErrorSelector", "u32"),
               ("DataOffset", "u32"),
               ("DataSelector", "u32"),
               ("RegisterArea", "80s"),
               ("Cr0NpxState", "u32"),
    ]

class Context_x86(CStruct):
    """CONTEXT x86
    https://msdn.microsoft.com/en-us/en-en/library/ms679284(v=vs.85).aspx
    http://terminus.rewolf.pl/terminus/structures/ntdll/_CONTEXT_x86.html
    """

    MAXIMUM_SUPPORTED_EXTENSION = 512

    def is_activated(flag):
        mask = contextFlags_x86[flag]
        def check_context(ctx):
            if (ctx.ContextFlags & mask == mask):
                return 1
            return 0
        return check_context

    _fields = [("ContextFlags", "u32"),
               # DebugRegisters
               ("Dr0", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr1", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr2", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr3", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr6", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),
               ("Dr7", "u32", is_activated("CONTEXT_DEBUG_REGISTERS")),

               ("FloatSave", "FloatingSaveArea",
                is_activated("CONTEXT_FLOATING_POINT")),

               # SegmentRegisters
               ("SegGs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegFs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegEs", "u32", is_activated("CONTEXT_SEGMENTS")),
               ("SegDs", "u32", is_activated("CONTEXT_SEGMENTS")),
               # IntegerRegisters
               ("Edi", "u32", is_activated("CONTEXT_INTEGER")),
               ("Esi", "u32", is_activated("CONTEXT_INTEGER")),
               ("Ebx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Edx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Ecx", "u32", is_activated("CONTEXT_INTEGER")),
               ("Eax", "u32", is_activated("CONTEXT_INTEGER")),
               # ControlRegisters
               ("Ebp", "u32", is_activated("CONTEXT_CONTROL")),
               ("Eip", "u32", is_activated("CONTEXT_CONTROL")),
               ("SegCs", "u32", is_activated("CONTEXT_CONTROL")),
               ("EFlags", "u32", is_activated("CONTEXT_CONTROL")),
               ("Esp", "u32", is_activated("CONTEXT_CONTROL")),
               ("SegSs", "u32", is_activated("CONTEXT_CONTROL")),

               ("ExtendedRegisters", "%ds" % MAXIMUM_SUPPORTED_EXTENSION,
                is_activated("CONTEXT_EXTENDED_REGISTERS")),
    ]


contextFlags_AMD64 = Enumeration({
    "CONTEXT_AMD64"               : 0x00100000,
    "CONTEXT_CONTROL"             : 0x00100001,
    "CONTEXT_INTEGER"             : 0x00100002,
    "CONTEXT_SEGMENTS"            : 0x00100004,
    "CONTEXT_FLOATING_POINT"      : 0x00100008,
    "CONTEXT_DEBUG_REGISTERS"     : 0x00100010,
    "CONTEXT_XSTATE"              : 0x00100020,
    "CONTEXT_EXCEPTION_ACTIVE"    : 0x08000000,
    "CONTEXT_SERVICE_ACTIVE"      : 0x10000000,
    "CONTEXT_EXCEPTION_REQUEST"   : 0x40000000,
    "CONTEXT_EXCEPTION_REPORTING" : 0x80000000,
})


class M128A(CStruct):
    """M128A
    http://terminus.rewolf.pl/terminus/structures/ntdll/_M128A_x64.html
    """
    _fields = [("Low", "u64"),
               ("High", "u64"),
    ]

class Context_AMD64(CStruct):
    """CONTEXT AMD64
    https://github.com/duarten/Threadjack/blob/master/WinNT.h
    """

    def is_activated(flag):
        mask = contextFlags_AMD64[flag]
        def check_context(ctx):
            if (ctx.ContextFlags & mask == mask):
                return 1
            return 0
        return check_context

    _fields = [

        # Only used for Convenience
        ("P1Home", "u64"),
        ("P2Home", "u64"),
        ("P3Home", "u64"),
        ("P4Home", "u64"),
        ("P5Home", "u64"),
        ("P6Home", "u64"),

        # Control
        ("ContextFlags", "u32"),
        ("MxCsr", "u32"),

        # Segment & processor
        # /!\ activation depends on multiple flags
        ("SegCs", "u16", is_activated("CONTEXT_CONTROL")),
        ("SegDs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegEs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegFs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegGs", "u16", is_activated("CONTEXT_SEGMENTS")),
        ("SegSs", "u16", is_activated("CONTEXT_CONTROL")),
        ("EFlags", "u32", is_activated("CONTEXT_CONTROL")),

        # Debug registers
        ("Dr0", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr1", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr2", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr3", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr6", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),
        ("Dr7", "u64", is_activated("CONTEXT_DEBUG_REGISTERS")),

        # Integer registers
        # /!\ activation depends on multiple flags
        ("Rax", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rcx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rdx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rbx", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rsp", "u64", is_activated("CONTEXT_CONTROL")),
        ("Rbp", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rsi", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rdi", "u64", is_activated("CONTEXT_INTEGER")),
        ("R8", "u64", is_activated("CONTEXT_INTEGER")),
        ("R9", "u64", is_activated("CONTEXT_INTEGER")),
        ("R10", "u64", is_activated("CONTEXT_INTEGER")),
        ("R11", "u64", is_activated("CONTEXT_INTEGER")),
        ("R12", "u64", is_activated("CONTEXT_INTEGER")),
        ("R13", "u64", is_activated("CONTEXT_INTEGER")),
        ("R14", "u64", is_activated("CONTEXT_INTEGER")),
        ("R15", "u64", is_activated("CONTEXT_INTEGER")),
        ("Rip", "u64", is_activated("CONTEXT_CONTROL")),

        # Floating point
        ("Header", "M128A", lambda ctx: 2),
        ("Legacy", "M128A", lambda ctx: 8),
        ("Xmm0", "M128A"),
        ("Xmm1", "M128A"),
        ("Xmm2", "M128A"),
        ("Xmm3", "M128A"),
        ("Xmm4", "M128A"),
        ("Xmm5", "M128A"),
        ("Xmm6", "M128A"),
        ("Xmm7", "M128A"),
        ("Xmm8", "M128A"),
        ("Xmm9", "M128A"),
        ("Xmm10", "M128A"),
        ("Xmm11", "M128A"),
        ("Xmm12", "M128A"),
        ("Xmm13", "M128A"),
        ("Xmm14", "M128A"),
        ("Xmm15", "M128A"),


        # Vector registers
        ("VectorRegister", "M128A", lambda ctx: 16),
        ("VectorControl", "u64"),

        # Special debug control regs
        ("DebugControl", "u64"),
        ("LastBranchToRip", "u64"),
        ("LastBranchFromRip", "u64"),
        ("LastExceptionToRip", "u64"),
        ("LastExceptionFromRip", "u64"),
    ]

processorArchitecture = Enumeration({
    "PROCESSOR_ARCHITECTURE_X86"       :  0,
    "PROCESSOR_ARCHITECTURE_MIPS"      :  1,
    "PROCESSOR_ARCHITECTURE_ALPHA"     :  2,
    "PROCESSOR_ARCHITECTURE_PPC"       :  3,
    "PROCESSOR_ARCHITECTURE_SHX"       :  4,
    "PROCESSOR_ARCHITECTURE_ARM"       :  5,
    "PROCESSOR_ARCHITECTURE_IA64"      :  6,
    "PROCESSOR_ARCHITECTURE_ALPHA64"   :  7,
    "PROCESSOR_ARCHITECTURE_MSIL"      :  8,
    "PROCESSOR_ARCHITECTURE_AMD64"     :  9,
    "PROCESSOR_ARCHITECTURE_X86_WIN64" : 10,
    "PROCESSOR_ARCHITECTURE_UNKNOWN"   : 0xffff,
})

class Thread(CStruct):
    """MINIDUMP_THREAD
    https://msdn.microsoft.com/en-us/library/ms680517(v=vs.85).aspx
    """

    arch2context_cls = {
        processorArchitecture.PROCESSOR_ARCHITECTURE_X86: Context_x86,
        processorArchitecture.PROCESSOR_ARCHITECTURE_AMD64: Context_AMD64,
    }

    def parse_context(self, content, offset):
        loc_desc = LocationDescriptor.unpack(content, offset, self.parent_head)

        # Use the correct context depending on architecture
        systeminfo = self.parent_head.systeminfo
        context_cls = self.arch2context_cls.get(systeminfo.ProcessorArchitecture,
                                                None)
        if context_cls is None:
            raise ValueError("Unsupported architecture: %s" % systeminfo.pretty_processor_architecture)

        ctxt = context_cls.unpack(content, loc_desc.Rva.rva, self.parent_head)
        fake_loc_descriptor = LocationDescriptor(DataSize=0, Rva=Rva(rva=0))
        return ctxt, offset + len(fake_loc_descriptor)

    _fields = [("ThreadId", "u32"),
               ("SuspendCount", "u32"),
               ("PriorityClass", "u32"),
               ("Priority", "u32"),
               ("Teb", "u64"),
               ("Stack", "MemoryDescriptor"),
               ("ThreadContext", (parse_context,
                                  lambda thread, value: NotImplemented)),
    ]

class ThreadList(CStruct):
    """MINIDUMP_THREAD_LIST
    https://msdn.microsoft.com/en-us/library/ms680515(v=vs.85).aspx
    """
    _fields = [("NumberOfThreads", "u32"),
               ("Threads", "Thread",
                lambda mlist: mlist.NumberOfThreads),
    ]


class SystemInfo(CStruct):
    """MINIDUMP_SYSTEM_INFO
    https://msdn.microsoft.com/en-us/library/ms680396(v=vs.85).aspx
    """
    _fields = [("ProcessorArchitecture", "u16"),
               ("ProcessorLevel", "u16"),
               ("ProcessorRevision", "u16"),
               ("NumberOfProcessors", "u08"),
               ("ProductType", "u08"),
               ("MajorVersion", "u32"),
               ("MinorVersion", "u32"),
               ("BuildNumber", "u32"),
               ("PlatformId", "u32"),
               ("CSDVersionRva", "Rva"),
               ("SuiteMask", "u16"),
               ("Reserved2", "u16"),
               ("VendorId", "u32", lambda sinfo: 3),
               ("VersionInformation", "u32"),
               ("FeatureInformation", "u32"),
               ("AMDExtendedCpuFeatures", "u32"),
    ]

    @property
    def pretty_processor_architecture(self):
        return processorArchitecture[self.ProcessorArchitecture]

