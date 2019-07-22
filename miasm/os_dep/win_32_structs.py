from miasm.core.types import MemStruct, Num, Ptr, Str, \
    Array, RawStruct, Union, \
    BitField, Self, Void, Bits, \
    set_allocator, MemUnion, Struct


class UnicodeString(MemStruct):
    fields = [
        ("length", Num("H")),
        ("maxlength", Num("H")),
        ("data", Ptr("<I", Str("utf16"))),
    ]


class ListEntry(MemStruct):
    fields = [
        ("flink", Ptr("<I", Void())),
        ("blink", Ptr("<I", Void())),
    ]


class LdrDataEntry(MemStruct):

    """
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x008 InMemoryOrderLinks : _LIST_ENTRY
    +0x010 InInitializationOrderLinks : _LIST_ENTRY
    +0x018 DllBase : Ptr32 Void
    +0x01c EntryPoint : Ptr32 Void
    +0x020 SizeOfImage : Uint4B
    +0x024 FullDllName : _UNICODE_STRING
    +0x02c BaseDllName : _UNICODE_STRING
    +0x034 Flags : Uint4B
    +0x038 LoadCount : Uint2B
    +0x03a TlsIndex : Uint2B
    +0x03c HashLinks : _LIST_ENTRY
    +0x03c SectionPointer : Ptr32 Void
    +0x040 CheckSum : Uint4B
    +0x044 TimeDateStamp : Uint4B
    +0x044 LoadedImports : Ptr32 Void
    +0x048 EntryPointActivationContext : Ptr32 Void
    +0x04c PatchInformation : Ptr32 Void
    """

    fields = [
        ("InLoadOrderLinks", ListEntry),
        ("InMemoryOrderLinks", ListEntry),
        ("InInitializationOrderLinks", ListEntry),
        ("DllBase", Ptr("<I", Void())),
        ("EntryPoint", Ptr("<I", Void())),
        ("SizeOfImage", Num("<I")),
        ("FullDllName", UnicodeString),
        ("BaseDllName", UnicodeString),
        ("Flags", Array(Num("B"), 4)),
        ("LoadCount", Num("H")),
        ("TlsIndex", Num("H")),
        ("union1", Union([
            ("HashLinks", Ptr("<I", Void())),
            ("SectionPointer", Ptr("<I", Void())),
        ])),
        ("CheckSum", Num("<I")),
        ("union2", Union([
            ("TimeDateStamp", Num("<I")),
            ("LoadedImports", Ptr("<I", Void())),
        ])),
        ("EntryPointActivationContext", Ptr("<I", Void())),
        ("PatchInformation", Ptr("<I", Void())),

    ]


class PEB_LDR_DATA(MemStruct):

    """
    +0x000 Length                          : Uint4B
    +0x004 Initialized                     : UChar
    +0x008 SsHandle                        : Ptr32 Void
    +0x00c InLoadOrderModuleList           : _LIST_ENTRY
    +0x014 InMemoryOrderModuleList         : _LIST_ENTRY
    +0x01C InInitializationOrderModuleList         : _LIST_ENTRY
    """

    fields = [
        ("Length", Num("<I")),
        ("Initialized", Num("<I")),
        ("SsHandle", Ptr("<I", Void())),
        ("InLoadOrderModuleList", ListEntry),
        ("InMemoryOrderModuleList", ListEntry),
        ("InInitializationOrderModuleList", ListEntry)
    ]


class PEB(MemStruct):

    """
    +0x000 InheritedAddressSpace    : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged            : UChar
    +0x003 SpareBool                : UChar
    +0x004 Mutant                   : Ptr32 Void
    +0x008 ImageBaseAddress         : Ptr32 Void
    +0x00c Ldr                      : Ptr32 _PEB_LDR_DATA
    +0x010 processparameter
    """

    fields = [
        ("InheritedAddressSpace", Num("B")),
        ("ReadImageFileExecOptions", Num("B")),
        ("BeingDebugged", Num("B")),
        ("SpareBool", Num("B")),
        ("Mutant", Ptr("<I", Void())),
        ("ImageBaseAddress", Num("<I")),
        ("Ldr", Ptr("<I", PEB_LDR_DATA)),
    ]


class EXCEPTION_REGISTRATION_RECORD(MemStruct):
    """
    +0x00 Next    : struct _EXCEPTION_REGISTRATION_RECORD *
    +0x04 Handler : Ptr32 Void
    """

    fields = [
        ("Next", Ptr("<I", Self())),
        ("Handler", Ptr("<I", Void())),
    ]


class EXCEPTION_RECORD(MemStruct):
    """
    DWORD                    ExceptionCode;
    DWORD                    ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID                    ExceptionAddress;
    DWORD                    NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    """
    EXCEPTION_MAXIMUM_PARAMETERS = 15

    fields = [
        ("ExceptionCode", Num("<I")),
        ("ExceptionFlags", Num("<I")),
        ("ExceptionRecord", Ptr("<I", Self())),
        ("ExceptionAddress", Ptr("<I", Void())),
        ("NumberParameters", Num("<I")),
        ("ExceptionInformation", Ptr("<I", Void())),
    ]


class NT_TIB(MemStruct):

    """
    +00 struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList
    +04 void *StackBase
    +08 void *StackLimit
    +0c void *SubSystemTib
    +10 void *FiberData
    +10 uint32 Version
    +14 void *ArbitraryUserPointer
    +18 struct _NT_TIB *Self
    """

    fields = [
        ("ExceptionList", Ptr("<I", EXCEPTION_REGISTRATION_RECORD)),
        ("StackBase", Ptr("<I", Void())),
        ("StackLimit", Ptr("<I", Void())),
        ("SubSystemTib", Ptr("<I", Void())),
        (None, Union([
            ("FiberData", Ptr("<I", Void())),
            ("Version", Num("<I"))
        ])),
        ("ArbitraryUserPointer", Ptr("<I", Void())),
        ("Self", Ptr("<I", Self())),
    ]


class TEB(MemStruct):

    """
    +0x000 NtTib                     : _NT_TIB
    +0x01c EnvironmentPointer        : Ptr32 Void
    +0x020 ClientId                  : _CLIENT_ID
    +0x028 ActiveRpcHandle           : Ptr32 Void
    +0x02c ThreadLocalStoragePointer : Ptr32 Void
    +0x030 ProcessEnvironmentBlock   : Ptr32 _PEB
    +0x034 LastErrorValue            : Uint4B
    ...
    """

    fields = [
        ("NtTib", NT_TIB),
        ("EnvironmentPointer", Ptr("<I", Void())),
        ("ClientId", Array(Num("B"), 0x8)),
        ("ActiveRpcHandle", Ptr("<I", Void())),
        ("ThreadLocalStoragePointer", Ptr("<I", Void())),
        ("ProcessEnvironmentBlock", Ptr("<I", PEB)),
        ("LastErrorValue", Num("<I")),
    ]


class ContextException(MemStruct):
    fields = [
        ("ContextFlags", Num("<I")),
        ("dr0", Num("<I")),
        ("dr1", Num("<I")),
        ("dr2", Num("<I")),
        ("dr3", Num("<I")),
        ("dr4", Num("<I")),
        ("dr5", Num("<I")),

        ("Float", Array(Num("B"), 112)),

        ("gs", Num("<I")),
        ("fs", Num("<I")),
        ("es", Num("<I")),
        ("ds", Num("<I")),

        ("edi", Num("<I")),
        ("esi", Num("<I")),
        ("ebx", Num("<I")),
        ("edx", Num("<I")),
        ("ecx", Num("<I")),
        ("eax", Num("<I")),
        ("ebp", Num("<I")),
        ("eip", Num("<I")),

        ("cs", Num("<I")),
        ("eflags", Num("<I")),
        ("esp", Num("<I")),
        ("ss", Num("<I")),
    ]
