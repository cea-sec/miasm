#! /usr/bin/env python

from miasm.loader.cstruct import CStruct

class Ehdr(CStruct):
    _fields = [ ("ident","16s"),
                ("type","u16"),
                ("machine","u16"),
                ("version","u32"),
                ("entry","ptr"),
                ("phoff","ptr"),
                ("shoff","ptr"),
                ("flags","u32"),
                ("ehsize","u16"),
                ("phentsize","u16"),
                ("phnum","u16"),
                ("shentsize","u16"),
                ("shnum","u16"),
                ("shstrndx","u16") ]


class Shdr(CStruct):
    _fields = [ ("name","u32"),
                ("type","u32"),
                ("flags","ptr"),
                ("addr","ptr"),
                ("offset","ptr"),
                ("size","ptr"),
                ("link","u32"),
                ("info","u32"),
                ("addralign","ptr"),
                ("entsize","ptr") ]

class Phdr(CStruct):
    _fields = [ ("type","u32"),
                ("offset","u32"),
                ("vaddr","u32"),
                ("paddr","u32"),
                ("filesz","u32"),
                ("memsz","u32"),
                ("flags","u32"),
                ("align","u32") ]

class Phdr64(CStruct):
    _fields = [ ("type","u32"),
                ("flags","u32"),
                ("offset","ptr"),
                ("vaddr","ptr"),
                ("paddr","ptr"),
                ("filesz","ptr"),
                ("memsz","ptr"),
                ("align","ptr") ]

class Nhdr(CStruct):
    _fields = [ ("namesz","u32"),
                ("descsz","u32"),
                ("type", "u32") ]


class Sym32(CStruct):
    _fields = [ ("name","u32"),
                ("value","u32"),
                ("size","u32"),
                ("info","u08"),
                ("other","u08"),
                ("shndx","u16") ]

class Sym64(CStruct):
    _fields = [ ("name","u32"),
                ("info","u08"),
                ("other","u08"),
                ("shndx","u16"),
                ("value","u64"),
                ("size","u64") ]

class Dym(CStruct):
    _fields = [ ("tag","u32"),
                ("val","u32") ]

class Rel32(CStruct):
    _fields = [ ("offset","ptr"),
                ("info","u32") ]

class Rel64(CStruct):
    _fields = [ ("offset","ptr"),
                ("info","u64") ]

class Rela32(CStruct):
    _fields = [ ("offset","ptr"),
                ("info","u32"),
                ("addend","ptr") ]

class Rela64(CStruct):
    _fields = [ ("offset","ptr"),
                ("info","u64"),
                ("addend","ptr") ]

class Dynamic(CStruct):
    _fields = [ ("type","ptr"),
                ("name","ptr") ]


# Legal values for e_ident (identification indexes)

EI_MAG0	=       0	# File identification
EI_MAG1	=       1	# File identification
EI_MAG2	=       2	# File identification
EI_MAG3	=       3	# File identification
EI_CLASS =      4	# File class
EI_DATA	=       5	# Data encoding
EI_VERSION =    6	# File version
EI_OSABI =      7	# Operating system/ABI identification
EI_ABIVERSION = 8	# ABI version
EI_PAD =        9	# Start of padding bytes
EI_NIDENT =     16	# Size of e_ident[]

# Legal values for e_ident[EI_CLASS]

ELFCLASSNONE =  0	# Invalid class
ELFCLASS32 =	1	# 32-bit objects
ELFCLASS64 =    2	# 64-bit objects

# Legal values for e_ident[EI_DATA]

ELFDATANONE =	0	# Invalid data encoding
ELFDATA2LSB =	1	# Least significant byte at lowest address
ELFDATA2MSB =	2	# Most significant byte at lowest address

# Legal values for e_type (object file type).

ET_NONE =         0               # No file type
ET_REL =          1               # Relocatable file
ET_EXEC =         2               # Executable file
ET_DYN =          3               # Shared object file
ET_CORE =         4               # Core file
ET_NUM =          5               # Number of defined types
ET_LOOS =         0xfe00         # OS-specific range start
ET_HIOS =         0xfeff         # OS-specific range end
ET_LOPROC =       0xff00         # Processor-specific range start
ET_HIPROC =       0xffff         # Processor-specific range end

# Legal values for e_machine (architecture).

EM_NONE =         0              # No machine
EM_M32 =          1              # AT&T WE 32100
EM_SPARC =        2              # SUN SPARC
EM_386 =          3              # Intel 80386
EM_68K =          4              # Motorola m68k family
EM_88K =          5              # Motorola m88k family
EM_486 =          6              # Intel 80486
EM_860 =          7              # Intel 80860
EM_MIPS =         8              # MIPS R3000 big-endian
EM_S370 =         9              # IBM System/370
EM_MIPS_RS3_LE = 10              # MIPS R3000 little-endian

EM_PARISC =      15              # HPPA
EM_VPP500 =      17              # Fujitsu VPP500
EM_SPARC32PLUS = 18              # Sun's "v8plus"
EM_960 =         19              # Intel 80960
EM_PPC =         20              # PowerPC
EM_PPC64 =       21              # PowerPC 64-bit
EM_S390 =        22              # IBM S390

EM_V800 =        36              # NEC V800 series
EM_FR20 =        37              # Fujitsu FR20
EM_RH32 =        38              # TRW RH-32
EM_RCE =         39              # Motorola RCE
EM_ARM =         40              # ARM
EM_FAKE_ALPHA =  41              # Digital Alpha
EM_SH =          42              # Hitachi SH
EM_SPARCV9 =     43              # SPARC v9 64-bit
EM_TRICORE =     44              # Siemens Tricore
EM_ARC =         45              # Argonaut RISC Core
EM_H8_300 =      46              # Hitachi H8/300
EM_H8_300H =     47              # Hitachi H8/300H
EM_H8S =         48              # Hitachi H8S
EM_H8_500 =      49              # Hitachi H8/500
EM_IA_64 =       50              # Intel Merced
EM_MIPS_X =      51              # Stanford MIPS-X
EM_COLDFIRE =    52              # Motorola Coldfire
EM_68HC12 =      53              # Motorola M68HC12
EM_MMA =         54              # Fujitsu MMA Multimedia Accelerator*/
EM_PCP =         55              # Siemens PCP
EM_NCPU =        56              # Sony nCPU embeeded RISC
EM_NDR1 =        57              # Denso NDR1 microprocessor
EM_STARCORE =    58              # Motorola Start*Core processor
EM_ME16 =        59              # Toyota ME16 processor
EM_ST100 =       60              # STMicroelectronic ST100 processor
EM_TINYJ =       61              # Advanced Logic Corp. Tinyj emb.fam*/
EM_X86_64 =      62              # AMD x86-64 architecture
EM_AARCH64 =     183             # Aarch64 architecture
EM_PDSP =        63              # Sony DSP Processor

EM_FX66 =        66              # Siemens FX66 microcontroller
EM_ST9PLUS =     67              # STMicroelectronics ST9+ 8/16 mc
EM_ST7 =         68              # STmicroelectronics ST7 8 bit mc
EM_68HC16 =      69              # Motorola MC68HC16 microcontroller
EM_68HC11 =      70              # Motorola MC68HC11 microcontroller
EM_68HC08 =      71              # Motorola MC68HC08 microcontroller
EM_68HC05 =      72              # Motorola MC68HC05 microcontroller
EM_SVX =         73              # Silicon Graphics SVx
EM_ST19 =        74              # STMicroelectronics ST19 8 bit mc
EM_VAX =         75              # Digital VAX
EM_CRIS =        76              # Axis Communications 32-bit embedded processor
EM_JAVELIN =     77              # Infineon Technologies 32-bit embedded processor
EM_FIREPATH =    78              # Element 14 64-bit DSP Processor
EM_ZSP =         79              # LSI Logic 16-bit DSP Processor
EM_MMIX =        80              # Donald Knuth's educational 64-bit processor
EM_HUANY =       81              # Harvard University machine-independent object files
EM_PRISM =       82              # SiTera Prism
EM_AVR =         83              # Atmel AVR 8-bit microcontroller
EM_FR30 =        84              # Fujitsu FR30
EM_D10V =        85              # Mitsubishi D10V
EM_D30V =        86              # Mitsubishi D30V
EM_V850 =        87              # NEC v850
EM_M32R =        88              # Mitsubishi M32R
EM_MN10300 =     89              # Matsushita MN10300
EM_MN10200 =     90              # Matsushita MN10200
EM_PJ =          91              # picoJava
EM_OPENRISC =    92              # OpenRISC 32-bit embedded processor
EM_ARC_A5 =      93              # ARC Cores Tangent-A5
EM_XTENSA =      94              # Tensilica Xtensa Architecture

EM_ALPHA =       0x9026

# Legal values for sh_type (section type).

SHT_NULL =          0             # Section header table entry unused
SHT_PROGBITS =      1             # Program data
SHT_SYMTAB =        2             # Symbol table
SHT_STRTAB =        3             # String table
SHT_RELA =          4             # Relocation entries with addends
SHT_HASH =          5             # Symbol hash table
SHT_DYNAMIC =       6             # Dynamic linking information
SHT_NOTE =          7             # Notes
SHT_NOBITS =        8             # Program space with no data (bss)
SHT_REL =           9             # Relocation entries, no addends
SHT_SHLIB =         10            # Reserved
SHT_DYNSYM =        11            # Dynamic linker symbol table
SHT_INIT_ARRAY =    14            # Array of constructors
SHT_FINI_ARRAY =    15            # Array of destructors
SHT_PREINIT_ARRAY = 16            # Array of pre-constructors
SHT_GROUP =         17            # Section group
SHT_SYMTAB_SHNDX =  18            # Extended section indices
SHT_NUM =           19            # Number of defined types.
SHT_LOOS =          0x60000000   # Start OS-specific
SHT_GNU_LIBLIST =   0x6ffffff7   # Prelink library list
SHT_CHECKSUM =      0x6ffffff8   # Checksum for DSO content.
SHT_LOSUNW =        0x6ffffffa   # Sun-specific low bound.
SHT_SUNW_move =     0x6ffffffa
SHT_SUNW_COMDAT =   0x6ffffffb
SHT_SUNW_syminfo =  0x6ffffffc
SHT_GNU_verdef =    0x6ffffffd   # Version definition section.
SHT_GNU_verneed =   0x6ffffffe   # Version needs section.
SHT_GNU_versym =    0x6fffffff   # Version symbol table.
SHT_HISUNW =        0x6fffffff   # Sun-specific high bound.
SHT_HIOS =          0x6fffffff   # End OS-specific type
SHT_LOPROC =        0x70000000   # Start of processor-specific
SHT_HIPROC =        0x7fffffff   # End of processor-specific
SHT_LOUSER =        0x80000000   # Start of application-specific
SHT_HIUSER =        0x8fffffff   # End of application-specific

# Legal values for sh_flags (section flags).

SHF_WRITE =            (1 << 0)   # Writable
SHF_ALLOC =            (1 << 1)   # Occupies memory during execution
SHF_EXECINSTR =        (1 << 2)   # Executable
SHF_MERGE =            (1 << 4)   # Might be merged
SHF_STRINGS =          (1 << 5)   # Contains nul-terminated strings
SHF_INFO_LINK =        (1 << 6)   # `sh_info' contains SHT index
SHF_LINK_ORDER =       (1 << 7)   # Preserve order after combining
SHF_OS_NONCONFORMING = (1 << 8)   # Non-standard OS specific handling required
SHF_GROUP =           (1 << 9)    # Section is member of a group.
SHF_TLS =             (1 << 10)   # Section hold thread-local data.
SHF_MASKOS =          0x0ff00000 # OS-specific.
SHF_MASKPROC =        0xf0000000 # Processor-specific

# Section group handling.

GRP_COMDAT =      0x1             # Mark group as COMDAT.

# Legal values for p_type (segment type).

PT_NULL =         0               # Program header table entry unused
PT_LOAD =         1               # Loadable program segment
PT_DYNAMIC =      2               # Dynamic linking information
PT_INTERP =       3               # Program interpreter
PT_NOTE =         4               # Auxiliary information
PT_SHLIB =        5               # Reserved
PT_PHDR =         6               # Entry for header table itself
PT_TLS =          7               # Thread-local storage segment
PT_NUM =          8               # Number of defined types
PT_LOOS =         0x60000000     # Start of OS-specific
PT_GNU_EH_FRAME = 0x6474e550     # GCC .eh_frame_hdr segment
PT_GNU_STACK =    0x6474e551     # Indicates stack executability
PT_LOSUNW =       0x6ffffffa
PT_SUNWBSS =      0x6ffffffa     # Sun Specific segment
PT_SUNWSTACK =    0x6ffffffb     # Stack segment
PT_HISUNW =       0x6fffffff
PT_HIOS =         0x6fffffff     # End of OS-specific
PT_LOPROC =       0x70000000     # Start of processor-specific
PT_HIPROC =       0x7fffffff     # End of processor-specific

# Legal values for p_flags (segment flags).

PF_X =            (1 << 0)        # Segment is executable
PF_W =            (1 << 1)        # Segment is writable
PF_R =            (1 << 2)        # Segment is readable
PF_MASKOS =       0x0ff00000     # OS-specific
PF_MASKPROC =     0xf0000000     # Processor-specific

# Legal values for note segment descriptor types for core files.

NT_PRSTATUS =     1               # Contains copy of prstatus struct
NT_FPREGSET =     2               # Contains copy of fpregset struct
NT_PRPSINFO =     3               # Contains copy of prpsinfo struct
NT_PRXREG =       4               # Contains copy of prxregset struct
NT_TASKSTRUCT =   4               # Contains copy of task structure
NT_PLATFORM =     5               # String from sysinfo(SI_PLATFORM)
NT_AUXV =         6               # Contains copy of auxv array
NT_GWINDOWS =     7               # Contains copy of gwindows struct
NT_ASRS =         8               # Contains copy of asrset struct
NT_PSTATUS =      10              # Contains copy of pstatus struct
NT_PSINFO =       13              # Contains copy of psinfo struct
NT_PRCRED =       14              # Contains copy of prcred struct
NT_UTSNAME =      15              # Contains copy of utsname struct
NT_LWPSTATUS =    16              # Contains copy of lwpstatus struct
NT_LWPSINFO =     17              # Contains copy of lwpinfo struct
NT_PRFPXREG =     20              # Contains copy of fprxregset struct

# Legal values for the note segment descriptor types for object files.

NT_VERSION =      1               # Contains a version string.

# Legal values for ST_BIND subfield of st_info (symbol binding).
# bind = Sym.info >> 4
# val = Sym.info 0xf

STB_LOCAL       = 0               # Local symbol
STB_GLOBAL      = 1               # Global symbol
STB_WEAK        = 2               # Weak symbol
STB_NUM         = 3               # Number of defined types.
STB_LOOS        = 10              # Start of OS-specific
STB_HIOS        = 12              # End of OS-specific
STB_LOPROC      = 13              # Start of processor-specific
STB_HIPROC      = 15              # End of processor-specific

#Legal values for ST_TYPE subfield of st_info (symbol type).

STT_NOTYPE      = 0               # Symbol type is unspecified
STT_OBJECT      = 1               # Symbol is a data object
STT_FUNC        = 2               # Symbol is a code object
STT_SECTION     = 3               # Symbol associated with a section
STT_FILE        = 4               # Symbol's name is file name
STT_COMMON      = 5               # Symbol is a common data object
STT_TLS         = 6               # Symbol is thread-local data object*/
STT_NUM         = 7               # Number of defined types.
STT_LOOS        = 10              # Start of OS-specific
STT_GNU_IFUNC   = 10              # Symbol is indirect code object
STT_HIOS        = 12              # End of OS-specific
STT_LOPROC      = 13              # Start of processor-specific
STT_HIPROC      = 15              # End of processor-specific

# Legal values for d_tag (dynamic entry type).

DT_NULL         = 0               # Marks end of dynamic section
DT_NEEDED       = 1               # Name of needed library
DT_PLTRELSZ     = 2               # Size in bytes of PLT relocs
DT_PLTGOT       = 3               # Processor defined value
DT_HASH         = 4               # Address of symbol hash table
DT_STRTAB       = 5               # Address of string table
DT_SYMTAB       = 6               # Address of symbol table
DT_RELA         = 7               # Address of Rela relocs
DT_RELASZ       = 8               # Total size of Rela relocs
DT_RELAENT      = 9               # Size of one Rela reloc
DT_STRSZ        = 10              # Size of string table
DT_SYMENT       = 11              # Size of one symbol table entry
DT_INIT         = 12              # Address of init function
DT_FINI         = 13              # Address of termination function
DT_SONAME       = 14              # Name of shared object
DT_RPATH        = 15              # Library search path (deprecated)
DT_SYMBOLIC     = 16              # Start symbol search here
DT_REL          = 17              # Address of Rel relocs
DT_RELSZ        = 18              # Total size of Rel relocs
DT_RELENT       = 19              # Size of one Rel reloc
DT_PLTREL       = 20              # Type of reloc in PLT
DT_DEBUG        = 21              # For debugging; unspecified
DT_TEXTREL      = 22              # Reloc might modify .text
DT_JMPREL       = 23              # Address of PLT relocs
DT_BIND_NOW     = 24              # Process relocations of object
DT_INIT_ARRAY   = 25              # Array with addresses of init fct
DT_FINI_ARRAY   = 26              # Array with addresses of fini fct
DT_INIT_ARRAYSZ = 27              # Size in bytes of DT_INIT_ARRAY
DT_FINI_ARRAYSZ = 28              # Size in bytes of DT_FINI_ARRAY
DT_RUNPATH      = 29              # Library search path
DT_FLAGS        = 30              # Flags for the object being loaded
DT_ENCODING     = 32              # Start of encoded range
DT_PREINIT_ARRAY = 32             # Array with addresses of preinit fct
DT_PREINIT_ARRAYSZ = 33           # size in bytes of DT_PREINIT_ARRAY
DT_NUM          = 34              # Number used
DT_LOOS         = 0x6000000d      # Start of OS-specific
DT_HIOS         = 0x6ffff000      # End of OS-specific
DT_LOPROC       = 0x70000000      # Start of processor-specific
DT_HIPROC       = 0x7fffffff      # End of processor-specific
#DT_PROCNUM      = DT_MIPS_NUM     # Most used by any processor

# DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
# Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
# approach.
DT_VALRNGLO     = 0x6ffffd00
DT_GNU_PRELINKED = 0x6ffffdf5     # Prelinking timestamp
DT_GNU_CONFLICTSZ = 0x6ffffdf6    # Size of conflict section
DT_GNU_LIBLISTSZ = 0x6ffffdf7     # Size of library list
DT_CHECKSUM     = 0x6ffffdf8
DT_PLTPADSZ     = 0x6ffffdf9
DT_MOVEENT      = 0x6ffffdfa
DT_MOVESZ       = 0x6ffffdfb
DT_FEATURE_1    = 0x6ffffdfc      # Feature selection (DTF_*).
DT_POSFLAG_1    = 0x6ffffdfd      # Flags for DT_* entries, effecting the following DT_* entry.
DT_SYMINSZ      = 0x6ffffdfe      # Size of syminfo table (in bytes)
DT_SYMINENT     = 0x6ffffdff      # Entry size of syminfo
DT_VALRNGHI     = 0x6ffffdff
DT_VALNUM = 12

# DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
# Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
#
# If any adjustment is made to the ELF object after it has been
# built these entries will need to be adjusted.
DT_ADDRRNGLO    = 0x6ffffe00
DT_GNU_CONFLICT = 0x6ffffef8      # Start of conflict section
DT_GNU_LIBLIST  = 0x6ffffef9      # Library list
DT_CONFIG       = 0x6ffffefa      # Configuration information.
DT_DEPAUDIT     = 0x6ffffefb      # Dependency auditing.
DT_AUDIT        = 0x6ffffefc      # Object auditing.
DT_PLTPAD       = 0x6ffffefd      # PLT padding.
DT_MOVETAB      = 0x6ffffefe      # Move table.
DT_SYMINFO      = 0x6ffffeff      # Syminfo table.
DT_ADDRRNGHI    = 0x6ffffeff
DT_ADDRNUM = 10

# The versioning entry types.  The next are defined as part of the
# GNU extension.
DT_VERSYM       = 0x6ffffff0

DT_RELACOUNT    = 0x6ffffff9
DT_RELCOUNT     = 0x6ffffffa

# These were chosen by Sun.
DT_FLAGS_1      = 0x6ffffffb      # State flags, see DF_1_* below.
DT_VERDEF       = 0x6ffffffc      # Address of version definition table
DT_VERDEFNUM    = 0x6ffffffd      # Number of version definitions
DT_VERNEED      = 0x6ffffffe      # Address of table with needed versions
DT_VERNEEDNUM   = 0x6fffffff      # Number of needed versions
DT_VERSIONTAGNUM = 16

# Sun added these machine-independent extensions in the "processor-specific"
# range.  Be compatible.
DT_AUXILIARY    = 0x7ffffffd      # Shared object to load before self
DT_FILTER       = 0x7fffffff      # Shared object to get values from
DT_EXTRANUM     = 3

# Values of `d_un.d_val' in the DT_FLAGS entry.
DF_ORIGIN       = 0x00000001      # Object may use DF_ORIGIN
DF_SYMBOLIC     = 0x00000002      # Symbol resolutions starts here
DF_TEXTREL      = 0x00000004      # Object contains text relocations
DF_BIND_NOW     = 0x00000008      # No lazy binding for this object
DF_STATIC_TLS   = 0x00000010      # Module uses the static TLS model

# State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
# entry in the dynamic section.
DF_1_NOW        = 0x00000001      # Set RTLD_NOW for this object.
DF_1_GLOBAL     = 0x00000002      # Set RTLD_GLOBAL for this object.
DF_1_GROUP      = 0x00000004      # Set RTLD_GROUP for this object.
DF_1_NODELETE   = 0x00000008      # Set RTLD_NODELETE for this object.
DF_1_LOADFLTR   = 0x00000010      # Trigger filtee loading at runtime.
DF_1_INITFIRST  = 0x00000020      # Set RTLD_INITFIRST for this object
DF_1_NOOPEN     = 0x00000040      # Set RTLD_NOOPEN for this object.
DF_1_ORIGIN     = 0x00000080      # $ORIGIN must be handled.
DF_1_DIRECT     = 0x00000100      # Direct binding enabled.
DF_1_TRANS      = 0x00000200
DF_1_INTERPOSE  = 0x00000400      # Object is used to interpose.
DF_1_NODEFLIB   = 0x00000800      # Ignore default lib search path.
DF_1_NODUMP     = 0x00001000      # Object can't be dldump'ed.
DF_1_CONFALT    = 0x00002000      # Configuration alternative created.
DF_1_ENDFILTEE  = 0x00004000      # Filtee terminates filters search.
DF_1_DISPRELDNE = 0x00008000      # Disp reloc applied at build time.
DF_1_DISPRELPND = 0x00010000      # Disp reloc applied at run-time.

# Flags for the feature selection in DT_FEATURE_1.
DTF_1_PARINIT   = 0x00000001
DTF_1_CONFEXP   = 0x00000002

# Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.
DF_P1_LAZYLOAD  = 0x00000001      # Lazyload following object.
DF_P1_GROUPPERM = 0x00000002      # Symbols from next object are not generally available.

# GNU Versioning
VER_FLG_BASE     = 1              # Version of the file itself, must not be used to match symbols
VER_FLG_WEAK     = 2              # Reference to this version is weak
VER_NEED_CURRENT = 1              # Versioning implementation number

# Relocs

# Motorola 68k relocations

R_68K_NONE      = 0               # No reloc
R_68K_32        = 1               # Direct 32 bit
R_68K_16        = 2               # Direct 16 bit
R_68K_8         = 3               # Direct 8 bit
R_68K_PC32      = 4               # PC relative 32 bit
R_68K_PC16      = 5               # PC relative 16 bit
R_68K_PC8       = 6               # PC relative 8 bit
R_68K_GOT32     = 7               # 32 bit PC relative GOT entry
R_68K_GOT16     = 8               # 16 bit PC relative GOT entry
R_68K_GOT8      = 9               # 8 bit PC relative GOT entry
R_68K_GOT32O    = 10              # 32 bit GOT offset
R_68K_GOT16O    = 11              # 16 bit GOT offset
R_68K_GOT8O     = 12              # 8 bit GOT offset
R_68K_PLT32     = 13              # 32 bit PC relative PLT address
R_68K_PLT16     = 14              # 16 bit PC relative PLT address
R_68K_PLT8      = 15              # 8 bit PC relative PLT address
R_68K_PLT32O    = 16              # 32 bit PLT offset
R_68K_PLT16O    = 17              # 16 bit PLT offset
R_68K_PLT8O     = 18              # 8 bit PLT offset
R_68K_COPY      = 19              # Copy symbol at runtime
R_68K_GLOB_DAT  = 20              # Create GOT entry
R_68K_JMP_SLOT  = 21              # Create PLT entry
R_68K_RELATIVE  = 22              # Adjust by program base
R_68K_TLS_GD32      = 25          # 32 bit GOT offset for GD
R_68K_TLS_GD16      = 26          # 16 bit GOT offset for GD
R_68K_TLS_GD8       = 27          # 8 bit GOT offset for GD
R_68K_TLS_LDM32     = 28          # 32 bit GOT offset for LDM
R_68K_TLS_LDM16     = 29          # 16 bit GOT offset for LDM
R_68K_TLS_LDM8      = 30          # 8 bit GOT offset for LDM
R_68K_TLS_LDO32     = 31          # 32 bit module-relative offset
R_68K_TLS_LDO16     = 32          # 16 bit module-relative offset
R_68K_TLS_LDO8      = 33          # 8 bit module-relative offset
R_68K_TLS_IE32      = 34          # 32 bit GOT offset for IE
R_68K_TLS_IE16      = 35          # 16 bit GOT offset for IE
R_68K_TLS_IE8       = 36          # 8 bit GOT offset for IE
R_68K_TLS_LE32      = 37          # 32 bit offset relative to static TLS block
R_68K_TLS_LE16      = 38          # 16 bit offset relative to static TLS block
R_68K_TLS_LE8       = 39          # 8 bit offset relative to static TLS block
R_68K_TLS_DTPMOD32  = 40          # 32 bit module number
R_68K_TLS_DTPREL32  = 41          # 32 bit module-relative offset
R_68K_TLS_TPREL32   = 42          # 32 bit TP-relative offset
# Keep this the last entry.
R_68K_NUM       = 43

# Intel 80386 relocations

R_386_NONE         = 0            # No reloc
R_386_32           = 1            # Direct 32 bit
R_386_PC32         = 2            # PC relative 32 bit
R_386_GOT32        = 3            # 32 bit GOT entry
R_386_PLT32        = 4            # 32 bit PLT address
R_386_COPY         = 5            # Copy symbol at runtime
R_386_GLOB_DAT     = 6            # Create GOT entry
R_386_JMP_SLOT     = 7            # Create PLT entry
R_386_RELATIVE     = 8            # Adjust by program base
R_386_GOTOFF       = 9            # 32 bit offset to GOT
R_386_GOTPC        = 10           # 32 bit PC relative offset to GOT
R_386_32PLT        = 11
R_386_TLS_TPOFF    = 14           # Offset in static TLS block
R_386_TLS_IE       = 15           # Address of GOT entry for static TLS block offset
R_386_TLS_GOTIE    = 16           # GOT entry for static TLS block offset
R_386_TLS_LE       = 17           # Offset relative to static TLS block
R_386_TLS_GD       = 18           # Direct 32 bit for GNU version of general dynamic thread local data
R_386_TLS_LDM      = 19           # Direct 32 bit for GNU version of local dynamic thread local data in LE code
R_386_16           = 20
R_386_PC16         = 21
R_386_8            = 22
R_386_PC8          = 23
R_386_TLS_GD_32    = 24           # Direct 32 bit for general dynamic thread local data
R_386_TLS_GD_PUSH  = 25           # Tag for pushl in GD TLS code
R_386_TLS_GD_CALL  = 26           # Relocation for call to __tls_get_addr()
R_386_TLS_GD_POP   = 27           # Tag for popl in GD TLS code
R_386_TLS_LDM_32   = 28           # Direct 32 bit for local dynamic thread local data in LE code
R_386_TLS_LDM_PUSH = 29           # Tag for pushl in LDM TLS code
R_386_TLS_LDM_CALL = 30           # Relocation for call to __tls_get_addr() in LDM code
R_386_TLS_LDM_POP  = 31           # Tag for popl in LDM TLS code
R_386_TLS_LDO_32   = 32           # Offset relative to TLS block
R_386_TLS_IE_32    = 33           # GOT entry for negated static TLS block offset
R_386_TLS_LE_32    = 34           # Negated offset relative to static TLS block
R_386_TLS_DTPMOD32 = 35           # ID of module containing symbol
R_386_TLS_DTPOFF32 = 36           # Offset in TLS block
R_386_TLS_TPOFF32  = 37           # Negated offset in static TLS block
# 38?
R_386_TLS_GOTDESC  = 39           # GOT offset for TLS descriptor.
R_386_TLS_DESC_CALL = 40          # Marker of call through TLS descriptor for relaxation.
R_386_TLS_DESC     = 41           # TLS descriptor containing pointer to code and to argument, returning the TLS offset for the symbol.
R_386_IRELATIVE    = 42           # Adjust indirectly by program base
# Keep this the last entry.
R_386_NUM          = 43

# SUN SPARC relocations

R_SPARC_NONE            = 0       # No reloc
R_SPARC_8               = 1       # Direct 8 bit
R_SPARC_16              = 2       # Direct 16 bit
R_SPARC_32              = 3       # Direct 32 bit
R_SPARC_DISP8           = 4       # PC relative 8 bit
R_SPARC_DISP16          = 5       # PC relative 16 bit
R_SPARC_DISP32          = 6       # PC relative 32 bit
R_SPARC_WDISP30         = 7       # PC relative 30 bit shifted
R_SPARC_WDISP22         = 8       # PC relative 22 bit shifted
R_SPARC_HI22            = 9       # High 22 bit
R_SPARC_22              = 10      # Direct 22 bit
R_SPARC_13              = 11      # Direct 13 bit
R_SPARC_LO10            = 12      # Truncated 10 bit
R_SPARC_GOT10           = 13      # Truncated 10 bit GOT entry
R_SPARC_GOT13           = 14      # 13 bit GOT entry
R_SPARC_GOT22           = 15      # 22 bit GOT entry shifted
R_SPARC_PC10            = 16      # PC relative 10 bit truncated
R_SPARC_PC22            = 17      # PC relative 22 bit shifted
R_SPARC_WPLT30          = 18      # 30 bit PC relative PLT address
R_SPARC_COPY            = 19      # Copy symbol at runtime
R_SPARC_GLOB_DAT        = 20      # Create GOT entry
R_SPARC_JMP_SLOT        = 21      # Create PLT entry
R_SPARC_RELATIVE        = 22      # Adjust by program base
R_SPARC_UA32            = 23      # Direct 32 bit unaligned

# Additional Sparc64 relocs.

R_SPARC_PLT32           = 24      # Direct 32 bit ref to PLT entry
R_SPARC_HIPLT22         = 25      # High 22 bit PLT entry
R_SPARC_LOPLT10         = 26      # Truncated 10 bit PLT entry
R_SPARC_PCPLT32         = 27      # PC rel 32 bit ref to PLT entry
R_SPARC_PCPLT22         = 28      # PC rel high 22 bit PLT entry
R_SPARC_PCPLT10         = 29      # PC rel trunc 10 bit PLT entry
R_SPARC_10              = 30      # Direct 10 bit
R_SPARC_11              = 31      # Direct 11 bit
R_SPARC_64              = 32      # Direct 64 bit
R_SPARC_OLO10           = 33      # 10bit with secondary 13bit addend
R_SPARC_HH22            = 34      # Top 22 bits of direct 64 bit
R_SPARC_HM10            = 35      # High middle 10 bits of ...
R_SPARC_LM22            = 36      # Low middle 22 bits of ...
R_SPARC_PC_HH22         = 37      # Top 22 bits of pc rel 64 bit
R_SPARC_PC_HM10         = 38      # High middle 10 bit of ...
R_SPARC_PC_LM22         = 39      # Low miggle 22 bits of ...
R_SPARC_WDISP16         = 40      # PC relative 16 bit shifted
R_SPARC_WDISP19         = 41      # PC relative 19 bit shifted
R_SPARC_GLOB_JMP        = 42      # was part of v9 ABI but was removed
R_SPARC_7               = 43      # Direct 7 bit
R_SPARC_5               = 44      # Direct 5 bit
R_SPARC_6               = 45      # Direct 6 bit
R_SPARC_DISP64          = 46      # PC relative 64 bit
R_SPARC_PLT64           = 47      # Direct 64 bit ref to PLT entry
R_SPARC_HIX22           = 48      # High 22 bit complemented
R_SPARC_LOX10           = 49      # Truncated 11 bit complemented
R_SPARC_H44             = 50      # Direct high 12 of 44 bit
R_SPARC_M44             = 51      # Direct mid 22 of 44 bit
R_SPARC_L44             = 52      # Direct low 10 of 44 bit
R_SPARC_REGISTER        = 53      # Global register usage
R_SPARC_UA64            = 54      # Direct 64 bit unaligned
R_SPARC_UA16            = 55      # Direct 16 bit unaligned
R_SPARC_TLS_GD_HI22     = 56
R_SPARC_TLS_GD_LO10     = 57
R_SPARC_TLS_GD_ADD      = 58
R_SPARC_TLS_GD_CALL     = 59
R_SPARC_TLS_LDM_HI22    = 60
R_SPARC_TLS_LDM_LO10    = 61
R_SPARC_TLS_LDM_ADD     = 62
R_SPARC_TLS_LDM_CALL    = 63
R_SPARC_TLS_LDO_HIX22   = 64
R_SPARC_TLS_LDO_LOX10   = 65
R_SPARC_TLS_LDO_ADD     = 66
R_SPARC_TLS_IE_HI22     = 67
R_SPARC_TLS_IE_LO10     = 68
R_SPARC_TLS_IE_LD       = 69
R_SPARC_TLS_IE_LDX      = 70
R_SPARC_TLS_IE_ADD      = 71
R_SPARC_TLS_LE_HIX22    = 72
R_SPARC_TLS_LE_LOX10    = 73
R_SPARC_TLS_DTPMOD32    = 74
R_SPARC_TLS_DTPMOD64    = 75
R_SPARC_TLS_DTPOFF32    = 76
R_SPARC_TLS_DTPOFF64    = 77
R_SPARC_TLS_TPOFF32     = 78
R_SPARC_TLS_TPOFF64     = 79
R_SPARC_GOTDATA_HIX22   = 80
R_SPARC_GOTDATA_LOX10   = 81
R_SPARC_GOTDATA_OP_HIX22        = 82
R_SPARC_GOTDATA_OP_LOX10        = 83
R_SPARC_GOTDATA_OP      = 84
R_SPARC_H34             = 85
R_SPARC_SIZE32          = 86
R_SPARC_SIZE64          = 87
R_SPARC_JMP_IREL        = 248
R_SPARC_IRELATIVE       = 249
R_SPARC_GNU_VTINHERIT   = 250
R_SPARC_GNU_VTENTRY     = 251
R_SPARC_REV32           = 252
# Keep this the last entry.
R_SPARC_NUM             = 253

# MIPS R3000 relocations

R_MIPS_NONE             = 0       # No reloc
R_MIPS_16               = 1       # Direct 16 bit
R_MIPS_32               = 2       # Direct 32 bit
R_MIPS_REL32            = 3       # PC relative 32 bit
R_MIPS_26               = 4       # Direct 26 bit shifted
R_MIPS_HI16             = 5       # High 16 bit
R_MIPS_LO16             = 6       # Low 16 bit
R_MIPS_GPREL16          = 7       # GP relative 16 bit
R_MIPS_LITERAL          = 8       # 16 bit literal entry
R_MIPS_GOT16            = 9       # 16 bit GOT entry
R_MIPS_PC16             = 10      # PC relative 16 bit
R_MIPS_CALL16           = 11      # 16 bit GOT entry for function
R_MIPS_GPREL32          = 12      # GP relative 32 bit

R_MIPS_SHIFT5           = 16
R_MIPS_SHIFT6           = 17
R_MIPS_64               = 18
R_MIPS_GOT_DISP         = 19
R_MIPS_GOT_PAGE         = 20
R_MIPS_GOT_OFST         = 21
R_MIPS_GOT_HI16         = 22
R_MIPS_GOT_LO16         = 23
R_MIPS_SUB              = 24
R_MIPS_INSERT_A         = 25
R_MIPS_INSERT_B         = 26
R_MIPS_DELETE           = 27
R_MIPS_HIGHER           = 28
R_MIPS_HIGHEST          = 29
R_MIPS_CALL_HI16        = 30
R_MIPS_CALL_LO16        = 31
R_MIPS_SCN_DISP         = 32
R_MIPS_REL16            = 33
R_MIPS_ADD_IMMEDIATE    = 34
R_MIPS_PJUMP            = 35
R_MIPS_RELGOT           = 36
R_MIPS_JALR             = 37
R_MIPS_TLS_DTPMOD32     = 38      # Module number 32 bit
R_MIPS_TLS_DTPREL32     = 39      # Module-relative offset 32 bit
R_MIPS_TLS_DTPMOD64     = 40      # Module number 64 bit
R_MIPS_TLS_DTPREL64     = 41      # Module-relative offset 64 bit
R_MIPS_TLS_GD           = 42      # 16 bit GOT offset for GD
R_MIPS_TLS_LDM          = 43      # 16 bit GOT offset for LDM
R_MIPS_TLS_DTPREL_HI16  = 44      # Module-relative offset, high 16 bits
R_MIPS_TLS_DTPREL_LO16  = 45      # Module-relative offset, low 16 bits
R_MIPS_TLS_GOTTPREL     = 46      # 16 bit GOT offset for IE
R_MIPS_TLS_TPREL32      = 47      # TP-relative offset, 32 bit
R_MIPS_TLS_TPREL64      = 48      # TP-relative offset, 64 bit
R_MIPS_TLS_TPREL_HI16   = 49      # TP-relative offset, high 16 bits
R_MIPS_TLS_TPREL_LO16   = 50      # TP-relative offset, low 16 bits
R_MIPS_GLOB_DAT         = 51
R_MIPS_COPY             = 126
R_MIPS_JUMP_SLOT        = 127
# Keep this the last entry.
R_MIPS_NUM              = 128

# HPPA relocations

R_PARISC_NONE           = 0       # No reloc.
R_PARISC_DIR32          = 1       # Direct 32-bit reference.
R_PARISC_DIR21L         = 2       # Left 21 bits of eff. address.
R_PARISC_DIR17R         = 3       # Right 17 bits of eff. address.
R_PARISC_DIR17F         = 4       # 17 bits of eff. address.
R_PARISC_DIR14R         = 6       # Right 14 bits of eff. address.
R_PARISC_PCREL32        = 9       # 32-bit rel. address.
R_PARISC_PCREL21L       = 10      # Left 21 bits of rel. address.
R_PARISC_PCREL17R       = 11      # Right 17 bits of rel. address.
R_PARISC_PCREL17F       = 12      # 17 bits of rel. address.
R_PARISC_PCREL14R       = 14      # Right 14 bits of rel. address.
R_PARISC_DPREL21L       = 18      # Left 21 bits of rel. address.
R_PARISC_DPREL14R       = 22      # Right 14 bits of rel. address.
R_PARISC_GPREL21L       = 26      # GP-relative, left 21 bits.
R_PARISC_GPREL14R       = 30      # GP-relative, right 14 bits.
R_PARISC_LTOFF21L       = 34      # LT-relative, left 21 bits.
R_PARISC_LTOFF14R       = 38      # LT-relative, right 14 bits.
R_PARISC_SECREL32       = 41      # 32 bits section rel. address.
R_PARISC_SEGBASE        = 48      # No relocation, set segment base.
R_PARISC_SEGREL32       = 49      # 32 bits segment rel. address.
R_PARISC_PLTOFF21L      = 50      # PLT rel. address, left 21 bits.
R_PARISC_PLTOFF14R      = 54      # PLT rel. address, right 14 bits.
R_PARISC_LTOFF_FPTR32   = 57      # 32 bits LT-rel. function pointer.
R_PARISC_LTOFF_FPTR21L  = 58      # LT-rel. fct ptr, left 21 bits.
R_PARISC_LTOFF_FPTR14R  = 62      # LT-rel. fct ptr, right 14 bits.
R_PARISC_FPTR64         = 64      # 64 bits function address.
R_PARISC_PLABEL32       = 65      # 32 bits function address.
R_PARISC_PLABEL21L      = 66      # Left 21 bits of fdesc address.
R_PARISC_PLABEL14R      = 70      # Right 14 bits of fdesc address.
R_PARISC_PCREL64        = 72      # 64 bits PC-rel. address.
R_PARISC_PCREL22F       = 74      # 22 bits PC-rel. address.
R_PARISC_PCREL14WR      = 75      # PC-rel. address, right 14 bits.
R_PARISC_PCREL14DR      = 76      # PC rel. address, right 14 bits.
R_PARISC_PCREL16F       = 77      # 16 bits PC-rel. address.
R_PARISC_PCREL16WF      = 78      # 16 bits PC-rel. address.
R_PARISC_PCREL16DF      = 79      # 16 bits PC-rel. address.
R_PARISC_DIR64          = 80      # 64 bits of eff. address.
R_PARISC_DIR14WR        = 83      # 14 bits of eff. address.
R_PARISC_DIR14DR        = 84      # 14 bits of eff. address.
R_PARISC_DIR16F         = 85      # 16 bits of eff. address.
R_PARISC_DIR16WF        = 86      # 16 bits of eff. address.
R_PARISC_DIR16DF        = 87      # 16 bits of eff. address.
R_PARISC_GPREL64        = 88      # 64 bits of GP-rel. address.
R_PARISC_GPREL14WR      = 91      # GP-rel. address, right 14 bits.
R_PARISC_GPREL14DR      = 92      # GP-rel. address, right 14 bits.
R_PARISC_GPREL16F       = 93      # 16 bits GP-rel. address.
R_PARISC_GPREL16WF      = 94      # 16 bits GP-rel. address.
R_PARISC_GPREL16DF      = 95      # 16 bits GP-rel. address.
R_PARISC_LTOFF64        = 96      # 64 bits LT-rel. address.
R_PARISC_LTOFF14WR      = 99      # LT-rel. address, right 14 bits.
R_PARISC_LTOFF14DR      = 100     # LT-rel. address, right 14 bits.
R_PARISC_LTOFF16F       = 101     # 16 bits LT-rel. address.
R_PARISC_LTOFF16WF      = 102     # 16 bits LT-rel. address.
R_PARISC_LTOFF16DF      = 103     # 16 bits LT-rel. address.
R_PARISC_SECREL64       = 104     # 64 bits section rel. address.
R_PARISC_SEGREL64       = 112     # 64 bits segment rel. address.
R_PARISC_PLTOFF14WR     = 115     # PLT-rel. address, right 14 bits.
R_PARISC_PLTOFF14DR     = 116     # PLT-rel. address, right 14 bits.
R_PARISC_PLTOFF16F      = 117     # 16 bits LT-rel. address.
R_PARISC_PLTOFF16WF     = 118     # 16 bits PLT-rel. address.
R_PARISC_PLTOFF16DF     = 119     # 16 bits PLT-rel. address.
R_PARISC_LTOFF_FPTR64   = 120     # 64 bits LT-rel. function ptr.
R_PARISC_LTOFF_FPTR14WR = 123     # LT-rel. fct. ptr., right 14 bits.
R_PARISC_LTOFF_FPTR14DR = 124     # LT-rel. fct. ptr., right 14 bits.
R_PARISC_LTOFF_FPTR16F  = 125     # 16 bits LT-rel. function ptr.
R_PARISC_LTOFF_FPTR16WF = 126     # 16 bits LT-rel. function ptr.
R_PARISC_LTOFF_FPTR16DF = 127     # 16 bits LT-rel. function ptr.
R_PARISC_LORESERVE      = 128
R_PARISC_COPY           = 128     # Copy relocation.
R_PARISC_IPLT           = 129     # Dynamic reloc, imported PLT
R_PARISC_EPLT           = 130     # Dynamic reloc, exported PLT
R_PARISC_TPREL32        = 153     # 32 bits TP-rel. address.
R_PARISC_TPREL21L       = 154     # TP-rel. address, left 21 bits.
R_PARISC_TPREL14R       = 158     # TP-rel. address, right 14 bits.
R_PARISC_LTOFF_TP21L    = 162     # LT-TP-rel. address, left 21 bits.
R_PARISC_LTOFF_TP14R    = 166     # LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP14F    = 167     # 14 bits LT-TP-rel. address.
R_PARISC_TPREL64        = 216     # 64 bits TP-rel. address.
R_PARISC_TPREL14WR      = 219     # TP-rel. address, right 14 bits.
R_PARISC_TPREL14DR      = 220     # TP-rel. address, right 14 bits.
R_PARISC_TPREL16F       = 221     # 16 bits TP-rel. address.
R_PARISC_TPREL16WF      = 222     # 16 bits TP-rel. address.
R_PARISC_TPREL16DF      = 223     # 16 bits TP-rel. address.
R_PARISC_LTOFF_TP64     = 224     # 64 bits LT-TP-rel. address.
R_PARISC_LTOFF_TP14WR   = 227     # LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP14DR   = 228     # LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP16F    = 229     # 16 bits LT-TP-rel. address.
R_PARISC_LTOFF_TP16WF   = 230     # 16 bits LT-TP-rel. address.
R_PARISC_LTOFF_TP16DF   = 231     # 16 bits LT-TP-rel. address.
R_PARISC_GNU_VTENTRY    = 232
R_PARISC_GNU_VTINHERIT  = 233
R_PARISC_TLS_GD21L      = 234     # GD 21-bit left.
R_PARISC_TLS_GD14R      = 235     # GD 14-bit right.
R_PARISC_TLS_GDCALL     = 236     # GD call to __t_g_a.
R_PARISC_TLS_LDM21L     = 237     # LD module 21-bit left.
R_PARISC_TLS_LDM14R     = 238     # LD module 14-bit right.
R_PARISC_TLS_LDMCALL    = 239     # LD module call to __t_g_a.
R_PARISC_TLS_LDO21L     = 240     # LD offset 21-bit left.
R_PARISC_TLS_LDO14R     = 241     # LD offset 14-bit right.
R_PARISC_TLS_DTPMOD32   = 242     # DTP module 32-bit.
R_PARISC_TLS_DTPMOD64   = 243     # DTP module 64-bit.
R_PARISC_TLS_DTPOFF32   = 244     # DTP offset 32-bit.
R_PARISC_TLS_DTPOFF64   = 245     # DTP offset 32-bit.
R_PARISC_TLS_LE21L      = R_PARISC_TPREL21L
R_PARISC_TLS_LE14R      = R_PARISC_TPREL14R
R_PARISC_TLS_IE21L      = R_PARISC_LTOFF_TP21L
R_PARISC_TLS_IE14R      = R_PARISC_LTOFF_TP14R
R_PARISC_TLS_TPREL32    = R_PARISC_TPREL32
R_PARISC_TLS_TPREL64    = R_PARISC_TPREL64
R_PARISC_HIRESERVE      = 255

# Alpha relocations

R_ALPHA_NONE            = 0       # No reloc
R_ALPHA_REFLONG         = 1       # Direct 32 bit
R_ALPHA_REFQUAD         = 2       # Direct 64 bit
R_ALPHA_GPREL32         = 3       # GP relative 32 bit
R_ALPHA_LITERAL         = 4       # GP relative 16 bit w/optimization
R_ALPHA_LITUSE          = 5       # Optimization hint for LITERAL
R_ALPHA_GPDISP          = 6       # Add displacement to GP
R_ALPHA_BRADDR          = 7       # PC+4 relative 23 bit shifted
R_ALPHA_HINT            = 8       # PC+4 relative 16 bit shifted
R_ALPHA_SREL16          = 9       # PC relative 16 bit
R_ALPHA_SREL32          = 10      # PC relative 32 bit
R_ALPHA_SREL64          = 11      # PC relative 64 bit
R_ALPHA_GPRELHIGH       = 17      # GP relative 32 bit, high 16 bits
R_ALPHA_GPRELLOW        = 18      # GP relative 32 bit, low 16 bits
R_ALPHA_GPREL16         = 19      # GP relative 16 bit
R_ALPHA_COPY            = 24      # Copy symbol at runtime
R_ALPHA_GLOB_DAT        = 25      # Create GOT entry
R_ALPHA_JMP_SLOT        = 26      # Create PLT entry
R_ALPHA_RELATIVE        = 27      # Adjust by program base
R_ALPHA_TLS_GD_HI       = 28
R_ALPHA_TLSGD           = 29
R_ALPHA_TLS_LDM         = 30
R_ALPHA_DTPMOD64        = 31
R_ALPHA_GOTDTPREL       = 32
R_ALPHA_DTPREL64        = 33
R_ALPHA_DTPRELHI        = 34
R_ALPHA_DTPRELLO        = 35
R_ALPHA_DTPREL16        = 36
R_ALPHA_GOTTPREL        = 37
R_ALPHA_TPREL64         = 38
R_ALPHA_TPRELHI         = 39
R_ALPHA_TPRELLO         = 40
R_ALPHA_TPREL16         = 41
# Keep this the last entry.
R_ALPHA_NUM             = 46

# PowerPC relocations

R_PPC_NONE              = 0
R_PPC_ADDR32            = 1       # 32bit absolute address
R_PPC_ADDR24            = 2       # 26bit address, 2 bits ignored.
R_PPC_ADDR16            = 3       # 16bit absolute address
R_PPC_ADDR16_LO         = 4       # lower 16bit of absolute address
R_PPC_ADDR16_HI         = 5       # high 16bit of absolute address
R_PPC_ADDR16_HA         = 6       # adjusted high 16bit
R_PPC_ADDR14            = 7       # 16bit address, 2 bits ignored
R_PPC_ADDR14_BRTAKEN    = 8
R_PPC_ADDR14_BRNTAKEN   = 9
R_PPC_REL24             = 10      # PC relative 26 bit
R_PPC_REL14             = 11      # PC relative 16 bit
R_PPC_REL14_BRTAKEN     = 12
R_PPC_REL14_BRNTAKEN    = 13
R_PPC_GOT16             = 14
R_PPC_GOT16_LO          = 15
R_PPC_GOT16_HI          = 16
R_PPC_GOT16_HA          = 17
R_PPC_PLTREL24          = 18
R_PPC_COPY              = 19
R_PPC_GLOB_DAT          = 20
R_PPC_JMP_SLOT          = 21
R_PPC_RELATIVE          = 22
R_PPC_LOCAL24PC         = 23
R_PPC_UADDR32           = 24
R_PPC_UADDR16           = 25
R_PPC_REL32             = 26
R_PPC_PLT32             = 27
R_PPC_PLTREL32          = 28
R_PPC_PLT16_LO          = 29
R_PPC_PLT16_HI          = 30
R_PPC_PLT16_HA          = 31
R_PPC_SDAREL16          = 32
R_PPC_SECTOFF           = 33
R_PPC_SECTOFF_LO        = 34
R_PPC_SECTOFF_HI        = 35
R_PPC_SECTOFF_HA        = 36

# PowerPC relocations defined for the TLS access ABI.
R_PPC_TLS               = 67 # none       (sym+add)@tls
R_PPC_DTPMOD32          = 68 # word32     (sym+add)@dtpmod
R_PPC_TPREL16           = 69 # half16*    (sym+add)@tprel
R_PPC_TPREL16_LO        = 70 # half16     (sym+add)@tprel@l
R_PPC_TPREL16_HI        = 71 # half16     (sym+add)@tprel@h
R_PPC_TPREL16_HA        = 72 # half16     (sym+add)@tprel@ha
R_PPC_TPREL32           = 73 # word32     (sym+add)@tprel
R_PPC_DTPREL16          = 74 # half16*    (sym+add)@dtprel
R_PPC_DTPREL16_LO       = 75 # half16     (sym+add)@dtprel@l
R_PPC_DTPREL16_HI       = 76 # half16     (sym+add)@dtprel@h
R_PPC_DTPREL16_HA       = 77 # half16     (sym+add)@dtprel@ha
R_PPC_DTPREL32          = 78 # word32     (sym+add)@dtprel
R_PPC_GOT_TLSGD16       = 79 # half16*    (sym+add)@got@tlsgd
R_PPC_GOT_TLSGD16_LO    = 80 # half16     (sym+add)@got@tlsgd@l
R_PPC_GOT_TLSGD16_HI    = 81 # half16     (sym+add)@got@tlsgd@h
R_PPC_GOT_TLSGD16_HA    = 82 # half16     (sym+add)@got@tlsgd@ha
R_PPC_GOT_TLSLD16       = 83 # half16*    (sym+add)@got@tlsld
R_PPC_GOT_TLSLD16_LO    = 84 # half16     (sym+add)@got@tlsld@l
R_PPC_GOT_TLSLD16_HI    = 85 # half16     (sym+add)@got@tlsld@h
R_PPC_GOT_TLSLD16_HA    = 86 # half16     (sym+add)@got@tlsld@ha
R_PPC_GOT_TPREL16       = 87 # half16*    (sym+add)@got@tprel
R_PPC_GOT_TPREL16_LO    = 88 # half16     (sym+add)@got@tprel@l
R_PPC_GOT_TPREL16_HI    = 89 # half16     (sym+add)@got@tprel@h
R_PPC_GOT_TPREL16_HA    = 90 # half16     (sym+add)@got@tprel@ha
R_PPC_GOT_DTPREL16      = 91 # half16*    (sym+add)@got@dtprel
R_PPC_GOT_DTPREL16_LO   = 92 # half16*    (sym+add)@got@dtprel@l
R_PPC_GOT_DTPREL16_HI   = 93 # half16*    (sym+add)@got@dtprel@h
R_PPC_GOT_DTPREL16_HA   = 94 # half16*    (sym+add)@got@dtprel@ha

# The remaining relocs are from the Embedded ELF ABI, and are not in the SVR4 ELF ABI.
R_PPC_EMB_NADDR32       = 101
R_PPC_EMB_NADDR16       = 102
R_PPC_EMB_NADDR16_LO    = 103
R_PPC_EMB_NADDR16_HI    = 104
R_PPC_EMB_NADDR16_HA    = 105
R_PPC_EMB_SDAI16        = 106
R_PPC_EMB_SDA2I16       = 107
R_PPC_EMB_SDA2REL       = 108
R_PPC_EMB_SDA21         = 109     # 16 bit offset in SDA
R_PPC_EMB_MRKREF        = 110
R_PPC_EMB_RELSEC16      = 111
R_PPC_EMB_RELST_LO      = 112
R_PPC_EMB_RELST_HI      = 113
R_PPC_EMB_RELST_HA      = 114
R_PPC_EMB_BIT_FLD       = 115
R_PPC_EMB_RELSDA        = 116     # 16 bit relative offset in SDA

# Diab tool relocations.
R_PPC_DIAB_SDA21_LO     = 180     # like EMB_SDA21, but lower 16 bit
R_PPC_DIAB_SDA21_HI     = 181     # like EMB_SDA21, but high 16 bit
R_PPC_DIAB_SDA21_HA     = 182     # like EMB_SDA21, adjusted high 16
R_PPC_DIAB_RELSDA_LO    = 183     # like EMB_RELSDA, but lower 16 bit
R_PPC_DIAB_RELSDA_HI    = 184     # like EMB_RELSDA, but high 16 bit
R_PPC_DIAB_RELSDA_HA    = 185     # like EMB_RELSDA, adjusted high 16

# GNU extension to support local ifunc.
R_PPC_IRELATIVE         = 248

# GNU relocs used in PIC code sequences.
R_PPC_REL16             = 249     # half16   (sym+add-.)
R_PPC_REL16_LO          = 250     # half16   (sym+add-.)@l
R_PPC_REL16_HI          = 251     # half16   (sym+add-.)@h
R_PPC_REL16_HA          = 252     # half16   (sym+add-.)@ha

# This is a phony reloc to handle any old fashioned TOC16 references that may still be in object files.
R_PPC_TOC16             = 255

# PowerPC64 relocations defined by the ABIs
R_PPC64_NONE            = R_PPC_NONE
R_PPC64_ADDR32          = R_PPC_ADDR32 # 32bit absolute address
R_PPC64_ADDR24          = R_PPC_ADDR24 # 26bit address, word aligned
R_PPC64_ADDR16          = R_PPC_ADDR16 # 16bit absolute address
R_PPC64_ADDR16_LO       = R_PPC_ADDR16_LO # lower 16bits of address
R_PPC64_ADDR16_HI       = R_PPC_ADDR16_HI # high 16bits of address.
R_PPC64_ADDR16_HA       = R_PPC_ADDR16_HA # adjusted high 16bits.
R_PPC64_ADDR14          = R_PPC_ADDR14 # 16bit address, word aligned
R_PPC64_ADDR14_BRTAKEN  = R_PPC_ADDR14_BRTAKEN
R_PPC64_ADDR14_BRNTAKEN = R_PPC_ADDR14_BRNTAKEN
R_PPC64_REL24           = R_PPC_REL24 # PC-rel. 26 bit, word aligned
R_PPC64_REL14           = R_PPC_REL14 # PC relative 16 bit
R_PPC64_REL14_BRTAKEN   = R_PPC_REL14_BRTAKEN
R_PPC64_REL14_BRNTAKEN  = R_PPC_REL14_BRNTAKEN
R_PPC64_GOT16           = R_PPC_GOT16
R_PPC64_GOT16_LO        = R_PPC_GOT16_LO
R_PPC64_GOT16_HI        = R_PPC_GOT16_HI
R_PPC64_GOT16_HA        = R_PPC_GOT16_HA

R_PPC64_COPY            = R_PPC_COPY
R_PPC64_GLOB_DAT        = R_PPC_GLOB_DAT
R_PPC64_JMP_SLOT        = R_PPC_JMP_SLOT
R_PPC64_RELATIVE        = R_PPC_RELATIVE

R_PPC64_UADDR32         = R_PPC_UADDR32
R_PPC64_UADDR16         = R_PPC_UADDR16
R_PPC64_REL32           = R_PPC_REL32
R_PPC64_PLT32           = R_PPC_PLT32
R_PPC64_PLTREL32        = R_PPC_PLTREL32
R_PPC64_PLT16_LO        = R_PPC_PLT16_LO
R_PPC64_PLT16_HI        = R_PPC_PLT16_HI
R_PPC64_PLT16_HA        = R_PPC_PLT16_HA

R_PPC64_SECTOFF         = R_PPC_SECTOFF
R_PPC64_SECTOFF_LO      = R_PPC_SECTOFF_LO
R_PPC64_SECTOFF_HI      = R_PPC_SECTOFF_HI
R_PPC64_SECTOFF_HA      = R_PPC_SECTOFF_HA
R_PPC64_ADDR30          = 37 # word30 (S + A - P) >> 2
R_PPC64_ADDR64          = 38 # doubleword64 S + A
R_PPC64_ADDR16_HIGHER   = 39 # half16 #higher(S + A)
R_PPC64_ADDR16_HIGHERA  = 40 # half16 #highera(S + A)
R_PPC64_ADDR16_HIGHEST  = 41 # half16 #highest(S + A)
R_PPC64_ADDR16_HIGHESTA = 42 # half16 #highesta(S + A)
R_PPC64_UADDR64         = 43 # doubleword64 S + A
R_PPC64_REL64           = 44 # doubleword64 S + A - P
R_PPC64_PLT64           = 45 # doubleword64 L + A
R_PPC64_PLTREL64        = 46 # doubleword64 L + A - P
R_PPC64_TOC16           = 47 # half16* S + A - .TOC
R_PPC64_TOC16_LO        = 48 # half16 #lo(S + A - .TOC.)
R_PPC64_TOC16_HI        = 49 # half16 #hi(S + A - .TOC.)
R_PPC64_TOC16_HA        = 50 # half16 #ha(S + A - .TOC.)
R_PPC64_TOC             = 51 # doubleword64 .TOC
R_PPC64_PLTGOT16        = 52 # half16* M + A
R_PPC64_PLTGOT16_LO     = 53 # half16 #lo(M + A)
R_PPC64_PLTGOT16_HI     = 54 # half16 #hi(M + A)
R_PPC64_PLTGOT16_HA     = 55 # half16 #ha(M + A)

R_PPC64_ADDR16_DS       = 56 # half16ds* (S + A) >> 2
R_PPC64_ADDR16_LO_DS    = 57 # half16ds  #lo(S + A) >> 2
R_PPC64_GOT16_DS        = 58 # half16ds* (G + A) >> 2
R_PPC64_GOT16_LO_DS     = 59 # half16ds  #lo(G + A) >> 2
R_PPC64_PLT16_LO_DS     = 60 # half16ds  #lo(L + A) >> 2
R_PPC64_SECTOFF_DS      = 61 # half16ds* (R + A) >> 2
R_PPC64_SECTOFF_LO_DS   = 62 # half16ds  #lo(R + A) >> 2
R_PPC64_TOC16_DS        = 63 # half16ds* (S + A - .TOC.) >> 2
R_PPC64_TOC16_LO_DS     = 64 # half16ds  #lo(S + A - .TOC.) >> 2
R_PPC64_PLTGOT16_DS     = 65 # half16ds* (M + A) >> 2
R_PPC64_PLTGOT16_LO_DS  = 66 # half16ds  #lo(M + A) >> 2

# PowerPC64 relocations defined for the TLS access ABI.
R_PPC64_TLS             = 67 # none       (sym+add)@tls
R_PPC64_DTPMOD64        = 68 # doubleword64 (sym+add)@dtpmod
R_PPC64_TPREL16         = 69 # half16*    (sym+add)@tprel
R_PPC64_TPREL16_LO      = 70 # half16     (sym+add)@tprel@l
R_PPC64_TPREL16_HI      = 71 # half16     (sym+add)@tprel@h
R_PPC64_TPREL16_HA      = 72 # half16     (sym+add)@tprel@ha
R_PPC64_TPREL64         = 73 # doubleword64 (sym+add)@tprel
R_PPC64_DTPREL16        = 74 # half16*    (sym+add)@dtprel
R_PPC64_DTPREL16_LO     = 75 # half16     (sym+add)@dtprel@l
R_PPC64_DTPREL16_HI     = 76 # half16     (sym+add)@dtprel@h
R_PPC64_DTPREL16_HA     = 77 # half16     (sym+add)@dtprel@ha
R_PPC64_DTPREL64        = 78 # doubleword64 (sym+add)@dtprel
R_PPC64_GOT_TLSGD16     = 79 # half16*    (sym+add)@got@tlsgd
R_PPC64_GOT_TLSGD16_LO  = 80 # half16     (sym+add)@got@tlsgd@l
R_PPC64_GOT_TLSGD16_HI  = 81 # half16     (sym+add)@got@tlsgd@h
R_PPC64_GOT_TLSGD16_HA  = 82 # half16     (sym+add)@got@tlsgd@ha
R_PPC64_GOT_TLSLD16     = 83 # half16*    (sym+add)@got@tlsld
R_PPC64_GOT_TLSLD16_LO  = 84 # half16     (sym+add)@got@tlsld@l
R_PPC64_GOT_TLSLD16_HI  = 85 # half16     (sym+add)@got@tlsld@h
R_PPC64_GOT_TLSLD16_HA  = 86 # half16     (sym+add)@got@tlsld@ha
R_PPC64_GOT_TPREL16_DS  = 87 # half16ds*  (sym+add)@got@tprel
R_PPC64_GOT_TPREL16_LO_DS = 88 # half16ds (sym+add)@got@tprel@l
R_PPC64_GOT_TPREL16_HI  = 89 # half16     (sym+add)@got@tprel@h
R_PPC64_GOT_TPREL16_HA  = 90 # half16     (sym+add)@got@tprel@ha
R_PPC64_GOT_DTPREL16_DS = 91 # half16ds*  (sym+add)@got@dtprel
R_PPC64_GOT_DTPREL16_LO_DS = 92 # half16ds (sym+add)@got@dtprel@l
R_PPC64_GOT_DTPREL16_HI = 93 # half16     (sym+add)@got@dtprel@h
R_PPC64_GOT_DTPREL16_HA = 94 # half16     (sym+add)@got@dtprel@ha
R_PPC64_TPREL16_DS      = 95 # half16ds*  (sym+add)@tprel
R_PPC64_TPREL16_LO_DS   = 96 # half16ds   (sym+add)@tprel@l
R_PPC64_TPREL16_HIGHER  = 97 # half16     (sym+add)@tprel@higher
R_PPC64_TPREL16_HIGHERA = 98 # half16     (sym+add)@tprel@highera
R_PPC64_TPREL16_HIGHEST = 99 # half16     (sym+add)@tprel@highest
R_PPC64_TPREL16_HIGHESTA = 100 # half16   (sym+add)@tprel@highesta
R_PPC64_DTPREL16_DS     = 101 # half16ds* (sym+add)@dtprel
R_PPC64_DTPREL16_LO_DS  = 102 # half16ds  (sym+add)@dtprel@l
R_PPC64_DTPREL16_HIGHER = 103 # half16    (sym+add)@dtprel@higher
R_PPC64_DTPREL16_HIGHERA = 104 # half16   (sym+add)@dtprel@highera
R_PPC64_DTPREL16_HIGHEST = 105 # half16   (sym+add)@dtprel@highest
R_PPC64_DTPREL16_HIGHESTA = 106 # half16  (sym+add)@dtprel@highesta

# GNU extension to support local ifunc.
R_PPC64_JMP_IREL        = 247
R_PPC64_IRELATIVE       = 248
R_PPC64_REL16           = 249     # half16   (sym+add-.)
R_PPC64_REL16_LO        = 250     # half16   (sym+add-.)@l
R_PPC64_REL16_HI        = 251     # half16   (sym+add-.)@h
R_PPC64_REL16_HA        = 252     # half16   (sym+add-.)@ha

# PowerPC64 specific values for the Dyn d_tag field.
DT_PPC64_GLINK  = (DT_LOPROC + 0)
DT_PPC64_OPD    = (DT_LOPROC + 1)
DT_PPC64_OPDSZ  = (DT_LOPROC + 2)
DT_PPC64_NUM    = 3

# ARM relocations

R_ARM_NONE              = 0       # No reloc
R_ARM_PC24              = 1       # PC relative 26 bit branch
R_ARM_ABS32             = 2       # Direct 32 bit
R_ARM_REL32             = 3       # PC relative 32 bit
R_ARM_PC13              = 4
R_ARM_ABS16             = 5       # Direct 16 bit
R_ARM_ABS12             = 6       # Direct 12 bit
R_ARM_THM_ABS5          = 7
R_ARM_ABS8              = 8       # Direct 8 bit
R_ARM_SBREL32           = 9
R_ARM_THM_PC22          = 10
R_ARM_THM_PC8           = 11
R_ARM_AMP_VCALL9        = 12
R_ARM_SWI24             = 13      # Obsolete static relocation.
R_ARM_TLS_DESC          = 13      # Dynamic relocation.
R_ARM_THM_SWI8          = 14
R_ARM_XPC25             = 15
R_ARM_THM_XPC22         = 16
R_ARM_TLS_DTPMOD32      = 17      # ID of module containing symbol
R_ARM_TLS_DTPOFF32      = 18      # Offset in TLS block
R_ARM_TLS_TPOFF32       = 19      # Offset in static TLS block
R_ARM_COPY              = 20      # Copy symbol at runtime
R_ARM_GLOB_DAT          = 21      # Create GOT entry
R_ARM_JUMP_SLOT         = 22      # Create PLT entry
R_ARM_RELATIVE          = 23      # Adjust by program base
R_ARM_GOTOFF            = 24      # 32 bit offset to GOT
R_ARM_GOTPC             = 25      # 32 bit PC relative offset to GOT
R_ARM_GOT32             = 26      # 32 bit GOT entry
R_ARM_PLT32             = 27      # 32 bit PLT address
R_ARM_ALU_PCREL_7_0     = 32
R_ARM_ALU_PCREL_15_8    = 33
R_ARM_ALU_PCREL_23_15   = 34
R_ARM_LDR_SBREL_11_0    = 35
R_ARM_ALU_SBREL_19_12   = 36
R_ARM_ALU_SBREL_27_20   = 37
R_ARM_TLS_GOTDESC       = 90
R_ARM_TLS_CALL          = 91
R_ARM_TLS_DESCSEQ       = 92
R_ARM_THM_TLS_CALL      = 93
R_ARM_GNU_VTENTRY       = 100
R_ARM_GNU_VTINHERIT     = 101
R_ARM_THM_PC11          = 102     # thumb unconditional branch
R_ARM_THM_PC9           = 103     # thumb conditional branch
R_ARM_TLS_GD32          = 104     # PC-rel 32 bit for global dynamic thread local data
R_ARM_TLS_LDM32         = 105     # PC-rel 32 bit for local dynamic thread local data
R_ARM_TLS_LDO32         = 106     # 32 bit offset relative to TLS block
R_ARM_TLS_IE32          = 107     # PC-rel 32 bit for GOT entry of static TLS block offset
R_ARM_TLS_LE32          = 108     # 32 bit offset relative to static TLS block
R_ARM_THM_TLS_DESCSEQ   = 129
R_ARM_IRELATIVE         = 160
R_ARM_RXPC25            = 249
R_ARM_RSBREL32          = 250
R_ARM_THM_RPC22         = 251
R_ARM_RREL32            = 252
R_ARM_RABS22            = 253
R_ARM_RPC24             = 254
R_ARM_RBASE             = 255
# Keep this the last entry.
R_ARM_NUM               = 256

# IA-64 relocations

R_IA64_NONE             = 0x00    # none
R_IA64_IMM14            = 0x21    # symbol + addend, add imm14
R_IA64_IMM22            = 0x22    # symbol + addend, add imm22
R_IA64_IMM64            = 0x23    # symbol + addend, mov imm64
R_IA64_DIR32MSB         = 0x24    # symbol + addend, data4 MSB
R_IA64_DIR32LSB         = 0x25    # symbol + addend, data4 LSB
R_IA64_DIR64MSB         = 0x26    # symbol + addend, data8 MSB
R_IA64_DIR64LSB         = 0x27    # symbol + addend, data8 LSB
R_IA64_GPREL22          = 0x2a    # @gprel(sym + add), add imm22
R_IA64_GPREL64I         = 0x2b    # @gprel(sym + add), mov imm64
R_IA64_GPREL32MSB       = 0x2c    # @gprel(sym + add), data4 MSB
R_IA64_GPREL32LSB       = 0x2d    # @gprel(sym + add), data4 LSB
R_IA64_GPREL64MSB       = 0x2e    # @gprel(sym + add), data8 MSB
R_IA64_GPREL64LSB       = 0x2f    # @gprel(sym + add), data8 LSB
R_IA64_LTOFF22          = 0x32    # @ltoff(sym + add), add imm22
R_IA64_LTOFF64I         = 0x33    # @ltoff(sym + add), mov imm64
R_IA64_PLTOFF22         = 0x3a    # @pltoff(sym + add), add imm22
R_IA64_PLTOFF64I        = 0x3b    # @pltoff(sym + add), mov imm64
R_IA64_PLTOFF64MSB      = 0x3e    # @pltoff(sym + add), data8 MSB
R_IA64_PLTOFF64LSB      = 0x3f    # @pltoff(sym + add), data8 LSB
R_IA64_FPTR64I          = 0x43    # @fptr(sym + add), mov imm64
R_IA64_FPTR32MSB        = 0x44    # @fptr(sym + add), data4 MSB
R_IA64_FPTR32LSB        = 0x45    # @fptr(sym + add), data4 LSB
R_IA64_FPTR64MSB        = 0x46    # @fptr(sym + add), data8 MSB
R_IA64_FPTR64LSB        = 0x47    # @fptr(sym + add), data8 LSB
R_IA64_PCREL60B         = 0x48    # @pcrel(sym + add), brl
R_IA64_PCREL21B         = 0x49    # @pcrel(sym + add), ptb, call
R_IA64_PCREL21M         = 0x4a    # @pcrel(sym + add), chk.s
R_IA64_PCREL21F         = 0x4b    # @pcrel(sym + add), fchkf
R_IA64_PCREL32MSB       = 0x4c    # @pcrel(sym + add), data4 MSB
R_IA64_PCREL32LSB       = 0x4d    # @pcrel(sym + add), data4 LSB
R_IA64_PCREL64MSB       = 0x4e    # @pcrel(sym + add), data8 MSB
R_IA64_PCREL64LSB       = 0x4f    # @pcrel(sym + add), data8 LSB
R_IA64_LTOFF_FPTR22     = 0x52    # @ltoff(@fptr(s+a)), imm22
R_IA64_LTOFF_FPTR64I    = 0x53    # @ltoff(@fptr(s+a)), imm64
R_IA64_LTOFF_FPTR32MSB  = 0x54    # @ltoff(@fptr(s+a)), data4 MSB
R_IA64_LTOFF_FPTR32LSB  = 0x55    # @ltoff(@fptr(s+a)), data4 LSB
R_IA64_LTOFF_FPTR64MSB  = 0x56    # @ltoff(@fptr(s+a)), data8 MSB
R_IA64_LTOFF_FPTR64LSB  = 0x57    # @ltoff(@fptr(s+a)), data8 LSB
R_IA64_SEGREL32MSB      = 0x5c    # @segrel(sym + add), data4 MSB
R_IA64_SEGREL32LSB      = 0x5d    # @segrel(sym + add), data4 LSB
R_IA64_SEGREL64MSB      = 0x5e    # @segrel(sym + add), data8 MSB
R_IA64_SEGREL64LSB      = 0x5f    # @segrel(sym + add), data8 LSB
R_IA64_SECREL32MSB      = 0x64    # @secrel(sym + add), data4 MSB
R_IA64_SECREL32LSB      = 0x65    # @secrel(sym + add), data4 LSB
R_IA64_SECREL64MSB      = 0x66    # @secrel(sym + add), data8 MSB
R_IA64_SECREL64LSB      = 0x67    # @secrel(sym + add), data8 LSB
R_IA64_REL32MSB         = 0x6c    # data 4 + REL
R_IA64_REL32LSB         = 0x6d    # data 4 + REL
R_IA64_REL64MSB         = 0x6e    # data 8 + REL
R_IA64_REL64LSB         = 0x6f    # data 8 + REL
R_IA64_LTV32MSB         = 0x74    # symbol + addend, data4 MSB
R_IA64_LTV32LSB         = 0x75    # symbol + addend, data4 LSB
R_IA64_LTV64MSB         = 0x76    # symbol + addend, data8 MSB
R_IA64_LTV64LSB         = 0x77    # symbol + addend, data8 LSB
R_IA64_PCREL21BI        = 0x79    # @pcrel(sym + add), 21bit inst
R_IA64_PCREL22          = 0x7a    # @pcrel(sym + add), 22bit inst
R_IA64_PCREL64I         = 0x7b    # @pcrel(sym + add), 64bit inst
R_IA64_IPLTMSB          = 0x80    # dynamic reloc, imported PLT, MSB
R_IA64_IPLTLSB          = 0x81    # dynamic reloc, imported PLT, LSB
R_IA64_COPY             = 0x84    # copy relocation
R_IA64_SUB              = 0x85    # Addend and symbol difference
R_IA64_LTOFF22X         = 0x86    # LTOFF22, relaxable.
R_IA64_LDXMOV           = 0x87    # Use of LTOFF22X.
R_IA64_TPREL14          = 0x91    # @tprel(sym + add), imm14
R_IA64_TPREL22          = 0x92    # @tprel(sym + add), imm22
R_IA64_TPREL64I         = 0x93    # @tprel(sym + add), imm64
R_IA64_TPREL64MSB       = 0x96    # @tprel(sym + add), data8 MSB
R_IA64_TPREL64LSB       = 0x97    # @tprel(sym + add), data8 LSB
R_IA64_LTOFF_TPREL22    = 0x9a    # @ltoff(@tprel(s+a)), imm2
R_IA64_DTPMOD64MSB      = 0xa6    # @dtpmod(sym + add), data8 MSB
R_IA64_DTPMOD64LSB      = 0xa7    # @dtpmod(sym + add), data8 LSB
R_IA64_LTOFF_DTPMOD22   = 0xaa    # @ltoff(@dtpmod(sym + add)), imm22
R_IA64_DTPREL14         = 0xb1    # @dtprel(sym + add), imm14
R_IA64_DTPREL22         = 0xb2    # @dtprel(sym + add), imm22
R_IA64_DTPREL64I        = 0xb3    # @dtprel(sym + add), imm64
R_IA64_DTPREL32MSB      = 0xb4    # @dtprel(sym + add), data4 MSB
R_IA64_DTPREL32LSB      = 0xb5    # @dtprel(sym + add), data4 LSB
R_IA64_DTPREL64MSB      = 0xb6    # @dtprel(sym + add), data8 MSB
R_IA64_DTPREL64LSB      = 0xb7    # @dtprel(sym + add), data8 LSB
R_IA64_LTOFF_DTPREL22   = 0xba    # @ltoff(@dtprel(s+a)), imm22

# SH relocations

R_SH_NONE               = 0
R_SH_DIR32              = 1
R_SH_REL32              = 2
R_SH_DIR8WPN            = 3
R_SH_IND12W             = 4
R_SH_DIR8WPL            = 5
R_SH_DIR8WPZ            = 6
R_SH_DIR8BP             = 7
R_SH_DIR8W              = 8
R_SH_DIR8L              = 9
R_SH_SWITCH16           = 25
R_SH_SWITCH32           = 26
R_SH_USES               = 27
R_SH_COUNT              = 28
R_SH_ALIGN              = 29
R_SH_CODE               = 30
R_SH_DATA               = 31
R_SH_LABEL              = 32
R_SH_SWITCH8            = 33
R_SH_GNU_VTINHERIT      = 34
R_SH_GNU_VTENTRY        = 35
R_SH_TLS_GD_32          = 144
R_SH_TLS_LD_32          = 145
R_SH_TLS_LDO_32         = 146
R_SH_TLS_IE_32          = 147
R_SH_TLS_LE_32          = 148
R_SH_TLS_DTPMOD32       = 149
R_SH_TLS_DTPOFF32       = 150
R_SH_TLS_TPOFF32        = 151
R_SH_GOT32              = 160
R_SH_PLT32              = 161
R_SH_COPY               = 162
R_SH_GLOB_DAT           = 163
R_SH_JMP_SLOT           = 164
R_SH_RELATIVE           = 165
R_SH_GOTOFF             = 166
R_SH_GOTPC              = 167
# Keep this the last entry.
R_SH_NUM                = 256

# S/390 relocations

R_390_NONE              = 0       # No reloc.
R_390_8                 = 1       # Direct 8 bit.
R_390_12                = 2       # Direct 12 bit.
R_390_16                = 3       # Direct 16 bit.
R_390_32                = 4       # Direct 32 bit.
R_390_PC32              = 5       # PC relative 32 bit.
R_390_GOT12             = 6       # 12 bit GOT offset.
R_390_GOT32             = 7       # 32 bit GOT offset.
R_390_PLT32             = 8       # 32 bit PC relative PLT address.
R_390_COPY              = 9       # Copy symbol at runtime.
R_390_GLOB_DAT          = 10      # Create GOT entry.
R_390_JMP_SLOT          = 11      # Create PLT entry.
R_390_RELATIVE          = 12      # Adjust by program base.
R_390_GOTOFF32          = 13      # 32 bit offset to GOT.
R_390_GOTPC             = 14      # 32 bit PC relative offset to GOT.
R_390_GOT16             = 15      # 16 bit GOT offset.
R_390_PC16              = 16      # PC relative 16 bit.
R_390_PC16DBL           = 17      # PC relative 16 bit shifted by 1.
R_390_PLT16DBL          = 18      # 16 bit PC rel. PLT shifted by 1.
R_390_PC32DBL           = 19      # PC relative 32 bit shifted by 1.
R_390_PLT32DBL          = 20      # 32 bit PC rel. PLT shifted by 1.
R_390_GOTPCDBL          = 21      # 32 bit PC rel. GOT shifted by 1.
R_390_64                = 22      # Direct 64 bit.
R_390_PC64              = 23      # PC relative 64 bit.
R_390_GOT64             = 24      # 64 bit GOT offset.
R_390_PLT64             = 25      # 64 bit PC relative PLT address.
R_390_GOTENT            = 26      # 32 bit PC rel. to GOT entry >> 1.
R_390_GOTOFF16          = 27      # 16 bit offset to GOT.
R_390_GOTOFF64          = 28      # 64 bit offset to GOT.
R_390_GOTPLT12          = 29      # 12 bit offset to jump slot.
R_390_GOTPLT16          = 30      # 16 bit offset to jump slot.
R_390_GOTPLT32          = 31      # 32 bit offset to jump slot.
R_390_GOTPLT64          = 32      # 64 bit offset to jump slot.
R_390_GOTPLTENT         = 33      # 32 bit rel. offset to jump slot.
R_390_PLTOFF16          = 34      # 16 bit offset from GOT to PLT.
R_390_PLTOFF32          = 35      # 32 bit offset from GOT to PLT.
R_390_PLTOFF64          = 36      # 16 bit offset from GOT to PLT.
R_390_TLS_LOAD          = 37      # Tag for load insn in TLS code.
R_390_TLS_GDCALL        = 38      # Tag for function call in general dynamic TLS code.
R_390_TLS_LDCALL        = 39      # Tag for function call in local dynamic TLS code.
R_390_TLS_GD32          = 40      # Direct 32 bit for general dynamic thread local data.
R_390_TLS_GD64          = 41      # Direct 64 bit for general dynamic thread local data.
R_390_TLS_GOTIE12       = 42      # 12 bit GOT offset for static TLS block offset.
R_390_TLS_GOTIE32       = 43      # 32 bit GOT offset for static TLS block offset.
R_390_TLS_GOTIE64       = 44      # 64 bit GOT offset for static TLS block offset.
R_390_TLS_LDM32         = 45      # Direct 32 bit for local dynamic thread local data in LE code.
R_390_TLS_LDM64         = 46      # Direct 64 bit for local dynamic thread local data in LE code.
R_390_TLS_IE32          = 47      # 32 bit address of GOT entry for negated static TLS block offset.
R_390_TLS_IE64          = 48      # 64 bit address of GOT entry for negated static TLS block offset.
R_390_TLS_IEENT         = 49      # 32 bit rel. offset to GOT entry for negated static TLS block offset.
R_390_TLS_LE32          = 50      # 32 bit negated offset relative to static TLS block.
R_390_TLS_LE64          = 51      # 64 bit negated offset relative to static TLS block.
R_390_TLS_LDO32         = 52      # 32 bit offset relative to TLS block.
R_390_TLS_LDO64         = 53      # 64 bit offset relative to TLS block.
R_390_TLS_DTPMOD        = 54      # ID of module containing symbol.
R_390_TLS_DTPOFF        = 55      # Offset in TLS block.
R_390_TLS_TPOFF         = 56      # Negated offset in static TLS block.
R_390_20                = 57      # Direct 20 bit.
R_390_GOT20             = 58      # 20 bit GOT offset.
R_390_GOTPLT20          = 59      # 20 bit offset to jump slot.
R_390_TLS_GOTIE20       = 60      # 20 bit GOT offset for static TLS block offset.
# Keep this the last entry.
R_390_NUM               = 61


# CRIS relocations.
R_CRIS_NONE             = 0
R_CRIS_8                = 1
R_CRIS_16               = 2
R_CRIS_32               = 3
R_CRIS_8_PCREL          = 4
R_CRIS_16_PCREL         = 5
R_CRIS_32_PCREL         = 6
R_CRIS_GNU_VTINHERIT    = 7
R_CRIS_GNU_VTENTRY      = 8
R_CRIS_COPY             = 9
R_CRIS_GLOB_DAT         = 10
R_CRIS_JUMP_SLOT        = 11
R_CRIS_RELATIVE         = 12
R_CRIS_16_GOT           = 13
R_CRIS_32_GOT           = 14
R_CRIS_16_GOTPLT        = 15
R_CRIS_32_GOTPLT        = 16
R_CRIS_32_GOTREL        = 17
R_CRIS_32_PLT_GOTREL    = 18
R_CRIS_32_PLT_PCREL     = 19

R_CRIS_NUM              = 20


# AMD x86-64 relocations.
R_X86_64_NONE           = 0       # No reloc
R_X86_64_64             = 1       # Direct 64 bit
R_X86_64_PC32           = 2       # PC relative 32 bit signed
R_X86_64_GOT32          = 3       # 32 bit GOT entry
R_X86_64_PLT32          = 4       # 32 bit PLT address
R_X86_64_COPY           = 5       # Copy symbol at runtime
R_X86_64_GLOB_DAT       = 6       # Create GOT entry
R_X86_64_JUMP_SLOT      = 7       # Create PLT entry
R_X86_64_RELATIVE       = 8       # Adjust by program base
R_X86_64_GOTPCREL       = 9       # 32 bit signed PC relative offset to GOT
R_X86_64_32             = 10      # Direct 32 bit zero extended
R_X86_64_32S            = 11      # Direct 32 bit sign extended
R_X86_64_16             = 12      # Direct 16 bit zero extended
R_X86_64_PC16           = 13      # 16 bit sign extended pc relative
R_X86_64_8              = 14      # Direct 8 bit sign extended
R_X86_64_PC8            = 15      # 8 bit sign extended pc relative
R_X86_64_DTPMOD64       = 16      # ID of module containing symbol
R_X86_64_DTPOFF64       = 17      # Offset in module's TLS block
R_X86_64_TPOFF64        = 18      # Offset in initial TLS block
R_X86_64_TLSGD          = 19      # 32 bit signed PC relative offset to two GOT entries for GD symbol
R_X86_64_TLSLD          = 20      # 32 bit signed PC relative offset to two GOT entries for LD symbol
R_X86_64_DTPOFF32       = 21      # Offset in TLS block
R_X86_64_GOTTPOFF       = 22      # 32 bit signed PC relative offset to GOT entry for IE symbol
R_X86_64_TPOFF32        = 23      # Offset in initial TLS block
R_X86_64_PC64           = 24      # PC relative 64 bit
R_X86_64_GOTOFF64       = 25      # 64 bit offset to GOT
R_X86_64_GOTPC32        = 26      # 32 bit signed pc relative offset to GOT
R_X86_64_GOT64          = 27      # 64-bit GOT entry offset
R_X86_64_GOTPCREL64     = 28      # 64-bit PC relative offset to GOT entry
R_X86_64_GOTPC64        = 29      # 64-bit PC relative offset to GOT
R_X86_64_GOTPLT64       = 30      # like GOT64, says PLT entry needed
R_X86_64_PLTOFF64       = 31      # 64-bit GOT relative offset to PLT entry
R_X86_64_SIZE32         = 32      # Size of symbol plus 32-bit addend
R_X86_64_SIZE64         = 33      # Size of symbol plus 64-bit addend
R_X86_64_GOTPC32_TLSDESC = 34     # GOT offset for TLS descriptor.
R_X86_64_TLSDESC_CALL   = 35      # Marker for call through TLS descriptor.
R_X86_64_TLSDESC        = 36      # TLS descriptor.
R_X86_64_IRELATIVE      = 37      # Adjust indirectly by program base

R_X86_64_NUM            = 38


# AM33 relocations.
R_MN10300_NONE          = 0       # No reloc.
R_MN10300_32            = 1       # Direct 32 bit.
R_MN10300_16            = 2       # Direct 16 bit.
R_MN10300_8             = 3       # Direct 8 bit.
R_MN10300_PCREL32       = 4       # PC-relative 32-bit.
R_MN10300_PCREL16       = 5       # PC-relative 16-bit signed.
R_MN10300_PCREL8        = 6       # PC-relative 8-bit signed.
R_MN10300_GNU_VTINHERIT = 7       # Ancient C++ vtable garbage...
R_MN10300_GNU_VTENTRY   = 8       # ... collection annotation.
R_MN10300_24            = 9       # Direct 24 bit.
R_MN10300_GOTPC32       = 10      # 32-bit PCrel offset to GOT.
R_MN10300_GOTPC16       = 11      # 16-bit PCrel offset to GOT.
R_MN10300_GOTOFF32      = 12      # 32-bit offset from GOT.
R_MN10300_GOTOFF24      = 13      # 24-bit offset from GOT.
R_MN10300_GOTOFF16      = 14      # 16-bit offset from GOT.
R_MN10300_PLT32         = 15      # 32-bit PCrel to PLT entry.
R_MN10300_PLT16         = 16      # 16-bit PCrel to PLT entry.
R_MN10300_GOT32         = 17      # 32-bit offset to GOT entry.
R_MN10300_GOT24         = 18      # 24-bit offset to GOT entry.
R_MN10300_GOT16         = 19      # 16-bit offset to GOT entry.
R_MN10300_COPY          = 20      # Copy symbol at runtime.
R_MN10300_GLOB_DAT      = 21      # Create GOT entry.
R_MN10300_JMP_SLOT      = 22      # Create PLT entry.
R_MN10300_RELATIVE      = 23      # Adjust by program base.

R_MN10300_NUM           = 24


# M32R relocs.
R_M32R_NONE             = 0       # No reloc.
R_M32R_16               = 1       # Direct 16 bit.
R_M32R_32               = 2       # Direct 32 bit.
R_M32R_24               = 3       # Direct 24 bit.
R_M32R_10_PCREL         = 4       # PC relative 10 bit shifted.
R_M32R_18_PCREL         = 5       # PC relative 18 bit shifted.
R_M32R_26_PCREL         = 6       # PC relative 26 bit shifted.
R_M32R_HI16_ULO         = 7       # High 16 bit with unsigned low.
R_M32R_HI16_SLO         = 8       # High 16 bit with signed low.
R_M32R_LO16             = 9       # Low 16 bit.
R_M32R_SDA16            = 10      # 16 bit offset in SDA.
R_M32R_GNU_VTINHERIT    = 11
R_M32R_GNU_VTENTRY      = 12
# M32R relocs use SHT_RELA.
R_M32R_16_RELA          = 33      # Direct 16 bit.
R_M32R_32_RELA          = 34      # Direct 32 bit.
R_M32R_24_RELA          = 35      # Direct 24 bit.
R_M32R_10_PCREL_RELA    = 36      # PC relative 10 bit shifted.
R_M32R_18_PCREL_RELA    = 37      # PC relative 18 bit shifted.
R_M32R_26_PCREL_RELA    = 38      # PC relative 26 bit shifted.
R_M32R_HI16_ULO_RELA    = 39      # High 16 bit with unsigned low
R_M32R_HI16_SLO_RELA    = 40      # High 16 bit with signed low
R_M32R_LO16_RELA        = 41      # Low 16 bit
R_M32R_SDA16_RELA       = 42      # 16 bit offset in SDA
R_M32R_RELA_GNU_VTINHERIT       = 43
R_M32R_RELA_GNU_VTENTRY = 44
R_M32R_REL32            = 45      # PC relative 32 bit.

R_M32R_GOT24            = 48      # 24 bit GOT entry
R_M32R_26_PLTREL        = 49      # 26 bit PC relative to PLT shifted
R_M32R_COPY             = 50      # Copy symbol at runtime
R_M32R_GLOB_DAT         = 51      # Create GOT entry
R_M32R_JMP_SLOT         = 52      # Create PLT entry
R_M32R_RELATIVE         = 53      # Adjust by program base
R_M32R_GOTOFF           = 54      # 24 bit offset to GOT
R_M32R_GOTPC24          = 55      # 24 bit PC relative offset to GOT
R_M32R_GOT16_HI_ULO     = 56      # High 16 bit GOT entry with unsigned low
R_M32R_GOT16_HI_SLO     = 57      # High 16 bit GOT entry with signed low
R_M32R_GOT16_LO         = 58      # Low 16 bit GOT entry
R_M32R_GOTPC_HI_ULO     = 59      # High 16 bit PC relative offset to GOT with unsigned low
R_M32R_GOTPC_HI_SLO     = 60      # High 16 bit PC relative offset to GOT with signed low
R_M32R_GOTPC_LO         = 61      # Low 16 bit PC relative offset to GOT
R_M32R_GOTOFF_HI_ULO    = 62      # High 16 bit offset to GOT with unsigned low
R_M32R_GOTOFF_HI_SLO    = 63      # High 16 bit offset to GOT with signed low
R_M32R_GOTOFF_LO        = 64      # Low 16 bit offset to GOT
R_M32R_NUM              = 256     # Keep this the last entry.
