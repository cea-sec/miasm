[![Miasm tests](https://github.com/cea-sec/miasm/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/cea-sec/miasm/actions/workflows/tests.yml?branch=master)

<p align="center">
<img src="https://raw.githubusercontent.com/cea-sec/miasm/master/doc/logo_miasm.png">
</p>


What is Miasm?
==============

Miasm is a free and open source (GPLv2) reverse engineering framework.
Miasm aims to analyze / modify / generate binary programs. Here is
a non-exhaustive list of features:

* Opening / modifying / generating PE / ELF 32 / 64 LE / BE
* Assembling / Disassembling X86 / ARM / MIPS / SH4 / MSP430
* Representing assembly semantic using intermediate language
* Emulating using JIT (dynamic code analysis, unpacking, ...)
* Expression simplification for automatic de-obfuscation
* ...

See the official [blog](http://miasm.re) for more examples and demos.

Table of Contents
=================

- [What is Miasm?](#user-content-what-is-miasm)
- [Basic examples](#user-content-basic-examples)
	- [Assembling / Disassembling](#user-content-assembling--disassembling)
	- [Intermediate representation](#user-content-intermediate-representation)
	- [Emulation](#user-content-emulation)
	- [Symbolic execution](#user-content-symbolic-execution)
- [How does it work?](#user-content-how-does-it-work)
- [Documentation](#user-content-documentation)
- [Obtaining Miasm](#user-content-obtaining-miasm)
	- [Software requirements](#user-content-software-requirements)
	- [Configuration](#user-content-configuration)
	- [Windows & IDA](#user-content-windows--ida)
- [Testing](#user-content-testing)
- [They already use Miasm](#user-content-they-already-use-miasm)
- [Misc](#user-content-misc)


Basic examples
==============

Assembling / Disassembling
--------------------------

Import Miasm x86 architecture:
```pycon
>>> from miasm.arch.x86.arch import mn_x86
>>> from miasm.core.locationdb import LocationDB
```
Get a location db:

```pycon
>>> loc_db = LocationDB()
```
Assemble a line:
```pycon
>>> l = mn_x86.fromstring('XOR ECX, ECX', loc_db, 32)
>>> print(l)
XOR        ECX, ECX
>>> mn_x86.asm(l)
['1\xc9', '3\xc9', 'g1\xc9', 'g3\xc9']
```
Modify an operand:
```pycon
>>> l.args[0] = mn_x86.regs.EAX
>>> print(l)
XOR        EAX, ECX
>>> a = mn_x86.asm(l)
>>> print(a)
['1\xc8', '3\xc1', 'g1\xc8', 'g3\xc1']
```
Disassemble the result:
```pycon
>>> print(mn_x86.dis(a[0], 32))
XOR        EAX, ECX
```
Using `Machine` abstraction:

```pycon
>>> from miasm.analysis.machine import Machine
>>> mn = Machine('x86_32').mn
>>> print(mn.dis('\x33\x30', 32))
XOR        ESI, DWORD PTR [EAX]
```

For MIPS:
```pycon
>>> mn = Machine('mips32b').mn
>>> print(mn.dis(b'\x97\xa3\x00 ', "b"))
LHU        V1, 0x20(SP)
```
Intermediate representation
---------------------------

Create an instruction:

```pycon
>>> machine = Machine('arml')
>>> instr = machine.mn.dis('\x00 \x88\xe0', 'l')
>>> print(instr)
ADD        R2, R8, R0
```

Create an intermediate representation object:
```pycon
>>> lifter = machine.lifter_model_call(loc_db)
```
Create an empty ircfg:
```pycon
>>> ircfg = lifter.new_ircfg()
```
Add instruction to the pool:
```pycon
>>> lifter.add_instr_to_ircfg(instr, ircfg)
```

Print current pool:
```pycon
>>> for lbl, irblock in ircfg.blocks.items():
...     print(irblock)
loc_0:
R2 = R8 + R0

IRDst = loc_4

```
Working with IR, for instance by getting side effects:
```pycon
>>> for lbl, irblock in ircfg.blocks.items():
...     for assignblk in irblock:
...         rw = assignblk.get_rw()
...         for dst, reads in rw.items():
...             print('read:   ', [str(x) for x in reads])
...             print('written:', dst)
...             print()
...
read:    ['R8', 'R0']
written: R2

read:    []
written: IRDst

```

More information on Miasm IR is in the [corresponding Jupyter Notebook](https://github.com/cea-sec/miasm/blob/master/doc/expression/expression.ipynb).

Emulation
---------

Giving a shellcode:
```pycon
00000000 8d4904      lea    ecx, [ecx+0x4]
00000003 8d5b01      lea    ebx, [ebx+0x1]
00000006 80f901      cmp    cl, 0x1
00000009 7405        jz     0x10
0000000b 8d5bff      lea    ebx, [ebx-1]
0000000e eb03        jmp    0x13
00000010 8d5b01      lea    ebx, [ebx+0x1]
00000013 89d8        mov    eax, ebx
00000015 c3          ret
>>> s = b'\x8dI\x04\x8d[\x01\x80\xf9\x01t\x05\x8d[\xff\xeb\x03\x8d[\x01\x89\xd8\xc3'
```
Import the shellcode thanks to the `Container` abstraction:

```pycon
>>> from miasm.analysis.binary import Container
>>> c = Container.from_string(s, loc_db)
>>> c
<miasm.analysis.binary.ContainerUnknown object at 0x7f34cefe6090>
```

Disassembling the shellcode at address `0`:

```pycon
>>> from miasm.analysis.machine import Machine
>>> machine = Machine('x86_32')
>>> mdis = machine.dis_engine(c.bin_stream, loc_db=loc_db)
>>> asmcfg = mdis.dis_multiblock(0)
>>> for block in asmcfg.blocks:
...  print(block)
...
loc_0
LEA        ECX, DWORD PTR [ECX + 0x4]
LEA        EBX, DWORD PTR [EBX + 0x1]
CMP        CL, 0x1
JZ         loc_10
->      c_next:loc_b    c_to:loc_10
loc_10
LEA        EBX, DWORD PTR [EBX + 0x1]
->      c_next:loc_13
loc_b
LEA        EBX, DWORD PTR [EBX + 0xFFFFFFFF]
JMP        loc_13
->      c_to:loc_13
loc_13
MOV        EAX, EBX
RET
```

Initializing the JIT engine with a stack:

```pycon
>>> jitter = machine.jitter(loc_db, jit_type='python')
>>> jitter.init_stack()
```

Add the shellcode in an arbitrary memory location:
```pycon
>>> run_addr = 0x40000000
>>> from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
>>> jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, s)
```

Create a sentinelle to catch the return of the shellcode:

```Python
def code_sentinelle(jitter):
    jitter.running = False
    jitter.pc = 0
    return True

>>> jitter.add_breakpoint(0x1337beef, code_sentinelle)
>>> jitter.push_uint32_t(0x1337beef)
```

Active logs:

```pycon
>>> jitter.set_trace_log()
```

Run at arbitrary address:

```pycon
>>> jitter.init_run(run_addr)
>>> jitter.continue_run()
RAX 0000000000000000 RBX 0000000000000000 RCX 0000000000000000 RDX 0000000000000000
RSI 0000000000000000 RDI 0000000000000000 RSP 000000000123FFF8 RBP 0000000000000000
zf 0000000000000000 nf 0000000000000000 of 0000000000000000 cf 0000000000000000
RIP 0000000040000000
40000000 LEA        ECX, DWORD PTR [ECX+0x4]
RAX 0000000000000000 RBX 0000000000000000 RCX 0000000000000004 RDX 0000000000000000
RSI 0000000000000000 RDI 0000000000000000 RSP 000000000123FFF8 RBP 0000000000000000
zf 0000000000000000 nf 0000000000000000 of 0000000000000000 cf 0000000000000000
....
4000000e JMP        loc_0000000040000013:0x40000013
RAX 0000000000000000 RBX 0000000000000000 RCX 0000000000000004 RDX 0000000000000000
RSI 0000000000000000 RDI 0000000000000000 RSP 000000000123FFF8 RBP 0000000000000000
zf 0000000000000000 nf 0000000000000000 of 0000000000000000 cf 0000000000000000
RIP 0000000040000013
40000013 MOV        EAX, EBX
RAX 0000000000000000 RBX 0000000000000000 RCX 0000000000000004 RDX 0000000000000000
RSI 0000000000000000 RDI 0000000000000000 RSP 000000000123FFF8 RBP 0000000000000000
zf 0000000000000000 nf 0000000000000000 of 0000000000000000 cf 0000000000000000
RIP 0000000040000013
40000015 RET
>>>

```

Interacting with the jitter:

```pycon
>>> jitter.vm
ad 1230000 size 10000 RW_ hpad 0x2854b40
ad 40000000 size 16 RW_ hpad 0x25e0ed0

>>> hex(jitter.cpu.EAX)
'0x0L'
>>> jitter.cpu.ESI = 12
```

Symbolic execution
------------------

Initializing the IR pool:

```pycon
>>> lifter = machine.lifter_model_call(loc_db)
>>> ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
```

Initializing the engine with default symbolic values:

```pycon
>>> from miasm.ir.symbexec import SymbolicExecutionEngine
>>> sb = SymbolicExecutionEngine(lifter)
```

Launching the execution:

```pycon
>>> symbolic_pc = sb.run_at(ircfg, 0)
>>> print(symbolic_pc)
((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
```

Same, with step logs (only changes are displayed):

```pycon
>>> sb = SymbolicExecutionEngine(lifter, machine.mn.regs.regs_init)
>>> symbolic_pc = sb.run_at(ircfg, 0, step=True)
Instr LEA        ECX, DWORD PTR [ECX + 0x4]
Assignblk:
ECX = ECX + 0x4
________________________________________________________________________________
ECX                = ECX + 0x4
________________________________________________________________________________
Instr LEA        EBX, DWORD PTR [EBX + 0x1]
Assignblk:
EBX = EBX + 0x1
________________________________________________________________________________
EBX                = EBX + 0x1
ECX                = ECX + 0x4
________________________________________________________________________________
Instr CMP        CL, 0x1
Assignblk:
zf = (ECX[0:8] + -0x1)?(0x0,0x1)
nf = (ECX[0:8] + -0x1)[7:8]
pf = parity((ECX[0:8] + -0x1) & 0xFF)
of = ((ECX[0:8] ^ (ECX[0:8] + -0x1)) & (ECX[0:8] ^ 0x1))[7:8]
cf = (((ECX[0:8] ^ 0x1) ^ (ECX[0:8] + -0x1)) ^ ((ECX[0:8] ^ (ECX[0:8] + -0x1)) & (ECX[0:8] ^ 0x1)))[7:8]
af = ((ECX[0:8] ^ 0x1) ^ (ECX[0:8] + -0x1))[4:5]
________________________________________________________________________________
af                 = (((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[4:5]
pf                 = parity((ECX + 0x4)[0:8] + 0xFF)
zf                 = ((ECX + 0x4)[0:8] + 0xFF)?(0x0,0x1)
ECX                = ECX + 0x4
of                 = ((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1))[7:8]
nf                 = ((ECX + 0x4)[0:8] + 0xFF)[7:8]
cf                 = (((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1)) ^ ((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[7:8]
EBX                = EBX + 0x1
________________________________________________________________________________
Instr JZ         loc_key_1
Assignblk:
IRDst = zf?(loc_key_1,loc_key_2)
EIP = zf?(loc_key_1,loc_key_2)
________________________________________________________________________________
af                 = (((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[4:5]
EIP                = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
pf                 = parity((ECX + 0x4)[0:8] + 0xFF)
IRDst              = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
zf                 = ((ECX + 0x4)[0:8] + 0xFF)?(0x0,0x1)
ECX                = ECX + 0x4
of                 = ((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1))[7:8]
nf                 = ((ECX + 0x4)[0:8] + 0xFF)[7:8]
cf                 = (((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1)) ^ ((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[7:8]
EBX                = EBX + 0x1
________________________________________________________________________________
>>>
```


Retry execution with a concrete ECX. Here, the symbolic / concolic execution reach the shellcode's end:

```pycon
>>> from miasm.expression.expression import ExprInt
>>> sb.symbols[machine.mn.regs.ECX] = ExprInt(-3, 32)
>>> symbolic_pc = sb.run_at(ircfg, 0, step=True)
Instr LEA        ECX, DWORD PTR [ECX + 0x4]
Assignblk:
ECX = ECX + 0x4
________________________________________________________________________________
af                 = (((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[4:5]
EIP                = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
pf                 = parity((ECX + 0x4)[0:8] + 0xFF)
IRDst              = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
zf                 = ((ECX + 0x4)[0:8] + 0xFF)?(0x0,0x1)
ECX                = 0x1
of                 = ((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1))[7:8]
nf                 = ((ECX + 0x4)[0:8] + 0xFF)[7:8]
cf                 = (((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1)) ^ ((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[7:8]
EBX                = EBX + 0x1
________________________________________________________________________________
Instr LEA        EBX, DWORD PTR [EBX + 0x1]
Assignblk:
EBX = EBX + 0x1
________________________________________________________________________________
af                 = (((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[4:5]
EIP                = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
pf                 = parity((ECX + 0x4)[0:8] + 0xFF)
IRDst              = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
zf                 = ((ECX + 0x4)[0:8] + 0xFF)?(0x0,0x1)
ECX                = 0x1
of                 = ((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1))[7:8]
nf                 = ((ECX + 0x4)[0:8] + 0xFF)[7:8]
cf                 = (((((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8]) & ((ECX + 0x4)[0:8] ^ 0x1)) ^ ((ECX + 0x4)[0:8] + 0xFF) ^ (ECX + 0x4)[0:8] ^ 0x1)[7:8]
EBX                = EBX + 0x2
________________________________________________________________________________
Instr CMP        CL, 0x1
Assignblk:
zf = (ECX[0:8] + -0x1)?(0x0,0x1)
nf = (ECX[0:8] + -0x1)[7:8]
pf = parity((ECX[0:8] + -0x1) & 0xFF)
of = ((ECX[0:8] ^ (ECX[0:8] + -0x1)) & (ECX[0:8] ^ 0x1))[7:8]
cf = (((ECX[0:8] ^ 0x1) ^ (ECX[0:8] + -0x1)) ^ ((ECX[0:8] ^ (ECX[0:8] + -0x1)) & (ECX[0:8] ^ 0x1)))[7:8]
af = ((ECX[0:8] ^ 0x1) ^ (ECX[0:8] + -0x1))[4:5]
________________________________________________________________________________
af                 = 0x0
EIP                = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
pf                 = 0x1
IRDst              = ((ECX + 0x4)[0:8] + 0xFF)?(0xB,0x10)
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x2
________________________________________________________________________________
Instr JZ         loc_key_1
Assignblk:
IRDst = zf?(loc_key_1,loc_key_2)
EIP = zf?(loc_key_1,loc_key_2)
________________________________________________________________________________
af                 = 0x0
EIP                = 0x10
pf                 = 0x1
IRDst              = 0x10
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x2
________________________________________________________________________________
Instr LEA        EBX, DWORD PTR [EBX + 0x1]
Assignblk:
EBX = EBX + 0x1
________________________________________________________________________________
af                 = 0x0
EIP                = 0x10
pf                 = 0x1
IRDst              = 0x10
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x3
________________________________________________________________________________
Instr LEA        EBX, DWORD PTR [EBX + 0x1]
Assignblk:
IRDst = loc_key_3
________________________________________________________________________________
af                 = 0x0
EIP                = 0x10
pf                 = 0x1
IRDst              = 0x13
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x3
________________________________________________________________________________
Instr MOV        EAX, EBX
Assignblk:
EAX = EBX
________________________________________________________________________________
af                 = 0x0
EIP                = 0x10
pf                 = 0x1
IRDst              = 0x13
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x3
EAX                = EBX + 0x3
________________________________________________________________________________
Instr RET
Assignblk:
IRDst = @32[ESP[0:32]]
ESP = {ESP[0:32] + 0x4 0 32}
EIP = @32[ESP[0:32]]
________________________________________________________________________________
af                 = 0x0
EIP                = @32[ESP]
pf                 = 0x1
IRDst              = @32[ESP]
zf                 = 0x1
ECX                = 0x1
of                 = 0x0
nf                 = 0x0
cf                 = 0x0
EBX                = EBX + 0x3
ESP                = ESP + 0x4
EAX                = EBX + 0x3
________________________________________________________________________________
>>>
```



How does it work?
=================

Miasm embeds its own disassembler, intermediate language and
instruction semantic. It is written in Python.

To emulate code, it uses LLVM, GCC, Clang or Python to JIT the
intermediate representation. It can emulate shellcodes and all or parts of
binaries. Python callbacks can be executed to interact with the execution, for
instance to emulate library functions effects.

Documentation
=============

Some documentation resources are available in the [doc](doc) folder.

An auto-generated documentation is available:
* [Doxygen](http://miasm.re/miasm_doxygen)
* [pdoc](http://miasm.re/miasm_pdoc)

Obtaining Miasm
===============

* Clone the repository: [Miasm on GitHub](https://github.com/cea-sec/miasm/)
* Get one of the Docker images at [Docker Hub](https://registry.hub.docker.com/u/miasm/)

Software requirements
---------------------

Miasm uses:

* Python >= 3.10
* future
* pyparsing >= 2.4.1

Native jitter components are built when the local build environment supports
them. If native extension compilation fails, installation continues and the
jitter-dependent features are unavailable. Set `MIASM_REQUIRE_JIT=1` when
building release wheels or when native jitter support must be present.

To enable non-Python JIT backends, one of the following is mandatory:
* GCC
* Clang
* LLVM with Numba llvmlite (`pip install miasm[llvm]`), see below

Optional Python features are grouped as extras:

| Extra | Dependency | Enables | Code using it |
| --- | --- | --- | --- |
| `cparser` | `pycparser>=2.17` | C type parsing and C-like expression access helpers | `miasm/core/ctypesmngr.py`, `miasm/core/objc.py` |
| `z3` | `z3-solver==4.16.0.0` | Z3 expression translation, solver-backed dependency graph, DSE constraints, and range tests | `miasm/ir/translators/z3_ir.py`, `miasm/analysis/depgraph.py`, `miasm/analysis/dse.py` |
| `llvm` | `llvmlite==0.50.0` | LLVM JIT backend and LLVM IR export | `miasm/jitter/jitcore_llvm.py`, `miasm/jitter/llvmconvert.py`, `example/expression/export_llvm.py` |
| `graph` | `graphviz` | Python Graphviz object export from Miasm graphs | `miasm/core/graph.py` (`DiGraph.graphviz`) |
| `crypto` | `pycryptodome` | Windows API crypto/hash emulation | `miasm/os_dep/win_api_x86_32.py` |
| `all` | runtime extras above | All optional runtime features | Convenience alias for users |

Development/test dependencies are not published as package extras. They live in
`[dependency-groups]` in `pyproject.toml`:

| Group | Dependency | Enables | Code using it |
| --- | --- | --- | --- |
| `dev` | `parameterized~=0.8.1` | Test runner parameterization | `test/test_all.py` |

Configuration
-------------

To use the jitter, GCC or LLVM is recommended
* GCC (any version)
* Clang (any version)
* LLVM
  * Debian (testing/unstable): Not tested
  * Debian stable/Ubuntu/Kali/whatever: `pip install llvmlite` or install from [llvmlite](https://github.com/numba/llvmlite)
  * Windows: Not tested
* Build and install Miasm:
```pycon
$ cd miasm_directory
$ python -m pip install .
```

Optional dependencies can be installed with extras, for example:
```pycon
$ python -m pip install '.[cparser,z3,llvm]'
$ python -m pip install '.[all]'
$ python -m pip install --group dev '.[all]'  # local development/test runs
```

If something goes wrong during native jitter compilation, Miasm will skip the
failing extension and keep the rest of the package installable. Set
`MIASM_REQUIRE_JIT=1` to make native extension failures abort the build.

Windows & IDA
-------------

Most of Miasm's IDA plugins use a subset of Miasm functionality.
A quick way to have them working is to add:
* `pyparsing.py` to `C:\...\IDA\python\` or `pip install pyparsing`
* `miasm/miasm` directory to `C:\...\IDA\python\`

All features excepting jitter related ones will be available. For a more complete installation, please refer to above paragraphs.

Testing
=======

Miasm comes with a set of regression tests. Test-only dependencies are declared
in the `dev` dependency group. `uv sync` installs this group by default; use
`--extra all` when you also want all optional runtime backends for full test
coverage. With pip, install the group explicitly.

```pycon
uv sync --extra all
# or: python -m pip install --group dev '.[all]'
cd miasm_directory/test

# Run tests using our own test runner
python test_all.py

# Run tests using standard frameworks (slower, require 'parameterized')
python -m unittest test_all.py        # sequential, requires 'unittest'
python -m pytest test_all.py          # sequential, requires 'pytest'
python -m pytest -n auto test_all.py  # parallel, requires 'pytest' and 'pytest-xdist'
```

Some options can be specified:

* Mono threading: `-m`
* Code coverage instrumentation: `-c`
* Only fast tests: `-t long` (excludes the long tests)

They already use Miasm
======================

Tools
-----

* [Sibyl](https://github.com/cea-sec/Sibyl): A function divination tool
* [R2M2](https://github.com/guedou/r2m2): Use miasm as a radare2 plugin
* [CGrex](https://github.com/mechaphish/cgrex): Targeted patcher for CGC binaries
* [ethRE](https://github.com/jbcayrou/ethRE): Reversing tool for Ethereum EVM (with corresponding Miasm2 architecture)

Blog posts / papers / conferences
---------------------------------

* [Deobfuscation: recovering an OLLVM-protected program](http://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html)
* [Taming a Wild Nanomite-protected MIPS Binary With Symbolic Execution: No Such Crackme](https://doar-e.github.io/blog/2014/10/11/taiming-a-wild-nanomite-protected-mips-binary-with-symbolic-execution-no-such-crackme/)
* [Miasm: Framework de reverse engineering](https://www.sstic.org/2012/presentation/miasm_framework_de_reverse_engineering/) (French)
* [Tutorial miasm](https://www.sstic.org/2014/presentation/Tutorial_miasm/) (French video)
* [Graphes de dépendances : Petit Poucet style](https://www.sstic.org/2016/presentation/graphes_de_dpendances__petit_poucet_style/): DepGraph (French)

Books
-----

* [Practical Reverse Engineering: X86, X64, Arm, Windows Kernel, Reversing Tools, and Obfuscation](https://www.wiley.com/en-us/shop/general-introductory-computer-science/practical-reverse-engineering-x86-x64-arm-windows-kernel-reversing-tools-and-obfuscation-p-9781118787311): Introduction to Miasm (Chapter 5 "Obfuscation")
* [BlackHat Python - Appendix](https://github.com/oreilly-japan/black-hat-python-jp-support/tree/master/appendix-A): Japan security book's samples
