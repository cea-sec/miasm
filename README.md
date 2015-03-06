Reverse engineering framework in Python

**Table of Contents** 

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


What is Miasm?
==============

Miasm is a free and open source (GPLv2) reverse engineering framework.
Miasm aims to analyze / modify / generate binary programs. Here is
a non exhaustive list of features:

* Opening / modifying / generating PE / ELF 32 / 64 LE / BE using Elfesteem
* Assembling / Disassembling X86 / ARM / MIPS / SH4 / MSP430
* Representing assembly semantic using intermediate language
* Emulating using JIT (dynamic code analysis, unpacking, ...)
* Expression simplification for automatic de-obfuscation
* ...

Basic examples
==============

Assembling / Disassembling
--------------------------

Import Miasm x86 architecture:
```
>>> from miasm2.arch.x86.arch import mn_x86
```
Assemble a line:
```
>>> l = mn_x86.fromstring('XOR ECX, ECX', 32)
>>> print l
XOR        ECX, ECX
>>> mn_x86.asm(l)
['1\xc9', '3\xc9', 'g1\xc9', 'g3\xc9']
```
Modify an operand:
```
>>> l.args[0] = mn_x86.regs.EAX
>>> print l
XOR        EAX, ECX
>>> a = mn_x86.asm(l)
>>> print a
['1\xc8', '3\xc1', 'g1\xc8', 'g3\xc1']
```
Disassemble the result:
```
>>> print mn_x86.dis(a[0], 32)
XOR        EAX, ECX
```
Using `Machine` abstraction:

```
>>> from miasm2.analysis.machine import Machine
>>> mn = Machine('x86_32').mn
>>> print mn.dis('\x33\x30', 32)
XOR        ESI, DWORD PTR [EAX]
```

For Mips:
```
>>> mn = Machine('mips32b').mn
>>> print  mn.dis('97A30020'.decode('hex'), "b")
LHU        V1, 0x20(SP)
```
Intermediate representation
---------------------------

Create an instruction:

```
>>> machine = Machine('arml')
>>> l = machine.mn.dis('002088e0'.decode('hex'), 'l')
>>> print l
ADD        R2, R8, R0
```

Create an intermediate representation (IR) object:
```
>>> ira = machine.ira()
```
Add instruction to the pool:
```
>>> ira.add_instr(l)
```

Print current pool:
```
>>> for lbl, b in ira.blocs.items():
...     print b
...
loc_0000000000000000:0x00000000

        R2 = (R8+R0)

        IRDst = loc_0000000000000004:0x00000004
```
Working with IR, for instance by getting side effects:
```
>>> from miasm2.expression.expression import get_rw
>>> for lbl, b in ira.blocs.items():
...     for irs in b.irs:
...         o_r, o_w = get_rw(irs)
...         print 'read:   ', [str(x) for x in o_r]
...         print 'written:', [str(x) for x in o_w]
...         print
... 
read:    ['R8', 'R0']
written: ['R2']

read:    ['loc_0000000000000004:0x00000004']
written: ['IRDst']
```

Emulation
---------

Giving a shellcode:
```
00000000 8d4904      lea    ecx, [ecx+0x4]
00000003 8d5b01      lea    ebx, [ebx+0x1]
00000006 80f901      cmp    cl, 0x1
00000009 7405        jz     0x10
0000000b 8d5bff      lea    ebx, [ebx-1]
0000000e eb03        jmp    0x13
00000010 8d5b01      lea    ebx, [ebx+0x1]
00000013 89d8        mov    eax, ebx
00000015 c3          ret
>>> s = '\x8dI\x04\x8d[\x01\x80\xf9\x01t\x05\x8d[\xff\xeb\x03\x8d[\x01\x89\xd8\xc3'
```
Import the shellcode thanks to the `Container` abstraction:

```
>>> from miasm2.analysis.binary import Container
>>> c = Container.from_string(s)
>>> c
<miasm2.analysis.binary.ContainerUnknown object at 0x7f34cefe6090>
```

Disassembling the shellcode at address `0`:

```
>>> from miasm2.analysis.machine import Machine
>>> machine = Machine('x86_32')
>>> mdis = machine.dis_engine(c.bin_stream)
>>> blocs = mdis.dis_multibloc(0)
>>> for b in blocs:
...  print b
...
loc_0000000000000000:0x00000000
LEA        ECX, DWORD PTR [ECX+0x4]
LEA        EBX, DWORD PTR [EBX+0x1]
CMP        CL, 0x1
JZ         loc_0000000000000010:0x00000010
->      c_next:loc_000000000000000B:0x0000000b  c_to:loc_0000000000000010:0x00000010
loc_0000000000000010:0x00000010
LEA        EBX, DWORD PTR [EBX+0x1]
->      c_next:loc_0000000000000013:0x00000013
loc_000000000000000B:0x0000000b
LEA        EBX, DWORD PTR [EBX+0xFFFFFFFF]
JMP        loc_0000000000000013:0x00000013
->      c_to:loc_0000000000000013:0x00000013
loc_0000000000000013:0x00000013
MOV        EAX, EBX
RET
>>>
```

Initializing the Jit engine with a stack:

```
>>> jitter = machine.jitter(jit_type='python')
>>> jitter.init_stack()
```

Add the shellcode in an arbitrary memory location:
```
>>> run_addr = 0x40000000
>>> myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, s)
```

Create a sentinelle to catch the return of the shellcode:

```
def code_sentinelle(jitter):
    jitter.run = False
    jitter.pc = 0
    return True

>>> jitter.add_breakpoint(0x1337beef, code_sentinelle)
>>> jitter.push_uint32_t(0x1337beef)
```

Active logs:

```
>>> jitter.jit.log_regs = True
>>> jitter.jit.log_mn = True
```

Run at arbitrary address:

```
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

```
>>> jitter.vm.dump_memory_page_pool()
ad 1230000 size 10000 RW_ hpad 0x2854b40
ad 40000000 size 16 RW_ hpad 0x25e0ed0

>>> hex(jitter.cpu.EAX)
'0x0L'
>>> jitter.cpu.ESI = 12
```

Symbolic execution
------------------

Initializing the IR pool:

```
>>> ira = machine.ira()
>>> for b in blocs:
...    ira.add_bloc(b)
... 
```

Initializing the engine with default symbolic values:

```
>>> from miasm2.ir.symbexec import symbexec
>>> sb = symbexec(ira, machine.mn.regs.regs_init)
```

Launching the execution:

```
>>> symbolic_pc = sb.emul_ir_blocs(ira, 0)
>>> print symbolic_pc
((ECX_init+0x4)[0:8]+0xFF)?(0xB,0x10)
```

Same, with step logs (only changes are displayed):

```
>>> sb = symbexec(ira, machine.mn.regs.regs_init)
>>> symbolic_pc = sb.emul_ir_blocs(ira, 0, step=True)
________________________________________________________________________________
ECX (ECX_init+0x4)
________________________________________________________________________________
ECX (ECX_init+0x4)
EBX (EBX_init+0x1)
________________________________________________________________________________
zf ((ECX_init+0x4)[0:8]+0xFF)?(0x0,0x1)
nf ((ECX_init+0x4)[0:8]+0xFF)[7:8]
pf (parity ((ECX_init+0x4)[0:8]+0xFF))
of ((((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8])&((ECX_init+0x4)[0:8]^0x1))[7:8]
cf (((((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8])&((ECX_init+0x4)[0:8]^0x1))^((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8]^0x1)[7:8]
af (((ECX_init+0x4)[0:8]+0xFF)&0x10)?(0x1,0x0)
ECX (ECX_init+0x4)
EBX (EBX_init+0x1)
________________________________________________________________________________
IRDst ((ECX_init+0x4)[0:8]+0xFF)?(0xB,0x10)
zf ((ECX_init+0x4)[0:8]+0xFF)?(0x0,0x1)
nf ((ECX_init+0x4)[0:8]+0xFF)[7:8]
pf (parity ((ECX_init+0x4)[0:8]+0xFF))
of ((((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8])&((ECX_init+0x4)[0:8]^0x1))[7:8]
cf (((((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8])&((ECX_init+0x4)[0:8]^0x1))^((ECX_init+0x4)[0:8]+0xFF)^(ECX_init+0x4)[0:8]^0x1)[7:8]
af (((ECX_init+0x4)[0:8]+0xFF)&0x10)?(0x1,0x0)
EIP ((ECX_init+0x4)[0:8]+0xFF)?(0xB,0x10)
ECX (ECX_init+0x4)
EBX (EBX_init+0x1)
```


Retry execution with a concrete ECX. Here, the symbolic / concolic execution reach the shellcode's end:

```
>>> from miasm2.expression.expression import ExprInt32
>>> sb.symbols[machine.mn.regs.ECX] = ExprInt32(-3)
>>> symbolic_pc = sb.emul_ir_blocs(ira, 0, step=True)
________________________________________________________________________________
ECX 0x1
________________________________________________________________________________
ECX 0x1
EBX (EBX_init+0x1)
________________________________________________________________________________
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
ECX 0x1
EBX (EBX_init+0x1)
________________________________________________________________________________
IRDst 0x10
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP 0x10
ECX 0x1
EBX (EBX_init+0x1)
________________________________________________________________________________
IRDst 0x10
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP 0x10
ECX 0x1
EBX (EBX_init+0x2)
________________________________________________________________________________
IRDst 0x13
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP 0x10
ECX 0x1
EBX (EBX_init+0x2)
________________________________________________________________________________
IRDst 0x13
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP 0x10
EAX (EBX_init+0x2)
ECX 0x1
EBX (EBX_init+0x2)
________________________________________________________________________________
IRDst @32[ESP_init]
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP @32[ESP_init]
EAX (EBX_init+0x2)
ECX 0x1
EBX (EBX_init+0x2)
ESP (ESP_init+0x4)
>>> print symbolic_pc
@32[ESP_init]
>>> sb.dump_id()
IRDst @32[ESP_init]
zf 0x1
nf 0x0
pf 0x1
of 0x0
cf 0x0
af 0x0
EIP @32[ESP_init]
EAX (EBX_init+0x2)
ECX 0x1
EBX (EBX_init+0x2)
ESP (ESP_init+0x4)
```



How does it work?
=================

Miasm embeds its own disassembler, intermediate language and
instruction semantic. It is written in Python.

To emulate code, it uses LibTCC, LLVM or Python to JIT the intermediate
representation. It can emulate shellcodes and all or parts of binaries. Python
callbacks can be executed to interact with the execution, for instance to
emulate library functions effects.

Documentation
=============
TODO

Obtaining Miasm
===============

* Clone the repository: [Miasm on GitHub](https://github.com/serpilliere/miasm)
* Get one of the Docker images at [Docker Hub](https://registry.hub.docker.com/u/miasm/)

Software requirements
---------------------

Miasm uses:

* LibTCC [tinycc](http://repo.or.cz/w/tinycc.git) to JIT code for emulation mode. See below
* or LLVM v3.2 with python-llvm, see below
* python-pyparsing
* python-dev
* elfesteem from [Elfesteem](http://code.google.com/p/elfesteem/)

Configuration
-------------

* Install elfesteem
```
hg clone https://code.google.com/p/elfesteem/
cd elfesteem_directory
python setup.py build
sudo python setup.py install
```

* To use the jitter, TCC or LLVM is recommended
* LibTCC needs to be configured with the `--disable-static` option
  * remove `libtcc-dev` from the system to avoid conflicts
  * clone [TinyCC](http://repo.or.cz/tinycc.git) and use [latest stable version](http://repo.or.cz/w/tinycc.git/tags)
  * `./configure --disable-static && make && make install`
* LLVM
  * Debian (testing/unstable): install python-llvm
  * Debian stable/Ubuntu/Kali/whatever: install from [llvmpy](http://www.llvmpy.org/)
  * Windows: python-llvm is not supported :/
* Build and install Miasm:
```
$ cd miasm_directory
$ python setup.py build
$ sudo python setup.py install
```

If something goes wrong during one of the jitter modules compilation, Miasm will
skip the error and disable the corresponding module (see the compilation
output).

Windows & IDA
-------------

Most of Miasm's IDA plugins use a subset of Miasm functionnality.
A quick way to have them working is to add:
* `elfesteem` directory and `pyparsing.py` to `C:\...\IDA\python\` or `pip install pyparsing elfesteem`
* `miasm2/miasm2` directory to `C:\...\IDA\python\` 

All features excepting JITter related ones will be available. For a more complete installation, please refer to above paragraphs.

Testing
=======

Miasm comes with a set of regression tests. To run all of them:

```
cd miasm_directory/test
python test_all.py
```

Some options can be specified:

* Mono threading: `-m`
* Code coverage instrumentation: `-c`
* Only fast tests: `-t long` (excludes the long tests)

They already use Miasm
======================
* [Sibyl](https://github.com/cea-sec/Sibyl): A function divination tool


Misc
====

* Man, does miasm has a link with rr0d?
* Yes! crappy code and uggly documentation.
