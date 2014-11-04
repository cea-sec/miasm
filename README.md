Reverse engineering framework in Python


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
* LibTCC needs a little fix in the `Makefile`:
  * remove libtcc-dev from the system to avoid conflicts
  * clone [tinycc release_0_9_26](http://repo.or.cz/w/tinycc.git/snapshot/d5e22108a0dc48899e44a158f91d5b3215eb7fe6.tar.gz)
  * edit the `Makefile`
  * add option `-fPIC` to the `CFLAGS` definition: `CFLAGS+= -fPIC`

```
#
# Tiny C Compiler Makefile
#

TOP ?= .
include $(TOP)/config.mak
VPATH = $(top_srcdir)

CPPFLAGS = -I$(TOP) # for config.h

# ADD NEXT LINE:
CFLAGS+= -fPIC
...
```

  * `./configure && make && make install`
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

Misc
====

* Man, does miasm has a link with rr0d?
* Yes! crappy code and uggly documentation.
