reverse engineering framework in python
What is Miasm?

Miasm is a a free and open source (GPLv2) reverse engineering framework. Miasm
aims at analyzing/modifying/generating binary programs. Here is a non exhausting
list of features:

    opening/modifying/generating PE/ELF 32/64 le/be using Elfesteem
    Assembling/Disassembling ia32/ppc/arm
    Representing assembly semantic using intermediate language
    Emulating using jit (dynamic code analysis, unpacking, ...)
    Expression simplification for automatic de-obfuscation
    Graphic disassembler using Grandalf
    ... 

How does it work?

Miasm embed its own disassembler, intermediate language and instruction
semantic. It is written in Python.

To emulate code, it uses libtcc to jit C code generate from intermediate
representation. It can emulate shellcodes, parts of binaries. Python callback
can be executed to emulate library functions.

Documentation

Documentation can be found under =doc/=.
Obtain Miasm

clone repo: http://code.google.com/p/smiasm/
Software requirements

Miasm uses:

    Grandalf (https://github.com/bdcht/grandalf) in order to render graphical
    disassembler.

    Modified libtcc (http://bellard.org/tcc/) to Jit code for emulation
    mode. see below

    python-ply for parsing 

    numpy 

    python-virtualenv 

    python-dev 

    python-qt4 

Configuration

    The libtcc needs a little fix in makefile to be used on 64bit systems
        remove libtcc-dev from the system to avoid conflicts
        clone http://repo.or.cz/w/tinycc.git
        edit makefile
        add option -fPIC to the CFLAGS definition
        ./configure && make && make install 
    clone grandalf repository
    set path:

      $ export PYTHONPATH=$PYTHONPATH:path_to_miasm:path_to_elfesteem

    Compile miasm emulation library:

    $ cd tools/emul_lib
    $ make

Misc

    Man, does miasm has a link with rr0d?
    Yes! crappy code and uggly documentation. 
