#! /usr/bin/env python

from distutils.core import setup,Extension

setup(
    name = 'Miasm',
    version = '0.1',
    packages=['miasm', 'miasm/tools', 
              'miasm/expression', 'miasm/graph', 'miasm/arch',
              'miasm/core', 'miasm/tools/emul_lib' ],
    package_data = {'miasm':['tools/emul_lib/*.h']},
#    data_files = [('toto', ['miasm/tools/emul_lib/queue.h'])],
    ext_modules = [
        Extension("miasm.tools.emul_lib.libcodenat_interface",
                  ["miasm/tools/emul_lib/libcodenat_interface.c",
                   "miasm/tools/emul_lib/libcodenat.c"]),
        Extension("miasm.tools.emul_lib.libcodenat_tcc",
                  ["miasm/tools/emul_lib/libcodenat_tcc.c"],
                  libraries=["tcc"])
        ],

    # Metadata
    author = 'Fabrice Desclaux',
    author_email = 'serpilliere@droid-corp.org',
    description = 'Machine code manipulation library',
    license = 'GPLv2',
    # keywords = '',
    # url = '',
)
