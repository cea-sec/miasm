#! /bin/bash
set -euo pipefail

# install
MIASM_REQUIRE_JIT=1 python -m pip install --group dev '.[cparser,z3,llvm]'

# extended tests
git clone --depth=1 https://github.com/cea-sec/miasm-extended-tests