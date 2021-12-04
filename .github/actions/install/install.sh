#! /bin/bash


# codespell
pip install codespell
# install
python setup.py build build_ext
python setup.py install
# extended tests
git clone https://github.com/cea-sec/miasm-extended-tests
