import sys
import struct
from elfesteem import *
import os
import sys

# example for extracting all pe ressources


def extract_res(res, name_o="", num=0, lvl=-1):
    lvl += 1
    if not res:
        return num
    for x in res.resentries:
        print "\t" * lvl, repr(x)
        num += 1

        if x.name_s:
            name = name_o[:] + repr(x.name_s.value[::2])
        else:
            name = name_o[:]

        if x.data:
            print "\t" * lvl, 'data', len(x.data.s)
            open('out/%.3d_%s.bin' % (num, name), 'w').write(str(x.data.s))
        else:
            print "\t" * lvl, None
        if x.offsettosubdir:
            num = extract_res(x.subdir, name, num, lvl + 1)
    return num

try:
    os.stat('out')
except:
    os.mkdir('out')

fname = sys.argv[1]
e = pe_init.PE(open(fname, 'rb').read())
res = e.DirRes.resdesc


extract_res(res)
