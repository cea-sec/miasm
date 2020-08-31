from miasm.core import asmblock
from miasm.arch.x86  import arch
from miasm.core import parse_asm
from miasm.core.interval import interval
from miasm.core.locationdb import LocationDB

my_mn = arch.mn_x86
loc_db = LocationDB()

asmcfg = parse_asm.parse_txt(
    my_mn, 64, r'''
main:
  PUSH   RBP
  MOV    RBP, RSP
loop_dec:
  CMP    RCX, RDX
  JB    loop_dec
end:
  MOV    RSP, RBP
  POP    RBP
  RET

''',
    loc_db
)

loc_db.set_location_offset(loc_db.get_name_location("main"), 0x100001000)
dst_interval = interval([(0x100001000, 0x100002000)])
patches = asmblock.asm_resolve_final(
    my_mn,
    asmcfg,
    dst_interval
)
