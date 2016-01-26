from miasm2.arch.x86.disasm import dis_x86_32

# MOV        EAX, 0x1337BEEF
# MOV        ECX, 0x4
# loop:
# ROL        EAX, 0x8
# LOOP       loop
# RET
shellcode = '\xb8\xef\xbe7\x13\xb9\x04\x00\x00\x00\xc1\xc0\x08\xe2\xfb\xc3'
mdis = dis_x86_32(shellcode)
blocks = mdis.dis_multibloc(0)

for block in blocks:
    print block

open('graph.dot', 'w').write(blocks.dot())
