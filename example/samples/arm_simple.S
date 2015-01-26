main:
  STMFD  SP!, {R4, R5, LR}
  MOV    R0, mystr & 0xffff
  ORR    R0, R0, mystr & 0xffff0000
  MOV    R4, R0
  MOV    R1, mystrend & 0xffff
  ORR    R1, R1, mystrend & 0xffff0000
xxx:
  LDRB    R2, [PC, key-$]
loop:
  LDRB   R3, [R0]
  EOR    R3, R3, R2
  STRB   R3, [R0], 1
  CMP    R0, R1
  BNE    loop
end:
  MOV    R0, R4
  LDMFD  SP!, {R4, R5, PC}
key:
.byte 0x11
mystr:
.string "test string"
mystrend:
.long 0
