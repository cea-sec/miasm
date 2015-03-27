memcpy:
     PUSH    {R0-R3, LR}
     B       test_end
loop:
     LDRB    R3, [R1]
     STRB    R3, [R0]
     ADDS    R0, R0, 1
     ADDS    R1, R1, 1
     SUBS    R2, R2, 1
test_end:
     CMP     R2, 0
     BNE     loop
     POP     {R0-R3, PC}
main:
     PUSH    {LR}
     SUB     SP, 0x100
     MOV     R0, SP
     ADD     R1, PC, mystr-$
     MOV     R0, R0
     EORS    R2, R2
     ADDS    R2, R2, 0x4
     BL      memcpy
     ADD     SP, 0x100
     POP     {PC}

mystr:
.string "toto"
