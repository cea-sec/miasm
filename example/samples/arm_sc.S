main:
    MOV R1, R0
    MOV R2, 0x100
    LDR R3, [PC, mykey1-$]
loop:
    ADD R2, R1, R2
    ADD R1, R1, 1
    LDR R3, [PC, mykey2-$]
    CMP R1, R3
    BEQ loop

    ADD R0, R1, R2
    BX LR
mykey1:
.long 0x1
mykey2:
.long 0x2
