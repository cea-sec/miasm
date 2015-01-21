main:
    ADDIU      A0, ZERO, 0x10
    ADDIU      A1, ZERO, 0
loop:
    ADDIU      A1, A1, 0x1
    BNE        A0, ZERO, loop
    ADDIU      A0, A0, 0xFFFFFFFF

    ADDIU      A2, A2, 0x1
    MOVN       A1, ZERO, ZERO
    JR         RA
    ADDIU      A2, A2, 0x1
