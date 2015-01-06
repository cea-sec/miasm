main:
    CALL test_automod
    RET

lbl_good:
    NOP
    NOP
    NOP
    NOP
    NOP
    NOP
    NOP
    NOP
    NOP

test_automod:
    PUSH EBP
    MOV  EBP, ESP

    LEA EDI, DWORD PTR [lbl_mod]
    LEA ESI, DWORD PTR [lbl_good]

    MOV ECX, 0x8
    REPE MOVSB
lbl_mod:
    XOR EAX, EAX
    MOV DWORD PTR [EAX], 0xDEADC0DE

    NOP
    NOP
    NOP

    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]

    MOV ESP, EBP
    POP EBP
    RET

title:
.string "Hello!"
msg:
.string "World!"
