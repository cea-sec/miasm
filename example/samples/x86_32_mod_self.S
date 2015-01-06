main:
    PUSH EBP
    MOV  EBP, ESP
    MOV  BYTE PTR [myint], 0x90
myint:
    INT 0x3

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
