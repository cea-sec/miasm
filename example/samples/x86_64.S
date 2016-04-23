main:
    MOV R9, 0x0
    LEA R8, QWORD PTR [title]
    LEA RDX, QWORD PTR [msg]
    MOV RCX, 0x0
    CALL QWORD PTR [ MessageBoxA ]
    RET

title:
.string "Hello!"
msg:
.string "World!"
