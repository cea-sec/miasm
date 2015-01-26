main:
    MOV R9, 0x0
    MOV R8, title
    MOV RDX, msg
    MOV RCX, 0x0
    MOV RAX, QWORD PTR [ MessageBoxA ]
    CALL RAX
    RET

title:
.string "Hello!"
msg:
.string "World!"
