main:
    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]
    RET

title:
.string "Hello!"
msg:
.string "World!"
