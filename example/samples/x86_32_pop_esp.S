main:
    MOV EAX, ESP
    CALL test
    MOV ESP, EAX
    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]
    RET

test:
    POP ESP
    JMP ESP
title:
.string "Hello!"
msg:
.string "World!"
