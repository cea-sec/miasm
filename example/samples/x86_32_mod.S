main:
    CALL test_automod
    CALL test_automod
    RET

test_automod:
    PUSH EBP
    MOV  EBP, ESP

loop:
    MOV  EAX, 0
    CMP  EAX, 0
    JMP  mod_addr
mod_addr:
    JNZ  end

    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]

    ; automodif code
    MOV BYTE PTR [mod_addr], 0xEB
    JMP loop
end:
    MOV BYTE PTR [mod_addr], 0x75
    MOV ESP, EBP
    POP EBP
    RET

title:
.string "Hello!"
msg:
.string "World!"
