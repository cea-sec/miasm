main:
    CALL cipher_code
    CALL msgbox_encrypted_start
    CALL cipher_code
    RET

cipher_code:
    PUSH EBP
    MOV  EBP, ESP

    LEA  ESI, DWORD PTR [msgbox_encrypted_start]
    LEA  EDI, DWORD PTR [msgbox_encrypted_stop]

loop:
    XOR  BYTE PTR [ESI], 0x42
    INC  ESI
    CMP  ESI, EDI
    JBE  loop

    MOV  ESP, EBP
    POP  EBP
    RET

msgbox_encrypted_start:
    PUSH 0
    PUSH title
    PUSH msg
    PUSH 0
    CALL DWORD PTR [ MessageBoxA ]
    RET
.dontsplit
msgbox_encrypted_stop:
.long 0

title:
.string "Hello!"
msg:
.string "World!"
