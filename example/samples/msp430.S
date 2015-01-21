main:
    mov.w      0x10, R10
    mov.w      0x0, R11
loop:
    add.w      1, R11
    sub.w      1, R10
    jnz        loop
    mov.w      @SP+, PC
