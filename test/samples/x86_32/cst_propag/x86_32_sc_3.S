main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]
loop:
	SUB         ECX, 1
	JZ          end
	PUSH        EDX
	POP         ESI
	JMP         loop
end:
	MOV         EAX, DWORD PTR [ESP+0xC]
	MOV         ESP, EBP
	POP         EBP
	RET
