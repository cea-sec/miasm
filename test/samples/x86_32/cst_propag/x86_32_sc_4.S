main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]
loop:
	PUSH        EDX
	POP         ESI
	SUB         ECX, 1
	JZ          end
	JMP         loop
end:
	MOV         EAX, DWORD PTR [ESP+0xC]
	MOV         ESP, EBP
	POP         EBP
	RET
