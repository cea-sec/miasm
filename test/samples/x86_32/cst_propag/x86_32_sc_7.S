main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]
	INC         EAX

loop:
	INC         EAX
	DEC         EAX
	SUB         ECX, 1
	JZ          loop

	INC         EAX
	MOV         ESP, EBP
	POP         EBP
	RET
