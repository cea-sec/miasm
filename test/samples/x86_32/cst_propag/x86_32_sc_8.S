main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]
	INC         EAX

loop:
	MOV         EDX, 1
	MOV         ESI, 1
	ADD         EAX, EDX
	SUB         EAX, ESI
	SUB         ECX, 1
	JZ          loop

	INC         EAX
	MOV         ESP, EBP
	POP         EBP
	RET
