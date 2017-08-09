main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]

	INC         EAX
	SUB         ECX, 1
	JZ          test1
	ADD         EAX, 1
	JMP         go1
test1:
	ADD         EAX, 2
go1:


	INC         EAX
	SUB         ECX, 1
	JZ          test2
	ADD         EAX, 0x10
	JMP         go2
test2:
	ADD         EAX, 0x20
go2:

	INC         EAX
	SUB         ECX, 1
	JZ          test3
	ADD         EAX, 0x30
	JMP         go3
test3:
	ADD         EAX, 0x40
go3:

	INC         EAX
	MOV         ESP, EBP
	POP         EBP
	RET
