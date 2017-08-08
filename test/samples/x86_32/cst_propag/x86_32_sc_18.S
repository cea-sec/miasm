main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         EAX, DWORD PTR [EBP+0x8]
	MOV         EBX, DWORD PTR [EBP+0xC]
	ADD         EAX, EBX
	TEST        EAX, EAX
	JNZ         test
	PUSH        1
	PUSH        2
	PUSH        DWORD PTR [EBP+0x10]
	CALL        func1
	ADD         ESP, 0xC
	JMP         goon
test:
	MOV         ECX, 10
loop:
	PUSH        1
	PUSH        2
	CALL        func2
	ADD         ESP, 0x8
	DEC         ECX
	JNZ         loop
goon:
	MOV         ESP, EBP
	POP         EBP
	RET


func1:
	RET
func2:
	RET
