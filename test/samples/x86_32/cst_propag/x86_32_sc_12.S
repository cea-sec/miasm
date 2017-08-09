main:
	MOV         EBX, 1
	MOV         ECX, 2
	CMP         EDX, 3
	JNZ         test1
	ADD         EBX, 1
	JMP         goon
test1:
	ADD         ECX, 1
goon:
	LEA         EAX, DWORD PTR [EBX+ECX]
	RET
