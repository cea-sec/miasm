main:
	MOV         EBX, 0
	MOV         ECX, 0

	CMP         EDX, 0
	JNZ         test1
	JMP         goon
test1:
	MOV         EDX, 1
	LEA         EDX, DWORD PTR [EDX+0xF]
	LEA         EBX, DWORD PTR [EBX+EDX]
	MOV         EDX, 2
	LEA         EDX, DWORD PTR [EDX+0xE]
	MOV         ECX, EDX
	LEA         EBX, DWORD PTR [EBX+ECX]
	JNZ         test1
goon:
	MOV         EAX, EBX
	RET
