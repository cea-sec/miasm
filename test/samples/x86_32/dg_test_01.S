main:
	MOV ECX, 0x1
	JMP lbl1
lbl1:
	MOV EBX, 0x2
	JMP lbl2
lbl2:
	LEA EAX, DWORD PTR [EBX + ECX]
	RET
