main:
	MOV ECX, 0x1
	JMP lbl1
lbl1:
	MOV EBX, ECX
	JMP lbl2
lbl2:
	MOV EAX, EBX
	RET
