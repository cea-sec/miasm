main:
	MOV EBX, 0x1
	JMP lbl1
lbl1:
	ADD EBX, 0x2
	CMP EBX, 0x0
	JNZ lbl1
end:
	MOV EAX, EBX
	RET
