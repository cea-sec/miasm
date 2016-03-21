main:
	MOV ECX, 0x1
	JMP lbl1
lbl1:
	ADD ECX, 0x2
	CMP ECX, 0x0
	JZ lbl1
end:
	MOV EAX, EBX
	RET
