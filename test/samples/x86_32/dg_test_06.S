main:
	MOV ECX, 0x1
	MOV EDX, 0x2
	JMP lbl1
lbl1:
	MOV EBX, ECX
	MOV ECX, EDX
	CMP EAX, 0x0
	JZ lbl1
end:
	MOV EAX, EBX
	RET
