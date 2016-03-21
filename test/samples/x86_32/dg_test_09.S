main:
	MOV ECX, 0x8
	JZ lbl2
lbl1:
	MOV EAX, 0x1
	MOV EBX, 0x2
	JMP end
lbl2:
	MOV EAX, 0x3
	MOV EBX, 0x4
	JMP end
end:
	RET
