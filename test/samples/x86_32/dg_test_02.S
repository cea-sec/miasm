main:
	MOV ECX, 0x1
	JZ lbl2
lbl1:
	MOV EBX, 0x2
	JMP end
lbl2:
	MOV EBX, 0x3
	JMP end
end:
	LEA EAX, DWORD PTR [EBX + ECX]
	RET
