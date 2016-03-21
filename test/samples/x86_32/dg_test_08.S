main:
	MOV ECX, 0x1
	MOV EBX, 0x2
	JMP lbl1
lbl1:
	XCHG EBX, ECX
	JMP end
end:
	MOV EAX, EBX
	RET
