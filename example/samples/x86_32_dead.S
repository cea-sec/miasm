main:
	MOV     ECX, ECX
	INC     ECX
	CMP     ECX, 0
	JZ      lbl0
	INC     EAX
lbl0:
	DEC     EAX
	JMP     lbl1
lbl1:
	MOV     EAX, 3
	JMP     lbl2
lbl2:
	MOV     EAX, 4
	RET
