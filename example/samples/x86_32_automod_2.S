main:
	MOV     EAX, 0
	MOV     ECX, 0x3
block1:
	DEC     ECX
block2:
	INC     EAX
tmp:
	DEC     ECX
	JNZ     block2
	; Modify block1
	MOV     BYTE PTR [block1], 0x90
	; Modify block2
	MOV     BYTE PTR [block2], 0x90
	MOV     BYTE PTR [tmp], 0x90
	MOV     ECX, 4
	MOV     EBX, EAX
	XOR     EAX, EAX
	CMP     EBX, 2
	JZ      block2
	CMP     EBX, 0
	JZ      ok
	INT     0x3
ok:
	RET
