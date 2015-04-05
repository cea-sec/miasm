main:
	XOR   EDX, EDX
	JZ    lbl_start

lbl_start:
	INC   EDX
	INC   EDX
	INC   EDX
	JZ    dum

	INC   EDX
	INC   EDX
	INC   EDX
	JZ    dum

	INC   EDX
	INC   EDX
	INC   EDX
	JZ    dum

lbl_stop:

	MOV   ESI, exit_code
	MOV   EDI, lbl_start
	MOV   AL, 0x90
	MOV   ECX, 24
	REPE  MOVSB
	JMP   lbl_start

exit_code:
	MOV  EAX, 0x11223344
	MOV  EAX, 0x11223344
	MOV  EAX, 0x11223344
	CMP  EDX, 0x12
	JZ   dum
	RET

dum:
	INT 0x3
	RET
