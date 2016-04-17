main:
	MOV   EAX, 0x0
	CMP   EBX, 0
	JZ    skip1
	OR    EAX, 0x11220000
skip1:
	CMP   EBX, 0
	JZ    skip2
	OR    EAX, 0x3344
skip2:
	RET
