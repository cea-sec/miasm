main:
	MOV         EBX, 1
	ADD         EDI, 1
	SUB         EBX, EDI
	SUB         EDI, 1
	ADD         EBX, EDI
	MOV         EAX, EBX
	RET
