main:
	MOV         EBX, 1
	ADD         EDI, 1
	MOV         ECX, 10
loop1:
	MOV         EDX, 10
	INC         EDI
loop2:
	LEA         EDI, DWORD PTR [EDI+EBX]
	LEA         EDI, DWORD PTR [EDI-1]
	SUB         EDX, 1
	JNZ         loop2
	DEC         EDI
	SUB         ECX, 1
	JNZ         loop1
	MOV         EAX, EDI
	RET
