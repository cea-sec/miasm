main:
	MOV         ECX, 10
	MOV         EDX, 10
loop:
	INC         EDX
	DEC         EDX
	DEC         ECX
	JNZ         loop
	MOV         EAX, EDX
	RET
