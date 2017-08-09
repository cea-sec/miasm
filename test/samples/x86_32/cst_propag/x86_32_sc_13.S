main:
	MOV         ECX, 10
loop:
	DEC         ECX
	JNZ         loop
	MOV         EAX, ECX
	RET
