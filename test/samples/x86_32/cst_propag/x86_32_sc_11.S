main:
	MOV         ECX, 10
loop1:
	DEC         ECX
	JNZ         less
	JMP         goon
less:
	DEC         ECX
goon:
	JNZ         loop1
	RET
