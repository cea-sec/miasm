main:

	MOV         EBX, 1
	MOV         ECX, 1
	CMP         EDX, 10
	JZ          test1
	ADD         EBX, 1
	ADD         ECX, 1
	JMP         gogon
test1:
	ADD         EBX, 2
	ADD         ECX, 2
gogon:
	ADD         EAX, EBX
	ADD         EAX, ECX
	RET
