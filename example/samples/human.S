	;;  Walk a human link list and print its information
main:
	TEST       RDI, RDI
	JZ         next

	PUSH       RBX
	MOV        RBX, RDI
loop_arg:
	LEA        RSI, QWORD PTR [RBX+0x10]
	LEA        RDI, QWORD PTR [name-_+RIP]
	XOR        EAX, EAX
	CALL       printf

	MOVZX      ESI, WORD PTR [RBX+0x8]
	LEA        RDI, QWORD PTR [age-_+RIP]
	XOR        EAX, EAX
	CALL       printf

	MOV        ESI, DWORD PTR [RBX+0xC]
	XOR        EAX, EAX
	LEA        RDI, QWORD PTR [height-_+RIP]
	CALL       printf

	MOV        RBX, QWORD PTR [RBX]
	TEST       RBX, RBX
	JNZ        loop_arg

	POP        RBX
next:


	LEA        RBX, QWORD PTR [struct_human_ptr-_+RIP]
loop_global:
	CMP        RBX, 0
	JZ         end

	LEA        RSI, QWORD PTR [RBX+0x10]
	LEA        RDI, QWORD PTR [name-_+RIP]
	XOR        EAX, EAX
	CALL       printf
	MOV        RBX, QWORD PTR [RBX]
	JMP        loop_global
end:
	RET

printf:
	;; Dummy printf
	RET

age:
.string "Age: %d\n"
height:
.string "Height: %d\n"
name:
.string "Name: %s\n"
struct_human_ptr:
.dword 0xdead, 0xcafe
