main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [EBP+0x8]

	SUB         ECX, 1
	JZ          test1
	SUB         ECX, 1
	JZ          test2
	SUB         ECX, 1
	JZ          test3

	JMP         end
test1:
	INC         EAX
test2:
	INC         EAX
test3:
	INC         EAX
end:
	INC         EAX
	MOV         ESP, EBP
	POP         EBP
	RET
