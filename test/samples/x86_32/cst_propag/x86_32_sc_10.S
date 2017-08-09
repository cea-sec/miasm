main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, DWORD PTR [ESP+0x8]
	INC         EBX
	CMP         CL, 0x1
	JZ          test1
	MOV         EAX, 8
	JMP         end
test1:
	MOV         EAX, 4
end:
	LEA         EBX, DWORD PTR [EAX+EBX]
	MOV         EAX, EBX
	MOV         ESP, EBP
	POP         EBP
	RET
