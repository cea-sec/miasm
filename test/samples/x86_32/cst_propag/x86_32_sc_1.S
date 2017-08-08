main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, 1
	MOV         EDX, 2
	LEA         ECX, DWORD PTR [ECX+0x4]
	LEA         EBX, DWORD PTR [ECX+0x1]
	CMP         CL, 0x1
	JZ          test1
	LEA         EBX, DWORD PTR [EBX-1]
	JMP         end
test1:
	LEA         EBX, DWORD PTR [EBX-1]
end:
	MOV         EAX, EBX
	LEA         EAX, DWORD PTR [EAX + EDX]
	MOV         EDX, DWORD PTR [EBP+0xC]
	LEA         EAX, DWORD PTR [EAX + EDX]
	MOV         ESP, EBP
	POP         EBP
	RET
