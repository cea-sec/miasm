main:
	CMP    EAX, 0x10
	JZ     lbl2
	MOV    ESI, EAX
	CMOVA  EAX, EBX
	JMP    end
lbl2:
	MOV    EAX, ECX
	CALL   0x11223344
	INC    EAX
end:
	RET
