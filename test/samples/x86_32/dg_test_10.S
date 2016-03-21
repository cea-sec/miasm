main:
	MOV ECX, 0x8
	JZ lbl2
lbl1:
	MOV EAX, 0x1
	JMP end1
lbl2:
	MOV EAX, 0x2
	JMP end1
end1:
	JZ lbl4
lbl3:
	MOV EBX, 0x3
	JMP end
lbl4:
	MOV EBX, 0x4
	JMP end

end:
	RET
