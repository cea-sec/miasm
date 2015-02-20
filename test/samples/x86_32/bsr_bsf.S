main:
	;; BSF
	;; standard case
	MOV ECX, 0xF0000004
	MOV EAX, 0x0
	BSF EAX, ECX
	JZ bad
	CMP EAX, 2
	JNZ bad


	 ;; case undef
	MOV ECX, 0x0
	MOV EAX, 0x1337beef
	BSF EAX, ECX
	JNZ bad
	CMP EAX, 0x1337beef
	JNZ bad

	;; BSR
	;; standard case
	MOV ECX, 0x4000000F
	MOV EAX, 0x0
	BSR EAX, ECX
	JZ bad
	CMP EAX, 30
	JNZ bad


	 ;; case undef
	MOV ECX, 0x0
	MOV EAX, 0x1337beef
	BSR EAX, ECX
	JNZ bad
	CMP EAX, 0x1337beef
	JNZ bad

	RET

bad:
	INT 0x3
	RET
