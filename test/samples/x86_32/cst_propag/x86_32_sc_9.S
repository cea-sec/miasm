main:
	PUSH        EBP
	MOV         EBP, ESP
	MOV         ECX, 10 ; DWORD PTR [EBP+0x8]

	MOV         EBX, 0x1000   ;
	INC         EBX		  ; EBX = 0x1001
	MOV         EAX, EBX	  ; EAX = 0x1001
	MOV         EBX, 0x10001  ; EBX = 0x10001
	DEC         EBX		  ; EBX = 0x10000
	MOV         ESI, EBX	  ; ESI = 0x10000
				  ;
	ADD         EDI, EAX	  ; EDI += 0x1001
	ADD         EDI, ESI      ; EDI += 0x10000
	;; EDI = EDI + 0x11001

loop:
	MOV         EBX, 0x1000   ;
	MOV         EAX, EBX	  ;
	MOV         EBX, 0x100001 ;
	MOV         ESI, EBX	  ;
	MUL         ESI		  ; EAX = 0x1000
	MOV         EBX, 0x1	  ;
	ADD         EDI, EBX	  ; EDI += 1
	MOV         EBX, 0x1000	  ;
	ADD         EDI, EBX	  ; EDI += 0x1000
	SUB         EDI, EAX      ; EDI -= 0x1000
	DEC         EDI		  ; EDI -= 1
	SUB         ECX, 1
	JNZ          loop

	INC         EDI
	MOV         EAX, EDI
	MOV         ESP, EBP
	POP         EBP
	RET
