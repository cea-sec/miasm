
main:
	PUSH       error
	PUSH       DWORD PTR FS:[0x0]
	MOV        DWORD PTR FS:[0x0], ESP
	XOR        EAX, EAX

;; Access violation
lbl_err_0:
	MOV        DWORD PTR [EAX], 0x0
lbl_err_end0:
	NOP


;; Breakpoint
lbl_err_1:
	INT        0x3
lbl_err_end1:
	NOP

;; Divide by 0
	XOR        EAX, EAX
lbl_err_2:
	DIV        EAX
lbl_err_end2:
	NOP

;; Privileged instruction
lbl_err_3:
	STI
lbl_err_end3:
	NOP

;; Unknown instruction (Bad LEA encoding)
lbl_err_4:
	.byte 0x8D, 0xC0
lbl_err_end4:
	NOP

	POP        DWORD PTR FS:[0x0]
	ADD        ESP, 4
	RET

;; Single step
lbl_err_5:
	INT        0x1
lbl_err_end5:
	NOP

error:
	MOV        ECX, DWORD PTR [ESP+0xC]
	MOV        EAX, DWORD PTR [ECX+0xB8]
	MOV        EBX, DWORD PTR [err_num]
	CMP        EAX, DWORD PTR [labels_err + 4*EBX]
	JZ         error_address_ok
	INT        0x3
error_address_ok:
	INC        DWORD PTR [err_num]
	MOV        EAX, DWORD PTR [labels_err_end + 4*EBX]
	MOV        DWORD PTR [ECX+0xB8], EAX
	XOR        EAX, EAX
	RET



err_num:
.dword 0

labels_err:
.dword lbl_err_0
.dword lbl_err_end1
.dword lbl_err_2
.dword lbl_err_3
.dword lbl_err_4
.dword lbl_err_5


labels_err_end:
.dword lbl_err_end0
.dword lbl_err_end1
.dword lbl_err_end2
.dword lbl_err_end3
.dword lbl_err_end4
.dword lbl_err_end5
