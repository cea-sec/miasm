main:
   PUSH EBP
   MOV  EBP, ESP
   SUB  ESP, 0x100
   MOV  EAX, 0x1337
   ; test ptr manip
   LEA  ESI, DWORD PTR [mystr^toto]
   CALL toto
mystr:
.string "test string"
 toto:
   POP  EDI

   PUSH EDI
   ; test scasb
   XOR  EAX, EAX
   XOR  ECX, ECX
   DEC  ECX
   REPNE SCASB
   NOT  ECX
   DEC  ECX

   ; test movsb
   POP  ESI
   LEA  EDI, DWORD PTR [EBP-0x100]
   REPE  MOVSB

   ; test float
   PUSH 0
   FLD1
   FLD1
   FADD ST, ST(1)
   FIST  DWORD PTR [ESP]
   POP  EAX

   ; test cond mnemo
   NOP
   NOP
   CMOVZ EAX, EBX
   ; test shr
   NOP
   SHR EAX, 1
   NOP
   NOP
   SHR EAX, CL
   NOP

   MOV  ESP, EBP
   POP  EBP
   RET
