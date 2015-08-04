main:
  SUB             SP, SP, 0x10
  STRB            W0, [SP,0xF]
  LDRB            W0, [SP,0xF]
  CMP             W0, 0x1F
  B.LS            is_print
  LDRB            W0, [SP,0xF]
  CMP             W0, 0x7E
  B.HI            is_print
  MOVZ            W0, 1
  B               ret_
is_print:
  MOVZ            W0, 0

ret_:
  ADD             SP, SP, 0x10
  RET             LR