import sys
import time

from miasm.core.utils import decode_hex
from miasm.arch.riscv.arch import mn_riscv
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()

# little-endian
reg_tests_riscv = [

    ("XXXXXXXX    ADDI       X1, X2, 0x0",
     "00010093"),   # addi x1, x2, 0

    ("XXXXXXXX    ANDI       X2, X1, 0xFF",
     "0FF0F113"),   # andi x2, x1, 0xFF

    ("XXXXXXXX    SLTI       X3, X4, 0x1",
     "00122193"),   # slti x3, x4, 1

    ("XXXXXXXX    SLTIU      X4, X5, 0x2",
     "0022B213"),   # sltiu x4, x5, 2

    ("XXXXXXXX    XORI       X6, X7, 0xAA",
     "0AA3C313"),   # xori x6, x7, 0xAA

    ("XXXXXXXX    ORI        X7, X8, 0x55",
     "05546393"),   # ori x7, x8, 0x55

    ("XXXXXXXX    ADD        X3, X1, X2",
     "002081B3"),   # add x3, x1, x2

    ("XXXXXXXX    SUB        X5, X6, X7",
     "407302B3"),   # sub x5, x6, x7

    ("XXXXXXXX    AND        X8, X9, X10",
     "00A4F433"),   # and x8, x9, x10

    ("XXXXXXXX    OR         X11, X12, X13",
     "00D665B3"),   # or x11, x12, x13

    ("XXXXXXXX    XOR        X14, X15, X16",
     "0107C733"),   # xor x14, x15, x16

    ("XXXXXXXX    SLL        X6, X7, X8",
     "00839333"),   # sll x6, x7, x8

    ("XXXXXXXX    SRL        X9, X10, X11",
     "00b554B3"),   # srl x9, x10, x11

    ("XXXXXXXX    SRA        X12, X13, X14",
     "40E6D633"),   # sra x12, x13, x14

    ("XXXXXXXX    SLT        X15, X16, X17",
     "011827B3"),   # slt x15, x16, x17

    ("XXXXXXXX    SLTU       X18, X19, X20",
     "0149B933"),   # sltu x18, x19, x20

    ("XXXXXXXX    LW         X5, X1, 0x0",
     "0000A283"),   # lw x5, 0(x1)

    ("XXXXXXXX    LB         X2, X3, 0x10",
     "01018103"),   # lb x2, 16(x3)

    ("XXXXXXXX    LH         X4, X5, 0x20",
     "02029203"),   # lh x4, 32(x5)

    ("XXXXXXXX    LD         X6, X7, 0x0",
     "0003B303"),   # ld x6, 0(x7)

    ("XXXXXXXX    LBU        X8, X9, 0x4",
     "0044C403"),   # lbu x8, 4(x9)

    ("XXXXXXXX    LHU        X10, X11, 0x6",
     "0065D503"),   # lhu x10, 6(x11)

    ("XXXXXXXX    LWU        X12, X13, 0x8",
     "0086E603"),   # lwu x12, 8(x13)

    ("XXXXXXXX    SW         X5, X1, 0x4",
     "0050A223"),   # sw x5, 4(x1)

    ("XXXXXXXX    SB         X2, X3, 0x0",
     "00218023"),   # sb x2, 0(x3)

    ("XXXXXXXX    SH         X4, X5, 0x2",
     "00429123"),   # sh x4, 2(x5)

    ("XXXXXXXX    SD         X6, X7, 0x8",
     "0063B423"),   # sd x6, 8(x7)

    ("XXXXXXXX    BEQ        X1, X2, 0x8",
     "00208463"),   # beq x1, x2, 8

    ("XXXXXXXX    BNE        X3, X4, 0xC",
     "00419663"),   # bne x3, x4, 12

    ("XXXXXXXX    BLT        X5, X6, 0x10",
     "0062C863"),   # blt x5, x6, 16

    ("XXXXXXXX    BGE        X7, X8, 0x14",
     "0083da63"),   # bge x7, x8, 20

    ("XXXXXXXX    BLTU       X9, X10, 0x18",
     "00A4EC63"),   # bltu x9, x10, 24

    ("XXXXXXXX    BGEU       X11, X12, 0x1C",
     "00C5FE63"),   # bgeu x11, x12, 28

    ("XXXXXXXX    JALR       X1, X2, 0x0",
     "000100E7"),   # jalr x1, 0(x2)

    ("XXXXXXXX    JAL        X1, 0x10",
     "010000EF"),   # jal x1, 16

    ("XXXXXXXX    LUI        X1, 0x10000",
     "100000B7"),   # lui x1, 0x10000

    ("XXXXXXXX    AUIPC      X2, 0x20000",
     "20000117"),   # auipc x2, 0x20000
]



def h2i(s):
    return decode_hex(s.replace(' ', ''))


def main():
    ts = time.time()

    for s, l in reg_tests_riscv[:]:
        print("-" * 80)
        print(s[:12], l)
        asm_str = s[12:]
        b = h2i(l)

        mn = mn_riscv.dis(b, 64)
        print("[args]", [str(x) for x in mn.args])
        print("expected asm:", asm_str)
        print("disasm asm:  ", mn)

        assert str(mn) == asm_str

        l_obj = mn_riscv.fromstring(asm_str, loc_db, 64)
        assert str(l_obj) == asm_str

        a = mn_riscv.asm(l_obj)
        print("asm bytes:", [x for x in a])
        print("orig bytes:", repr(b))
        assert b in a

        print(l_obj.to_html())

    print("done in %f seconds" % (time.time() - ts))

if __name__ == "__main__":
    main()