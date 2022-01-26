# Toshiba MeP-c4 - miasm architecture definition
# Guillaume Valadon <guillaume@valadon.net>

from builtins import range
from miasm.core.cpu import *
from miasm.core.utils import Disasm_Exception
from miasm.expression.expression import ExprId, ExprInt, ExprLoc, \
    ExprMem, ExprOp, is_expr
from miasm.core.asm_ast import AstId, AstMem

from miasm.arch.mep.regs import *
import miasm.arch.mep.regs as mep_regs_module  # will be used to set mn_mep.regs
from miasm.ir.ir import color_expr_html


# Note: pyparsing is used to alter the way special operands are parsed
from pyparsing import Literal, Group, Word, hexnums


# These definitions will help parsing dereferencing instructions (i.e. that uses
# parenthesis) with pyparsing
LPARENTHESIS = Literal("(")
RPARENTHESIS = Literal(")")
PLUSSIGN = Literal("+")
HEX_INTEGER = str_int_pos | str_int_neg


def ExprInt2SignedString(expr, pos_fmt="%d", neg_fmt="%d", size=None, offset=0):
    """Return the signed string corresponding to an ExprInt

       Note: this function is only useful to mimic objdump output"""

    # Apply a mask to the integer
    if size is None:
        mask_length = expr.size
    else:
        mask_length = size
    mask = (1 << mask_length) - 1
    value = int(expr) & mask

    # Return a signed integer if necessary
    if (value >> mask_length - 1) == 1:
        value = offset - ((value ^ mask) + 1)
        if value < 0:
            return "-" + neg_fmt % -value
    else:
        value += offset

    return pos_fmt % value


class instruction_mep(instruction):
    """Generic MeP-c4 instruction

    Notes:
        - this object is used to build internal miasm instructions based
          on mnemonics
        - it must be implemented !
    """

    @staticmethod
    def arg2str(expr, pos=None, loc_db=None):
        """Convert mnemonics arguments into readable strings according to the
        MeP-c4 architecture manual and their internal types

        Notes:
            - it must be implemented ! However, a simple 'return str(expr)'
              could do the trick.
            - it is used to mimic objdump output

        Args:
            expr: argument as a miasm expression
            pos: position index in the arguments list
        """

        if isinstance(expr, ExprId) or isinstance(expr, ExprInt):
            return str(expr)

        elif isinstance(expr, ExprLoc):
            if loc_db is not None:
                return loc_db.pretty_str(expr.loc_key)
            else:
                return str(expr)

        elif isinstance(expr, ExprMem) and (isinstance(expr.ptr, ExprId) or isinstance(expr.ptr, ExprInt)):
            return "(%s)" % expr.ptr

        elif isinstance(expr, ExprMem) and isinstance(expr.ptr, ExprOp):
            return "0x%X(%s)" % (int(expr.ptr.args[1]), expr.ptr.args[0])

        # Raise an exception if the expression type was not processed
        message = "instruction_mep.arg2str(): don't know what \
                   to do with a '%s' instance." % type(expr)
        raise Disasm_Exception(message)

    @staticmethod
    def arg2html(expr, pos=None, loc_db=None):
        """Convert mnemonics arguments into readable html strings according to the
        MeP-c4 architecture manual and their internal types

        Notes:
            - it must be implemented ! However, a simple 'return str(expr)'
              could do the trick.
            - it is used to mimic objdump output

        Args:
            expr: argument as a miasm expression
            pos: position index in the arguments list
        """

        if isinstance(expr, ExprId) or isinstance(expr, ExprInt) or isinstance(expr, ExprLoc):
            return color_expr_html(expr, loc_db)

        elif isinstance(expr, ExprMem) and (isinstance(expr.ptr, ExprId) or isinstance(expr.ptr, ExprInt)):
            return "(%s)" % color_expr_html(expr.ptr, loc_db)

        elif isinstance(expr, ExprMem) and isinstance(expr.ptr, ExprOp):
            return "%s(%s)" % (
                color_expr_html(expr.ptr.args[1], loc_db),
                color_expr_html(expr.ptr.args[0], loc_db)
            )

        # Raise an exception if the expression type was not processed
        message = "instruction_mep.arg2str(): don't know what \
                   to do with a '%s' instance." % type(expr)
        raise Disasm_Exception(message)

    def __str__(self):
        """Return the mnemonic as a string.

        Note:
            - it is not mandatory as the instruction class already implement
              it. It used to get rid of the padding between the opcode and the
              arguments.
            - most of this code is copied from miasm/core/cpu.py
        """

        o = "%s" % self.name

        if self.name == "SSARB":
            # The first operand is displayed in decimal, not in hex
            o += " %d" % int(self.args[0])
            o += self.arg2str(self.args[1])

        elif self.name in ["MOV", "ADD"] and isinstance(self.args[1], ExprInt):
            # The second operand is displayed in decimal, not in hex
            o += " " + self.arg2str(self.args[0])
            o += ", %s" % ExprInt2SignedString(self.args[1])

        elif "CPI" in self.name:
            # The second operand ends with the '+' sign
            o += " " + self.arg2str(self.args[0])
            deref_reg_str = self.arg2str(self.args[1])
            o += ", %s+)" % deref_reg_str[:-1]  # GV: looks ugly

        elif self.name[0] in ["S", "L"] and self.name[-3:] in ["CPA", "PM0", "PM1"]:
            # The second operand ends with the '+' sign
            o += " " + self.arg2str(self.args[0])
            deref_reg_str = self.arg2str(self.args[1])
            o += ", %s+)" % deref_reg_str[:-1]  # GV: looks ugly
            # The third operand is displayed in decimal, not in hex
            o += ", %s" % ExprInt2SignedString(self.args[2])

        elif len(self.args) == 2 and self.name in ["SB", "SH", "LBU", "LB", "LH", "LW"] and \
                isinstance(self.args[1], ExprMem) and isinstance(self.args[1].ptr, ExprOp):  # Major Opcodes #12
            # The second operand is an offset to a register
            o += " " + self.arg2str(self.args[0])
            o += ", %s" % ExprInt2SignedString(self.args[1].ptr.args[1], "0x%X")
            o += "(%s)" % self.arg2str(self.args[1].ptr.args[0])

        elif len(self.args) == 2 and self.name in ["SWCP", "LWCP", "SMCP", "LMCP"] \
                and isinstance(self.args[1], ExprMem) and isinstance(self.args[1].ptr, ExprOp):  # Major Opcodes #12
            # The second operand is an offset to a register
            o += " " + self.arg2str(self.args[0])
            o += ", %s" % ExprInt2SignedString(self.args[1].ptr.args[1])
            o += "(%s)" % self.arg2str(self.args[1].ptr.args[0])

        elif self.name == "SLL" and isinstance(self.args[1], ExprInt):  # Major Opcodes #6
            # The second operand is displayed in hex, not in decimal
            o += " " + self.arg2str(self.args[0])
            o += ", 0x%X" % int(self.args[1])

        elif self.name in ["ADD3", "SLT3"] and isinstance(self.args[2], ExprInt):
            o += " %s" % self.arg2str(self.args[0])
            o += ", %s" % self.arg2str(self.args[1])
            # The third operand is displayed in decimal, not in hex
            o += ", %s" % ExprInt2SignedString(self.args[2], pos_fmt="0x%X")

        elif self.name == "(RI)":
            return o

        else:
            args = []
            if self.args:
                o += " "
            for i, arg in enumerate(self.args):
                if not is_expr(arg):
                    raise ValueError('zarb arg type')
                x = self.arg2str(arg, pos=i)
                args.append(x)
            o += self.gen_args(args)

        return o

    def breakflow(self):
        """Instructions that stop a basic block."""

        if self.name in ["BRA", "BEQZ", "BNEZ", "BEQI", "BNEI", "BLTI", "BGEI", "BEQ", "BNE", "BSR"]:
            return True

        if self.name in ["JMP", "JSR", "RET"]:
            return True

        if self.name in ["RETI", "HALT", "SLEEP"]:
            return True

        return False

    def splitflow(self):
        """Instructions that splits a basic block, i.e. the CPU can go somewhere else."""

        if self.name in ["BEQZ", "BNEZ", "BEQI", "BNEI", "BLTI", "BGEI", "BEQ", "BNE", "BSR"]:
            return True

        return False

    def dstflow(self):
        """Instructions that explicitly provide the destination."""

        if self.name in ["BRA", "BEQZ", "BNEZ", "BEQI", "BNEI", "BLTI", "BGEI", "BEQ", "BNE", "BSR"]:
            return True

        if self.name in ["JMP"]:
            return True

        return False

    def dstflow2label(self, loc_db):
        """Set the label for the current destination.

           Note: it is used at disassembly"""

        if self.name == "JMP" and isinstance(self.args[0], ExprId):
            # 'JMP RM' does not provide the destination
            return

        # Compute the correct address
        num = self.get_dst_num()
        addr = int(self.args[num])
        if not self.name == "JMP":
            addr += self.offset

        # Get a new label at the address
        label = loc_db.get_or_create_offset_location(addr)

        # Assign the label to the correct instruction argument
        self.args[num] = ExprLoc(label, self.args[num].size)

    def get_dst_num(self):
        """Get the index of the argument that points to the instruction destination."""

        if self.name[-1] == "Z":
            num = 1
        elif self.name in ["BEQI", "BNEI", "BLTI", "BGEI", "BEQ", "BNE"]:
            num = 2
        else:
            num = 0

        return num

    def getdstflow(self, loc_db):
        """Get the argument that points to the instruction destination."""

        num = self.get_dst_num()
        return [self.args[num]]

    def is_subcall(self):
        """Instructions used to call sub functions."""

        return self.name in ["JSR", "BSR"]

    def fixDstOffset(self):
        """Fix/correct the instruction immediate according to the current offset

           Note: - it is used at assembly
                 - code inspired by miasm/arch/mips32/arch.py"""

        if self.name == "JMP" and isinstance(self.args[0], ExprInt):
            # 'JMP IMMEDIATE' does not need to be fixed
            return

        # Get the argument that needs to be fixed
        if not len(self.args):
            return
        num = self.get_dst_num()
        expr = self.args[num]

        # Check that the argument can be fixed
        if self.offset is None:
            raise ValueError("Symbol not resolved %s" % self.l)
        if not isinstance(expr, ExprInt):
            return

        # Adjust the immediate according to the current instruction offset
        off = expr.arg - self.offset
        if int(off % 2):
            raise ValueError("Strange offset! %r" % off)
        self.args[num] = ExprInt(off, 32)


class mep_additional_info(object):
    """Additional MeP instructions information
    """

    def __init__(self):
        self.except_on_instr = False


class mn_mep(cls_mn):
    """Toshiba MeP-c4 disassembler & assembler
    """

    # Define variables that stores information used to disassemble & assemble
    # Notes: - these variables are mandatory
    #        - they could be moved to the cls_mn class

    num = 0  # holds the number of mnemonics

    all_mn = list()  # list of mnenomnics, converted to metamn objects

    all_mn_mode = defaultdict(list)  # mneomnics, converted to metamn objects
                                     # Note:
                                     #   - the key is the mode # GV: what is it ?
                                     #   - the data is a list of mnemonics

    all_mn_name = defaultdict(list)  # mnenomnics strings
                                     # Note:
                                     #   - the key is the mnemonic string
                                     #   - the data is the corresponding
                                     #     metamn object

    all_mn_inst = defaultdict(list)  # mnemonics objects
                                     # Note:
                                     #   - the key is the mnemonic Python class
                                     #   - the data is an instantiated object

    bintree = dict()  # Variable storing internal values used to guess a
                      # mnemonic during disassembly

    # Defines the instruction set that will be used
    instruction = instruction_mep

    # Python module that stores registers information
    regs = mep_regs_module

    # Default delay slot
    # Note:
    #   - mandatory for the miasm Machine
    delayslot = 0

    # Architecture name
    name = "mep"

    # PC name depending on architecture attributes (here, l or b)
    pc = {'l': PC, 'b': PC}

    def additional_info(self):
        """Define instruction side effects # GV: not fully understood yet

        When used, it must return an object that implements specific
        variables, such as except_on_instr.

        Notes:
            - it must be implemented !
            - it could be moved to the cls_mn class
        """

        return mep_additional_info()

    @classmethod
    def gen_modes(cls, subcls, name, bases, dct, fields):
        """Ease populating internal variables used to disassemble & assemble, such
        as self.all_mn_mode, self.all_mn_name and self.all_mn_inst

        Notes:
            - it must be implemented !
            - it could be moved to the cls_mn class. All miasm architectures
              use the same code

        Args:
            cls: ?
            sublcs:
            name: mnemonic name
            bases: ?
            dct: ?
            fields: ?

        Returns:
            a list of ?

        """

        dct["mode"] = None
        return [(subcls, name, bases, dct, fields)]

    @classmethod
    def getmn(cls, name):
        """Get the mnemonic name

        Notes:
            - it must be implemented !
            - it could be moved to the cls_mn class. Most miasm architectures
              use the same code

        Args:
            cls:  the mnemonic class
            name: the mnemonic string
        """

        return name.upper()

    @classmethod
    def getpc(cls, attrib=None):
        """"Return the ExprId that represents the Program Counter.

        Notes:
            - mandatory for the symbolic execution
            - PC is defined in regs.py

        Args:
           attrib: architecture dependent attributes (here, l or b)
        """

        return PC

    @classmethod
    def getsp(cls, attrib=None):
        """"Return the ExprId that represents the Stack Pointer.

        Notes:
            - mandatory for the symbolic execution
            - SP is defined in regs.py

        Args:
           attrib: architecture dependent attributes (here, l or b)
        """

        return SP

    @classmethod
    def getbits(cls, bitstream, attrib, start, n):
        """Return an integer of n bits at the 'start' offset

           Note: code from miasm/arch/mips32/arch.py
        """

        # Return zero if zero bits are requested
        if not n:
            return 0

        o = 0  # the returned value
        while n:
            # Get a byte, the offset is adjusted according to the endianness
            offset = start // 8  # the offset in bytes
            n_offset = cls.endian_offset(attrib, offset)  # the adjusted offset
            c = cls.getbytes(bitstream, n_offset, 1)
            if not c:
                raise IOError

            # Extract the bits value
            c = ord(c)
            r = 8 - start % 8
            c &= (1 << r) - 1
            l = min(r, n)
            c >>= (r - l)
            o <<= l
            o |= c
            n -= l
            start += l

        return o

    @classmethod
    def endian_offset(cls, attrib, offset):
        """Adjust the byte offset according to the endianness"""

        if attrib == "l":  # Little Endian
            if offset % 2:
                return offset - 1
            else:
                return offset + 1

        elif attrib == "b":  # Big Endian
            return offset

        else:
            raise NotImplementedError("Bad MeP endianness")

    def value(self, mode):
        """Adjust the assembled instruction based on the endianness

           Note: code inspired by miasm/arch/mips32/arch.py
        """

        # Get the candidated
        candidates = super(mn_mep, self).value(mode)

        if mode == "l":
            # Invert bytes per 16-bits
            for i in range(len(candidates)):
                tmp = candidates[i][1] + candidates[i][0]
                if len(candidates[i]) == 4:
                    tmp += candidates[i][3] + candidates[i][2]
                candidates[i] = tmp
            return candidates

        elif mode == "b":
            return candidates

        else:
            raise NotImplementedError("Bad MeP endianness (%s)" % mode)


def addop(name, fields, args=None, alias=False):
    """Dynamically create the "name" object

    Notes:
        - it could be moved to a generic function such as:
          addop(name, fields, cls_mn, args=None, alias=False).
        - most architectures use the same code

    Args:
        name:   the mnemonic name
        fields: used to fill the object.__dict__'fields' attribute # GV: not understood yet
        args:   used to fill the object.__dict__'fields' attribute # GV: not understood yet
        alias:  used to fill the object.__dict__'fields' attribute # GV: not understood yet
    """

    namespace = {"fields": fields, "alias": alias}

    if args is not None:
        namespace["args"] = args

    # Dynamically create the "name" object
    type(name, (mn_mep,), namespace)


# Define specific operand parsers & converters

def deref2expr(s, l, parse_results):
    """Convert a parsed dereferenced register to an ExprMem"""

    # Only use the first results
    parse_results = parse_results[0]

    if type(parse_results[0]) == AstInt and isinstance(parse_results[2], AstId):
        return AstMem(parse_results[2] + parse_results[0], 32)  # 1 == "(" and 3 == ")"

    elif type(parse_results[0]) == int and isinstance(parse_results[2], AstId):
        return AstMem(parse_results[2] + AstOp('-', AstInt(-parse_results[0])), 32)  # 1 == "(" and 3 == ")"

    else:
        return AstMem(parse_results[1], 32)  # 0 == "(" and 2 == ")"


deref_reg_parser = Group(LPARENTHESIS + gpr_infos.parser + RPARENTHESIS).setParseAction(deref2expr)
deref_inc_reg_parser = Group(LPARENTHESIS + gpr_infos.parser + PLUSSIGN + RPARENTHESIS).setParseAction(deref2expr)
abs24_deref_parser = Group(LPARENTHESIS + HEX_INTEGER + RPARENTHESIS).setParseAction(deref2expr)
offset_deref_reg_parser = Group(HEX_INTEGER + LPARENTHESIS + gpr_infos.parser + RPARENTHESIS).setParseAction(deref2expr)

# Define registers decoders and encoders

class mep_arg(m_arg):
    def asm_ast_to_expr(self, arg, loc_db):
        """Convert AST to expressions

           Note: - code inspired by miasm/arch/mips32/arch.py"""

        if isinstance(arg, AstId):
            if isinstance(arg.name, ExprId):
                return arg.name
            if isinstance(arg.name, str) and arg.name in gpr_names:
                return None  # GV: why?
            loc_key = loc_db.get_or_create_name_location(arg.name)
            return ExprLoc(loc_key, 32)

        elif isinstance(arg, AstMem):
            addr = self.asm_ast_to_expr(arg.ptr, loc_db)
            if addr is None:
                return None
            return ExprMem(addr, 32)

        elif isinstance(arg, AstInt):
            return ExprInt(arg.value, 32)

        elif isinstance(arg, AstOp):
            args = [self.asm_ast_to_expr(tmp, loc_db) for tmp in arg.args]
            if None in args:
                return None
            return ExprOp(arg.op, *args)

        # Raise an exception if the argument was not processed
        message = "mep_arg.asm_ast_to_expr(): don't know what \
                   to do with a '%s' instance." % type(arg)
        raise Exception(message)

class mep_reg(reg_noarg, mep_arg):
    """Generic Toshiba MeP-c4 register

    Note:
        - the register size will be set using bs()
    """
    reg_info = gpr_infos  # the list of MeP-c4 registers defined in regs.py
    parser = reg_info.parser  # GV: not understood yet


class mep_deref_reg(mep_arg):
    """Generic Toshiba MeP-c4 dereferenced register

    Note:
        - the arg2str() method could be defined to change the output string
    """
    parser = deref_reg_parser

    def decode(self, v):
        """Transform the decoded value to a ExprMem(ExprId()) expression"""
        r = gpr_infos.expr[v]  # get the ExprId, i.e. the register expression
        self.expr = ExprMem(r, 32)
        return True

    def encode(self):
        """Ensure that we have a ExprMem(ExprId()) expression, and return the
        register value."""

        if not isinstance(self.expr, ExprMem):
            return False
        if not isinstance(self.expr.ptr, ExprId):
            return False

        # Get the ExprId index, i.e. its value
        self.value = gpr_exprs.index(self.expr.ptr)
        return True


class mep_reg_sp(mep_reg):
    """Dummy Toshiba MeP-c4 register that represents SP. It is used in
    instructions that implicitly use SP, such as ADD3.
    """
    implicit_reg = SP

    def decode(self, v):
        """Always return 'implicit_reg."""
        self.expr = self.implicit_reg
        return True

    def encode(self):
        """Do nothing"""
        return True


class mep_reg_tp(mep_reg_sp):
    """Dummy Toshiba MeP-c4 register that represents TP.
    """
    implicit_reg = TP


class mep_deref_reg_offset(mep_arg):
    """Toshiba MeP-c4 dereferenced register that represents SP, plus an
    offset.
    """
    parser = offset_deref_reg_parser

    def decode(self, v):
        """Modify the decoded value using the previously decoded
        register id.
        """

        # Apply the immediate mask
        se = sign_ext(v & 0xFFFF, 16, 32)  # GV: might not belong here
        int_id = ExprInt(se, 32)

        # Get the register expression
        reg_id = gpr_infos.expr[self.parent.reg04_deref.value]

        # Build the internal expression
        self.expr = ExprMem(reg_id + int_id, 32)

        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in reg04_deref.
        """

        # Verify the expression
        if not isinstance(self.expr, ExprMem):
            return False
        if not isinstance(self.expr.ptr, ExprOp):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr.ptr.args[1]) & 0xFFFF

        # Encode the values
        self.parent.reg04_deref.value = gpr_exprs.index(self.expr.ptr.args[0])
        self.value = v & 0xFFFF
        return True


class mep_deref_sp_offset(mep_deref_reg):
    """Dummy Toshiba MeP-c4 dereferenced register that represents SP, plus an
    offset.
    Note: it is as generic as possible to ease its use in different instructions
    """
    implicit_reg = SP
    parser = offset_deref_reg_parser

    def decode(self, v):
        """Modify the decoded value using the previously decoded
        immediate.
        """

        immediate = None
        if getattr(self.parent, "imm7_align4", False):
            # Apply the immediate mask
            v = self.parent.imm7_align4.value & 0x1F

            # Shift value such as:
            #   imm7=iii_ii||00
            immediate = v << 2

        elif getattr(self.parent, "imm7", False):
            # Apply the immediate mask
            immediate = self.parent.imm7.value & 0x7F

        elif getattr(self.parent, "disp7_align2", False):
            # Apply the immediate mask
            disp7_align2 = self.parent.disp7_align2.value & 0x3F

            # Shift value such as:
            #   disp7 = ddd_ddd||0
            immediate = disp7_align2 << 1

        if immediate is not None:
            self.expr = ExprMem(self.implicit_reg + ExprInt(immediate, 32), 32)
            return True
        else:
            return False

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in a parent immediate.
        """

        # Verify the expression
        if not isinstance(self.expr, ExprMem):
            return False
        if not isinstance(self.expr.ptr, ExprOp):
            return False
        if self.expr.ptr.args[0] != self.implicit_reg:
            return False

        if getattr(self.parent, "imm7_align4", False):

            # Get the integer and check the upper bound
            v = int(self.expr.ptr.args[1].arg)
            if v > 0x80:
                return False

            # Encode the value
            self.parent.imm7_align4.value = v >> 2

            return True

        elif getattr(self.parent, "imm7", False):

            # Get the integer and check the upper bound
            v = int(self.expr.ptr.args[1].arg)
            if v > 0x80:
                return False

            # Encode the value
            self.parent.imm7.value = v

            return True

        elif getattr(self.parent, "disp7_align2", False):

            # Get the integer and check the upper bound
            v = int(self.expr.ptr.args[1].arg)
            if v > 0x80:
                return False

            # Encode the value
            self.parent.disp7_align2.value = v >> 1

            return True

        return False


class mep_deref_tp_offset(mep_deref_sp_offset):
    """Dummy Toshiba MeP-c4 dereferenced register that represents TP, plus an
    offset.
    """
    implicit_reg = TP


class mep_copro_reg(reg_noarg, mep_arg):
    """Generic Toshiba MeP-c4 coprocessor register
    """
    reg_info = copro_gpr_infos  # the list of MeP-c4 coprocessor registers defined in regs.py
    parser = reg_info.parser  # GV: not understood yet


class mep_copro_reg_split(mep_copro_reg):
    """Generic Toshiba MeP-c4 coprocessor register encode into different fields
    """

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm4_noarg.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift values such as:
        #   CRn=NNnnnn
        crn = (v << 4) + (self.parent.imm4.value & 0xF)

        # Build the internal expression
        self.expr = ExprId("C%d" % crn, 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm4_noarg.
        """

        if not isinstance(self.expr, ExprId):
            return False

        # Get the register and check the upper bound
        reg_name = self.expr.name
        if reg_name[0] != "C":
            return False
        reg_value = copro_gpr_names.index(reg_name)
        if reg_value > 0x3f:
            return False

        # Encode the value into two parts
        self.parent.imm4.value = (reg_value & 0xF)
        self.value = (reg_value >> 4) & 0x3
        return True


class mep_deref_inc_reg(mep_deref_reg):
    """Generic Toshiba MeP-c4 coprocess dereferenced & incremented register
    """
    parser = deref_inc_reg_parser


# Immediate decoders and encoders

class mep_int32_noarg(int32_noarg):
    """Generic Toshiba MeP-c4 signed immediate

       Note: encode() is copied from int32_noarg.encode() and modified to allow
             small (< 32 bits) signed immediate to be manipulated.

    """

    def encode(self):
        if not isinstance(self.expr, ExprInt):
            return False
        v = int(self.expr)
        # Note: the following lines were commented on purpose
        #if sign_ext(v & self.lmask, self.l, self.intsize) != v:
        #    return False
        v = self.encodeval(v & self.lmask)
        self.value = v & self.lmask
        return True


class mep_imm(imm_noarg, mep_arg):
    """Generic Toshiba MeP-c4 immediate

    Note:
        - the immediate size will be set using bs()
    """
    parser = base_expr


class mep_imm6(mep_int32_noarg):
    """Toshiba MeP-c4 signed 6 bits immediate."""
    parser = base_expr
    intsize = 6
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: ExprInt(sign_ext(x, self.l, 32), 32)


class mep_imm8(mep_int32_noarg):
    """Toshiba MeP-c4 signed 8 bits immediate."""
    parser = base_expr
    intsize = 8
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: ExprInt(sign_ext(x, self.l, 32), 32)


class mep_imm16(mep_int32_noarg):
    """Toshiba MeP-c4 16 bits immediate."""
    parser = base_expr
    intsize = 16
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: ExprInt(x, 32)


class mep_imm16_signed(mep_int32_noarg):
    """Toshiba MeP-c4 signed 16 bits immediate."""
    parser = base_expr
    intsize = 16
    intmask = (1 << intsize) - 1
    int2expr = lambda self, x: ExprInt(sign_ext(x, self.l, 32), 32)


class mep_target24(mep_imm):
    """Toshiba MeP-c4 target24 immediate, as used in JMP
    """

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm7.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift values such as:
        #   target24=tttt_tttt_tttt_tttt||TTT_TTTT||0
        target24 = (v << 8) + ((self.parent.imm7.value & 0x7F) << 1)

        # Build the internal expression
        self.expr = ExprInt(target24, 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm7.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer and apply a mask
        v = int(self.expr) & 0x00FFFFFF

        # Encode the value into two parts
        self.parent.imm7.value = (v & 0xFF) >> 1
        self.value = v >> 8
        return True


class mep_target24_signed(mep_target24):
    """Toshiba MeP-c4 target24 signed immediate, as used in BSR
    """

    def decode(self, v):
        """Perform sign extension
        """

        mep_target24.decode(self, v)
        v = int(self.expr)
        self.expr = ExprInt(sign_ext(v, 24, 32), 32)

        return True


class mep_code20(mep_imm):
    """Toshiba MeP-c4 code20 immediate, as used in DSP1
    """

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm4_noarg.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift values such as:
        #   code20=mmmm_cccc_cccc_cccc_cccc
        code20 = v + ((self.parent.imm4.value & 0xFF) << 16)

        # Build the internal expression
        self.expr = ExprInt(code20, 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm4_noarg.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr.arg)
        if v > 0xffffff:
            return False

        # Encode the value into two parts
        self.parent.imm4 = ((v >> 16) & 0xFF)
        self.value = v
        return True


class mep_code24(mep_imm):
    """Toshiba MeP-c4 code24 immediate, as used in CP
    """

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm8_CCCC_CCCC.
        """

        # Shift values such as:
        #   code24=CCCC_CCCC||cccc_cccc_cccc_cccc
        code24 = v + ((self.parent.imm8_CCCC_CCCC.value & 0xFF) << 16)

        # Build the internal expression
        self.expr = ExprInt(code24, 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm8_CCCC_CCCC.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr.arg)
        if v > 0xFFFFFF:
            return False

        # Encode the value into two parts
        self.parent.imm8_CCCC_CCCC.value = ((v >> 16) & 0xFF)
        self.value = v & 0xFFFF
        return True


class mep_imm7_align4(mep_imm):
    """Toshiba MeP-c4 imm7.align4 immediate, as used in Major #4 opcodes
    """

    def decode(self, v):
        """Modify the decoded value.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift value such as:
        #   imm7=iii_ii||00
        imm7_align4 = v << 2

        # Build the internal expression
        self.expr = ExprInt(imm7_align4, 32)
        return True

    def encode(self):
        """Modify the encoded value.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr)
        if v > 0x80:
            return False

        # Encode the value
        self.value = v >> 2
        return True


class mep_imm5_Iiiii (mep_imm):
    """Toshiba MeP-c4 imm5 immediate, as used in STC & LDC. It encodes a
    control/special register.
    """

    reg_info = csr_infos  # the list of MeP-c4 control/special registers defined in regs.py
    parser = reg_info.parser  # GV: not understood yet

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm4_iiii
        """

        # Apply the immediate mask
        I = v & self.lmask

        # Shift values such as:
        #   imm5=I||iiii
        imm5 = (I << 4) + (self.parent.imm4_iiii.value & 0xF)

        # Build the internal register expression
        self.expr = ExprId(csr_names[imm5], 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm4_iiii.
        """

        if not isinstance(self.expr, ExprId):
            return False

        # Get the register number and check the upper bound
        v = csr_names.index(self.expr.name)
        if v > 0x1F:
            return False

        # Encode the value into two parts
        self.parent.imm4_iiii.value = v & 0xF  # iiii
        self.value = (v >> 4) & 0b1  # I
        return True


class mep_disp7_align2(mep_imm):
    """Toshiba MeP-c4 disp7.align2 immediate, as used in Major #8 opcodes
    """
    upper_bound = 0x7F
    bits_shift = 1

    def decode(self, v):
        """Modify the decoded value.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift value such as:
        #   disp7 = ddd_ddd||0
        disp7_align2 = (v << self.bits_shift)

        # Sign extension
        disp7_align2 = sign_ext(disp7_align2, self.l + self.bits_shift, 32)

        # Build the internal expression
        self.expr = ExprInt(disp7_align2, 32)
        return True

    def encode(self):
        """Modify the encoded value.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer
        v = int(self.expr) & self.upper_bound

        # Encode the value
        self.value = (v >> self.bits_shift) & self.upper_bound
        self.value = (v & self.upper_bound) >> self.bits_shift
        return True


class mep_disp8_align2(mep_disp7_align2):
    upper_bound = 0xFF


class mep_disp8_align4(mep_disp7_align2):
    upper_bound = 0xFF
    bits_shift = 2


class mep_imm8_align8(mep_disp7_align2):
    upper_bound = 0xFF
    bits_shift = 3


class mep_disp12_align2(mep_disp7_align2):
    upper_bound = 0xFFF


class mep_disp12_align2_signed(mep_disp12_align2):

    def decode(self, v):
        """Perform sign extension.
        """
        mep_disp12_align2.decode(self, v)
        v = int(self.expr)

        self.expr = ExprInt(sign_ext(v, 12, 32), 32)
        return True


class mep_disp17(mep_disp7_align2):
    upper_bound = 0x1FFFF


class mep_imm24(mep_imm):
    """Toshiba MeP-c4 imm24 immediate, as used in MOVU
    """

    def decode(self, v):
        """Modify the decoded value.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift values such as:
        #   imm24=iiii_iiii_iiii_iiii||IIII_IIIII
        imm24 = ((v & 0xFFFF) << 8) + ((v & 0xFF0000) >> 16)

        # Build the internal expression
        self.expr = ExprInt(imm24, 32)
        return True

    def encode(self):
        """Modify the encoded value.
        """

        if not isinstance(self.expr, ExprInt):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr)
        if v > 0xFFFFFF:
            return False

        # Encode the value
        self.value = ((v & 0xFFFF00) >> 8) + ((v & 0xFF) << 16)
        return True


class mep_abs24(mep_imm):
    """Toshiba MeP-c4 abs24 immediate
    """
    parser = abs24_deref_parser

    def decode(self, v):
        """Modify the decoded value using the previously decoded imm6.
        """

        # Apply the immediate mask
        v = v & self.lmask

        # Shift values such as:
        #   abs24=dddd_dddd_dddd_dddd||DDDD_DD||00
        abs24 = (v << 8) + ((self.parent.imm6.value & 0x3F) << 2)

        # Build the internal expression
        self.expr = ExprMem(ExprInt(abs24, 32), 32)
        return True

    def encode(self):
        """Modify the encoded value. One part is stored in this object, and
        the other one in imm6.
        """

        if not (isinstance(self.expr, ExprMem) and isinstance(self.expr.ptr, ExprInt)):
            return False

        # Get the integer and check the upper bound
        v = int(self.expr.ptr)
        if v > 0xffffff:
            return False

        # Encode the value into two parts
        self.parent.imm6.value = (v & 0xFF) >> 2
        self.value = v >> 8
        return True


# Define MeP-c4 assembly operands

reg04 = bs(l=4,  # length in bits
           cls=(mep_reg, ))  # class implementing decoding & encoding

reg04_l = bs(l=4, cls=(mep_reg, ))

reg04_m = bs(l=4, cls=(mep_reg, ))

reg04_n = bs(l=4, cls=(mep_reg, ))

reg00 = bs(l=0, cls=(mep_reg, ))

reg00_sp = bs(l=0, cls=(mep_reg_sp, ))

reg00_tp = bs(l=0, cls=(mep_reg_tp, ))

reg00_deref_sp = bs(l=0, cls=(mep_deref_sp_offset, ))

reg00_deref_tp = bs(l=0, cls=(mep_deref_tp_offset, ))

reg03 = bs(l=3, cls=(mep_reg, ))

reg04_deref = bs(l=4, cls=(mep_deref_reg,))

reg04_deref_noarg = bs(l=4, fname="reg04_deref")

reg04_inc_deref = bs(l=4, cls=(mep_deref_inc_reg,))

copro_reg04 = bs(l=4, cls=(mep_copro_reg,))

copro_reg05 = bs(l=1, cls=(mep_copro_reg_split,))

copro_reg06 = bs(l=2, cls=(mep_copro_reg_split,))

disp2 = bs(l=2, cls=(mep_imm, ))

imm2 = disp2

imm3 = bs(l=3, cls=(mep_imm, ))

imm4 = bs(l=4, cls=(mep_imm, ))

imm4_noarg = bs(l=4, fname="imm4")

imm4_iiii_noarg = bs(l=4, fname="imm4_iiii")

imm5 = bs(l=5, cls=(mep_imm, ))

imm5_Iiiii = bs(l=1, cls=(mep_imm5_Iiiii, ))  # it is not an immediate, but a
                                              # control/special register.

imm6 = bs(l=6, cls=(mep_imm6, mep_arg))

imm6_noarg = bs(l=6, fname="imm6")

imm7 = bs(l=7, cls=(mep_imm, ))

imm7_noarg = bs(l=7, fname="imm7")  # Note:
                                    #   - will be decoded as a 7 bits immediate
                                    #   - fname is used to set the operand name
                                    #     used in mep_target24 to merge operands
                                    #     values. By default, the bs class fills
                                    #     fname with an hex string compute from
                                    #     arguments passed to __init__

imm7_align4 = bs(l=5, cls=(mep_imm7_align4,))

imm7_align4_noarg = bs(l=5, fname="imm7_align4")

disp7_align2 = bs(l=6, cls=(mep_disp7_align2,))

disp7_align2_noarg = bs(l=6, fname="disp7_align2")

imm8 = bs(l=8, cls=(mep_imm8, mep_arg))

imm8_noarg = bs(l=8, fname="imm8_CCCC_CCCC")

disp8 = bs(l=7, cls=(mep_disp8_align2, ))

imm8_align2 = bs(l=7, cls=(mep_disp8_align2, ))

imm8_align4 = bs(l=6, cls=(mep_disp8_align4, ))

imm8_align8 = bs(l=5, cls=(mep_imm8_align8, ))

imm12 = bs(l=12, cls=(mep_imm, ))

disp12_signed = bs(l=11, cls=(mep_disp12_align2_signed, ))

imm16 = bs(l=16, cls=(mep_imm16, mep_arg))
imm16_signed = bs(l=16, cls=(mep_imm16_signed, mep_arg))

disp16_reg_deref = bs(l=16, cls=(mep_deref_reg_offset,))

disp17 = bs(l=16, cls=(mep_disp17, ))

imm18 = bs(l=19, cls=(mep_imm, ))

imm_code20 = bs(l=16, cls=(mep_code20, ))

imm24 = bs(l=24, cls=(mep_imm24, ))

imm_target24 = bs(l=16, cls=(mep_target24, ))
imm_target24_signed = bs(l=16, cls=(mep_target24_signed, ))

imm_code24 = bs(l=16, cls=(mep_code24, ))

abs24 = bs(l=16, cls=(mep_abs24, ))


# MeP-c4 mnemonics objects

### <Major Opcode #0>

# MOV Rn,Rm - 0000_nnnn_mmmm_0000
addop("MOV", [bs("0000"), reg04, reg04, bs("0000")])

# NEG Rn,Rm - 0000_nnnn_mmmm_0001
addop("NEG", [bs("0000"), reg04, reg04, bs("0001")])

# SLT3 R0,Rn,Rm - 0000_nnnn_mmmm_0010
addop("SLT3", [bs("0000"), reg00, reg04, reg04, bs("0010")])

# SLTU3 R0,Rn,Rm - 0000_nnnn_mmmm_0011
addop("SLTU3", [bs("0000"), reg00, reg04, reg04, bs("0011")])

# SUB Rn,Rm - 0000_nnnn_mmmm_0100
addop("SUB", [bs("0000"), reg04, reg04, bs("0100")])

# SBVCK3 R0,Rn,Rm - 0000_nnnn_mmmm_0101
addop("SBVCK3", [bs("0000"), reg00, reg04, reg04, bs("0101")])

# (RI) - 0000_xxxx_xxxx_0110
addop("(RI)", [bs("0000"), reg04, reg04, bs("0110")])

# ADVCK3 R0,Rn,Rm - 0000_nnnn_mmmm_0111
addop("ADVCK3", [bs("0000"), reg00, reg04, reg04, bs("0111")])

# SB Rn,(Rm) - 0000_nnnn_mmmm_1000
addop("SB", [bs("0000"), reg04, reg04_deref, bs("1000")])

# SH Rn,(Rm) - 0000_nnnn_mmmm_1001
addop("SH", [bs("0000"), reg04, reg04_deref, bs("1001")])

# SW Rn,(Rm) - 0000_nnnn_mmmm_1010
addop("SW", [bs("0000"), reg04, reg04_deref, bs("1010")])

# LBU Rn,(Rm) - 0000_nnnn_mmmm_1011
addop("LBU", [bs("0000"), reg04, reg04_deref, bs("1011")])

# LB Rn,(Rm) - 0000_nnnn_mmmm_1100
addop("LB", [bs("0000"), reg04, reg04_deref, bs("1100")])

# LH Rn,(Rm) - 0000_nnnn_mmmm_1101
addop("LH", [bs("0000"), reg04, reg04_deref, bs("1101")])

# LW Rn,(Rm) - 0000_nnnn_mmmm_1110
addop("LW", [bs("0000"), reg04, reg04_deref, bs("1110")])

# LHU Rn,(Rm) - 0000_nnnn_mmmm_1111
addop("LHU", [bs("0000"), reg04, reg04_deref, bs("1111")])


### <Major Opcode #1>

# OR Rn,Rm - 0001_nnnn_mmmm_0000
addop("OR", [bs("0001"), reg04, reg04, bs("0000")])

# AND Rn,Rm - 0001_nnnn_mmmm_0001
addop("AND", [bs("0001"), reg04, reg04, bs("0001")])

# XOR Rn,Rm - 0001_nnnn_mmmm_0010
addop("XOR", [bs("0001"), reg04, reg04, bs("0010")])

# NOR Rn,Rm - 0001_nnnn_mmmm_0011
addop("NOR", [bs("0001"), reg04, reg04, bs("0011")])

# MUL Rn,Rm - 0001_nnnn_mmmm_0100
addop("MUL", [bs("0001"), reg04, reg04, bs("0100")])

# MULU Rn,Rm - 0001_nnnn_mmmm_0101
addop("MULU", [bs("0001"), reg04, reg04, bs("0101")])

# MULR Rn,Rm - 0001_nnnn_mmmm_0110
addop("MULR", [bs("0001"), reg04, reg04, bs("0110")])

# MULRU Rn,Rm - 0001_nnnn_mmmm_0111
addop("MULRU", [bs("0001"), reg04, reg04, bs("0111")])

# DIV Rn,Rm - 0001_nnnn_mmmm_1000
addop("DIV", [bs("0001"), reg04, reg04, bs("1000")])

# DIVU Rn,Rm - 0001_nnnn_mmmm_1001
addop("DIVU", [bs("0001"), reg04, reg04, bs("1001")])

# (RI) - 0001_xxxx_xxxx_1010
addop("(RI)", [bs("0001"), reg04, reg04, bs("1010")])

# (RI) - 0001_xxxx_xxxx_1011
addop("(RI)", [bs("0001"), reg04, reg04, bs("1011")])

# SSARB disp2(Rm) - 0001_00dd_mmmm_1100
addop("SSARB", [bs("000100"), disp2, reg04_deref, bs("1100")])

# EXTB Rn - 0001_nnnn_0000_1101
addop("EXTB", [bs("0001"), reg04, bs("00001101")])

# EXTH Rn - 0001_nnnn_0010_1101
addop("EXTH", [bs("0001"), reg04, bs("00101101")])

# EXTUB Rn - 0001_nnnn_1000_1101
addop("EXTUB", [bs("0001"), reg04, bs("10001101")])

# EXTUH Rn - 0001_nnnn_1010_1101
addop("EXTUH", [bs("0001"), reg04, bs("10101101")])

# JMP Rm - 0001_0000_mmmm_1110
addop("JMP", [bs("00010000"), reg04, bs("1110")])

# JSR Rm - 0001_0000_mmmm_1111
addop("JSR", [bs("00010000"), reg04, bs("1111")])

# JSRV Rm - 0001_1000_mmmm_1111
addop("JSRV", [bs("00011000"), reg04, bs("1111")])


### <Major Opcode #2>

# BSETM (Rm),imm3 - 0010_0iii_mmmm_0000
addop("BSETM", [bs("00100"), imm3, reg04_deref, bs("0000")], [reg04_deref, imm3])

# BCLRM (Rn),imm3 - 0010_0iii_mmmm_0001
addop("BCLRM", [bs("00100"), imm3, reg04_deref, bs("0001")], [reg04_deref, imm3])

# BNOTM (Rm),imm3 - 0010_0iii_mmmm_0010
addop("BNOTM", [bs("00100"), imm3, reg04_deref, bs("0010")], [reg04_deref, imm3])

# BTSTM R0,(Rm),imm3 - 0010_0iii_mmmm_0011
addop("BTSTM", [bs("00100"), reg00, imm3, reg04_deref, bs("0011")], [reg00, reg04_deref, imm3])

# TAS Rn,(Rm) - 0010_nnnn_mmmm_0100
addop("TAS", [bs("0010"), reg04, reg04_deref, bs("0100")])

# (RI) - 0010_xxxx_xxxx_0101
addop("(RI)", [bs("0010"), reg04, reg04, bs("0101")])

# SL1AD3 R0,Rn,Rm - 0010_nnnn_mmmm_0110
addop("SL1AD3", [bs("0010"), reg00, reg04, reg04, bs("0110")])

# SL2AD3 R0,Rn,Rm - 0010_nnnn_mmmm_0111
addop("SL2AD3", [bs("0010"), reg00, reg04, reg04, bs("0111")])

# (RI) - 0010_xxxx_xxxx_1000
addop("(RI)", [bs("0010"), reg04, reg04, bs("1000")])

# (RI) - 0010_xxxx_xxxx_1001
addop("(RI)", [bs("0010"), reg04, reg04, bs("1001")])

# (RI) - 0010_xxxx_xxxx_1010
addop("(RI)", [bs("0010"), reg04, reg04, bs("1010")])

# (RI) - 0010_xxxx_xxxx_1011
addop("(RI)", [bs("0010"), reg04, reg04, bs("1011")])

# SRL Rn,Rm - 0010_nnnn_mmmm_1100
addop("SRL", [bs("0010"), reg04, reg04, bs("1100")])

# SRA Rn,Rm - 0010_nnnn_mmmm_1101
addop("SRA", [bs("0010"), reg04, reg04, bs("1101")])

# SLL Rn,Rm - 0010_nnnn_mmmm_1110
addop("SLL", [bs("0010"), reg04, reg04, bs("1110")])

# FSFT Rn,Rm - 0010_nnnn_mmmm_1111
addop("FSFT", [bs("0010"), reg04, reg04, bs("1111")])


### <Major Opcode #3>

# SWCPI CRn,(Rm+) - 0011_nnnn_mmmm_0000
addop("SWCPI", [bs("0011"), copro_reg04, reg04_inc_deref, bs("0000")])

# LWCPI CRn,(Rm+) - 0011_nnnn_mmmm_0001
addop("LWCPI", [bs("0011"), copro_reg04, reg04_inc_deref, bs("0001")])

# SMCPI CRn,(Rm+) - 0011_nnnn_mmmm_0010
addop("SMCPI", [bs("0011"), copro_reg04, reg04_inc_deref, bs("0010")])

# LMCPI CRn,(Rm+) - 0011_nnnn_mmmm_0011
addop("LMCPI", [bs("0011"), copro_reg04, reg04_inc_deref, bs("0011")])

# SWCP CRn,(Rm) - 0011_nnnn_mmmm_1000
addop("SWCP", [bs("0011"), copro_reg04, reg04_deref, bs("1000")])

# LWCP CRn,(Rm) - 0011_nnnn_mmmm_1001
addop("LWCP", [bs("0011"), copro_reg04, reg04_deref, bs("1001")])

# SMCP CRn,(Rm) - 0011_nnnn_mmmm_1010
addop("SMCP", [bs("0011"), copro_reg04, reg04_deref, bs("1010")])

# LMCP CRn,(Rm) - 0011_nnnn_mmmm_1011
addop("LMCP", [bs("0011"), copro_reg04, reg04_deref, bs("1011")])


### <Major Opcode #4>

# ADD3 Rn,SP,imm7.align4 - 0100_nnnn_0iii_ii00
addop("ADD3", [bs("0100"), reg04, reg00_sp, bs("0"), imm7_align4, bs("00")])

# SW Rn,disp7.align4(SP) - 0100_nnnn_0ddd_dd10
# Note: disp7.align4 is the same as imm7.align4
addop("SW", [bs("0100"), reg04, bs("0"), imm7_align4_noarg, reg00_deref_sp, bs("10")])

# LW Rn,disp7.align4(SP) - 0100_nnnn_0ddd_dd11
addop("LW", [bs("0100"), reg04, bs("0"), imm7_align4_noarg, reg00_deref_sp, bs("11")])

# SW Rn[0-7],disp7.align4(TP) - 0100_0nnn_1ddd_dd10
addop("SW", [bs("01000"), reg03, bs("1"), imm7_align4_noarg, reg00_deref_tp, bs("10")])

# LW Rn[0-7],disp7.align4(TP) - 0100_0nnn_1ddd_dd11
addop("LW", [bs("01000"), reg03, bs("1"), imm7_align4_noarg, reg00_deref_tp, bs("11")])

# LBU Rn[0-7],disp7(TP) - 0100_1nnn_1ddd_dddd
addop("LBU", [bs("01001"), reg03, bs("1"), imm7_noarg, reg00_deref_tp], [reg03, reg00_deref_tp])

### <Major Opcode #5>

# MOV Rn,imm8 - 0101_nnnn_iiii_iiii
addop("MOV", [bs("0101"), reg04, imm8])


### <Major Opcode #6>

# ADD Rn,imm6 - 0110_nnnn_iiii_ii00
addop("ADD",  # mnemonic name
      [bs("0110"), reg04, imm6, bs("00")])  # mnemonic description

# SLT3 R0,Rn,imm5 - 0110_nnnn_iiii_i001
addop("SLT3", [bs("0110"), reg00, reg04, imm5, bs("001")])

# SRL Rn,imm5 - 0110_nnnn_iiii_i010
addop("SRL", [bs("0110"), reg04, imm5, bs("010")])

# SRA Rn,imm5 - 0110_nnnn_iiii_i011
addop("SRA", [bs("0110"), reg04, imm5, bs("011")])

# SLTU3 R0,Rn,imm5 - 0110_nnnn_iiii_i101
addop("SLTU3", [bs("0110"), reg00, reg04, imm5, bs("101")])

# SLL Rn,imm5 - 0110_nnnn_iiii_i110
addop("SLL", [bs("0110"), reg04, imm5, bs("110")])

# SLL3 R0,Rn,imm5 - 0110_nnnn_iiii_i111
addop("SLL3", [bs("0110"), reg00, reg04, imm5, bs("111")])


### <Major Opcode #7>

# DI - 0111_0000_0000_0000
addop("DI", [bs("0111000000000000")])

# EI - 0111_0000_0001_0000
addop("EI", [bs("0111000000010000")])

# SYNCM - 0111_0000_0001_0001
addop("SYNCM", [bs("0111000000010001")])

# SYNCCP - 0111_0000_0010_0001
addop("SYNCCP", [bs("0111000000100001")])

# RET - 0111_0000_0000_0010
addop("RET", [bs("0111000000000010")])

# RETI - 0111_0000_0001_0010
addop("RETI", [bs("0111000000010010")])

# HALT - 0111_0000_0010_0010
addop("HALT", [bs("0111000000100010")])

# BREAK - 0111_0000_0011_0010
addop("BREAK", [bs("0111000000110010")])

# SLEEP - 0111_0000_0110_0010
addop("SLEEP", [bs("0111000001100010")])

# DRET - 0111_0000_0001_0011
addop("DRET", [bs("0111000000010011")])

# DBREAK - 0111_0000_0011_0011
addop("DBREAK", [bs("0111000000110011")])

# CACHE imm4,(Rm) - 0111_iiii_mmmm_0100
addop("CACHE", [bs("0111"), imm4, reg04_deref, bs("0100")])

# (RI) - 0111_xxxx_xxxx_0101
addop("(RI)", [bs("0111"), reg04, reg04, bs("0101")])

# SWI imm2 - 0111_0000_00ii_0110
addop("SWI", [bs("0111000000"), imm2, bs("0110")])

# (RI) - 0111_xxxx_xxxx_0111
addop("(RI)", [bs("0111"), reg04, reg04, bs("0111")])

# STC Rn,imm5 - 0111_nnnn_iiii_100I
addop("STC", [bs("0111"), reg04, imm4_iiii_noarg, bs("100"), imm5_Iiiii])

# LDC Rn,imm5 - 0111_nnnn_iiii_101I
addop("LDC", [bs("0111"), reg04, imm4_iiii_noarg, bs("101"), imm5_Iiiii])

# (RI) - 0111_xxxx_xxxx_1100
addop("(RI)", [bs("0111"), reg04, reg04, bs("1100")])

# (RI) - 0111_xxxx_xxxx_1101
addop("(RI)", [bs("0111"), reg04, reg04, bs("1101")])

# (RI) - 0111_xxxx_xxxx_1110
addop("(RI)", [bs("0111"), reg04, reg04, bs("1110")])

# (RI) - 0111_xxxx_xxxx_1111
addop("(RI)", [bs("0111"), reg04, reg04, bs("1111")])


### <Major Opcode #8>

# SB Rn[0-7],disp7(TP) - 1000_0nnn_0ddd_dddd
addop("SB", [bs("10000"), reg03, bs("0"), imm7_noarg, reg00_deref_tp])

# SH Rn[0-7],disp7.align2(TP) - 1000_0nnn_1ddd_ddd0
# (disp7.align2 = ddd_ddd||0)
addop("SH", [bs("10000"), reg03, bs("1"), disp7_align2_noarg, bs("0"), reg00_deref_tp])

# LB Rn[0-7],disp7(TP) - 1000_1nnn_0ddd_dddd
addop("LB", [bs("10001"), reg03, bs("0"), imm7_noarg, reg00_deref_tp])

# LH Rn[0-7],disp7.align2(TP) - 1000_1nnn_1ddd_ddd0
addop("LH", [bs("10001"), reg03, bs("1"), disp7_align2_noarg, bs("0"), reg00_deref_tp])

# LHU Rn[0-7],disp7.align2(TP) - 1000_1nnn_1ddd_ddd1
addop("LHU", [bs("10001"), reg03, bs("1"), disp7_align2_noarg, bs("1"), reg00_deref_tp])


### <Major Opcode #9>

# ADD3 Rl,Rn,Rm - 1001_nnnn_mmmm_llll
addop("ADD3", [bs("1001"), reg04_n, reg04_m, reg04_l], [reg04_l, reg04_n, reg04_m])


### <Major Opcode #10>

# BEQZ Rn,disp8.align2 - 1010_nnnn_dddd_ddd0
# (disp8=dddd_ddd||0)
addop("BEQZ", [bs("1010"), reg04, disp8, bs("0")])

# BNEZ Rn,disp8.align2 - 1010_nnnn_dddd_ddd1
addop("BNEZ", [bs("1010"), reg04, disp8, bs("1")])


### <Major Opcode #11>

# BRA disp12.align2 - 1011_dddd_dddd_ddd0
# (disp12=dddd_dddd_ddd||0)
addop("BRA", [bs("1011"), disp12_signed, bs("0")])

# BSR disp12.align2 - 1011_dddd_dddd_ddd1
addop("BSR", [bs("1011"), disp12_signed, bs("1")])


### <Major Opcode #12>

# ADD3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0000 iiii_iiii_iiii_iiii
addop("ADD3", [bs("1100"), reg04, reg04, bs("0000"), imm16_signed])

# MOV Rn,imm16 - 1100_nnnn_0000_0001 iiii_iiii_iiii_iiii
addop("MOV", [bs("1100"), reg04, bs("00000001"), imm16])

# MOVU Rn,imm16 - 1100_nnnn_0001_0001 iiii_iiii_iiii_iiii
addop("MOVU", [bs("1100"), reg04, bs("00010001"), imm16])

# MOVH Rn,imm16 - 1100_nnnn_0010_0001 iiii_iiii_iiii_iiii
addop("MOVH", [bs("1100"), reg04, bs("00100001"), imm16])

# SLT3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0010 iiii_iiii_iiii_iiii
addop("SLT3", [bs("1100"), reg04, reg04, bs("0010"), imm16_signed])

# SLTU3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0011 iiii_iiii_iiii_iiii
addop("SLTU3", [bs("1100"), reg04, reg04, bs("0011"), imm16])

# OR3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0100 iiii_iiii_iiii_iiii
addop("OR3", [bs("1100"), reg04, reg04, bs("0100"), imm16])

# AND3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0101 iiii_iiii_iiii_iiii
addop("AND3", [bs("1100"), reg04, reg04, bs("0101"), imm16])

# XOR3 Rn,Rm,imm16 - 1100_nnnn_mmmm_0110 iiii_iiii_iiii_iiii
addop("XOR3", [bs("1100"), reg04, reg04, bs("0110"), imm16])

# (RI) - 1100_xxxx_xxxx_0111 xxxx_xxxx_xxxx_xxxx
addop("(RI)", [bs("1100"), imm8, bs("0111"), imm16])

# SB Rn,disp16(Rm) - 1100_nnnn_mmmm_1000 dddd_dddd_dddd_dddd
addop("SB", [bs("1100"), reg04, reg04_deref_noarg, bs("1000"), disp16_reg_deref], [reg04, disp16_reg_deref])

# SH Rn,disp16(Rm) - 1100_nnnn_mmmm_1001 dddd_dddd_dddd_dddd
addop("SH", [bs("1100"), reg04, reg04_deref_noarg, bs("1001"), disp16_reg_deref], [reg04, disp16_reg_deref])

# SW Rn,disp16(Rm) - 1100_nnnn_mmmm_1010 dddd_dddd_dddd_dddd
addop("SW", [bs("1100"), reg04, reg04_deref_noarg, bs("1010"), disp16_reg_deref], [reg04, disp16_reg_deref])

# LBU Rn,disp16(Rm) - 1100_nnnn_mmmm_1011 dddd_dddd_dddd_dddd
addop("LBU", [bs("1100"), reg04, reg04_deref_noarg, bs("1011"), disp16_reg_deref], [reg04, disp16_reg_deref])

# LB Rn,disp16(Rm) - 1100_nnnn_mmmm_1100 dddd_dddd_dddd_dddd
addop("LB", [bs("1100"), reg04, reg04_deref_noarg, bs("1100"), disp16_reg_deref], [reg04, disp16_reg_deref])

# LH Rn,disp16(Rm) - 1100_nnnn_mmmm_1101 dddd_dddd_dddd_dddd
addop("LH", [bs("1100"), reg04, reg04_deref_noarg, bs("1101"), disp16_reg_deref], [reg04, disp16_reg_deref])

# LW Rn,disp16(Rm) - 1100_nnnn_mmmm_1110 dddd_dddd_dddd_dddd
addop("LW", [bs("1100"), reg04, reg04_deref_noarg, bs("1110"), disp16_reg_deref], [reg04, disp16_reg_deref])

# LHU Rn,disp16(Rm) - 1100_nnnn_mmmm_1111 dddd_dddd_dddd_dddd
addop("LHU", [bs("1100"), reg04, reg04_deref_noarg, bs("1111"), disp16_reg_deref], [reg04, disp16_reg_deref])


### <Major Opcode #13>

# MOVU Rn[0-7],imm24 - 1101_0nnn_IIII_IIII iiii_iiii_iiii_iiii
addop("MOVU", [bs("11010"), reg03, imm24])

# BCPEQ cccc,disp17 - 1101_1000_cccc_0100 dddd_dddd_dddd_dddd
addop("BCPEQ", [bs("11011000"), imm4, bs("0100"), disp17])

# BCPNE cccc,disp17 - 1101_1000_cccc_0101 dddd_dddd_dddd_dddd
addop("BCPNE", [bs("11011000"), imm4, bs("0101"), disp17])

# BCPAT cccc,disp17 - 1101_1000_cccc_0110 dddd_dddd_dddd_dddd
addop("BCPAT", [bs("11011000"), imm4, bs("0110"), disp17])

# BCPAF cccc,disp17 - 1101_1000_cccc_0111 dddd_dddd_dddd_dddd
addop("BCPAF", [bs("11011000"), imm4, bs("0111"), disp17])

# JMP target24 - 1101_1TTT_TTTT_1000 tttt_tttt_tttt_tttt
addop("JMP", [bs("11011"), imm7_noarg, bs("1000"), imm_target24],
      [imm_target24])  # the only interesting operand is imm_target24

# BSR disp24 - 1101_1DDD_DDDD_1001 dddd_dddd_dddd_dddd
addop("BSR", [bs("11011"), imm7_noarg, bs("1001"), imm_target24_signed], [imm_target24_signed])

# BSRV disp24 1101_1DDD_DDDD_1011 dddd_dddd_dddd_dddd
addop("BSRV", [bs("11011"), imm7_noarg, bs("1011"), imm_target24], [imm_target24])


### <Major Opcode #14>

# BEQI Rn,imm4,disp17 - 1110_nnnn_iiii_0000 dddd_dddd_dddd_dddd
addop("BEQI", [bs("1110"), reg04, imm4, bs("0000"), disp17])

# BEQ Rn,Rm,disp17 - 1110_nnnn_mmmm_0001 dddd_dddd_dddd_dddd
addop("BEQ", [bs("1110"), reg04, reg04, bs("0001"), disp17])

# BNEI Rn,imm4,disp17 - 1110_nnnn_iiii_0100 dddd_dddd_dddd_dddd
addop("BNEI", [bs("1110"), reg04, imm4, bs("0100"), disp17])

# BNE Rn,Rm,disp17 - 1110_nnnn_mmmm_0101 dddd_dddd_dddd_dddd
addop("BNE", [bs("1110"), reg04, reg04, bs("0101"), disp17])

# BGEI Rn,imm4,disp17 - 1110_nnnn_iiii_1000 dddd_dddd_dddd_dddd
addop("BGEI", [bs("1110"), reg04, imm4, bs("1000"), disp17])

# REPEAT Rn,disp17 - 1110_nnnn_0000_1001 dddd_dddd_dddd_dddd
addop("REPEAT", [bs("1110"), reg04, bs("00001001"), disp17])

# EREPEAT disp17 - 1110_0000_0001_1001 dddd_dddd_dddd_dddd
addop("EREPEAT", [bs("1110000000011001"), disp17])

# BLTI Rn,imm4,disp17 - 1110_nnnn_iiii_1100 dddd_dddd_dddd_dddd
addop("BLTI", [bs("1110"), reg04, imm4, bs("1100"), disp17])

# (RI) - 1110_xxxx_xxxx_1101 xxxx_xxxx_xxxx_xxxx
addop("(RI)", [bs("1110"), imm8, bs("1101"), imm16])

# SW Rn,(abs24) - 1110_nnnn_DDDD_DD10 dddd_dddd_dddd_dddd
addop("SW", [bs("1110"), reg04, imm6_noarg, bs("10"), abs24])

# LW Rn,(abs24) - 1110_nnnn_DDDD_DD11 dddd_dddd_dddd_dddd
addop("LW", [bs("1110"), reg04, imm6_noarg, bs("11"), abs24])


### <Major Opcode #15>

# DSP Rn,Rm,code16 - 1111_nnnn_mmmm_0000 cccc_cccc_cccc_cccc
addop("DSP", [bs("1111"), reg04, reg04, bs("0000"), imm16])

# Note: DSP, DSP0 & DSP1 look exactly the same. This is ambiguous, and prevent
#       them for being correctly disassembled. DSP0 & DSP1 are arbitrarily
#       disabled.

# DSP0 code24 - 1111_nnnn_mmmm_0000 cccc_cccc_cccc_cccc
#addop("DSP0", [bs("1111"), imm8_noarg, bs("0000"), imm_code24], [imm_code24])

# DSP1 Rn,code20 - 1111_nnnn_mmmm_0000 cccc_cccc_cccc_cccc
#addop("DSP1", [bs("1111"), reg04, imm4_noarg, bs("0000"), imm_code20])

# LDZ Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0000
addop("LDZ", [bs("1111"), reg04, reg04, bs("00010000000000000000")])

# AVE Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0010
addop("AVE", [bs("1111"), reg04, reg04, bs("00010000000000000010")])

# ABS Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0011
addop("ABS", [bs("1111"), reg04, reg04, bs("00010000000000000011")])

# MIN Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0100
addop("MIN", [bs("1111"), reg04, reg04, bs("00010000000000000100")])

# MAX Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0101
addop("MAX", [bs("1111"), reg04, reg04, bs("00010000000000000101")])

# MINU Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0110
addop("MINU", [bs("1111"), reg04, reg04, bs("00010000000000000110")])

# MAXU Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_0111
addop("MAXU", [bs("1111"), reg04, reg04, bs("00010000000000000111")])

# SADD Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_1000
addop("SADD", [bs("1111"), reg04, reg04, bs("00010000000000001000")])

# SADDU Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_1001
addop("SADDU", [bs("1111"), reg04, reg04, bs("00010000000000001001")])

# SSUB Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_1010
addop("SSUB", [bs("1111"), reg04, reg04, bs("00010000000000001010")])

# SSUBU Rn,Rm - 1111_nnnn_mmmm_0001 0000_0000_0000_1011
addop("SSUBU", [bs("1111"), reg04, reg04, bs("00010000000000001011")])

# CLIP Rn,imm5 - 1111_nnnn_0000_0001 0001_0000_iiii_i000
addop("CLIP", [bs("1111"), reg04, bs("0000000100010000"), imm5, bs("000")])

# CLIPU Rn,imm5 - 1111_nnnn_0000_0001 0001_0000_iiii_i001
addop("CLIPU", [bs("1111"), reg04, bs("0000000100010000"), imm5, bs("001")])

# (RI) - 1111_xxxx_xxxx_0001 0010_xxxx_xxxx_xxxx
addop("(RI)", [bs("1111"), imm8, bs("00010010"), imm12])

# MADD Rn,Rm - 1111_nnnn_mmmm_0001 0011_0000_0000_0100
addop("MADD", [bs("1111"), reg04, reg04, bs("00010011000000000100")])

# MADDU Rn,Rm - 1111_nnnn_mmmm_0001 0011_0000_0000_0101
addop("MADDU", [bs("1111"), reg04, reg04, bs("00010011000000000101")])

# MADDR Rn,Rm - 1111_nnnn_mmmm_0001 0011_0000_0000_0110
addop("MADDR", [bs("1111"), reg04, reg04, bs("00010011000000000110")])

# MADDRU Rn,Rm - 1111_nnnn_mmmm_0001 0011_0000_0000_0111
addop("MADDRU", [bs("1111"), reg04, reg04, bs("00010011000000000111")])

# UCI Rn,Rm,code16 - 1111_nnnn_mmmm_0010 cccc_cccc_cccc_cccc
addop("UCI", [bs("1111"), reg04, reg04, bs("0010"), imm16])

# (RI) - 1111_xxxx_xxxx_0011 xxxx_xxxx_xxxx_xxxx
addop("(RI)", [bs("1111"), imm8, bs("0011"), imm16])

# STCB Rn,abs16 - 1111_nnnn_0000_0100 aaaa_aaaa_aaaa_aaaa
addop("STCB", [bs("1111"), reg04, bs("00000100"), imm16])

# LDCB Rn,abs16 - 1111_nnnn_0001_0100 aaaa_aaaa_aaaa_aaaa
addop("LDCB", [bs("1111"), reg04, bs("00010100"), imm16])

# SBCPA CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0000_0000_iiii_iiii
addop("SBCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100000000"), imm8])

# SHCPA CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0001_0000_iiii_iii0
addop("SHCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100010000"), imm8_align2, bs("0")])

# SWCPA CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0010_0000_iiii_ii00
addop("SWCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100100000"), imm8_align4, bs("00")])

# SMCPA CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0011_0000_iiii_i000
addop("SMCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100110000"), imm8_align8, bs("000")])

# LBCPA CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0100_0000_iiii_iiii
addop("LBCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101000000"), imm8])

# LHCPA CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0101_0000_iiii_iii0
addop("LHCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101010000"), imm8_align2, bs("0")])

# LWCPA CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0110_0000_iiii_ii00
addop("LWCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101100000"), imm8_align4, bs("00")])

# LMCPA CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0111_0000_iiii_i000
addop("LMCPA", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101110000"), imm8_align8, bs("000")])

# SBCPM0 CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0000_1000_iiii_iiii
addop("SBCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100001000"), imm8])

# SHCPM0 CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0001_1000_iiii_iii0
addop("SHCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100011000"), imm8_align2, bs("0")])

# SWCPM0 CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0010_1000_iiii_ii00
addop("SWCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100101000"), imm8_align4, bs("00")])

# SMCPM0 CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0011_1000_iiii_i000
addop("SMCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100111000"), imm8_align8, bs("000")])

# LBCPM0 CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0100_1000_iiii_iiii
addop("LBCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101001000"), imm8])

# LHCPM0 CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0101_1000_iiii_iii0
addop("LHCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101011000"), imm8_align2, bs("0")])

# LWCPM0 CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0110_1000_iiii_ii00
addop("LWCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101101000"), imm8_align4, bs("00")])

# LMCPM0 CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0111_1000_iiii_i000
addop("LMCPM0", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101111000"), imm8_align8, bs("000")])

# SBCPM1 CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0000_1100_iiii_iiii
addop("SBCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100001100"), imm8])

# SHCPM1 CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0001_1100_iiii_iii0
addop("SHCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100011100"), imm8_align2, bs("0")])

# SWCPM1 CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0010_1100_iiii_ii00
addop("SWCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100101100"), imm8_align4, bs("00")])

# SMCPM1 CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0011_1100_iiii_i000
addop("SMCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010100111100"), imm8_align8, bs("000")])

# LBCPM1 CRn,(Rm+),imm8 - 1111_nnnn_mmmm_0101 0100_1100_iiii_iiii
addop("LBCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101001100"), imm8])

# LHCPM1 CRn,(Rm+),imm8.align2 - 1111_nnnn_mmmm_0101 0101_1100_iiii_iii0
addop("LHCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101011100"), imm8_align2, bs("0")])

# LWCPM1 CRn,(Rm+),imm8.align4 - 1111_nnnn_mmmm_0101 0110_1100_iiii_ii00
addop("LWCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101101100"), imm8_align4, bs("00")])

# LMCPM1 CRn,(Rm+),imm8.align8 - 1111_nnnn_mmmm_0101 0111_1100_iiii_i000
addop("LMCPM1", [bs("1111"), copro_reg04, reg04_inc_deref, bs("010101111100"), imm8_align8, bs("000")])

# (RI) - 1111_xxxx_xxxx_0110 xxxx_xxxx_xxxx_xxxx
addop("(RI)", [bs("1111"), imm8, bs("0110"), imm16])

# CP code24 - 1111_CCCC_CCCC_0111 cccc_cccc_cccc_cccc
#addop("CP", [bs("1111"), imm8_noarg, bs("0111"), imm_code24], [imm_code24])
# Note: CP & CMOV* look exactly the same. This is ambiguous, and prevent
#       them for being correctly disassembled. CP was arbitrarily disabled.

# CP code56 - 1111_CCCC_CCCC_0111 cccc_cccc_cccc_cccc cccc_cccc_cccc_cccc
# 64-bit VLIW operation mode - not implemented

# CMOV CRn,Rm - 1111_nnnn_mmmm_0111 1111_0000_0000_0000
#addop("CMOV", [bs("1111"), copro_reg04, reg04, bs("01111111000000000000")])

# CMOV Rm,CRn - 1111_nnnn_mmmm_0111 1111_0000_0000_0001
#addop("CMOV", [bs("1111"), copro_reg04, reg04, bs("01111111000000000001")], [reg04, copro_reg04])

# CMOVC CCRn,Rm - 1111_nnnn_mmmm_0111 1111_0000_0000_NN10
# CRn=NNnnnn
addop("CMOVC", [bs("1111"), imm4_noarg, reg04, bs("0111111100000000"), copro_reg06, bs("10")], [copro_reg06, reg04])

# CMOVC Rm,CCRn - 1111_nnnn_mmmm_0111 1111_0000_0000_NN11
# CRn=NNnnnn
addop("CMOVC", [bs("1111"), imm4_noarg, reg04, bs("0111111100000000"), copro_reg06, bs("11")], [reg04, copro_reg06])

# CMOVH CRn,Rm - 1111_nnnn_mmmm_0111 1111_0001_0000_0000
#addop("CMOVH", [bs("1111"), copro_reg04, reg04, bs("01111111000100000000")])

# CMOVH Rm,CRn - 1111_nnnn_mmmm_0111 1111_0001_0000_0001
#addop("CMOVH", [bs("1111"), copro_reg04, reg04, bs("01111111000100000001")], [reg04, copro_reg04])

# Note: the following CMOV* instructions are extensions used when the processor
#       has more than 16 coprocessor general-purpose registers. They can be
#       used to assemble and disassemble both CMOV* instructuons sets.

# CMOV CRn,Rm - 1111_nnnn_mmmm_0111 1111_0000_0000_N000
# CRn=Nnnnn
addop("CMOV", [bs("1111"), imm4_noarg, reg04, bs("0111111100000000"), copro_reg05, bs("000")], [copro_reg05, reg04])

# CMOV Rm,CRn - 1111_nnnn_mmmm_0111 1111_0000_0000_N001
addop("CMOV", [bs("1111"), imm4_noarg, reg04, bs("0111111100000000"), copro_reg05, bs("001")], [reg04, copro_reg05])

# CMOVH CRn,Rm - 1111_nnnn_mmmm_0111 1111_0001_0000_N000
addop("CMOVH", [bs("1111"), imm4_noarg, reg04, bs("0111111100010000"), copro_reg05, bs("000")], [copro_reg05, reg04])

# CMOVH Rm,CRn - 1111_nnnn_mmmm_0111 1111_0001_0000_N001
addop("CMOVH", [bs("1111"), imm4_noarg, reg04, bs("0111111100010000"), copro_reg05, bs("001")], [reg04, copro_reg05])

# (RI) - 1111_xxxx_xxxx_10xx xxxx_xxxx_xxxx_xxxx
addop("(RI)", [bs("1111"), imm8, bs("10"), imm18])

# SWCP CRn,disp16(Rm) - 1111_nnnn_mmmm_1100 dddd_dddd_dddd_dddd
addop("SWCP", [bs("1111"), copro_reg04, reg04_deref_noarg, bs("1100"), disp16_reg_deref], [copro_reg04, disp16_reg_deref])

# LWCP CRn,disp16(Rm) - 1111_nnnn_mmmm_1101 dddd_dddd_dddd_dddd
addop("LWCP", [bs("1111"), copro_reg04, reg04_deref_noarg, bs("1101"), disp16_reg_deref], [copro_reg04, disp16_reg_deref, reg04_deref])

# SMCP CRn,disp16(Rm) - 1111_nnnn_mmmm_1110 dddd_dddd_dddd_dddd
addop("SMCP", [bs("1111"), copro_reg04, reg04_deref_noarg, bs("1110"), disp16_reg_deref], [copro_reg04, disp16_reg_deref, reg04_deref])

# LMCP CRn,disp16(Rm) - 1111_nnnn_mmmm_1111 dddd_dddd_dddd_dddd
addop("LMCP", [bs("1111"), copro_reg04, reg04_deref_noarg, bs("1111"), disp16_reg_deref], [copro_reg04, disp16_reg_deref])
