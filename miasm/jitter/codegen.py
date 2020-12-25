"""
Module to generate C code for a given native @block
"""

from builtins import zip
import warnings

from future.utils import viewitems, viewvalues

from miasm.expression.expression import ExprId, ExprLoc, ExprInt, \
    ExprMem, ExprCond, LocKey, is_expr
from miasm.ir.ir import IRBlock, AssignBlock

from miasm.ir.translators.C import TranslatorC
from miasm.core.asmblock import AsmBlockBad
from miasm.expression.simplifications import expr_simp_high_to_explicit

TRANSLATOR_NO_SYMBOL = TranslatorC(loc_db=None)

SIZE_TO_MASK = {size: TRANSLATOR_NO_SYMBOL.from_expr(ExprInt(0, size).mask)
                for size in (1, 2, 3, 7, 8, 16, 32, 64)}






class Attributes(object):

    """
    Store an irblock attributes
    """

    def __init__(self, log_mn=False, log_regs=False):
        self.mem_read = False
        self.mem_write = False
        self.set_exception = False
        self.log_mn = log_mn
        self.log_regs = log_regs
        self.instr = None


class CGen(object):
    """
    Helper to generate C code for a given AsmBlock
    """

    """
    Translate native assembly block to C
    """

    CODE_EXCEPTION_MEM_AT_INSTR = r"""
    // except fetch mem at instr noauto
    if ((VM_exception_flag & ~EXCEPT_CODE_AUTOMOD) & EXCEPT_DO_NOT_UPDATE_PC) {
        %s = %s;
        BlockDst->address = %s;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_EXCEPTION_AT_INSTR = r"""
    if (CPU_exception_flag_at_instr) {
        %s = %s;
        BlockDst->address = %s;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_RETURN_EXCEPTION = r"""
    return JIT_RET_EXCEPTION;
    """

    CODE_RETURN_NO_EXCEPTION = r"""
    %s:
    %s = %s;
    BlockDst->address = %s;
    return JIT_RET_NO_EXCEPTION;
    """

    CODE_CPU_EXCEPTION_POST_INSTR = r"""
    if (CPU_exception_flag) {
        %s = DST_value;
        BlockDst->address = DST_value;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_VM_EXCEPTION_POST_INSTR = r"""
    check_memory_breakpoint(&(jitcpu->pyvm->vm_mngr));
    check_invalid_code_blocs(&(jitcpu->pyvm->vm_mngr));
    if (VM_exception_flag) {
        %s = DST_value;
        BlockDst->address = DST_value;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_INIT = r"""
    int DST_case;
    uint64_t DST_value;
    struct vm_cpu *mycpu = jitcpu->cpu;

    goto %s;
    """

    CODE_BAD_BLOCK = r"""
    // Unknown mnemonic
    CPU_exception_flag = EXCEPT_UNK_MNEMO;
    """ + CODE_RETURN_EXCEPTION

    def __init__(self, lifter):
        self.lifter = lifter
        self.PC = self.lifter.pc
        self.translator = TranslatorC(self.lifter.loc_db)
        self.init_arch_C()

    @property
    def ir_arch(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir_arch"')
        return self.lifter

    def init_arch_C(self):
        """Iinitialize jitter internals"""
        self.id_to_c_id = {}
        for reg in self.lifter.arch.regs.all_regs_ids:
            self.id_to_c_id[reg] = ExprId('mycpu->%s' % reg, reg.size)

        self.C_PC = self.id_to_c(self.PC)

    def dst_to_c(self, src):
        """Translate Expr @src into C code"""
        if not is_expr(src):
            src = ExprInt(src, self.PC.size)
        return self.id_to_c(src)

    def patch_c_id(self, expr):
        """Replace ExprId in @expr with corresponding C variables"""
        return expr.replace_expr(self.id_to_c_id)

    def id_to_c(self, expr):
        """Translate Expr @expr into corresponding C code"""
        return self.translator.from_expr(self.patch_c_id(expr))

    def add_label_index(self, dst2index, loc_key):
        """Insert @lbl to the dictionary @dst2index with a uniq value
        @dst2index: LocKey -> uniq value
        @loc_key: LocKey instance"""

        if loc_key not in dst2index:
            dst2index[loc_key] = len(dst2index)

    def assignblk_to_irbloc(self, instr, assignblk):
        """
        Ensure IRDst is always set in the head @assignblk of the @instr
        @instr: an instruction instance
        @assignblk: Assignblk instance
        """
        new_assignblk = dict(assignblk)
        if self.lifter.IRDst not in assignblk:
            offset = instr.offset + instr.l
            loc_key = self.lifter.loc_db.get_or_create_offset_location(offset)
            dst = ExprLoc(loc_key, self.lifter.IRDst.size)
            new_assignblk[self.lifter.IRDst] = dst
        irs = [AssignBlock(new_assignblk, instr)]
        return IRBlock(self.lifter.loc_db, self.lifter.get_loc_key_for_instr(instr), irs)

    def block2assignblks(self, block):
        """
        Return the list of irblocks for a native @block
        @block: AsmBlock
        """
        irblocks_list = []
        for instr in block.lines:
            assignblk_head, assignblks_extra = self.lifter.instr2ir(instr)
            # Keep result in ordered list as first element is the assignblk head
            # The remainings order is not really important
            irblock_head = self.assignblk_to_irbloc(instr, assignblk_head)
            irblocks = [irblock_head] + assignblks_extra

            # Simplify high level operators
            out = []
            for irblock in irblocks:
                new_irblock = self.lifter.irbloc_fix_regs_for_mode(irblock, self.lifter.attrib)
                new_irblock = new_irblock.simplify(expr_simp_high_to_explicit)[1]
                out.append(new_irblock)
            irblocks = out

            for irblock in irblocks:
                assert irblock.dst is not None
            irblocks_list.append(irblocks)

        return irblocks_list

    def add_local_var(self, dst_var, dst_index, expr):
        """
        Add local variable used to store temporary result
        @dst_var: dictionary of Expr -> local_var_expr
        @dst_index : dictionary of size -> local var count
        @expr: Expression source
        """
        size = expr.size
        if size < 8:
            size = 8
        if size not in dst_index:
            raise RuntimeError("Unsupported operand size %s", size)
        var_num = dst_index[size]
        dst = ExprId("var_%.2d_%.2d" % (size, var_num), size)
        dst_index[size] += 1
        dst_var[expr] = dst
        return dst

    def get_mem_prefetch(self, assignblk):
        """
        Generate temporary variables used to fetch memory used in the @assignblk
        Return a dictionary: ExprMem -> temporary variable
        @assignblk: AssignBlock instance
        """
        mem_index = {8: 0, 16: 0, 32: 0, 64: 0, 128:0}
        mem_var = {}

        # Prefetch memory read
        for expr in assignblk.get_r(mem_read=True):
            if not isinstance(expr, ExprMem):
                continue
            var_num = mem_index[expr.size]
            mem_index[expr.size] += 1
            var = ExprId(
                "prefetch_%.2d_%.2d" % (expr.size, var_num), expr.size
            )
            mem_var[expr] = var

        # Generate memory prefetch
        return mem_var

    def gen_c_assignments(self, assignblk):
        """
        Return C information used to generate the C code of the @assignblk
        @assignblk: an AssignBlock instance
        """
        c_var = []
        c_main = []
        c_mem = []
        c_updt = []
        c_prefetch = []

        dst_index = {8: 0, 16: 0, 32: 0, 64: 0, 128:0}
        dst_var = {}

        prefetchers = self.get_mem_prefetch(assignblk)

        for expr, prefetcher in viewitems(prefetchers):
            str_src = self.id_to_c(expr)
            str_dst = self.id_to_c(prefetcher)
            c_prefetch.append('%s = %s;' % (str_dst, str_src))

        for var in viewvalues(prefetchers):
            if var.size <= self.translator.NATIVE_INT_MAX_SIZE:
                c_var.append("uint%d_t %s;" % (var.size, var))
            else:
                c_var.append("bn_t %s; // %d" % (var, var.size))

        for dst, src in viewitems(assignblk):
            src = src.replace_expr(prefetchers)
            if dst == self.lifter.IRDst:
                pass
            elif isinstance(dst, ExprId):
                new_dst = self.add_local_var(dst_var, dst_index, dst)
                if dst in self.lifter.arch.regs.regs_flt_expr:
                    # Don't mask float assignment
                    c_main.append(
                        '%s = (%s);' % (self.id_to_c(new_dst), self.id_to_c(src)))
                elif new_dst.size <= self.translator.NATIVE_INT_MAX_SIZE:
                    c_main.append(
                        '%s = (%s)&%s;' % (self.id_to_c(new_dst),
                                           self.id_to_c(src),
                                           SIZE_TO_MASK[src.size]))
                else:
                    c_main.append(
                        '%s = bignum_mask(%s, %d);' % (
                            self.id_to_c(new_dst),
                            self.id_to_c(src),
                            src.size
                        )
                    )
            elif isinstance(dst, ExprMem):
                ptr = dst.ptr.replace_expr(prefetchers)
                if ptr.size <= self.translator.NATIVE_INT_MAX_SIZE:
                    new_dst = ExprMem(ptr, dst.size)
                    str_dst = self.id_to_c(new_dst).replace('MEM_LOOKUP', 'MEM_WRITE')
                    c_mem.append('%s, %s);' % (str_dst[:-1], self.id_to_c(src)))
                else:
                    ptr_str = self.id_to_c(ptr)
                    if ptr.size <= self.translator.NATIVE_INT_MAX_SIZE:
                        c_mem.append('%s, %s);' % (str_dst[:-1], self.id_to_c(src)))
                    else:
                        if src.size <= self.translator.NATIVE_INT_MAX_SIZE:
                            c_mem.append('MEM_WRITE_BN_INT(jitcpu, %d, %s, %s);' % (
                                src.size, ptr_str, self.id_to_c(src))
                            )
                        else:
                            c_mem.append('MEM_WRITE_BN_BN(jitcpu, %d, %s, %s);' % (
                                src.size, ptr_str, self.id_to_c(src))
                            )
            else:
                raise ValueError("Unknown dst")

        for dst, new_dst in viewitems(dst_var):
            if dst == self.lifter.IRDst:
                continue

            c_updt.append('%s = %s;' % (self.id_to_c(dst), self.id_to_c(new_dst)))
            if dst.size <= self.translator.NATIVE_INT_MAX_SIZE:
                c_var.append("uint%d_t %s;" % (new_dst.size, new_dst))
            else:
                c_var.append("bn_t %s; // %d" % (new_dst, new_dst.size))

        return c_prefetch, c_var, c_main, c_mem, c_updt

    def gen_check_memory_exception(self, address):
        """Generate C code to check memory exceptions
        @address: address of the faulty instruction"""
        dst = self.dst_to_c(address)
        return (self.CODE_EXCEPTION_MEM_AT_INSTR % (self.C_PC, dst, dst)).split('\n')

    def gen_check_cpu_exception(self, address):
        """Generate C code to check cpu exceptions
        @address: address of the faulty instruction"""
        dst = self.dst_to_c(address)
        return (self.CODE_EXCEPTION_AT_INSTR % (self.C_PC, dst, dst)).split('\n')

    def traverse_expr_dst(self, expr, dst2index):
        """
        Generate the index of the destination label for the @expr
        @dst2index: dictionary to link label to its index
        """

        if isinstance(expr, ExprCond):
            src1, src1b = self.traverse_expr_dst(expr.src1, dst2index)
            src2, src2b = self.traverse_expr_dst(expr.src2, dst2index)
            cond = self.id_to_c(expr.cond)
            if not expr.cond.size <= self.translator.NATIVE_INT_MAX_SIZE:
                cond = "(!bignum_is_zero(%s))" % cond

            return ("((%s)?(%s):(%s))" % (cond, src1, src2),
                    "((%s)?(%s):(%s))" % (cond, src1b, src2b))
        if isinstance(expr, ExprInt):
            offset = int(expr)
            loc_key = self.lifter.loc_db.get_or_create_offset_location(offset)
            self.add_label_index(dst2index, loc_key)
            out = hex(offset)
            return ("%s" % dst2index[loc_key], out)
        if expr.is_loc():
            loc_key = expr.loc_key
            offset = self.lifter.loc_db.get_location_offset(expr.loc_key)
            if offset is not None:
                self.add_label_index(dst2index, loc_key)
                out = hex(offset)
                return ("%s" % dst2index[loc_key], out)
            self.add_label_index(dst2index, loc_key)
            out = hex(0)
            return ("%s" % dst2index[loc_key], out)
        dst2index[expr] = -1
        return ("-1", self.id_to_c(expr))

    def gen_assignblk_dst(self, dst):
        """Generate C code to handle instruction destination
        @dst: instruction destination Expr"""
        dst2index = {}
        (ret, retb) = self.traverse_expr_dst(dst, dst2index)
        ret = "DST_case = %s;" % ret
        retb = 'DST_value = %s;' % retb
        return ['// %s' % dst2index,
                '%s' % ret,
                '%s' % retb], dst2index

    def gen_post_instr_checks(self, attrib):
        """Generate C code for handling potential exceptions
        @attrib: Attributes instance"""
        out = []
        if attrib.mem_read | attrib.mem_write:
            out += (self.CODE_VM_EXCEPTION_POST_INSTR % (self.C_PC)).split('\n')
        if attrib.set_exception:
            out += (self.CODE_CPU_EXCEPTION_POST_INSTR % (self.C_PC)).split('\n')

        if attrib.mem_read | attrib.mem_write:
            out.append("reset_memory_access(&(jitcpu->pyvm->vm_mngr));")

        return out

    def gen_pre_code(self, instr_attrib):
        """Callback to generate code BEFORE the instruction execution
        @instr_attrib: Attributes instance"""

        out = []

        if instr_attrib.log_mn:
            out.append(
                'printf("%.8X %s\\n");' % (
                    instr_attrib.instr.offset,
                    instr_attrib.instr.to_string(self.lifter.loc_db)
                )
            )
        return out

    def gen_post_code(self, attrib, pc_value):
        """Callback to generate code AFTER the instruction execution
        @attrib: Attributes instance"""
        out = []
        if attrib.log_regs:
            # Update PC for dump_gpregs
            out.append("%s = %s;" % (self.C_PC, pc_value))
            out.append('dump_gpregs(jitcpu->cpu);')
        return out

    def gen_goto_code(self, attrib, instr_offsets, dst):
        """Generate C code for a potential destination @dst
        @attrib: instruction Attributes
        @instr_offsets: instructions offsets list
        @dst: potential instruction destination"""

        out = []
        if is_expr(dst):
            out += self.gen_post_code(attrib, "DST_value")
            out.append('BlockDst->address = DST_value;')
            out += self.gen_post_instr_checks(attrib)
            out.append('\t\treturn JIT_RET_NO_EXCEPTION;')
            return out

        assert isinstance(dst, LocKey)
        offset = self.lifter.loc_db.get_location_offset(dst)
        if offset is None:
            # Generate goto for local labels
            return ['goto %s;' % dst]
        if (offset > attrib.instr.offset and
            offset in instr_offsets):
            # Only generate goto for next instructions.
            # (consecutive instructions)
            out += self.gen_post_code(attrib, "0x%x" % offset)
            out += self.gen_post_instr_checks(attrib)
            out.append('goto %s;' % dst)
        else:
            out += self.gen_post_code(attrib, "0x%x" % offset)
            out.append('BlockDst->address = DST_value;')
            out += self.gen_post_instr_checks(attrib)
            out.append('\t\treturn JIT_RET_NO_EXCEPTION;')
        return out

    def gen_dst_goto(self, attrib, instr_offsets, dst2index):
        """
        Generate code for possible @dst2index.

        @attrib: an Attributes instance
        @instr_offsets: list of instructions offsets
        @dst2index: link from destination to index
        """

        if not dst2index:
            return []
        out = []
        out.append('switch(DST_case) {')

        stopcase = False
        for dst, index in sorted(viewitems(dst2index), key=lambda lblindex: lblindex[1]):
            if index == -1:
                # Handle '-1' case only once
                if not stopcase:
                    stopcase = True
                else:
                    continue

            out.append('\tcase %d:' % index)

            out += self.gen_goto_code(attrib, instr_offsets, dst)
            out.append('\t\tbreak;')
        out.append('};')
        return out

    def gen_c_code(self, attrib, c_dst, c_assignmnts):
        """
        Generate the C code for assignblk.
        @attrib: Attributes instance
        @c_dst: irdst C code
        """

        c_prefetch, c_var, c_main, c_mem, c_updt = c_assignmnts
        out = []
        out.append("{")
        out.append("// var")
        out += c_var
        out.append("// Prefetch")
        out += c_prefetch
        out.append("// Dst")
        out += c_dst
        out.append("// Main")
        out += c_main

        out.append("// Check op/mem exceptions")

        # Check memory access if assignblk has memory read
        if c_prefetch:
            out += self.gen_check_memory_exception(attrib.instr.offset)

        out.append("// Mem updt")
        out += c_mem

        out.append("// Check exception Mem write")
        # Check memory write exceptions
        if attrib.mem_write:
            out += self.gen_check_memory_exception(attrib.instr.offset)

        out.append("// Updt")
        out += c_updt

        out.append("// Checks exception")

        # Check post assignblk exception flags
        if attrib.set_exception:
            out += self.gen_check_cpu_exception(attrib.instr.offset)

        out.append("}")

        return out

    def get_caracteristics(self, assignblk, attrib):
        """
        Set the carateristics in @attrib according to the @assignblk
        @assignblk: an AssignBlock instance
        @attrib: an Attributes instance
        """

        # Check explicit exception raising
        attrib.set_exception = self.lifter.arch.regs.exception_flags in assignblk

        element_read = assignblk.get_r(mem_read=True)
        # Check mem read
        attrib.mem_read = any(isinstance(expr, ExprMem)
                              for expr in element_read)
        # Check mem write
        attrib.mem_write = any(isinstance(dst, ExprMem)
                               for dst in assignblk)

    def get_attributes(self, instr, irblocks, log_mn=False, log_regs=False):
        """
        Get the carateristics of each @irblocks. Returns the corresponding
        attributes object.
        @irblock: a list of irbloc instance
        @log_mn: generate code to log instructions
        @log_regs: generate code to log registers states
        """

        instr_attrib = Attributes(log_mn, log_regs)
        instr_attrib.instr = instr
        irblocks_attributes = []

        for irblock in irblocks:
            attributes = []
            irblocks_attributes.append(attributes)
            for assignblk in irblock:
                attrib = Attributes(log_mn, log_regs)
                attributes.append(attrib)
                self.get_caracteristics(assignblk, attrib)
                attrib.instr = instr
                instr_attrib.mem_read |= attrib.mem_read
                instr_attrib.mem_write |= attrib.mem_write
                instr_attrib.set_exception |= attrib.set_exception

        return instr_attrib, irblocks_attributes

    def gen_bad_block(self):
        """
        Generate the C code for a bad_block instance
        """
        return self.CODE_BAD_BLOCK.split("\n")

    def get_block_post_label(self, block):
        """Get label next to the @block
        @block: AsmBlock instance"""

        last_instr = block.lines[-1]
        offset = last_instr.offset + last_instr.l
        return self.lifter.loc_db.get_or_create_offset_location(offset)

    def gen_init(self, block):
        """
        Generate the init C code for a @block
        @block: an asm_bloc instance
        """

        instr_offsets = [line.offset for line in block.lines]
        post_label = self.get_block_post_label(block)
        post_offset = self.lifter.loc_db.get_location_offset(post_label)
        instr_offsets.append(post_offset)
        lbl_start = block.loc_key
        return (self.CODE_INIT % lbl_start).split("\n"), instr_offsets

    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """
        Generate the C code for an @irblock
        @irblock: an irbloc instance
        @attributes: an Attributes instance list
        """

        out = []
        dst2index = None
        for index, assignblk in enumerate(irblock):
            if index == irblock.dst_linenb:
                c_dst, dst2index = self.gen_assignblk_dst(irblock.dst)
            else:
                c_dst = []

            c_assignmnts = self.gen_c_assignments(assignblk)
            out += self.gen_c_code(attributes[index], c_dst, c_assignmnts)

        if dst2index:
            out.append("// Set irdst")
            # Gen goto on irdst set
            out += self.gen_dst_goto(instr_attrib, instr_offsets, dst2index)

        return out

    def gen_finalize(self, block):
        """
        Generate the C code for the final block instruction
        """

        loc_key = self.get_block_post_label(block)
        offset = self.lifter.loc_db.get_location_offset(loc_key)
        dst = self.dst_to_c(offset)
        code = self.CODE_RETURN_NO_EXCEPTION % (loc_key, self.C_PC, dst, dst)
        return code.split('\n')

    def gen_c(self, block, log_mn=False, log_regs=False):
        """
        Generate the C code for the @block and return it as a list of lines
        @log_mn: log mnemonics
        @log_regs: log registers
        """

        if isinstance(block, AsmBlockBad):
            return self.gen_bad_block()
        irblocks_list = self.block2assignblks(block)
        out, instr_offsets = self.gen_init(block)
        assert len(block.lines) == len(irblocks_list)
        for instr, irblocks in zip(block.lines, irblocks_list):
            instr_attrib, irblocks_attributes = self.get_attributes(instr, irblocks, log_mn, log_regs)
            for index, irblock in enumerate(irblocks):
                label = str(irblock.loc_key)
                out.append("%-40s // %.16X %s" %
                           (label + ":", instr.offset, instr))
                if index == 0:
                    out += self.gen_pre_code(instr_attrib)
                out += self.gen_irblock(instr_attrib, irblocks_attributes[index], instr_offsets, irblock)

        out += self.gen_finalize(block)

        return ['\t' + line for line in out]
