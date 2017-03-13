import miasm2.expression.expression as m2_expr
from miasm2.ir.ir import IRBlock
from miasm2.ir.translators import Translator
from miasm2.core.asmblock import expr_is_label, AsmBlockBad, AsmLabel

# Miasm to C translator
translator = Translator.to_language("C")

SIZE_TO_MASK = {x: 2**x - 1 for x in (1, 2, 3, 7, 8, 16, 32, 64)}

MASK_INT = 0xffffffffffffffff


class Attributes(object):

    """
    Store an irblock attributes
    """

    def __init__(self, log_mn=False, log_regs=False):
        self.mem_read = False
        self.mem_write = False
        self.set_exception = False
        self.op_set_exception = False
        self.log_mn = log_mn
        self.log_regs = log_regs
        self.instr = None


class CGen(object):

    IMPLICIT_EXCEPTION_OP = set(['umod', 'udiv'])

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
        %s = %s;
        BlockDst->address = DST_value;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_VM_EXCEPTION_POST_INSTR = r"""
    check_memory_breakpoint(&(jitcpu->pyvm->vm_mngr));
    check_invalid_code_blocs(&(jitcpu->pyvm->vm_mngr));
    if (VM_exception_flag) {
        %s = %s;
        BlockDst->address = DST_value;
        return JIT_RET_EXCEPTION;
    }
    """

    CODE_INIT = r"""
    int DST_case;
    unsigned long long DST_value;
    vm_cpu_t* mycpu = (vm_cpu_t*)jitcpu->cpu;

    goto %s;
    """

    CODE_BAD_BLOCK = r"""
    // Unknown mnemonic
    CPU_exception_flag = EXCEPT_UNK_MNEMO;
    """ + CODE_RETURN_EXCEPTION

    def __init__(self, ir_arch):
        self.ir_arch = ir_arch
        self.PC = self.ir_arch.pc
        self.init_arch_C()

    def init_arch_C(self):
        self.id_to_c_id = {}
        for reg in self.ir_arch.arch.regs.all_regs_ids:
            self.id_to_c_id[reg] = m2_expr.ExprId('mycpu->%s' % reg, reg.size)

        self.C_PC = self.id_to_c(self.PC)

    def dst_to_c(self, src):
        if not isinstance(src, m2_expr.Expr):
            src = m2_expr.ExprInt(src, self.PC.size)
        return self.id_to_c(src)

    def patch_c_id(self, expr):
        return expr.replace_expr(self.id_to_c_id)

    def id_to_c(self, expr):
        return translator.from_expr(self.patch_c_id(expr))

    def get_post_instr_label(self, offset):
        return self.ir_arch.symbol_pool.getby_name_create("lbl_gen_post_instr_%.8X" % (offset))

    def add_label_index(self, dst2index, lbl):
        dst2index[lbl] = len(dst2index)

    def assignblk_to_irbloc(self, instr, assignblk):
        """
        Ensure IRDst is always set in the head @assignblk of the @instr
        @assignblk: Assignblk instance
        @instr: an instruction instance
        """
        if self.ir_arch.IRDst not in assignblk:
            assignblk[self.ir_arch.IRDst] = m2_expr.ExprInt(
                instr.offset + instr.l,
                self.ir_arch.IRDst.size)

        return IRBlock(self.ir_arch.get_instr_label(instr), [assignblk])

    def block2assignblks(self, block):
        irblocks_list = []
        for instr in block.lines:
            assignblk_head, assignblks_extra = self.ir_arch.instr2ir(instr)
            # Keep result in ordered list as first element is the assignblk head
            # The remainings order is not really important
            irblock_head = self.assignblk_to_irbloc(instr, assignblk_head)
            irblocks = [irblock_head] + assignblks_extra

            for irblock in irblocks:
                assert irblock.dst is not None
            irblocks_list.append(irblocks)
        return irblocks_list

    def gen_mem_prefetch(self, assignblk, mems_to_prefetch):
        out = []
        for expr, prefetcher in sorted(mems_to_prefetch.iteritems()):
            str_src = self.id_to_c(expr)
            str_dst = self.id_to_c(prefetcher)
            out.append('%s = %s;' % (str_dst, str_src))
        assignblk.C_prefetch = out
        return out

    def add_local_var(self, dst_var, dst_index, expr):
        size = expr.size
        if size < 8:
            size = 8
        if size not in dst_index:
            raise RuntimeError("Unsupported operand size %s", size)
        var_num = dst_index[size]
        dst = m2_expr.ExprId("var_%.2d_%.2d" % (size, var_num), size)
        dst_index[size] += 1
        dst_var[expr] = dst
        return dst

    def gen_assignments(self, assignblk, prefetchers):
        out_var = []
        out_main = []
        out_mem = []
        out_updt = []

        dst_index = {8: 0, 16: 0, 32: 0, 64: 0}
        dst_var = {}

        for var in prefetchers.itervalues():
            out_var.append("uint%d_t %s;" % (var.size, var))

        for dst, src in sorted(assignblk.iteritems()):
            src = src.replace_expr(prefetchers)
            if dst is self.ir_arch.IRDst:
                pass
            elif isinstance(dst, m2_expr.ExprId):
                new_dst = self.add_local_var(dst_var, dst_index, dst)
                if dst in self.ir_arch.arch.regs.regs_flt_expr:
                    # Dont mask float affectation
                    out_main.append(
                        '%s = (%s);' % (self.id_to_c(new_dst), self.id_to_c(src)))
                else:
                    out_main.append(
                        '%s = (%s)&0x%X;' % (self.id_to_c(new_dst),
                                             self.id_to_c(src),
                                             SIZE_TO_MASK[src.size]))
            elif isinstance(dst, m2_expr.ExprMem):
                ptr = dst.arg.replace_expr(prefetchers)
                new_dst = m2_expr.ExprMem(ptr, dst.size)
                str_dst = self.id_to_c(new_dst).replace('MEM_LOOKUP', 'MEM_WRITE')
                out_mem.append('%s, %s);' % (str_dst[:-1], self.id_to_c(src)))
            else:
                raise ValueError("Unknown dst")

        for dst, new_dst in dst_var.iteritems():
            if dst is self.ir_arch.IRDst:
                continue
            out_updt.append('%s = %s;' % (self.id_to_c(dst), self.id_to_c(new_dst)))
            out_var.append("uint%d_t %s;" % (new_dst.size, new_dst))

        assignblk.C_var = out_var
        assignblk.C_main = out_main
        assignblk.C_mem = out_mem
        assignblk.C_updt = out_updt

    def gen_c_assignblk(self, assignblk):
        mem_read, mem_write = False, False

        mem_index = {8: 0, 16: 0, 32: 0, 64: 0}
        mem_var = {}
        prefetch_index = {8: 0, 16: 0, 32: 0, 64: 0}

        # Prefetch memory read
        for expr in assignblk.get_r(mem_read=True):
            if not isinstance(expr, m2_expr.ExprMem):
                continue
            mem_read = True
            var_num = mem_index[expr.size]
            mem_index[expr.size] += 1
            var = m2_expr.ExprId(
                "prefetch_%.2d_%.2d" % (expr.size, var_num), expr.size)
            mem_var[expr] = var

        # Check if assignblk can write mem
        mem_write = any(isinstance(expr, m2_expr.ExprMem)
                        for expr in assignblk.get_w())

        assignblk.mem_write = mem_write
        assignblk.mem_read = mem_read

        # Generate memory prefetch
        return mem_var

    def gen_check_memory_exception(self, address):
        dst = self.dst_to_c(address)
        return (self.CODE_EXCEPTION_MEM_AT_INSTR % (self.C_PC, dst, dst)).split('\n')

    def gen_check_cpu_exception(self, address):
        dst = self.dst_to_c(address)
        return (self.CODE_EXCEPTION_AT_INSTR % (self.C_PC, dst, dst)).split('\n')

    def traverse_expr_dst(self, expr, dst2index):
        """
        Generate the index of the destination label for the @expr
        @dst2index: dictionnary to link label to its index
        """

        if isinstance(expr, m2_expr.ExprCond):
            cond = self.id_to_c(expr.cond)
            src1, src1b = self.traverse_expr_dst(expr.src1, dst2index)
            src2, src2b = self.traverse_expr_dst(expr.src2, dst2index)
            return ("((%s)?(%s):(%s))" % (cond, src1, src2),
                    "((%s)?(%s):(%s))" % (cond, src1b, src2b))
        elif isinstance(expr, m2_expr.ExprInt):
            offset = int(expr)
            self.add_label_index(dst2index, offset)
            return ("%s" % dst2index[offset],
                    hex(offset))
        elif expr_is_label(expr):
            label = expr.name
            if label.offset != None:
                offset = label.offset
                self.add_label_index(dst2index, offset)
                return ("%s" % dst2index[offset],
                        hex(offset))
            else:
                self.add_label_index(dst2index, label)
                return ("%s" % dst2index[label],
                        "0")

        else:
            dst2index[expr] = -1
            return ("-1",
                    self.id_to_c(expr))

    def gen_assignblk_dst(self, dst):
        dst2index = {}
        (ret, retb) = self.traverse_expr_dst(dst, dst2index)
        ret = "DST_case = %s;" % ret
        retb = "DST_value = %s;" % retb
        return ['// %s' % dst2index,
                '%s' % ret,
                '%s' % retb], dst2index

    def gen_post_instr_checks(self, attrib, dst):
        out = []
        dst = self.dst_to_c(dst)
        if attrib.mem_read | attrib.mem_write:
            out += (self.CODE_VM_EXCEPTION_POST_INSTR % (self.C_PC, dst)).split('\n')
        if attrib.set_exception or attrib.op_set_exception:
            out += (self.CODE_CPU_EXCEPTION_POST_INSTR % (self.C_PC, dst)).split('\n')

        if attrib.mem_read | attrib.mem_write:
            out.append("reset_memory_access(&(jitcpu->pyvm->vm_mngr));")

        return out

    def gen_pre_code(self, attrib):
        out = []

        if attrib.log_mn:
            out.append('printf("%.8X %s\\n");' % (attrib.instr.offset,
                                                  attrib.instr))
        return out

    def gen_post_code(self, attrib):
        out = []
        if attrib.log_regs:
            out.append('dump_gpregs(jitcpu->cpu);')
        return out

    def gen_goto_code(self, attrib, instr_offsets, dst):
        if isinstance(dst, AsmLabel) and dst.offset is None:
            # Generate goto for local labels
            return ['goto %s;' % dst.name]
        offset = None
        if isinstance(dst, AsmLabel) and dst.offset is not None:
            offset = dst.offset
        elif isinstance(dst, (int, long)):
            offset = dst
        out = []
        if (offset is not None and
            offset > attrib.instr.offset and
            offset in instr_offsets):
            # Only generate goto for next instructions.
            # (consecutive instructions)
            lbl = self.ir_arch.symbol_pool.getby_offset_create(dst)
            out += self.gen_post_code(attrib)
            out += self.gen_post_instr_checks(attrib, dst)
            out.append('goto %s;' % lbl.name)
        else:
            out += self.gen_post_code(attrib)
            out.append('BlockDst->address = DST_value;')
            out += self.gen_post_instr_checks(attrib, dst)
            out.append('\t\treturn JIT_RET_NO_EXCEPTION;')
        return out

    def gen_dst_goto(self, attrib, instr_offsets, dst2index):
        """
        Generate code for possible @dst2index.

        @attrib: an Attributs instance
        @instr_offsets: list of instructions offsets
        @dst2index: link from destination to index
        """

        if not dst2index:
            return []
        out = []
        out.append('switch(DST_case) {')

        stopcase = False
        for dst, index in sorted(dst2index.iteritems(), key=lambda lblindex: lblindex[1]):
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

    def gen_c_code(self, assignblk, c_dst):
        """
        Generate the C code for @assignblk.
        @assignblk: an Assignblk instance
        @c_dst: irdst C code
        """
        out = []
        out.append("{")
        out.append("// var")
        out += assignblk.C_var
        out.append("// Prefetch")
        out += assignblk.C_prefetch
        out.append("// Dst")
        out += c_dst
        out.append("// Main")
        out += assignblk.C_main

        out.append("// Check op/mem exceptions")

        # Check memory access if assignblk has memory read
        if assignblk.C_prefetch:
            out += self.gen_check_memory_exception(assignblk.instr_addr)

        # Check if operator raised exception flags
        if assignblk.op_set_exception:
            out += self.gen_check_cpu_exception(assignblk.instr_addr)

        out.append("// Mem updt")
        out += assignblk.C_mem

        out.append("// Check exception Mem write")
        # Check memory write exceptions
        if assignblk.mem_write:
            out += self.gen_check_memory_exception(assignblk.instr_addr)

        out.append("// Updt")
        out += assignblk.C_updt

        out.append("// Checks exception")

        # Check post assignblk exception flags
        if assignblk.set_exception:
            out += self.gen_check_cpu_exception(assignblk.instr_addr)

        out.append("}")

        return out

    def is_exception_operator(self, operator):
        """Return True if the @op operator can raise a runtime exception"""

        return any(operator.startswith(except_op)
                   for except_op in self.IMPLICIT_EXCEPTION_OP)

    def get_caracteristics(self, irblock):
        """
        Get the carateristics of each assignblk in the @irblock
        @irblock: an irbloc instance
        """

        for assignblk in irblock.irs:
            assignblk.mem_read, assignblk.mem_write = False, False
            assignblk.op_set_exception = False
            # Check explicit exception raising
            assignblk.set_exception = self.ir_arch.arch.regs.exception_flags in assignblk

            element_read = assignblk.get_r(mem_read=True)
            # Check implicit exception raising
            assignblk.op_set_exception = any(self.is_exception_operator(operator)
                                             for elem in assignblk.values()
                                             for operator in m2_expr.get_expr_ops(elem))
            # Check mem read
            assignblk.mem_read = any(isinstance(expr, m2_expr.ExprMem)
                                     for expr in element_read)
            # Check mem write
            assignblk.mem_write = any(isinstance(dst, m2_expr.ExprMem)
                                      for dst in assignblk)

    def get_attributes(self, instr, irblocks, log_mn=False, log_regs=False):
        """
        Get the carateristics of each @irblocks. Returns the corresponding
        attributes object.
        @irblock: a list of irbloc instance
        @log_mn: generate code to log instructions
        @log_regs: generate code to log registers states
        """

        attrib = Attributes(log_mn, log_regs)

        for irblock in irblocks:
            for assignblk in irblock.irs:
                self.get_caracteristics(irblock)
                attrib.mem_read |= assignblk.mem_read
                attrib.mem_write |= assignblk.mem_write
                attrib.set_exception |= assignblk.set_exception
                attrib.op_set_exception |= assignblk.op_set_exception
        attrib.instr = instr
        return attrib

    def gen_bad_block(self):
        """
        Generate the C code for a bad_block instance
        """
        return self.CODE_BAD_BLOCK.split("\n")

    def get_block_post_label(self, block):
        last_instr = block.lines[-1]
        offset = last_instr.offset + last_instr.l
        return self.ir_arch.symbol_pool.getby_offset_create(offset)

    def gen_init(self, block):
        """
        Generate the init C code for a @block
        @block: an asm_bloc instance
        """

        instr_offsets = [line.offset for line in block.lines]
        instr_offsets.append(self.get_block_post_label(block).offset)
        lbl_start = self.ir_arch.symbol_pool.getby_offset_create(instr_offsets[0])
        return (self.CODE_INIT % lbl_start.name).split("\n"), instr_offsets

    def gen_irblock(self, attrib, instr_offsets, instr, irblock):
        """
        Generate the C code for an @irblock
        @instr: the current instruction to translate
        @irblock: an irbloc instance
        @attrib: an Attributs instance
        """

        out = []
        dst2index = None
        for index, assignblk in enumerate(irblock.irs):
            if index == irblock.dst_linenb:
                c_dst, dst2index = self.gen_assignblk_dst(irblock.dst)
            else:
                c_dst = []
            assignblk.instr_addr = instr.offset
            prefetchers = self.gen_c_assignblk(assignblk)
            self.gen_mem_prefetch(assignblk, prefetchers)
            self.gen_assignments(assignblk, prefetchers)

            out += self.gen_c_code(assignblk, c_dst)

        if dst2index:
            out.append("// Set irdst")
            # Gen goto on irdst set
            out += self.gen_dst_goto(attrib, instr_offsets, dst2index)

        return out

    def gen_finalize(self, block):
        """
        Generate the C code for the final block instruction
        """

        lbl = self.get_block_post_label(block)
        dst = self.dst_to_c(lbl.offset)
        code = self.CODE_RETURN_NO_EXCEPTION % (lbl.name, self.C_PC, dst, dst)
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

        for instr, irblocks in zip(block.lines, irblocks_list):
            attrib = self.get_attributes(instr, irblocks, log_mn, log_regs)

            for index, irblock in enumerate(irblocks):
                self.ir_arch.irbloc_fix_regs_for_mode(
                    irblock, self.ir_arch.attrib)

                out.append("%-40s // %.16X %s" %
                           (str(irblock.label.name) + ":", instr.offset, instr))
                if index == 0:
                    out += self.gen_pre_code(attrib)
                out += self.gen_irblock(attrib, instr_offsets, instr, irblock)

        out += self.gen_finalize(block)
        return ['\t' + line for line in out]
