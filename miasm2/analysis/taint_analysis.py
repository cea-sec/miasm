import miasm2.jitter.csts as csts
import miasm2.expression.expression as m2_expr

class TaintGen(object):

    ## Taint Analysis

    CODE_INIT_TAINT = r"""
    struct taint_colors_t* taint_analysis = jitcpu->taint_analysis;
    vm_mngr_t* vm_mngr = &jitcpu->pyvm->vm_mngr;
    uint64_t current_color;
    uint64_t addr;
    uint64_t size;
    """

    CODE_EXCEPTION_TAINT = r"""
    // Check taint analysis exceptions
    if (VM_exception_flag & EXCEPT_TAINT) {
        %s = %s;
        BlockDst->address = DST_value;
        return JIT_RET_EXCEPTION;
    }
    """

    def gen_segm2addr(self, expr, prefetchers):
        """ Properly convert ExprMem to C """
        ptr = expr.arg.replace_expr(prefetchers)
        new_expr = m2_expr.ExprMem(ptr, expr.size)
        return self.id_to_c(new_expr.arg)

    def gen_check_taint_exception(self, address):
        dst = self.dst_to_c(address)
        return (self.CODE_EXCEPTION_TAINT % (self.C_PC, dst)).split('\n')

    def gen_get_register_taint(self, reg_name):
        c_code =  "taint_get_register("
        c_code += "taint_analysis, "
        c_code += "current_color, "
        c_code += "%s)" % (self.regs_index[reg_name])
        return c_code

    def gen_add_register(self, reg_name):
        c_code =  "taint_add_register("
        c_code += "taint_analysis, "
        c_code += "current_color, "
        c_code += "%s);" % (self.regs_index[reg_name])
        return c_code

    def gen_remove_register(self, reg_name):
        c_code =  "taint_remove_register("
        c_code += "taint_analysis, "
        c_code += "current_color, "
        c_code += "%s);" % (self.regs_index[reg_name])
        return c_code

    def gen_get_memory_taint(self, start_addr=None, size=None):
        c_code =  "taint_get_memory("
        c_code += "vm_mngr, "
        if start_addr is not None and size is not None:
            c_code += "%s, %s, " % (start_addr, size)
        else:
            c_code += "addr, size, "
        c_code += "current_color)"
        return c_code

    def gen_add_memory(self):
        c_code =  "taint_add_memory("
        c_code += "vm_mngr, "
        c_code += "addr, size, "
        c_code += "current_color);"
        return c_code

    def gen_remove_memory(self):
        c_code =  "taint_remove_memory("
        c_code += "vm_mngr, "
        c_code += "addr, size, "
        c_code += "current_color);"
        return c_code

    def gen_taint_calculation(self, src, prefetchers, dst=None):
        c_code = "0"
        for read in src.get_r(mem_read=True):
            if ("IRDst" in str(read)) or ("loc_" in str(read)):
                pass # NOTE: taint_get_register should return 0 now
            elif isinstance(read, m2_expr.ExprMem):
                start = self.gen_segm2addr(read, prefetchers)
                c_code += " | " + self.gen_get_memory_taint(start, read.size/8) # We use bytes for size
            else:
                c_code += " | " + self.gen_get_register_taint(str(read))
        if dst is not None: # dst is an Expr_Mem so we look in its address for taint source
           for read in dst.get_r(mem_read=True):
                if ("IRDst" in str(read)) or ("loc_" in str(read)):
                    pass # NOTE: taint_get_register should return 0 now
                elif not isinstance(read, m2_expr.ExprMem):
                    c_code += " | " + self.gen_get_register_taint(str(read))
        return c_code

    def gen_analyse_mem(self, dst, src, prefetchers):
        c_code = []

        start = self.gen_segm2addr(dst, prefetchers)
        size = dst.size/8 # We use a size in byte not bit
        c_code.append("addr = %s;" % (start))
        c_code.append("size = %s;" % (size))

        c_code.append("if (%s)" % (self.gen_taint_calculation(src, prefetchers, dst)))
        c_code.append("{")
        c_code += ['\t' + line for line in self.gen_taint_memory()]
        c_code.append("}")
        c_code.append("else")
        c_code.append("{")
        c_code.append("\tif (%s)" % (self.gen_get_memory_taint()))
        c_code.append("\t{")
        c_code += ['\t\t' + line for line in self.gen_untaint_memory()]
        c_code.append("\t}")
        c_code.append("}")

        return c_code

    def gen_taint_memory(self):
        c_code = []

        c_code.append(self.gen_add_memory())
        c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_TAINT_MEM_CB )")
        c_code.append("{")
        c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_ADD_MEM;")
        c_code.append("taint_update_memory_callback_info(taint_analysis, current_color, addr, size);")
        c_code.append("}")

        return c_code

    def gen_untaint_memory(self):
        c_code = []

        c_code.append(self.gen_remove_memory())
        c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_UNTAINT_MEM_CB )")
        c_code.append("{")
        c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_REMOVE_MEM;")
        c_code.append("taint_update_memory_callback_info(taint_analysis, current_color, addr, size);")
        c_code.append("}")

        return c_code

    def gen_analyse_reg(self, dst, src, prefetchers):
        c_code = []

        c_code.append("if (%s)" % (self.gen_taint_calculation(src, prefetchers)))
        c_code.append("{")
        c_code += ['\t' + line for line in self.gen_taint_register(dst)]
        c_code.append("}")
        c_code.append("else")
        c_code.append("{")
        c_code.append("\tif (%s)" % (self.gen_get_register_taint(str(dst))))
        c_code.append("\t{")
        c_code += ['\t\t' + line for line in self.gen_untaint_register(dst)]
        c_code.append("\t}")
        c_code.append("}")

        return c_code

    def gen_taint_register(self, dst):
        c_code = []

        c_code.append(self.gen_add_register(str(dst)))
        c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_TAINT_REG_CB )")
        c_code.append("{")
        c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_ADD_REG;")
        c_code.append(self.gen_callback_info_reg(str(dst)))
        c_code.append("}")

        return c_code

    def gen_untaint_register(self, dst):
        c_code = []

        c_code.append(self.gen_remove_register(str(dst)))
        c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_UNTAINT_REG_CB )")
        c_code.append("{")
        c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_REMOVE_REG;")
        c_code.append(self.gen_callback_info_reg(str(dst)))
        c_code.append("}")

        return c_code

    def gen_callback_info_reg(self, reg_name):
        c_code = "taint_add_callback_register("
        c_code += "taint_analysis, "
        c_code += "current_color, "
        c_code += "%s);" % (self.regs_index[reg_name])

        return c_code

    def gen_clean_callback_info(self):
        c_code = []

        c_code.append("taint_clean_all_callback_info(taint_analysis);")

        return c_code

    def gen_taint(self, assignblk, prefetchers):
        c_taint = []

        for dst, src in assignblk.iteritems():
            c_taint.append("// Analysing %s = %s " % (dst, src))
            c_taint.append("for (current_color = 0 ; current_color < taint_analysis->nb_colors ; current_color++)")
            c_taint.append("{")
            if isinstance(dst, m2_expr.ExprMem):
                c_taint += self.gen_analyse_mem(dst, src, prefetchers)
            elif ("IRDst" not in str(dst)) and ("loc_" not in str(dst)):
                c_taint += self.gen_analyse_reg(dst, src, prefetchers)
            else:
                c_taint.append("// Not tainting %s for now" % (dst))
            c_taint.append("}")

        return c_taint

## Utils

def init_registers_index(jitter):
    """ Associate register names with an index (needed during JiT) """

    gpregs = jitter.cpu.get_gpreg()
    regs_index = dict()
    index = 0
    for reg in jitter.arch.regs.all_regs_ids_byname.keys():
        regs_index[reg] = index
        index += 1
    jitter.jit.codegen.regs_index = regs_index
    return len(regs_index)

def enable_taint_analysis(jitter, nb_colors=1):
    """ Init all component of the taint analysis engine """

    # Enable generation of C code analysing taint
    jitter.jit.codegen.do_taint = True
    nb_regs = init_registers_index(jitter)
    # Allocate taint holder
    jitter.cpu.init_taint_analysis(nb_colors, nb_regs)
    jitter.nb_colors = nb_colors # NOTE: dirty..
    empty_cache(jitter)

def disable_taint_analysis(jitter):
    jitter.jit.codegen.do_taint = False
    empty_cache(jitter)
    # NOTE: free memory and registers ?

# API examples

def on_taint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.cpu.last_tainted_registers(color)
        if last_regs:
            print "[Color:%s] Taint registers" % (color)
            sorted_regs = sorted(jitter.jit.codegen.regs_index, key=jitter.jit.codegen.regs_index.__getitem__)
            for reg_id in last_regs:
                print "\t+ %s" % (sorted_regs[reg_id])
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
    return True

def on_untaint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.cpu.last_tainted_registers(color)
        if last_regs:
            print "[Color:%s] Untaint registers" % (color)
            sorted_regs = sorted(jitter.jit.codegen.regs_index, key=jitter.jit.codegen.regs_index.__getitem__)
            for reg_id in last_regs:
                print "\t- %s" % (sorted_regs[reg_id])
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
    is_taint_vanished(jitter)
    return True

def on_taint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.cpu.last_tainted_memory(color)
        if last_mem:
            print "[Color:%s] Taint memory" % (color)
            for addr, size in last_mem:
                print "\t+ addr:0x%x size:%s bytes" % (addr, size)
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
    return True

def on_untaint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.cpu.last_tainted_memory(color)
        if last_mem:
            print "[Color%s] Untaint memory" % (color)
            for addr, size in last_mem:
                print "\t- addr:0x%x size:%s bytes" % (addr, size)
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
    is_taint_vanished(jitter)
    return True

def display_all_taint(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.cpu.get_all_taint(color)
        print "\n","_"*20
        print "Color: %s" % (color)
        print "_"*20
        print "Registers:"
        sorted_regs = sorted(jitter.jit.codegen.regs_index, key=jitter.jit.codegen.regs_index.__getitem__)
        for reg_id in regs:
            print "\t* %s" % (sorted_regs[reg_id])
        print "-"*20
        print "Memory:"
        for addr, size in mems:
            print "\t* addr:0x%x size:%d bytes" % (addr, size)
        print "_"*20,"\n"

def is_taint_vanished(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.cpu.get_all_taint(color)
        if regs or mems:
            return; # There is still some taint
    print "\n\n/!\\ All taint is gone ! /!\\\n\n"

# Utils

def empty_cache(jitter):
    """ Empty the cache directory in order to create new code """

    import os
    import shutil

    folder = jitter.jit.tempdir
    for the_file in os.listdir(folder):
        file_path = os.path.join(folder, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(e)
