import miasm2.jitter.csts as csts
import miasm2.expression.expression as m2_expr

def makeTaintGen(C_Gen, ir_arch):
  class TaintGen(C_Gen):

      ## Taint Analysis

      CODE_INIT_TAINT = r"""
      struct taint_colors_t* taint_analysis = jitcpu->taint_analysis;
      vm_mngr_t* vm_mngr = &jitcpu->pyvm->vm_mngr;
      uint64_t current_color;
      uint64_t taint_addr;
      uint64_t taint_size;
      struct taint_interval_t* taint_interval;
      struct taint_interval_t* taint_interval_ret;
      struct taint_interval_t* taint_interval_arg;
      taint_interval = malloc(sizeof(*taint_interval));
      taint_interval_arg = malloc(sizeof(*taint_interval_arg));
      int do_not_clean_taint_cb_info = 1;
      int is_tainted;
      """

      CODE_INIT = CODE_INIT_TAINT + C_Gen.CODE_INIT

      CODE_PREPARE_ANALYSE_REG = r"""
          is_tainted = 0;
          taint_interval->start = -1;
          taint_interval->end = 0;
      """

      CODE_REG_ACCESS = r"""
          taint_register_generic_access(taint_analysis,
                                    current_color,
                                    %s,
                                    taint_interval,
                                    %s);
      """

      CODE_GET_REG_TAINT_1 = r"""
      taint_interval_arg->start = DEFAULT_REG_START;
      taint_interval_arg->end = DEFAULT_MAX_REG_SIZE - 1;
      """

      CODE_GET_REG_TAINT_2 = r"""
      taint_interval_arg->start = %d;
      taint_interval_arg->end = %d;
      """

      CODE_PREPARE_ANALYSE_MEM = r"""
      taint_addr = %s;
      taint_size = %s;
      is_tainted = 0;
      taint_interval->start = -1;
      taint_interval->end = 0;
      """

      CODE_TAINT_MEM = r"""
          taint_addr = taint_addr + taint_interval->start;
          taint_size = taint_interval->end-taint_interval->start+1;
          taint_memory_generic_access(vm_mngr, taint_addr, taint_size, ADD, current_color);
          if ( taint_analysis->colors[current_color].callback_info->exception_flag
               & DO_TAINT_MEM_CB )
          {
              vm_mngr->exception_flags |= EXCEPT_TAINT_ADD_MEM;
              taint_update_memory_callback_info(taint_analysis,
                                                current_color,
                                                taint_addr,
                                                taint_size,
                                                TAINT_EVENT);
          }
      """

      CODE_UNTAINT_MEM = r"""
          taint_addr = taint_addr - taint_interval_ret->start;
          taint_size = taint_interval_ret->end-taint_interval_ret->start+1;
          taint_memory_generic_access(vm_mngr, taint_addr, taint_size, REMOVE, current_color);

          if ( taint_analysis->colors[current_color].callback_info->exception_flag
               & DO_UNTAINT_MEM_CB )
          {
              vm_mngr->exception_flags |= EXCEPT_TAINT_REMOVE_MEM;
              taint_update_memory_callback_info(taint_analysis, current_color,
                                                taint_addr,
                                                taint_size,
                                                UNTAINT_EVENT);
          }
      """

      CODE_UPDATE_INTERVALLE = r"""
      if (taint_interval_ret != NULL)
      {
          taint_interval->end = MAX(taint_interval_ret->end,
                                      taint_interval->end);
          taint_interval->start = MIN(taint_interval_ret->start,
                                        taint_interval->start);
      }
      """

      CODE_CHECK_IF_FOUND_TAINT = r"""
      if (taint_interval->start != -1)
      {
          // Some taint was found
          is_tainted = 1;
      }
      """

      CODE_EXCEPTION_TAINT = r"""
      // Check taint analysis exceptions
      if (VM_exception_flag & EXCEPT_TAINT) {
          // When DST_value == 0 we do not want to raise exception.
          // If we raise an exception in this case, the execution will try to
          // continue at address 0 after exception is handled.
          // DST_value == 0 when a branching is occuring within an instruction
          // (LODSD for example). In this case, we want to raise an exception
          // only at the end of the instruction, not during branching.
          if (DST_value) {
              %s = %s;
              BlockDst->address = DST_value;
              return JIT_RET_EXCEPTION;
          } else {
             do_not_clean_taint_cb_info = 0;
          }
      }
      """

      def get_read_elements_with_real_size(self, dst, src):
          """We could have used the get_r function of miasm2.expression.
          Never the less, this function could loose some information.
          For example, in this case:
              'MOV BX, AX'
                  with AX tainted.
              The get_r() function would have return: RAX.
              We would have loose the information that only the 16 lower bits
              of RAX are used.
              In this case, get_read_elements_with_real_size() will return:
              RAX[0,16].
          """
          read_elements = set()
          src.visit(lambda x: visit_get_read_elements_with_real_size(x,
                                                                     read_elements),
                    lambda x: get_id_slice(x, read_elements))
          if isinstance(dst, m2_expr.ExprMem):
              # If dst is an ExprMem, Expr composing its address can spread taint
              # to the ExprMem
              dst.arg.visit(lambda x: visit_get_read_elements_with_real_size(x,
                                                                             read_elements),
                            lambda x: get_id_slice(x, read_elements))
          return read_elements

      def gen_segm2addr(self, expr, prefetchers):
          """ Properly convert ExprMem to C """
          ptr = expr.arg.replace_expr(prefetchers)
          new_expr = m2_expr.ExprMem(ptr, expr.size)
          return self.id_to_c(new_expr.arg)

      def gen_check_taint_exception(self, address):
          dst = self.dst_to_c(address)
          return (self.CODE_EXCEPTION_TAINT % (self.C_PC, dst)).split('\n')

      def gen_get_register_taint(self, reg_name, start=None, end=None):
          c_code = []
          if start is None:
              c_code += (self.CODE_GET_REG_TAINT_1).split('\n')
          else:
              c_code += (self.CODE_GET_REG_TAINT_2 % ((start/8), (end/8-1))).split('\n')
              # NOTE: end/8-1 -> from size in bits to end in bytes
          c_code.append("""
          taint_interval_ret = taint_get_register_color(taint_analysis,
                                                          current_color,
                                                          %s,
                                                          taint_interval_arg
                                                          );
          """ % (self.regs_index[reg_name]))
          return c_code

      def gen_add_register(self, reg_name, start=None, end=None):
          c_code = []
          if start is None:
              c_code.append(self.CODE_REG_ACCESS % (self.regs_index[reg_name],
                            "ADD"))
              return c_code
          else:
              raise NotImplementedError("Taint analysis: gen_add_register with 3 \
                      args is not implemented yet.")

      def gen_remove_register(self, reg_name, start=None, end=None):
          c_code = []
          if start is None:
              c_code.append(self.CODE_REG_ACCESS % (self.regs_index[reg_name],
                            "REMOVE"))
              return c_code
          else:
              raise NotImplementedError("Taint analysis: gen_remove_register with\
                      3 args is not implemented yet.")

      def gen_get_memory_taint(self, start_addr=None, size=None):
          c_code = ""
          c_code += "taint_interval_ret = taint_get_memory("
          c_code += "vm_mngr, "
          if start_addr is not None and size is not None:
              c_code += "%s, %s, " % (start_addr, size)
          else:
              c_code += "taint_addr, taint_size, "
          c_code += "current_color);"
          return c_code

      def gen_taint_calculation(self, src, prefetchers, dst=None):
          c_code = []

          reads = self.get_read_elements_with_real_size(dst, src)
          if not reads:
              c_code.append("// No taint found (source is a constante)")
              return c_code
          for read in reads:
              if ("IRDst" in str(read)) or ("loc_" in str(read)):
                  pass # NOTE: taint_get_register return 0 in this case but there
                       # is no need to generate this useless code
              elif isinstance(read, m2_expr.ExprSlice):
                  c_code += self.gen_get_register_taint(str(read.arg),
                                                        read.start,
                                                        read.stop)
                  c_code += (self.CODE_UPDATE_INTERVALLE).split('\n')
              elif isinstance(read, m2_expr.ExprMem):
                  start = self.gen_segm2addr(read, prefetchers)
                  size = read.size/8 # We use bytes for size
                  c_code.append(self.gen_get_memory_taint(start, size))
                  c_code += (self.CODE_UPDATE_INTERVALLE).split('\n')
              elif isinstance(read, m2_expr.ExprId):
                  c_code += self.gen_get_register_taint(str(read))
                  c_code += (self.CODE_UPDATE_INTERVALLE).split('\n')
              else:
                  raise NotImplementedError("Taint analysis: do not know how to \
                          handle expression type %s",
                                            type(read))
          c_code += (self.CODE_CHECK_IF_FOUND_TAINT).split('\n')
          return c_code

      def gen_analyse_mem(self, dst, src, prefetchers):
          c_code = []

          start = self.gen_segm2addr(dst, prefetchers)
          size = dst.size/8 # We use a size in byte not bit
          c_code += (self.CODE_PREPARE_ANALYSE_MEM % (start, size)).split('\n')

          c_code += self.gen_taint_calculation(src, prefetchers, dst)
          c_code.append("if (is_tainted)")
          c_code.append("{")
          c_code += ['\t' + line for line in (self.CODE_TAINT_MEM).split('\n')]
          c_code.append("}")
          c_code.append("else")
          c_code.append("{")
          c_code.append(self.gen_get_memory_taint())
          c_code.append("\tif (taint_interval_ret != NULL)")
          c_code.append("\t{")
          c_code += ['\t\t' + line for line in (self.CODE_UNTAINT_MEM).split('\n')]
          c_code.append("\t}")
          c_code.append("}")

          return c_code

      def gen_analyse_reg(self, dst, src, prefetchers):
          c_code = []

          c_code += (self.CODE_PREPARE_ANALYSE_REG).split('\n')

          c_code += self.gen_taint_calculation(src, prefetchers)
          c_code.append("if (is_tainted)")
          c_code.append("{")
          c_code += ['\t' + line for line in self.gen_taint_register(dst)]
          c_code.append("}")
          c_code.append("else")
          c_code.append("{")
          # NOTE: If destination is an ExprSlice, we may untaint a part of the
          # ExprId that was no affected at all by the current instruction
          c_code += self.gen_get_register_taint(str(dst))
          c_code.append("\tif (taint_interval_ret != NULL)")
          c_code.append("\t{")
          c_code += ['\t\t' + line for line in self.gen_untaint_register(dst)]
          c_code.append("\t}")
          c_code.append("}")

          return c_code

      def gen_taint_register(self, dst):
          c_code = []

          c_code += self.gen_add_register(str(dst))
          c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_TAINT_REG_CB )")
          c_code.append("{")
          c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_ADD_REG;")
          c_code.append(self.gen_callback_info_reg(str(dst), "TAINT_EVENT"))
          c_code.append("}")

          return c_code

      def gen_untaint_register(self, dst):
          c_code = []

          c_code.append("\ttaint_interval->start = taint_interval_ret->start;")
          c_code.append("\ttaint_interval->end = taint_interval_ret->end;")
          c_code += self.gen_remove_register(str(dst))
          c_code.append("if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_UNTAINT_REG_CB )")
          c_code.append("{")
          c_code.append("vm_mngr->exception_flags |= EXCEPT_TAINT_REMOVE_REG;")
          c_code.append(self.gen_callback_info_reg(str(dst), "UNTAINT_EVENT"))
          c_code.append("}")

          return c_code

      def gen_callback_info_reg(self, reg_name, event_type):
          c_code = """
          taint_update_register_callback_info(taint_analysis,
                                              current_color,
                                              %s,
                                              taint_interval,
                                              %s
                                              );
          """ % (self.regs_index[reg_name], event_type)

          return c_code

      def gen_clean_callback_info(self):
          c_code = []

          # When DST_value == 0, we do not raise exception.
          # This mean that the exception will be raised at the 'real' end of
          # the instruction.
          # In this case, we do not want to clean callback information because
          # we want to be able to retrieve them when we actually raise the
          # exception.
          c_code.append("if (do_not_clean_taint_cb_info) {")
          c_code.append("\ttaint_clean_all_callback_info(taint_analysis);")
          c_code.append("\tdo_not_clean_taint_cb_info = 1;")
          c_code.append("}")

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

      def gen_c_assignments(self, assignblk):
          """
          Return C informations used to generate the C code of the @assignblk
          Only add c_taint compare to the parent method
          @assignblk: an AssignBlock instance
          """

          c_prefetch, c_var, c_main, c_mem, c_updt = super(TaintGen, self).gen_c_assignments(assignblk)

          self.c_taint = []
          prefetchers = self.get_mem_prefetch(assignblk) # XXX: could be optimised, this is already done in G_Gen.gen_c_assignments
          self.c_taint = self.gen_taint(assignblk, prefetchers)

          return c_prefetch, c_var, c_main, c_mem, c_updt #, c_taint # XXX: for convenience we use a attribute for c_taint

      def gen_c_code(self, attrib, c_dst, c_assignmnts):
          """
          Generate the C code for assignblk.
          Only add taint analysis C code compare to the parent method
          @attrib: Attributes instance
          @c_dst: irdst C code
          """
          # XXX: pas tres propre comme facon de s'integrer au code
          # -> serait peut etre mieux si on manipulait un objet plutot qu'un
          # tableau de strings

          new_out = []
          out = super(TaintGen, self).gen_c_code(attrib, c_dst, c_assignmnts)

          try:
            exception_index = out.index("// Checks exception")
          except ValueError:
            raise NotImplementedError("Taint: do not know where to insert C code for taint analysis !")

          if out[0] == "{" and out[1] == "// var":
            # Taint propagation
            new_out.append(out[0])
            new_out.append("// Taint analysis")
            new_out += self.gen_clean_callback_info()
            new_out += self.c_taint
            new_out += out[1:exception_index]

            # Taint callbacks
            new_out += self.gen_check_taint_exception(attrib.instr.offset)
            new_out += out[exception_index+1:]
          else:
            raise NotImplementedError("Taint: do not know where to insert C code for taint analysis !")

          return new_out

  return TaintGen(ir_arch)

## Utils

def visit_get_read_elements_with_real_size(expr, read):
    if isinstance(expr, m2_expr.ExprId):
        read.add(expr)
    elif isinstance(expr, m2_expr.ExprMem):
        read.add(expr)
    return expr

def get_id_slice(expr, read):
    if isinstance(expr, m2_expr.ExprSlice):
        if isinstance(expr.arg, m2_expr.ExprId):
            read.add(expr)
            return False
    return True

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

def init_registers_index(jitter):
    """ Associate register names with an index (needed during JiT) """

    regs_index = dict()
    regs_name = dict()
    index = 0
    for reg in jitter.arch.regs.all_regs_ids_byname.keys():
        regs_index[reg] = index
        regs_name[index] = reg
        index += 1
    jitter.jit.codegen.regs_index = regs_index
    jitter.jit.codegen.regs_name = regs_name
    return len(regs_index)

def enable_taint_analysis(jitter, nb_colors=1):
    """ Init all component of the taint analysis engine """

    # Enable generation of C code analysing taint
    jitter.jit.codegen = makeTaintGen(jitter.C_Gen, jitter.ir_arch)
    nb_regs = init_registers_index(jitter)
    # Allocate taint holder
    jitter.cpu.init_taint_analysis(nb_colors, nb_regs)
    jitter.nb_colors = nb_colors
    empty_cache(jitter)

def disable_taint_analysis(jitter):
    # TODO: Add a test for this function
    jitter.jit.codegen = jitter.C_Gen(jitter.ir_arch)
    empty_cache(jitter)

# API examples

def on_taint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.cpu.last_tainted_registers(color)
        if last_regs:
            print "[Color:%s] Taint registers" % (color)

            for reg_id, start, end in last_regs:
                print "\t+ %s[%d,%d]" % (jitter.jit.codegen.regs_name[reg_id], start, end)
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
    return True

def on_untaint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.cpu.last_untainted_registers(color)
        if last_regs:
            print "[Color:%s] Untaint registers" % (color)

            for reg_id, start, end in last_regs:
                print "\t- %s[%d,%d]" % (jitter.jit.codegen.regs_name[reg_id], start, end)
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
        last_mem = jitter.cpu.last_untainted_memory(color)
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
        for reg_id, start, end in regs:
            print "\t* %s[%d,%d]" % (jitter.jit.codegen.regs_name[reg_id], start, end)
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

