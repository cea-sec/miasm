import miasm.jitter.csts as csts
from miasm.expression.expression import ExprMem, ExprId
from miasm.core.interval import interval


def makeTaintGen(C_Gen, ir_arch):
  class TaintGen(C_Gen):

      CODE_INIT_TAINT = r"""
      struct taint_colors_t* taint_analysis = jitcpu->taint_analysis;
      uint64_t current_color;
      uint64_t current_mem_addr, current_mem_size, current_reg_size, current_reg_index;
      struct rb_root taint_interval_tree_tmp, taint_interval_tree, taint_interval_tree_before;
      taint_interval_tree_tmp = interval_tree_new();
      taint_interval_tree = interval_tree_new();
      taint_interval_tree_before = interval_tree_new();
      struct interval_tree_node *node;
      struct rb_node *rb_node;
      struct interval taint_interval, interval_tmp;
      int do_not_clean_taint_cb_info = 1;
      int current_compose_start;
      int fully_tainted;
      """

      CODE_INIT = CODE_INIT_TAINT + C_Gen.CODE_INIT

      CODE_RETURN_EXCEPTION = r"""
      interval_tree_free(&taint_interval_tree_tmp);
      interval_tree_free(&taint_interval_tree);
      interval_tree_free(&taint_interval_tree_before);
      """ + C_Gen.CODE_RETURN_EXCEPTION

      # TODO: use C_Gen.CODE_EXCEPTION_AT_INSTR
      CODE_EXCEPTION_AT_INSTR = r"""
      if (CPU_exception_flag_at_instr) {
          interval_tree_free(&taint_interval_tree_tmp);
          interval_tree_free(&taint_interval_tree);
          interval_tree_free(&taint_interval_tree_before);
          %s = %s;
          BlockDst->address = %s;
          return JIT_RET_EXCEPTION;
      }
      """

      # TODO: use C_Gen.CODE_RETURN_NO_EXCEPTION
      CODE_RETURN_NO_EXCEPTION = r"""
      %s:
      %s = %s;
      BlockDst->address = %s;
      interval_tree_free(&taint_interval_tree_tmp);
      interval_tree_free(&taint_interval_tree);
      interval_tree_free(&taint_interval_tree_before);
      return JIT_RET_NO_EXCEPTION;
      """

      # TODO: use C_Gen.CODE_CPU_EXCEPTION_POST_INSTR
      CODE_CPU_EXCEPTION_POST_INSTR = r"""
      if (CPU_exception_flag) {
          %s = DST_value;
          BlockDst->address = DST_value;
          interval_tree_free(&taint_interval_tree_tmp);
          interval_tree_free(&taint_interval_tree);
          interval_tree_free(&taint_interval_tree_before);
          return JIT_RET_EXCEPTION;
      }
      """

      # TODO: use C_Gen.CODE_VM_EXCEPTION_POST_INSTR
      CODE_VM_EXCEPTION_POST_INSTR = r"""
      check_memory_breakpoint(&(jitcpu->pyvm->vm_mngr));
      check_invalid_code_blocs(&(jitcpu->pyvm->vm_mngr));
      if (VM_exception_flag) {
          interval_tree_free(&taint_interval_tree_tmp);
          interval_tree_free(&taint_interval_tree);
          interval_tree_free(&taint_interval_tree_before);
          %s = DST_value;
          BlockDst->address = DST_value;
          return JIT_RET_EXCEPTION;
      }
      """

      # TODO: use C_Gen.CODE_EXCEPTION_MEM_AT_INSTR
      CODE_EXCEPTION_MEM_AT_INSTR = r"""
      // except fetch mem at instr noauto
      if ((VM_exception_flag & ~EXCEPT_CODE_AUTOMOD) & EXCEPT_DO_NOT_UPDATE_PC) {
          %s = %s;
          BlockDst->address = %s;
          interval_tree_free(&taint_interval_tree_tmp);
          interval_tree_free(&taint_interval_tree);
          interval_tree_free(&taint_interval_tree_before);
          return JIT_RET_EXCEPTION;
      }
      """

      CODE_GET_REG_TAINT = r"""
      taint_interval.start = %d;
      taint_interval.last = %d;
      interval_tree_free(&taint_interval_tree_tmp);
      taint_interval_tree_tmp = taint_get_register_color(taint_analysis,
                                                         current_color,
                                                         %s,
                                                         taint_interval
                                                         );
      """

      CODE_GET_MEM_TAINT = r"""
      taint_interval.start = %s;
      taint_interval.last = taint_interval.start + (%d - 1);
      interval_tree_free(&taint_interval_tree_tmp);
      taint_interval_tree_tmp = taint_get_memory(taint_analysis,
                                                 current_color,
                                                 taint_interval);
      """


      CODE_PREPARE_ANALYSE_REG = r"""
          interval_tree_free(&taint_interval_tree);
          taint_interval_tree = interval_tree_new();
          current_reg_size = %d;
          current_reg_index = %d;
          taint_interval.start = 0;
          taint_interval.last = current_reg_size;
          interval_tree_free(&taint_interval_tree_before);
          taint_interval_tree_before = taint_get_register_color(taint_analysis, current_color, current_reg_index, taint_interval);
      """

      CODE_CHECK_FULLY_TAINTED = r"""
          if (rb_first(&taint_interval_tree_tmp) != NULL)
          {
              fully_tainted = 1;
          }
      """

      CODE_TAINT_REG = r"""
        if (fully_tainted)
        {
            taint_interval.start = 0;
            taint_interval.last = current_reg_size;
            taint_register_generic_access(taint_analysis,
                                        current_color,
                                        current_reg_index,
                                        taint_interval,
                                        ADD);

            if ( taint_analysis->colors[current_color].callback_info->exception_flag & DO_TAINT_REG_CB )
            {
              jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_ADD_REG;
              taint_update_register_callback_info(taint_analysis,
                                                  current_color,
                                                  current_reg_index,
                                                  taint_interval,
                                                  TAINT_EVENT
                                                  );
            }
        }
        else
        {
            // Remove previous taint
            rb_node = rb_first(&taint_interval_tree_before);

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                taint_interval = node->interval;
                taint_register_generic_access(taint_analysis,current_color, current_reg_index, taint_interval, REMOVE);
                rb_node = rb_next(rb_node);
            }

            // Add new taint
            rb_node = rb_first(&taint_interval_tree);

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                taint_interval = node->interval;
                taint_register_generic_access(taint_analysis, current_color, current_reg_index, taint_interval, ADD);
                rb_node = rb_next(rb_node);
                // Update TAINT callback information
                if ( taint_analysis->colors[current_color].callback_info->exception_flag
                     & DO_TAINT_REG_CB )
                {
                    jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_ADD_REG;
                    taint_update_register_callback_info(taint_analysis,
                                                      current_color,
                                                      current_reg_index,
                                                      taint_interval,
                                                      TAINT_EVENT);
                }
            }

            // Update untaint callback information
            if ( taint_analysis->colors[current_color].callback_info->exception_flag
                 & DO_UNTAINT_REG_CB )
            {
                rb_node = rb_first(&taint_interval_tree);

                while(rb_node != NULL)
                {
                    node = rb_entry(rb_node, struct interval_tree_node, rb);
                    interval_tree_sub(&taint_interval_tree_before, node->interval);
                    rb_node = rb_next(rb_node);
                }


                rb_node = rb_first(&taint_interval_tree_before);

                while(rb_node != NULL)
                {
                    node = rb_entry(rb_node, struct interval_tree_node, rb);
                    taint_interval = node->interval;
                    jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_REMOVE_REG;
                    taint_update_register_callback_info(taint_analysis, current_color, current_reg_index,
                                                      taint_interval,
                                                      UNTAINT_EVENT);
                    rb_node = rb_next(rb_node);
                }
            }
        }
      """

      CODE_PREPARE_ANALYSE_MEM = r"""
      current_mem_addr = %s;
      current_mem_size = %d;
      taint_interval.start = current_mem_addr;
      taint_interval.last = current_mem_addr + (current_mem_size - 1);
      interval_tree_free(&taint_interval_tree);
      taint_interval_tree = interval_tree_new();
      interval_tree_free(&taint_interval_tree_before);
      taint_interval_tree_before = taint_get_memory(taint_analysis, current_color, taint_interval);
      """

      CODE_TAINT_MEM = r"""
        if (fully_tainted)
        {
            taint_interval.start = current_mem_addr;
            taint_interval.last = current_mem_addr + (current_mem_size - 1);
            taint_memory_generic_access(taint_analysis,current_color, taint_interval, ADD);
            if ( taint_analysis->colors[current_color].callback_info->exception_flag
                 & DO_TAINT_MEM_CB )
            {
                jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_ADD_MEM;
                taint_update_memory_callback_info(taint_analysis,
                                                  current_color,
                                                  taint_interval,
                                                  TAINT_EVENT);
            }
        }
        else
        {
            // Remove previous taint
            rb_node = rb_first(&taint_interval_tree_before);

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                taint_interval = node->interval;
                taint_memory_generic_access(taint_analysis,current_color, taint_interval, REMOVE);
                rb_node = rb_next(rb_node);
            }

            // Add new taint
            rb_node = rb_first(&taint_interval_tree);

            while(rb_node != NULL)
            {
                node = rb_entry(rb_node, struct interval_tree_node, rb);
                taint_interval.start = current_mem_addr + node->interval.start;
                taint_interval.last = current_mem_addr + node->interval.last;
                taint_memory_generic_access(taint_analysis,current_color, taint_interval, ADD);
                rb_node = rb_next(rb_node);
                // Update TAINT callback information
                if ( taint_analysis->colors[current_color].callback_info->exception_flag
                     & DO_TAINT_MEM_CB )
                {
                    jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_ADD_MEM;
                    taint_update_memory_callback_info(taint_analysis,
                                                      current_color,
                                                      taint_interval,
                                                      TAINT_EVENT);
                }
            }

            // Update untaint callback information
            if ( taint_analysis->colors[current_color].callback_info->exception_flag
                 & DO_UNTAINT_MEM_CB )
            {
                rb_node = rb_first(&taint_interval_tree);

                while(rb_node != NULL)
                {
                    node = rb_entry(rb_node, struct interval_tree_node, rb);
                    interval_tmp.start = node->interval.start + current_mem_addr;
                    interval_tmp.last = node->interval.last + current_mem_addr;
                    interval_tree_sub(&taint_interval_tree_before, interval_tmp);
                    rb_node = rb_next(rb_node);
                }


                rb_node = rb_first(&taint_interval_tree_before);

                while(rb_node != NULL)
                {
                    node = rb_entry(rb_node, struct interval_tree_node, rb);
                    taint_interval = node->interval;
                    jitcpu->pyvm->vm_mngr.exception_flags |= EXCEPT_TAINT_REMOVE_MEM;
                    taint_update_memory_callback_info(taint_analysis, current_color,
                                                      taint_interval,
                                                      UNTAINT_EVENT);
                    rb_node = rb_next(rb_node);
                }
            }
        }
      """

      CODE_UPDATE_INTERVALLE = r"""
      if (rb_first(&taint_interval_tree_tmp) != NULL)
      {
        rb_node = rb_first(&taint_interval_tree_tmp);

        while(rb_node != NULL)
        {
            node = rb_entry(rb_node, struct interval_tree_node, rb);
            interval_tmp.start = node->interval.start+current_compose_start-taint_interval.start;
            interval_tmp.last = node->interval.last+current_compose_start-taint_interval.start;
            interval_tree_add(&taint_interval_tree, interval_tmp);
            rb_node = rb_next(rb_node);
        }
      }
      """

      CODE_UPDATE_INTERVALLE_MEM = r"""
      if (rb_first(&taint_interval_tree_tmp) != NULL)
      {
        rb_node = rb_first(&taint_interval_tree_tmp);

        while(rb_node != NULL)
        {
            node = rb_entry(rb_node, struct interval_tree_node, rb);
            interval_tmp.start = node->interval.start-taint_interval.start+current_compose_start;
            interval_tmp.last = node->interval.last-taint_interval.start+current_compose_start;
            interval_tree_add(&taint_interval_tree, interval_tmp);
            rb_node = rb_next(rb_node);
        }
      }
      """

      CODE_EXCEPTION_TAINT = r"""
      // Check taint analysis exceptions
      if (VM_exception_flag & EXCEPT_TAINT) {
          // When DST_value == 0 we do not want to raise exception.
          // If we raise an exception in this case, the execution will try to
          // continue at address 0 after exception is handled.
          // DST_value == 0 when a branching is occurring within an instruction
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

      def get_detailed_read_elements(self, dst, src):
          """TODO
            - retrieve:
                - ExprMem and ExprId in src
                - addr in src and dst
            - handle
                - ExprOp
                    - elements goes in "full"
                        -> could do something more clever
                - ExprCond
                    - elements of conds goes in "full"
                    - elements of src1 and src2 could go in "composition" but not sure
                - ExprCompose
                    - each elements are analyse with as a new entry in "composition"
                - ExprSlice
                    - Keep ExprSlice(ExprId)

                reads:
                    "start":
                    "full": if an element is tainted, dst gets fully tainted
                    "composition":
                        [(start, composition, full)]
                            interval tainted in elements taint interval [start, last] in dst
          """
          read_elements = dict()
          read_elements["full"] = get_read_elements_in_addr_with_real_size(dst, src)
          read_elements["elements"] = set()
          read_elements["composition"] = list()
          read_elements["start"] = 0

          src.visit(lambda x: visit_get_read_elements(x, read_elements["elements"]),
                    lambda x: test_cond_op_compose_slice_not_addr(x, read_elements))

          return read_elements

      def gen_segm2addr(self, expr, prefetchers):
          """ Properly convert ExprMem to C """
          ptr = expr.ptr.replace_expr(prefetchers)
          new_expr = ExprMem(ptr, expr.size)
          return self.id_to_c(new_expr.ptr)

      def gen_check_taint_exception(self, address):
          dst = self.dst_to_c(address)
          return (self.CODE_EXCEPTION_TAINT % (self.C_PC, dst)).split('\n')

      def gen_get_register_taint(self, reg_name, start, end):
          # NOTE: end/8-1 -> from size in bits to end in bytes
          return (self.CODE_GET_REG_TAINT % (start / 8,
                                             end / 8 - 1,
                                             self.regs_index[reg_name])).split('\n')

      def gen_get_memory_taint(self, start_addr, size):
          return self.CODE_GET_MEM_TAINT % (start_addr,
                                            size)

      def gen_taint_calculation_from_other_elements(self, elements, start, prefetchers):
          c_code = []

          c_code.append("if (!fully_tainted) {")
          c_code.append("current_compose_start = %d;" % start)
          for element in elements:
              if ("IRDst" in str(element)) or ("loc_" in str(element)):
                  pass # NOTE: taint_get_register return 0 in this case but there
                       # is no need to generate this useless code
              elif element.is_slice():
                  c_code += self.gen_get_register_taint(str(element.arg),
                                                        element.start,
                                                        element.stop)
                  c_code += (self.CODE_UPDATE_INTERVALLE).split('\n')
              elif element.is_mem():
                  start = self.gen_segm2addr(element, prefetchers)
                  size = element.size / 8 # We use bytes for size
                  c_code.append(self.gen_get_memory_taint(start, size))
                  c_code += (self.CODE_UPDATE_INTERVALLE_MEM).split('\n')
              elif element.is_id():
                  c_code.append(self.gen_get_register_taint(str(element),
                                                            0,
                                                            element.size))
                  c_code += (self.CODE_UPDATE_INTERVALLE).split('\n')
              else:
                  raise NotImplementedError("Taint analysis: do not know how to \
                          handle expression type %s",
                                            type(element))
          c_code.append("}")

          return c_code

      def gen_taint_calculation_from_full_elements(self, full_elements, prefetchers):
          c_code = []

          for element in full_elements:
              if ("IRDst" in str(element)) or ("loc_" in str(element)):
                  pass # NOTE: taint_get_register return 0 in this case but there
                       # is no need to generate this useless code
              elif element.is_slice():
                  c_code += self.gen_get_register_taint(str(element.arg),
                                                        element.start,
                                                        element.stop)
                  c_code += (self.CODE_CHECK_FULLY_TAINTED).split('\n')
              elif element.is_mem():
                  start = self.gen_segm2addr(element, prefetchers)
                  size = element.size/8 # We use bytes for size
                  c_code.append(self.gen_get_memory_taint(start, size))
                  c_code += (self.CODE_CHECK_FULLY_TAINTED).split('\n')
              elif element.is_id():
                  c_code += self.gen_get_register_taint(str(element),
                                                        0,
                                                        element.size)
                  c_code += (self.CODE_CHECK_FULLY_TAINTED).split('\n')
              else:
                  raise NotImplementedError("Taint analysis: do not know how to \
                          handle expression type %s",
                                            type(element))
          return c_code

      def gen_taint_calculation_from_read_elements(self, read_elements, prefetchers):
          c_code = [] 

          for composant in read_elements:
              c_code += self.gen_taint_calculation_from_full_elements(composant["full"], prefetchers)
              c_code += self.gen_taint_calculation_from_other_elements(composant["elements"],
                                                                       composant["start"],
                                                                       prefetchers)
              if "composition" in composant:
                  c_code += self.gen_taint_calculation_from_read_elements(composant["composition"], prefetchers)

          return c_code

      def gen_taint_calculation(self, src, prefetchers, dst=None):
          c_code = []
          c_code.append("fully_tainted = 0;")

          read_elements = self.get_detailed_read_elements(dst, src)

          c_code += self.gen_taint_calculation_from_read_elements([read_elements], prefetchers)

          return c_code

      def gen_analyse_mem(self, dst, src, prefetchers):
          c_code = []

          start = self.gen_segm2addr(dst, prefetchers)
          size = dst.size/8 # We use a size in byte not bit

          c_code.append("// Analyse mem")
          c_code.append(self.CODE_PREPARE_ANALYSE_MEM % (start, size))
          c_code += self.gen_taint_calculation(src, prefetchers, dst)
          c_code += self.CODE_TAINT_MEM.split('\n')

          return c_code

      def gen_analyse_reg(self, dst, src, prefetchers):
          c_code = []

          c_code.append("// Analyse reg")
          c_code += (self.CODE_PREPARE_ANALYSE_REG % ((dst.size/8 - 1), self.regs_index[str(dst)])).split('\n')
          c_code += self.gen_taint_calculation(src, prefetchers)
          c_code += self.CODE_TAINT_REG.split('\n')

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
          c_code.append("} else {")
          c_code.append("\tdo_not_clean_taint_cb_info = 1;")
          c_code.append("}")

          return c_code

      def gen_taint(self, assignblk, prefetchers):
          c_taint = []

          for dst, src in assignblk.iteritems():
              c_taint.append("// Analysing %s = %s " % (dst, src))
              c_taint.append("for (current_color = 0 ; current_color < taint_analysis->nb_colors ; current_color++)")
              c_taint.append("{")
              if dst.is_mem():
                  c_taint += self.gen_analyse_mem(dst, src, prefetchers)
              elif ("IRDst" not in str(dst)) and ("loc_" not in str(dst)):
                  c_taint += self.gen_analyse_reg(dst, src, prefetchers)
              else:
                  c_taint.append("// Not tainting %s for now" % (dst))
              c_taint.append("}")

          return c_taint

      def gen_c_assignments(self, assignblk):
          """
          Return C information used to generate the C code of the @assignblk
          Only add c_taint compare to the parent method
          @assignblk: an AssignBlock instance
          """

          self.c_taint = []
          prefetchers = self.get_mem_prefetch(assignblk) # XXX: could be optimised, this is already done in G_Gen.gen_c_assignments
          self.c_taint = self.gen_taint(assignblk, prefetchers) # XXX: for convenience we use a attribute for c_taint

          return super(TaintGen, self).gen_c_assignments(assignblk)

      def gen_c_code(self, attrib, c_dst, c_assignmnts):
          """
          Generate the C code for assignblk.
          Only add taint analysis C code compare to the parent method
          @attrib: Attributes instance
          @c_dst: irdst C code
          """

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

def get_read_elements_in_addr_with_real_size(dst, src):
  mem_elements = set()
  addr_elements = set()
  src.visit(lambda x: visit_get_mem_elements(x, mem_elements))
  if dst and dst.is_mem():
      # If dst is an ExprMem, Expr composing its address can spread taint
      # to the ExprMem
      mem_elements.add(dst.ptr)

  for element in mem_elements:
      element.visit(lambda x: visit_get_read_elements_with_real_size(x,
                                                                     addr_elements),
                    lambda x: test_id_slice(x, addr_elements))

  return addr_elements

def visit_get_mem_elements(expr, mem):
    if expr.is_mem():
        mem.add(expr.ptr)
    return expr

def visit_get_read_elements(expr, read):
    if expr.is_id():
        read.add(expr)
    elif expr.is_mem():
        read.add(expr)
    return expr

def visit_get_read_elements_with_real_size(expr, read):
    if expr.is_id():
        read.add(expr)
    elif expr.is_mem():
        read.add(expr)
    return expr

def test_id_slice(expr, read):
    if expr.is_slice():
        if expr.arg.is_id():
            read.add(expr)
            return False
    return True

def test_cond_op_compose_slice_not_addr(expr, read):
    if expr.is_cond():
        # TODO: expr.src1 -> ???
        # TODO: expr.src2 -> ???
        # expr.cond -> FULL
        expr.cond.visit(lambda x: visit_get_read_elements_with_real_size(x, read["full"]),
                        lambda x: test_id_slice(x, read["full"]))
        return False
    elif expr.is_op():
        # expr.args -> FULL
        # XXX: could test some known op ('+' for example)
        for element in expr.args:
            element.visit(lambda x: visit_get_read_elements_with_real_size(x, read["full"]),
                          lambda x: test_id_slice(x, read["full"]))
        return False
    elif expr.is_compose():
        # expr.args -> COMPOSITION
        old_start = read["start"]
        new_last = old_start
        for element in expr.args:
            new_start = new_last 
            new_last = new_start + (element.size/8 - 1)
            new_composition = dict()
            new_composition["start"]  = new_start
            new_composition["full"] = get_read_elements_in_addr_with_real_size(None, element)
            new_composition["elements"] = set()
            new_composition["composition"] = list()
            read["composition"].append(new_composition)
            element.visit(lambda x: visit_get_read_elements(x, new_composition["elements"]),
                          lambda x: test_cond_op_compose_slice_not_addr(x, new_composition))
            new_last += 1
            
        return False
    elif expr.is_slice():
        if expr.arg.is_id():
            read["elements"].add(expr)
            return False
    elif expr.is_mem():
        read["elements"].add(expr)
        return False
    #else:
    #    only ExprInt left
    return True

def empty_cache(jitter):
    """ Empty the cache directory in order to create new code """

    # TODO: use other cache for taint jitter instead of deleting the normal
    # one...
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
            print("[Color:%s] Taint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t+ %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_REG))
    return True

def on_untaint_register(jitter):
    for color in range(jitter.nb_colors):
        last_regs = jitter.cpu.last_untainted_registers(color)
        if last_regs:
            print("[Color:%s] Untaint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t- %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_REG))
    is_taint_vanished(jitter)
    return True

def on_taint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.cpu.last_tainted_memory(color)
        if last_mem:
            print("[Color:%s] Taint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_ADD_MEM))
    return True

def on_untaint_memory(jitter):
    for color in range(jitter.nb_colors):
        last_mem = jitter.cpu.last_untainted_memory(color)
        if last_mem:
            print("[Color%s] Untaint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REMOVE_MEM))
    is_taint_vanished(jitter)
    return True

def display_all_taint(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.cpu.get_all_taint(color)
        print("\n","_"*20)
        print("Color: %s" % (color))
        print("_"*20)
        print("Registers:")
        for reg_id, intervals in regs:
            print("\t* %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
        print("-"*20)
        print("Memory:")
        print(interval(mems))
        print("_"*20,"\n")

def is_taint_vanished(jitter):
    for color in range(jitter.nb_colors):
        regs, mems = jitter.cpu.get_all_taint(color)
        if regs or mems:
            return; # There is still some taint
    print("\n\n/!\\ All taint is gone ! /!\\\n\n")

