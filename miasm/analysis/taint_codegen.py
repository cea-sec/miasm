from miasm.expression.expression import ExprMem

def makeTaintGen(C_Gen, ir_arch):
  class TaintGen(C_Gen):

      CODE_INIT_TAINT = r"""
      struct taint_t* taint_analysis = jitcpu->taint->taint;
      uint64_t current_color, current_mem_addr, current_mem_size,
      current_reg_size, current_reg_index, current_compose_start;
      struct rb_root taint_interval_tree_tmp, taint_interval_tree_new,
      taint_interval_tree_before;
      struct interval_tree_node *node;
      struct rb_node *rb_node;
      struct interval taint_interval;
      uint8_t do_not_clean_taint_cb_info = 1, fully_tainted;
      """

      CODE_INIT = CODE_INIT_TAINT + C_Gen.CODE_INIT

      CODE_GET_REG_TAINT = r"""
      taint_interval.start = %d;
      taint_interval.last = %d;
      taint_interval_tree_tmp = taint_get_register_color(taint_analysis,
                                                         current_color,
                                                         %s,
                                                         taint_interval
                                                         );
      """

      CODE_GET_MEM_TAINT = r"""
      taint_interval.start = %s;
      taint_interval.last = taint_interval.start + (%d - 1);
      taint_interval_tree_tmp = taint_get_memory(taint_analysis,
                                                 current_color,
                                                 taint_interval);
      """


      CODE_PREPARE_ANALYSE_REG = r"""
      taint_interval_tree_new = interval_tree_new();
      current_reg_size = %d;
      current_reg_index = %d;
      taint_interval.start = 0;
      taint_interval.last = current_reg_size;
      taint_interval_tree_before = taint_get_register_color(taint_analysis,
                                                            current_color,
                                                            current_reg_index,
                                                            taint_interval);
      fully_tainted = 0;
      """

      CODE_CHECK_FULLY_TAINTED = r"""
      if (rb_first(&taint_interval_tree_tmp) != NULL)
      {
          fully_tainted = 1;
      }
      """

      CODE_TAINT_REG = r"""
      taint_register(fully_tainted,
                     current_reg_index,
                     current_reg_size,
                     current_color,
                     taint_analysis,
                     &jitcpu->pyvm->vm_mngr,
                     &taint_interval_tree_before,
                     &taint_interval_tree_new);
      interval_tree_free(&taint_interval_tree_before);
      interval_tree_free(&taint_interval_tree_new);
      """

      CODE_PREPARE_ANALYSE_MEM = r"""
      current_mem_addr = %s;
      current_mem_size = %d;
      taint_interval.start = current_mem_addr;
      taint_interval.last = current_mem_addr + (current_mem_size - 1);
      taint_interval_tree_new = interval_tree_new();
      taint_interval_tree_before = taint_get_memory(taint_analysis,
                                                    current_color,
                                                    taint_interval);
      fully_tainted = 0;
      """

      CODE_TAINT_MEM = r"""
      taint_memory(fully_tainted,
                   current_mem_addr,
                   current_mem_size,
                   current_color,
                   taint_analysis,
                   &jitcpu->pyvm->vm_mngr,
                   &taint_interval_tree_before,
                   &taint_interval_tree_new);
      interval_tree_free(&taint_interval_tree_before);
      interval_tree_free(&taint_interval_tree_new);
      """

      CODE_UPDATE_INTERVAL = r"""
      interval_tree_merge(&taint_interval_tree_new,
                          &taint_interval_tree_tmp,
                          current_compose_start-taint_interval.start);
      interval_tree_free(&taint_interval_tree_tmp);
      """

      CODE_EXCEPTION_TAINT = r"""
      // Check taint analysis exceptions
      if (VM_exception_flag & EXCEPT_TAINT) {
          /*
             When DST_value == 0 we do not want to raise exception.
             If we raise an exception in this case, the execution will try to
             continue at address 0 after exception is handled.
             DST_value == 0 when a branching is occurring within an instruction
             (LODSD for example). In this case, we want to raise an exception
             only at the end of the instruction, not during branching.
          */
          if (DST_value) {
              %s = %s;
              BlockDst->address = DST_value;
              return JIT_RET_EXCEPTION;
          } else {
             do_not_clean_taint_cb_info = 0;
          }
      }
      """

      CODE_CHECK_CLEAN_CB = r"""
      /*
         When DST_value == 0, we do not raise exception.
         This mean that the exception will be raised at the 'real' end of
         the instruction.
         In this case, we do not want to clean callback information because
         we want to be able to retrieve them when we actually raise the
         exception.
      */
      if (do_not_clean_taint_cb_info) {
          taint_clean_all_callback_info(taint_analysis);
      } else {
          do_not_clean_taint_cb_info = 1;
      }
      """

      def get_detailed_read_elements(self, dst, src):
          """Retrieve read elements from @src and @dst of an ExprAssign

          Read elements can be ExprMem or ExprId from @src.
          Furthermore if @dst is an ExprMem, we retrieve any ExprMem or ExprId
          of this ExprMem address (i.e. ExprMem.ptr).

          This function will not only return a list of read elements but a
          structure that will give us information about which byte of read
          elements is influencing each byte of @dst.

          To do so, the structure is organised like this:

          {
            full: []
            elements:
            start:
            composition:
            {
              [
                {
                  full: []
                  elements:
                  start:
                  composition: ...
                },

                ...

                {
                  full: []
                  elements:
                  start:
                  composition: ...
                }
              ]
            }
          }

          Elements in "full" fully taint current section of @dst if any taint
          is found in them.

          For elements in "elements" only bytes found with taint propagate
          taint to equivalent bytes in @dst.


          Elements put in "full":
            - elements of addresses in @src (and @dst if it is an ExprMem)
            - elements in ExprOp (XXX: could be more precise for some ExprOp)
            - elements in condition of ExprCond (XXX: what about src1 and src2 ?)

          When an ExprCompose is encounter, a new entry in "composition" is added.

          ExprSlice of ExprId will be keep as is to be able to tell which bytes
          of the ExprId need to be analyse.
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
          ptr = expr.ptr.replace_expr(prefetchers)
          new_expr = ExprMem(ptr, expr.size)
          return self.id_to_c(new_expr.ptr)

      def gen_check_taint_exception(self, address):
          dst = self.dst_to_c(address)
          return self.CODE_EXCEPTION_TAINT % (self.C_PC, dst)

      def gen_get_register_taint(self, reg_name, start, end):
          return self.CODE_GET_REG_TAINT % (start / 8,
                                            end / 8 - 1,
                                            self.regs_index[reg_name])

      def gen_get_memory_taint(self, start_addr, size):
          return self.CODE_GET_MEM_TAINT % (start_addr,
                                            size)

      def gen_taint_calculation_from_read_elements(self, elements, prefetchers, full):
          c_code = []

          for element in elements:
              if ("IRDst" in str(element)) or ("loc_" in str(element)):
                  continue
              elif element.is_slice():
                  c_code.append(self.gen_get_register_taint(str(element.arg),
                                                            element.start,
                                                            element.stop))
              elif element.is_mem():
                  start = self.gen_segm2addr(element, prefetchers)
                  size = element.size / 8
                  c_code.append(self.gen_get_memory_taint(start, size))
              elif element.is_id():
                  c_code.append(self.gen_get_register_taint(str(element),
                                                            0,
                                                            element.size))
              else:
                  raise NotImplementedError("Taint analysis: do not know how to "
                                            "handle expression type %s",
                                            type(element))

              if full:
                  c_code.append(self.CODE_CHECK_FULLY_TAINTED)
              else:
                  c_code.append(self.CODE_UPDATE_INTERVAL)
          return c_code

      def gen_taint_calculation_from_all_read_elements(self, read_elements, prefetchers):
          c_code = []

          for composant in read_elements:
              c_code += self.gen_taint_calculation_from_read_elements(composant["full"],
                                                                      prefetchers,
                                                                      full=True)

              c_code.append("if (!fully_tainted) {")
              c_code.append("current_compose_start = %d;" % composant["start"])
              c_code += self.gen_taint_calculation_from_read_elements(composant["elements"],
                                                                      prefetchers,
                                                                      full=False)
              c_code.append("}")

              if "composition" in composant:
                  c_code += self.gen_taint_calculation_from_all_read_elements(composant["composition"],
                                                                              prefetchers)

          return c_code

      def gen_taint_calculation(self, src, prefetchers, dst=None):
          read_elements = self.get_detailed_read_elements(dst, src)
          return self.gen_taint_calculation_from_all_read_elements([read_elements], prefetchers)

      def gen_analyse_mem(self, dst, src, prefetchers):
          c_code = []

          start = self.gen_segm2addr(dst, prefetchers)
          size = dst.size / 8

          c_code.append("// Analyse mem")
          c_code.append(self.CODE_PREPARE_ANALYSE_MEM % (start, size))
          c_code += self.gen_taint_calculation(src, prefetchers, dst)
          c_code.append(self.CODE_TAINT_MEM)

          return c_code

      def gen_analyse_reg(self, dst, src, prefetchers):
          c_code = []

          c_code.append("// Analyse reg")
          c_code.append(self.CODE_PREPARE_ANALYSE_REG % ((dst.size/8 - 1), self.regs_index[str(dst)]))
          c_code += self.gen_taint_calculation(src, prefetchers)
          c_code.append(self.CODE_TAINT_REG)

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
            new_out.append(self.CODE_CHECK_CLEAN_CB)
            new_out += self.c_taint
            new_out += out[1:exception_index]

            # Taint callbacks
            new_out.append(self.gen_check_taint_exception(attrib.instr.offset))
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
        expr.cond.visit(lambda x: visit_get_read_elements_with_real_size(x, read["full"]),
                        lambda x: test_id_slice(x, read["full"]))
        return False
    elif expr.is_op():
        for element in expr.args:
            element.visit(lambda x: visit_get_read_elements_with_real_size(x, read["full"]),
                          lambda x: test_id_slice(x, read["full"]))
        return False
    elif expr.is_compose():
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
