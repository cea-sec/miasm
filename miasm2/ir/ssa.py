import miasm2.expression.expression as m2_expr
from miasm2.expression.expression_dissector import ExprDissector
from miasm2.ir.ir import AssignBlock, irbloc


class SSA(object):
    """
    Generic class for static single assignment (SSA) transformation

    Handling of
    - variable generation
    - variable renaming
    - conversion of an IRA block into SSA

    Variables will be renamed to <variable>.<index>, whereby the
    index will be increased in every definition of <variable>.

    Memory expressions are stateless. The addresses are in SSA form,
    but memory aliasing will occur. For instance, if it holds
    that RAX == RBX.0 + (-0x8) and

    @64[RBX.0 + (-0x8)] = RDX
    RCX.0 = @64[RAX],

    then it cannot be tracked that RCX.0 == RDX.
    """

    def __init__(self, ira):
        """
        Initialises generic class for SSA
        :param ira: instance of IRA
        """
        # IRA instance
        self.ira = ira

        # SSA blocks
        self.blocks = dict()

        # stack for RHS
        self._stack_rhs = dict()
        # stack for LHS
        self._stack_lhs = dict()

        # dict of SSA expressions
        self.expressions = dict()

        # architecture variables
        regs = self.ira.arch.regs.all_regs_ids
        irdst = self.ira.IRDst
        # class for parsing expressions
        self._expr_dissect = ExprDissector(regs, irdst)

    def transform(self, *args, **kwargs):
        """Transforms into SSA"""
        raise NotImplementedError("")

    def get_block(self, block):
        """
        Returns an IRA block
        :param block: asm_label
        :return: IRA block
        """
        # block has not been copied
        if block not in self.blocks:
            ib = self._copy_block(block)
        else:
            ib = self.blocks[block]

        return ib

    @staticmethod
    def reverse_variable(v):
        """
        Transforms a variable in SSA form into non-SSA form
        :param v: ExprId, variable in SSA form
        :return: ExprId, variable in non-SSA form
        """
        name = v.name.split(".")[0]
        return m2_expr.ExprId(name, v.size)

    def reset(self):
        """Resets SSA transformation"""
        self.blocks = dict()
        self.expressions = dict()
        self._stack_rhs = dict()
        self._stack_lhs = dict()

    def _gen_var_expr(self, v, stack):
        """
        Generates a variable expression in SSA form
        :param v: variable expression which will be translated
        :param stack: self._stack_rhs or self._stack_lhs
        :return: variable expression in SSA form
        """
        index = stack[v]
        name = v.name + "." + str(index)
        e = m2_expr.ExprId(name, v.size)

        return e

    def _transform_var_rhs(self, v):
        """
        Transforms a variable on the right hand side into SSA
        :param v: variable
        :return: transformed variable
        """
        # variable has never been on the LHS
        if v not in self._stack_rhs:
            return v
        # variable has been on the LHS
        else:
            stack = self._stack_rhs
            return self._gen_var_expr(v, stack)

    def _transform_var_lhs(self, v):
        """
        Transforms a variable on the left hand side into SSA
        :param v: variable
        :return: transformed variable
        """
        # check if variable has already been on the LHS
        if v not in self._stack_lhs:
            self._stack_lhs[v] = 0
        # save last value for RHS transformation
        self._stack_rhs[v] = self._stack_lhs[v]

        # generate SSA expression
        stack = self._stack_lhs
        e = self._gen_var_expr(v, stack)

        return e

    def _transform_expression_lhs(self, dst):
        """
        Transforms an expression on the left hand side into SSA
        :param dst: expression
        :return: expression in SSA form
        """
        if isinstance(dst, m2_expr.ExprMem):
            # transform with last RHS instance
            e = self._transform_expression_rhs(dst)
        else:
            # transform LHS
            e = self._transform_var_lhs(dst)

            # increase SSA variable counter
            self._stack_lhs[dst] += 1

        return e

    def _transform_expression_rhs(self, src):
        """
        Transforms an expression on the right hand side into SSA
        :param src: expression
        :return: expression in SSA form
        """
        # dissect expression in variables
        variables = self._expr_dissect.variables(src)
        src_ssa = src
        # transform variables
        for v in variables:
            v_ssa = self._transform_var_rhs(v)
            src_ssa = src_ssa.replace_expr({v: v_ssa})

        return src_ssa

    @staticmethod
    def _parallel_instructions(assignblk):
        """
        Extracts the instruction from a AssignBlock.

        Since instructions in a AssignBlock are evaluated
        in parallel, memory instructions on the left hand
        side will be inserted into the start of the list.
        Then, memory instruction on the LHS will be
        transformed firstly.

        :param assignblk: assignblock
        :return: sorted list of expressions
        """
        instructions = []
        for dst in assignblk:
            # dst = src
            aff = m2_expr.ExprAff(dst, assignblk[dst])
            # insert memory expression into start of list
            if isinstance(dst, m2_expr.ExprMem):
                instructions.insert(0, aff)
            else:
                instructions.append(aff)

        return instructions

    @staticmethod
    def _convert_block(ib, l):
        """
        Transforms an IRA block inplace into SSA
        :param ib: IRA block to be transformed
        :param l: list of SSA expressions
        """
        # iterator over SSA expressions
        ssa_iter = iter(l)
        # walk over IR blocks' assignblocks
        for index, assignblk in enumerate(ib.irs):
            # list of instructions
            instructions = []
            # insert SSA instructions
            for dst in assignblk:
                instructions.append(ssa_iter.next())
            # replace instructions of assignblock in IRA block
            ib.irs[index] = AssignBlock(instructions)

    def _copy_block(self, block):
        """
        Returns a copy on an IRA block
        :param block: asm_label
        :return: IRA block
        """
        # retrieve IRA block
        ib = self.ira.get_bloc(block)

        # copy IRA block
        irs = [assignblk.copy() for assignblk in ib.irs]
        ib_ssa = irbloc(ib.label, irs)

        # set next block
        ib_ssa.dst = ib.dst.copy()

        # add to SSA blocks dict
        self.blocks.update({ib_ssa.label: ib_ssa})

        return ib_ssa

    def _rename_expressions(self, block):
        """
        Transforms variables and expressions
        of an IRA block into SSA.

        IR representations of an assembly instruction are evaluated
        in parallel. Thus, RHS and LHS instructions will be performed
        separately.
        :param block: IRA block label
        """
        # list of IRA block's SSA expressions
        ssa_expressions_block = []

        # retrieve IRA block
        ib = self.get_block(block)

        # iterate block's IR expressions
        for assignblk in ib.irs:
            # list of parallel instructions
            instructions = self._parallel_instructions(assignblk)
            # list for transformed RHS expressions
            rhs = []

            # transform RHS
            for e in instructions:
                src = e.src
                src_ssa = self._transform_expression_rhs(src)
                # save transformed RHS
                rhs.append(src_ssa)

            # transform LHS
            for e in instructions:
                dst = e.dst
                dst_ssa = self._transform_expression_lhs(dst)

                # retrieve corresponding RHS expression
                src_ssa = rhs.pop(0)

                # rebuild SSA expression
                e = m2_expr.ExprAff(dst_ssa, src_ssa)
                self.expressions[dst_ssa] = src_ssa

                # append ssa expression to list
                ssa_expressions_block.append(e)

        # replace blocks IR expressions with corresponding SSA transformations
        self._convert_block(ib, ssa_expressions_block)


class SSABlock(SSA):
    """
    SSA transformation on block level

    It handles
    - transformation of a single IRA block into SSA
    - reassembling an SSA expression into a non-SSA
      expression through iterative resolving of the RHS
    """

    def transform(self, block):
        """
        Transforms a block into SSA form
        :param block: IRA block label
        """
        self._rename_expressions(block)

    def reassemble_expr(self, e):
        """
        Reassembles an expression in SSA form into a solely non-SSA expression
        :param e: expression
        :return: non-SSA expression
        """
        # worklist
        todo = {e.copy()}

        while todo:
            # current expression
            cur = todo.pop()
            # RHS of current expression
            cur_rhs = self.expressions[cur]

            # replace cur with RHS in e
            e = e.replace_expr({cur: cur_rhs})

            # parse ExprIDs on RHS
            ids_rhs = self._expr_dissect.id(cur_rhs)

            # add RHS ids to worklist
            for id_rhs in ids_rhs:
                if id_rhs in self.expressions:
                    todo.add(id_rhs)
        return e


class SSAPath(SSABlock):
    """
    SSA transformation on path level

    It handles
    - transformation of a path of IRA blocks into SSA
    """

    def transform(self, path):
        """
        Transforms a path into SSA
        :param path: list of IRA block labels
        """
        for block in path:
            self._rename_expressions(block)


class SSADiGraph(SSA):
    """
    SSA transformation on DiGraph level

    It handles
    - transformation of a DiGraph into SSA
    - generation, insertion and filling of phi nodes

    The implemented SSA form is known as minimal SSA.
    """

    def __init__(self, ira):
        """
        Initialises SSA class for directed acyclic graphs
        :param ira: instance of IRA
        """
        super(SSADiGraph, self).__init__(ira)

        # variable definitions
        self.defs = {}

        # dict of blocks' phi nodes
        self._phinodes = dict()

        # IRA control flow graph
        self.graph = ira.graph

    def transform(self, head):
        """Transforms into SSA"""
        self._init_variable_defs(head)
        self._place_phi(head)
        self._rename(head)
        self._insert_phi()
        self._convert_phi()

    def reset(self):
        """Resets SSA transformation"""
        super(SSADiGraph, self).reset()
        self.defs = {}
        self._phinodes = dict()

    def _init_variable_defs(self, head):
        """
        Initialises all variable definitions and
        assigns the corresponding IRA blocks.

        All variable definitions in self.defs contain
        a set of IRA blocks in which the variable gets assigned
        """
        # architecture's instruction pointer
        instruction_pointer = set(self.ira.arch.pc.values() + [self.ira.IRDst])

        for block in self.graph.walk_depth_first_forward(head):
            ib = self.get_block(block)
            # blocks IR expressions
            ir_expressions = (m2_expr.ExprAff(dst, assignblk[dst])
                              for assignblk in ib.irs for dst in assignblk)
            for e in ir_expressions:
                # enforce ExprId
                if isinstance(e.dst, m2_expr.ExprId):
                    # exclude architecture's instruction pointer
                    if e.dst in instruction_pointer:
                        continue
                    if e.dst not in self.defs:
                        self.defs[e.dst] = set()
                    self.defs[e.dst].add(ib.label)

    def _place_phi(self, head):
        """
        For all blocks, empty phi functions will be placed for every
        variable in the block's dominance frontier.

        self.phinodes contains a dict for every block in the
        dominance frontier. In this dict, each variable
        definition maps to its corresponding phi function.

        Source: Cytron, Ron, et al.
        "An efficient method of computing static single assignment form"
        Proceedings of the 16th ACM SIGPLAN-SIGACT symposium on
        Principles of programming languages (1989), p. 30
        """
        # dominance frontier
        frontier = self.graph.compute_dominance_frontier(head)

        for variable in self.defs:
            done = set()
            todo = set()
            intodo = set()

            for block in self.defs[variable]:
                todo.add(block)
                intodo.add(block)

            while todo:
                block = todo.pop()
                if block not in frontier:
                    continue

                # walk through block's dominance frontier
                for node in frontier[block]:
                    if node in done:
                        continue

                    # remember blocks that contain phi nodes
                    if node not in self._phinodes:
                        self._phinodes[node] = dict()

                    # place empty phi functions for a variable
                    e = self._gen_empty_phi(variable)
                    self._phinodes[node][variable] = e.src
                    done.add(node)

                    if node not in intodo:
                        intodo.add(node)
                        todo.add(node)

    @staticmethod
    def _gen_empty_phi(v):
        """
        Generates an empty phi function for a variable
        :param v: variable
        :return: ExprAff, empty phi function for v
        """
        phi = m2_expr.ExprId("phi", v.size)
        return m2_expr.ExprAff(v, phi)

    @staticmethod
    def _fill_phi(*args):
        """
        Fills a phi function with variables.

        phi(x.1, x.5, x.6)

        :param args: list of ExprId
        :return: ExprOp
        """
        return m2_expr.ExprOp("phi", *args)

    def _transform_phi_rhs(self, src):
        """
        Transforms an expression of a phi function on the
        right hand side into SSA
        :param src: expression of a phi function on RHS
        :return: expression in SSA form
        """
        # transform variable on RHS in non-SSA form
        e = self.reverse_variable(src)

        # transform into SSA form
        src_ssa = self._transform_expression_rhs(e)

        return src_ssa

    def _rename(self, head):
        """
        Transforms each variable expression in the CFG into SSA
        by traversing the dominator tree in depth-first search.

        1. Transform variables of phi functions on LHS into SSA
        2. Transform all non-phi expressions into SSA
        3. Update the successor's phi functions' RHS with current SSA variables
        4. Save current SSA variable stack for successors in the dominator tree

        Source: Cytron, Ron, et al.
        "An efficient method of computing static single assignment form"
        Proceedings of the 16th ACM SIGPLAN-SIGACT symposium on
        Principles of programming languages (1989), p. 31
        """
        # compute dominator tree
        dominator_tree = self.graph.compute_dominator_tree(head)

        # init SSA variable stack
        stack = [self._stack_rhs.copy()]

        # walk in DFS over the dominator tree
        for block in dominator_tree.walk_depth_first_forward(head):
            # restore SSA variable stack of the predecessor in the dominator tree
            self._stack_rhs = stack.pop().copy()

            '''Transform variables of phi functions on LHS into SSA'''
            self._rename_phi_lhs(block)

            '''Transform all non-phi expressions into SSA'''
            self._rename_expressions(block)

            '''Update the successor's phi functions' RHS with current SSA variables'''
            # walk over block's successors in the CFG
            for successor in self.graph.successors_iter(block):
                self._rename_phi_rhs(successor)

            '''Save current SSA variable stack for successors in the dominator tree'''
            for successor in dominator_tree.successors_iter(block):
                stack.append(self._stack_rhs.copy())

    def _rename_phi_lhs(self, block):
        """
        Transforms phi function's expressions of an IRA block
        on the left hand side into SSA
        :param block: IRA block label
        """
        if block in self._phinodes:
            # create temporary list of phi function assignments for inplace renaming
            tmp = list(self._phinodes[block])

            # iterate over all block's phi nodes
            for dst in tmp:
                # transform variables on LHS inplace
                self._phinodes[block][self._transform_expression_lhs(dst)] = self._phinodes[block].pop(dst)

    def _rename_phi_rhs(self, successor):
        """
        Transforms the right hand side of each successor's phi function
        into SSA. Each transformed expression of a phi function's
        right hand side is of the form

        phi(<var>.<index 1>, <var>.<index 2>, ..., <var>.<index n>)

        :param successor: label of block's direct successor in the CFG
        """
        # if successor is in block's dominance frontier
        if successor in self._phinodes:
            # walk over all variables on LHS
            for dst in self._phinodes[successor]:
                # transform RHS expression into SSA
                src = self._phinodes[successor][dst]
                src_ssa = self._transform_phi_rhs(dst)

                # phi function is empty
                if isinstance(src, m2_expr.ExprId) and src.name == "phi":
                    e = self._fill_phi(src_ssa)
                # phi function contains at least one value
                else:
                    e = self._fill_phi(src_ssa, *src.args)

                # update phi function
                self._phinodes[successor][dst] = e

    def _insert_phi(self):
        """Inserts phi functions into the list of SSA expressions"""
        for block in self._phinodes:
            for dst in self._phinodes[block]:
                self.expressions[dst] = self._phinodes[block][dst]

    def _convert_phi(self):
        """Inserts corresponding phi functions inplace
        into IRA block at the beginning"""
        for block in self._phinodes:
            ib = self.get_block(block)
            # list of instructions
            instructions = []
            # walk over all variables
            for dst in self._phinodes[block]:
                src = self._phinodes[block][dst]
                # build ssa expression
                e = m2_expr.ExprAff(dst, src)
                # insert SSA expression
                instructions.append(e)
            # create assignblock
            assignblk = AssignBlock(instructions)
            # insert at the beginning
            ib.irs.insert(0, assignblk)
