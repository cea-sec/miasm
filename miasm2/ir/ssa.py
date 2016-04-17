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
