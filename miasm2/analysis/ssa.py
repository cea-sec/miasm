from collections import deque

from miasm2.expression.expression import ExprId, ExprAff, ExprOp, get_expr_ids
from miasm2.ir.ir import AssignBlock, IRBlock



class SSA(object):
    """
    Generic class for static single assignment (SSA) transformation

    Handling of
    - variable generation
    - variable renaming
    - conversion of an IRCFG block into SSA

    Variables will be renamed to <variable>.<index>, whereby the
    index will be increased in every definition of <variable>.

    Memory expressions are stateless. The addresses are in SSA form,
    but memory aliasing will occur. For instance, if it holds
    that RAX == RBX.0 + (-0x8) and

    @64[RBX.0 + (-0x8)] = RDX
    RCX.0 = @64[RAX],

    then it cannot be tracked that RCX.0 == RDX.
    """


    def __init__(self, ircfg):
        """
        Initialises generic class for SSA
        :param ircfg: instance of IRCFG
        """
        # IRCFG instance
        self.ircfg = ircfg

        # SSA blocks
        self.blocks = {}

        # stack for RHS
        self._stack_rhs = {}
        # stack for LHS
        self._stack_lhs = {}

        self._ssa_variable_to_expr = {}

        # dict of SSA expressions
        self.expressions = {}

        # dict of SSA to original location
        self.ssa_to_location = {}

        # Don't SSA IRDst
        self.immutable_ids = set([self.ircfg.IRDst])

    def get_regs(self, expr):
        return get_expr_ids(expr)

    def transform(self, *args, **kwargs):
        """Transforms into SSA"""
        raise NotImplementedError("Abstract method")

    def get_block(self, loc_key):
        """
        Returns an IRBlock
        :param loc_key: LocKey instance
        :return: IRBlock
        """
        irblock = self.ircfg.blocks.get(loc_key, None)

        return irblock

    def reverse_variable(self, ssa_var):
        """
        Transforms a variable in SSA form into non-SSA form
        :param ssa_var: ExprId, variable in SSA form
        :return: ExprId, variable in non-SSA form
        """
        expr = self._ssa_variable_to_expr.get(ssa_var, ssa_var)
        return expr

    def reset(self):
        """Resets SSA transformation"""
        self.blocks = {}
        self.expressions = {}
        self._stack_rhs = {}
        self._stack_lhs = {}
        self.ssa_to_location = {}

    def _gen_var_expr(self, expr, stack):
        """
        Generates a variable expression in SSA form
        :param expr: variable expression which will be translated
        :param stack: self._stack_rhs or self._stack_lhs
        :return: variable expression in SSA form
        """
        index = stack[expr]
        name = "%s.%d" % (expr.name, index)
        ssa_var = ExprId(name, expr.size)
        self._ssa_variable_to_expr[ssa_var] = expr

        return ssa_var

    def _transform_var_rhs(self, ssa_var):
        """
        Transforms a variable on the right hand side into SSA
        :param ssa_var: variable
        :return: transformed variable
        """
        # variable has never been on the LHS
        if ssa_var not in self._stack_rhs:
            return ssa_var
        # variable has been on the LHS
        stack = self._stack_rhs
        return self._gen_var_expr(ssa_var, stack)

    def _transform_var_lhs(self, expr):
        """
        Transforms a variable on the left hand side into SSA
        :param expr: variable
        :return: transformed variable
        """
        # check if variable has already been on the LHS
        if expr not in self._stack_lhs:
            self._stack_lhs[expr] = 0
        # save last value for RHS transformation
        self._stack_rhs[expr] = self._stack_lhs[expr]

        # generate SSA expression
        stack = self._stack_lhs
        ssa_var = self._gen_var_expr(expr, stack)

        return ssa_var

    def _transform_expression_lhs(self, dst):
        """
        Transforms an expression on the left hand side into SSA
        :param dst: expression
        :return: expression in SSA form
        """
        if dst.is_mem():
            # transform with last RHS instance
            ssa_var = self._transform_expression_rhs(dst)
        else:
            # transform LHS
            ssa_var = self._transform_var_lhs(dst)

            # increase SSA variable counter
            self._stack_lhs[dst] += 1

        return ssa_var

    def _transform_expression_rhs(self, src):
        """
        Transforms an expression on the right hand side into SSA
        :param src: expression
        :return: expression in SSA form
        """
        # dissect expression in variables
        variables = self.get_regs(src)
        src_ssa = src
        # transform variables
        for expr in variables:
            ssa_var = self._transform_var_rhs(expr)
            src_ssa = src_ssa.replace_expr({expr: ssa_var})

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
            aff = assignblk.dst2ExprAff(dst)
            # insert memory expression into start of list
            if dst.is_mem():
                instructions.insert(0, aff)
            else:
                instructions.append(aff)

        return instructions

    @staticmethod
    def _convert_block(irblock, ssa_list):
        """
        Transforms an IRBlock inplace into SSA
        :param irblock: IRBlock to be transformed
        :param ssa_list: list of SSA expressions
        """
        # iterator over SSA expressions
        ssa_iter = iter(ssa_list)
        new_irs = []
        # walk over IR blocks' assignblocks
        for assignblk in irblock.assignblks:
            # list of instructions
            instructions = []
            # insert SSA instructions
            for _ in assignblk:
                instructions.append(ssa_iter.next())
            # replace instructions of assignblock in IRBlock
            new_irs.append(AssignBlock(instructions, assignblk.instr))
        return IRBlock(irblock.loc_key, new_irs)

    def _rename_expressions(self, loc_key):
        """
        Transforms variables and expressions
        of an IRBlock into SSA.

        IR representations of an assembly instruction are evaluated
        in parallel. Thus, RHS and LHS instructions will be performed
        separately.
        :param loc_key: IRBlock loc_key
        """
        # list of IRBlock's SSA expressions
        ssa_expressions_block = []

        # retrieve IRBlock
        irblock = self.get_block(loc_key)
        if irblock is None:
            # Incomplete graph
            return

        # iterate block's IR expressions
        for index, assignblk in enumerate(irblock.assignblks):
            # list of parallel instructions
            instructions = self._parallel_instructions(assignblk)
            # list for transformed RHS expressions
            rhs = deque()

            # transform RHS
            for expr in instructions:
                src = expr.src
                src_ssa = self._transform_expression_rhs(src)
                # save transformed RHS
                rhs.append(src_ssa)

            # transform LHS
            for expr in instructions:
                if expr.dst in self.immutable_ids:
                    dst_ssa = expr.dst
                else:
                    dst_ssa = self._transform_expression_lhs(expr.dst)

                # retrieve corresponding RHS expression
                src_ssa = rhs.popleft()

                # rebuild SSA expression
                expr = ExprAff(dst_ssa, src_ssa)
                self.expressions[dst_ssa] = src_ssa
                self.ssa_to_location[dst_ssa] = (loc_key, index)


                # append ssa expression to list
                ssa_expressions_block.append(expr)

        # replace blocks IR expressions with corresponding SSA transformations
        new_irblock = self._convert_block(irblock, ssa_expressions_block)
        self.ircfg.blocks[loc_key] = new_irblock


class SSABlock(SSA):
    """
    SSA transformation on block level

    It handles
    - transformation of a single IRBlock into SSA
    - reassembling an SSA expression into a non-SSA
      expression through iterative resolving of the RHS
    """

    def transform(self, loc_key):
        """
        Transforms a block into SSA form
        :param loc_key: IRBlock loc_key
        """
        self._rename_expressions(loc_key)

    def reassemble_expr(self, expr):
        """
        Reassembles an expression in SSA form into a solely non-SSA expression
        :param expr: expression
        :return: non-SSA expression
        """
        # worklist
        todo = {expr.copy()}

        while todo:
            # current expression
            cur = todo.pop()
            # RHS of current expression
            cur_rhs = self.expressions[cur]

            # replace cur with RHS in expr
            expr = expr.replace_expr({cur: cur_rhs})

            # parse ExprIDs on RHS
            ids_rhs = self.get_regs(cur_rhs)

            # add RHS ids to worklist
            for id_rhs in ids_rhs:
                if id_rhs in self.expressions:
                    todo.add(id_rhs)
        return expr


class SSAPath(SSABlock):
    """
    SSA transformation on path level

    It handles
    - transformation of a path of IRBlocks into SSA
    """

    def transform(self, path):
        """
        Transforms a path into SSA
        :param path: list of IRBlock loc_key
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

    PHI_STR = 'Phi'


    def __init__(self, ircfg):
        """
        Initialises SSA class for directed graphs
        :param ircfg: instance of IRCFG
        """
        super(SSADiGraph, self).__init__(ircfg)

        # variable definitions
        self.defs = {}

        # dict of blocks' phi nodes
        self._phinodes = {}

        # IRCFG control flow graph
        self.graph = ircfg


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
        self._phinodes = {}

    def _init_variable_defs(self, head):
        """
        Initialises all variable definitions and
        assigns the corresponding IRBlocks.

        All variable definitions in self.defs contain
        a set of IRBlocks in which the variable gets assigned
        """

        for loc_key in self.graph.walk_depth_first_forward(head):
            irblock = self.get_block(loc_key)
            if irblock is None:
                # Incomplete graph
                continue

            # search for block's IR definitions/destinations
            for assignblk in irblock.assignblks:
                for dst in assignblk:
                    # enforce ExprId
                    if dst.is_id():
                        # exclude immutable ids
                        if dst in self.immutable_ids:
                            continue
                        # map variable definition to blocks
                        self.defs.setdefault(dst, set()).add(irblock.loc_key)

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

            for loc_key in self.defs[variable]:
                todo.add(loc_key)
                intodo.add(loc_key)

            while todo:
                loc_key = todo.pop()

                # walk through block's dominance frontier
                for node in frontier.get(loc_key, []):
                    if node in done:
                        continue

                    # place empty phi functions for a variable
                    empty_phi = self._gen_empty_phi(variable)

                    # add empty phi node for variable in node
                    self._phinodes.setdefault(node, {})[variable] = empty_phi.src

                    done.add(node)

                    if node not in intodo:
                        intodo.add(node)
                        todo.add(node)

    def _gen_empty_phi(self, expr):
        """
        Generates an empty phi function for a variable
        :param expr: variable
        :return: ExprAff, empty phi function for expr
        """
        phi = ExprId(self.PHI_STR, expr.size)
        return ExprAff(expr, phi)

    def _fill_phi(self, *args):
        """
        Fills a phi function with variables.

        phi(x.1, x.5, x.6)

        :param args: list of ExprId
        :return: ExprOp
        """
        return ExprOp(self.PHI_STR, *set(args))

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
        stack = [self._stack_rhs]

        # walk in DFS over the dominator tree
        for loc_key in dominator_tree.walk_depth_first_forward(head):
            # restore SSA variable stack of the predecessor in the dominator tree
            self._stack_rhs = stack.pop().copy()

            # Transform variables of phi functions on LHS into SSA
            self._rename_phi_lhs(loc_key)

            # Transform all non-phi expressions into SSA
            self._rename_expressions(loc_key)

            # Update the successor's phi functions' RHS with current SSA variables
            # walk over block's successors in the CFG
            for successor in self.graph.successors_iter(loc_key):
                self._rename_phi_rhs(successor)

            # Save current SSA variable stack for successors in the dominator tree
            for _ in dominator_tree.successors_iter(loc_key):
                stack.append(self._stack_rhs)

    def _rename_phi_lhs(self, loc_key):
        """
        Transforms phi function's expressions of an IRBlock
        on the left hand side into SSA
        :param loc_key: IRBlock loc_key
        """
        if loc_key in self._phinodes:
            # create temporary list of phi function assignments for inplace renaming
            tmp = list(self._phinodes[loc_key])

            # iterate over all block's phi nodes
            for dst in tmp:
                # transform variables on LHS inplace
                self._phinodes[loc_key][self._transform_expression_lhs(dst)] = self._phinodes[loc_key].pop(dst)

    def _rename_phi_rhs(self, successor):
        """
        Transforms the right hand side of each successor's phi function
        into SSA. Each transformed expression of a phi function's
        right hand side is of the form

        phi(<var>.<index 1>, <var>.<index 2>, ..., <var>.<index n>)

        :param successor: loc_key of block's direct successor in the CFG
        """
        # if successor is in block's dominance frontier
        if successor in self._phinodes:
            # walk over all variables on LHS
            for dst, src in self._phinodes[successor].iteritems():
                # transform variable on RHS in non-SSA form
                expr = self.reverse_variable(dst)
                # transform expr into it's SSA form using current stack
                src_ssa = self._transform_expression_rhs(expr)

                # Add src_ssa to phi args
                if src.is_id(self.PHI_STR):
                    # phi function is empty
                    expr = self._fill_phi(src_ssa)
                else:
                    # phi function contains at least one value
                    expr = self._fill_phi(src_ssa, *src.args)

                # update phi function
                self._phinodes[successor][dst] = expr

    def _insert_phi(self):
        """Inserts phi functions into the list of SSA expressions"""
        for loc_key in self._phinodes:
            for dst in self._phinodes[loc_key]:
                self.expressions[dst] = self._phinodes[loc_key][dst]

    def _convert_phi(self):
        """Inserts corresponding phi functions inplace
        into IRBlock at the beginning"""
        for loc_key in self._phinodes:
            irblock = self.get_block(loc_key)
            if irblock is None:
                continue
            assignblk = AssignBlock(self._phinodes[loc_key])
            # insert at the beginning
            new_irs = IRBlock(loc_key, [assignblk] + list(irblock.assignblks))
            self.ircfg.blocks[loc_key] = new_irs



def get_assignblk(graph, loc, index):
    """
    Return the dictionnary of the AssignBlock from @graph at location @loc at
    @index
    @graph: IRCFG instance
    @loc: Location instance
    @index: assignblock index
    """

    irblock = graph.blocks[loc]
    assignblks = irblock.assignblks
    assignblk = assignblks[index]
    assignblk_dct = dict(assignblk)
    return assignblk_dct


def set_assignblk(graph, loc, index, assignblk_dct):
    """
    Set the Assignblock in @graph at location @loc at @index using dictionnary
    @assignblk_dct

    @graph: IRCFG instance
    @loc: Location instance
    @index: assignblock index
    @assignblk_dct: dictionnary representing the AssignBlock
    """

    irblock = graph.blocks[loc]
    assignblks = list(irblock.assignblks)
    assignblk = assignblks[index]

    assignblks[index] = AssignBlock(
        assignblk_dct,
        assignblk.instr
    )
    new_irblock = IRBlock(loc, assignblks)
    return new_irblock


def remove_phi(ssa, head):
    """
    Remove Phi using naive algorithm
    Note: The _ssa_variable_to_expr must be up to date

    @ssa: a SSADiGraph instance
    @head: the loc_key of the graph head
    """

    phivar2var = {}

    all_ssa_vars = ssa._ssa_variable_to_expr

    # Retrive Phi nodes
    phi_nodes = []
    for irblock in ssa.graph.blocks.itervalues():
        for index, assignblk in enumerate(irblock):
            for dst, src in assignblk.iteritems():
                if src.is_op('Phi'):
                    phi_nodes.append((irblock.loc_key, index))


    for phi_loc, phi_index in phi_nodes:
        assignblk_dct = get_assignblk(ssa.graph, phi_loc, phi_index)
        for dst, src in assignblk_dct.iteritems():
            if src.is_op('Phi'):
                break
        else:
            raise RuntimeError('Cannot find phi?')
        node_src = src
        var = dst

        # Create new variable
        new_var = ExprId('var%d' % len(phivar2var), var.size)
        phivar2var[var] = new_var
        phi_sources = set(node_src.args)

        # Place var init for non ssa variables
        to_remove = set()
        for phi_source in list(phi_sources):
            if phi_source not in all_ssa_vars.union(phivar2var.values()):
                assignblk_dct = get_assignblk(ssa.graph, head, 0)
                assignblk_dct[new_var] = phi_source
                new_irblock = set_assignblk(ssa.graph, head, 0, assignblk_dct)
                ssa.graph.blocks[head] = new_irblock
                to_remove.add(phi_source)
        phi_sources.difference_update(to_remove)

        var_to_replace = set([var])
        var_to_replace.update(phi_sources)




        # Replace variables
        to_replace_dct = {x:new_var for x in var_to_replace}
        for loc in ssa.graph.blocks:
            irblock = ssa.graph.blocks[loc]
            assignblks = []
            for assignblk in irblock:
                assignblk_dct = {}
                for dst, src in assignblk.iteritems():
                    dst = dst.replace_expr(to_replace_dct)
                    src = src.replace_expr(to_replace_dct)
                    assignblk_dct[dst] = src
                assignblks.append(AssignBlock(assignblk_dct, assignblk.instr))
            new_irblock = IRBlock(loc, assignblks)
            ssa.graph.blocks[loc] = new_irblock

        # Remove phi
        assignblk_dct = get_assignblk(ssa.graph, phi_loc, phi_index)
        del assignblk_dct[new_var]


        new_irblock = set_assignblk(ssa.graph, phi_loc, phi_index, assignblk_dct)
        ssa.graph.blocks[phi_loc] = new_irblock
