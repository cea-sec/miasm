from collections import deque
from future.utils import viewitems, viewvalues

from miasm.expression.expression import ExprId, ExprAssign, ExprOp, \
    ExprLoc, get_expr_ids
from miasm.ir.ir import AssignBlock, IRBlock


def sanitize_graph_head(ircfg, head):
    """
    In multiple algorithm, the @head of the ircfg may not have predecessors.
    The function transform the @ircfg in order to ensure this property
    @ircfg: IRCFG instance
    @head: the location of the graph's head
    """

    if not ircfg.predecessors(head):
        return
    original_edges = ircfg.predecessors(head)
    sub_head = ircfg.loc_db.add_location()

    # Duplicate graph, replacing references to head by sub_head
    replaced_expr = {
        ExprLoc(head, ircfg.IRDst.size):
        ExprLoc(sub_head, ircfg.IRDst.size)
    }
    ircfg.simplify(
        lambda expr:expr.replace_expr(replaced_expr)
    )
    # Duplicate head block
    ircfg.add_irblock(IRBlock(ircfg.loc_db, sub_head, list(ircfg.blocks[head])))

    # Remove original head block
    ircfg.del_node(head)

    for src in original_edges:
        ircfg.add_edge(src, sub_head)

    # Create new head, jumping to sub_head
    assignblk = AssignBlock({ircfg.IRDst:ExprLoc(sub_head, ircfg.IRDst.size)})
    new_irblock = IRBlock(ircfg.loc_db, head, [assignblk])
    ircfg.add_irblock(new_irblock)


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

        # stack for RHS
        self._stack_rhs = {}
        # stack for LHS
        self._stack_lhs = {}

        self.ssa_variable_to_expr = {}

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
        expr = self.ssa_variable_to_expr.get(ssa_var, ssa_var)
        return expr

    def reset(self):
        """Resets SSA transformation"""
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
        self.ssa_variable_to_expr[ssa_var] = expr

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
        to_replace = {}
        for expr in variables:
            ssa_var = self._transform_var_rhs(expr)
            to_replace[expr] = ssa_var
        src_ssa = src_ssa.replace_expr(to_replace)

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
            aff = assignblk.dst2ExprAssign(dst)
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
                instructions.append(next(ssa_iter))
            # replace instructions of assignblock in IRBlock
            new_irs.append(AssignBlock(instructions, assignblk.instr))
        return IRBlock(irblock.loc_db, irblock.loc_key, new_irs)

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
                if expr.dst in self.immutable_ids or expr.dst in self.ssa_variable_to_expr:
                    dst_ssa = expr.dst
                else:
                    dst_ssa = self._transform_expression_lhs(expr.dst)

                # retrieve corresponding RHS expression
                src_ssa = rhs.popleft()

                # rebuild SSA expression
                expr = ExprAssign(dst_ssa, src_ssa)
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
        sanitize_graph_head(self.graph, head)
        self._init_variable_defs(head)
        self._place_phi(head)
        self._rename(head)
        self._insert_phi()
        self._convert_phi()
        self._fix_no_def_var(head)

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

        visited_loc = set()
        for loc_key in self.graph.walk_depth_first_forward(head):
            irblock = self.get_block(loc_key)
            if irblock is None:
                # Incomplete graph
                continue
            visited_loc.add(loc_key)
            # search for block's IR definitions/destinations
            for assignblk in irblock.assignblks:
                for dst in assignblk:
                    # enforce ExprId
                    if dst.is_id():
                        # exclude immutable ids
                        if dst in self.immutable_ids or dst in self.ssa_variable_to_expr:
                            continue
                        # map variable definition to blocks
                        self.defs.setdefault(dst, set()).add(irblock.loc_key)
        if visited_loc != set(self.graph.blocks):
            raise RuntimeError("Cannot operate on a non connected graph")

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
        :return: ExprAssign, empty phi function for expr
        """
        phi = ExprId(self.PHI_STR, expr.size)
        return ExprAssign(expr, phi)

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
            for dst, src in list(viewitems(self._phinodes[successor])):
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
            if irblock_has_phi(irblock):
                # If first block contains phi, we are updating an existing ssa form
                # so update phi
                assignblks = list(irblock.assignblks)
                out = dict(assignblks[0])
                out.update(dict(assignblk))
                assignblks[0] = AssignBlock(out, assignblk.instr)
                new_irblock = IRBlock(self.ircfg.loc_db, loc_key, assignblks)
            else:
                # insert at the beginning
                new_irblock = IRBlock(self.ircfg.loc_db, loc_key, [assignblk] + list(irblock.assignblks))
            self.ircfg.blocks[loc_key] = new_irblock

    def _fix_no_def_var(self, head):
        """
        Replace phi source variables which are not ssa vars by ssa vars.
        @head: loc_key of the graph head
        """
        var_to_insert = set()
        for loc_key in self._phinodes:
            for dst, sources in viewitems(self._phinodes[loc_key]):
                for src in sources.args:
                    if src in self.ssa_variable_to_expr:
                        continue
                    var_to_insert.add(src)
        var_to_newname = {}
        newname_to_var = {}
        for var in var_to_insert:
            new_var = self._transform_var_lhs(var)
            var_to_newname[var] = new_var
            newname_to_var[new_var] = var

        # Replace non modified node used in phi with new variable
        self.ircfg.simplify(lambda expr:expr.replace_expr(var_to_newname))

        if newname_to_var:
            irblock = self.ircfg.blocks[head]
            assignblks = list(irblock)
            assignblks[0:0] = [AssignBlock(newname_to_var, assignblks[0].instr)]
            self.ircfg.blocks[head] = IRBlock(self.ircfg.loc_db, head, assignblks)

        # Updt structure
        for loc_key in self._phinodes:
            for dst, sources in viewitems(self._phinodes[loc_key]):
                self._phinodes[loc_key][dst] = sources.replace_expr(var_to_newname)

        for var, (loc_key, index) in list(viewitems(self.ssa_to_location)):
            if loc_key == head:
                self.ssa_to_location[var] = loc_key, index + 1

        for newname, var in viewitems(newname_to_var):
            self.ssa_to_location[newname] = head, 0
            self.ssa_variable_to_expr[newname] = var
            self.expressions[newname] = var


def irblock_has_phi(irblock):
    """
    Return True if @irblock has Phi assignments
    @irblock: IRBlock instance
    """
    if not irblock.assignblks:
        return False
    for src in viewvalues(irblock[0]):
        return src.is_op('Phi')
    return False


class Varinfo(object):
    """Store liveness information for a variable"""
    __slots__ = ["live_index", "loc_key", "index"]

    def __init__(self, live_index, loc_key, index):
        self.live_index = live_index
        self.loc_key = loc_key
        self.index = index


def get_var_assignment_src(ircfg, node, variables):
    """
    Return the variable of @variables which is written by the irblock at @node
    @node: Location
    @variables: a set of variable to test
    """
    irblock = ircfg.blocks[node]
    for assignblk in irblock:
        result = set(assignblk).intersection(variables)
        if not result:
            continue
        assert len(result) == 1
        return list(result)[0]
    return None


def get_phi_sources_parent_block(ircfg, loc_key, sources):
    """
    Return a dictionary linking a variable to it's direct parent label
    which belong to a path which affects the node.
    @loc_key: the starting node
    @sources: set of variables to resolve
    """
    source_to_parent = {}
    for parent in ircfg.predecessors(loc_key):
        done = set()
        todo = set([parent])
        found = False
        while todo:
            node = todo.pop()
            if node in done:
                continue
            done.add(node)
            ret = get_var_assignment_src(ircfg, node, sources)
            if ret:
                source_to_parent.setdefault(ret, set()).add(parent)
                found = True
                break
            for pred in ircfg.predecessors(node):
                todo.add(pred)
        assert found
    return source_to_parent
