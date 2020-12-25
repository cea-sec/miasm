import logging

from future.utils import viewitems

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprMem
from miasm.expression.expression_helper import possible_values
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import IRBlock, AssignBlock

LOG_CST_PROPAG = logging.getLogger("cst_propag")
CONSOLE_HANDLER = logging.StreamHandler()
CONSOLE_HANDLER.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
LOG_CST_PROPAG.addHandler(CONSOLE_HANDLER)
LOG_CST_PROPAG.setLevel(logging.WARNING)


class SymbExecState(SymbolicExecutionEngine):
    """
    State manager for SymbolicExecution
    """
    def __init__(self, lifter, ircfg, state):
        super(SymbExecState, self).__init__(lifter, {})
        self.set_state(state)


def add_state(ircfg, todo, states, addr, state):
    """
    Add or merge the computed @state for the block at @addr. Update @todo
    @todo: modified block set
    @states: dictionary linking a label to its entering state.
    @addr: address of the considered block
    @state: computed state
    """
    addr = ircfg.get_loc_key(addr)
    todo.add(addr)
    if addr not in states:
        states[addr] = state
    else:
        states[addr] = states[addr].merge(state)


def is_expr_cst(lifter, expr):
    """Return true if @expr is only composed of ExprInt and init_regs
    @lifter: Lifter instance
    @expr: Expression to test"""

    elements = expr.get_r(mem_read=True)
    for element in elements:
        if element.is_mem():
            continue
        if element.is_id() and element in lifter.arch.regs.all_regs_ids_init:
            continue
        if element.is_int():
            continue
        return False
    # Expr is a constant
    return True


class SymbExecStateFix(SymbolicExecutionEngine):
    """
    Emul blocks and replace expressions with their corresponding constant if
    any.

    """
    # Function used to test if an Expression is considered as a constant
    is_expr_cst = lambda _, lifter, expr: is_expr_cst(lifter, expr)

    def __init__(self, lifter, ircfg, state, cst_propag_link):
        self.ircfg = ircfg
        super(SymbExecStateFix, self).__init__(lifter, {})
        self.set_state(state)
        self.cst_propag_link = cst_propag_link

    def propag_expr_cst(self, expr):
        """Propagate constant expressions in @expr
        @expr: Expression to update"""
        elements = expr.get_r(mem_read=True)
        to_propag = {}
        for element in elements:
            # Only ExprId can be safely propagated
            if not element.is_id():
                continue
            value = self.eval_expr(element)
            if self.is_expr_cst(self.lifter, value):
                to_propag[element] = value
        return expr_simp(expr.replace_expr(to_propag))

    def eval_updt_irblock(self, irb, step=False):
        """
        Symbolic execution of the @irb on the current state
        @irb: IRBlock instance
        @step: display intermediate steps
        """
        assignblks = []
        for index, assignblk in enumerate(irb):
            new_assignblk = {}
            links = {}
            for dst, src in viewitems(assignblk):
                src = self.propag_expr_cst(src)
                if dst.is_mem():
                    ptr = dst.ptr
                    ptr = self.propag_expr_cst(ptr)
                    dst = ExprMem(ptr, dst.size)
                new_assignblk[dst] = src

            if assignblk.instr is not None:
                for arg in assignblk.instr.args:
                    new_arg = self.propag_expr_cst(arg)
                    links[new_arg] = arg
                self.cst_propag_link[(irb.loc_key, index)] = links

            self.eval_updt_assignblk(assignblk)
            assignblks.append(AssignBlock(new_assignblk, assignblk.instr))
        self.ircfg.blocks[irb.loc_key] = IRBlock(irb.loc_db, irb.loc_key, assignblks)


def compute_cst_propagation_states(lifter, ircfg, init_addr, init_infos):
    """
    Propagate "constant expressions" in a function.
    The attribute "constant expression" is true if the expression is based on
    constants or "init" regs values.

    @lifter: Lifter instance
    @init_addr: analysis start address
    @init_infos: dictionary linking expressions to their values at @init_addr
    """

    done = set()
    state = SymbExecState.StateEngine(init_infos)
    lbl = ircfg.get_loc_key(init_addr)
    todo = set([lbl])
    states = {lbl: state}

    while todo:
        if not todo:
            break
        lbl = todo.pop()
        state = states[lbl]
        if (lbl, state) in done:
            continue
        done.add((lbl, state))
        if lbl not in ircfg.blocks:
            continue

        symbexec_engine = SymbExecState(lifter, ircfg, state)
        addr = symbexec_engine.run_block_at(ircfg, lbl)
        symbexec_engine.del_mem_above_stack(lifter.sp)

        for dst in possible_values(addr):
            value = dst.value
            if value.is_mem():
                LOG_CST_PROPAG.warning('Bad destination: %s', value)
                continue
            elif value.is_int():
                value = ircfg.get_loc_key(value)
            add_state(
                ircfg, todo, states, value,
                symbexec_engine.get_state()
            )

    return states


def propagate_cst_expr(lifter, ircfg, addr, init_infos):
    """
    Propagate "constant expressions" in a @lifter.
    The attribute "constant expression" is true if the expression is based on
    constants or "init" regs values.

    @lifter: Lifter instance
    @addr: analysis start address
    @init_infos: dictionary linking expressions to their values at @init_addr

    Returns a mapping between replaced Expression and their new values.
    """
    states = compute_cst_propagation_states(lifter, ircfg, addr, init_infos)
    cst_propag_link = {}
    for lbl, state in viewitems(states):
        if lbl not in ircfg.blocks:
            continue
        symbexec = SymbExecStateFix(lifter, ircfg, state, cst_propag_link)
        symbexec.eval_updt_irblock(ircfg.blocks[lbl])
    return cst_propag_link
