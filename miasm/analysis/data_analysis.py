from __future__ import print_function

from future.utils import viewitems

from builtins import object
from functools import cmp_to_key
from miasm.expression.expression \
    import get_expr_mem, get_list_rw, ExprId, ExprInt, \
    compare_exprs
from miasm.ir.symbexec import SymbolicExecutionEngine


def get_node_name(label, i, n):
    n_name = (label, i, n)
    return n_name


def intra_block_flow_raw(lifter, ircfg, flow_graph, irb, in_nodes, out_nodes):
    """
    Create data flow for an irbloc using raw IR expressions
    """
    current_nodes = {}
    for i, assignblk in enumerate(irb):
        dict_rw = assignblk.get_rw(cst_read=True)
        current_nodes.update(out_nodes)

        # gen mem arg to mem node links
        all_mems = set()
        for node_w, nodes_r in viewitems(dict_rw):
            for n in nodes_r.union([node_w]):
                all_mems.update(get_expr_mem(n))
            if not all_mems:
                continue

            for n in all_mems:
                node_n_w = get_node_name(irb.loc_key, i, n)
                if not n in nodes_r:
                    continue
                o_r = n.ptr.get_r(mem_read=False, cst_read=True)
                for n_r in o_r:
                    if n_r in current_nodes:
                        node_n_r = current_nodes[n_r]
                    else:
                        node_n_r = get_node_name(irb.loc_key, i, n_r)
                        current_nodes[n_r] = node_n_r
                        in_nodes[n_r] = node_n_r
                    flow_graph.add_uniq_edge(node_n_r, node_n_w)

        # gen data flow links
        for node_w, nodes_r in viewitems(dict_rw):
            for n_r in nodes_r:
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = get_node_name(irb.loc_key, i, n_r)
                    current_nodes[n_r] = node_n_r
                    in_nodes[n_r] = node_n_r

                flow_graph.add_node(node_n_r)

                node_n_w = get_node_name(irb.loc_key, i + 1, node_w)
                out_nodes[node_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)



def inter_block_flow_link(lifter, ircfg, flow_graph, irb_in_nodes, irb_out_nodes, todo, link_exec_to_data):
    lbl, current_nodes, exec_nodes = todo
    current_nodes = dict(current_nodes)

    # link current nodes to block in_nodes
    if not lbl in ircfg.blocks:
        print("cannot find block!!", lbl)
        return set()
    irb = ircfg.blocks[lbl]
    to_del = set()
    for n_r, node_n_r in viewitems(irb_in_nodes[irb.loc_key]):
        if not n_r in current_nodes:
            continue
        flow_graph.add_uniq_edge(current_nodes[n_r], node_n_r)
        to_del.add(n_r)

    # if link exec to data, all nodes depends on exec nodes
    if link_exec_to_data:
        for n_x_r in exec_nodes:
            for n_r, node_n_r in viewitems(irb_in_nodes[irb.loc_key]):
                if not n_x_r in current_nodes:
                    continue
                if isinstance(n_r, ExprInt):
                    continue
                flow_graph.add_uniq_edge(current_nodes[n_x_r], node_n_r)

    # update current nodes using block out_nodes
    for n_w, node_n_w in viewitems(irb_out_nodes[irb.loc_key]):
        current_nodes[n_w] = node_n_w

    # get nodes involved in exec flow
    x_nodes = tuple(sorted(irb.dst.get_r(), key=cmp_to_key(compare_exprs)))

    todo = set()
    for lbl_dst in ircfg.successors(irb.loc_key):
        todo.add((lbl_dst, tuple(viewitems(current_nodes)), x_nodes))

    return todo


def create_implicit_flow(lifter, flow_graph, irb_in_nodes, irb_out_nodes):

    # first fix IN/OUT
    # If a son read a node which in not in OUT, add it
    todo = set(lifter.blocks.keys())
    while todo:
        lbl = todo.pop()
        irb = lifter.blocks[lbl]
        for lbl_son in lifter.graph.successors(irb.loc_key):
            if not lbl_son in lifter.blocks:
                print("cannot find block!!", lbl)
                continue
            irb_son = lifter.blocks[lbl_son]
            for n_r in irb_in_nodes[irb_son.loc_key]:
                if n_r in irb_out_nodes[irb.loc_key]:
                    continue
                if not isinstance(n_r, ExprId):
                    continue

                node_n_w = irb.loc_key, len(irb), n_r
                irb_out_nodes[irb.loc_key][n_r] = node_n_w
                if not n_r in irb_in_nodes[irb.loc_key]:
                    irb_in_nodes[irb.loc_key][n_r] = irb.loc_key, 0, n_r
                node_n_r = irb_in_nodes[irb.loc_key][n_r]
                for lbl_p in lifter.graph.predecessors(irb.loc_key):
                    todo.add(lbl_p)

                flow_graph.add_uniq_edge(node_n_r, node_n_w)


def inter_block_flow(lifter, ircfg, flow_graph, irb_0, irb_in_nodes, irb_out_nodes, link_exec_to_data=True):

    todo = set()
    done = set()
    todo.add((irb_0, (), ()))

    while todo:
        state = todo.pop()
        if state in done:
            continue
        done.add(state)
        out = inter_block_flow_link(lifter, ircfg, flow_graph, irb_in_nodes, irb_out_nodes, state, link_exec_to_data)
        todo.update(out)


class symb_exec_func(object):

    """
    This algorithm will do symbolic execution on a function, trying to propagate
    states between basic blocks in order to extract inter-blocks dataflow. The
    algorithm tries to merge states from blocks with multiple parents.

    There is no real magic here, loops and complex merging will certainly fail.
    """

    def __init__(self, lifter):
        self.todo = set()
        self.stateby_ad = {}
        self.cpt = {}
        self.states_var_done = set()
        self.states_done = set()
        self.total_done = 0
        self.lifter = lifter

    def add_state(self, parent, ad, state):
        variables = dict(state.symbols)

        # get block dead, and remove from state
        b = self.lifter.get_block(ad)
        if b is None:
            raise ValueError("unknown block! %s" % ad)
        s = parent, ad, tuple(sorted(viewitems(variables)))
        self.todo.add(s)

    def get_next_state(self):
        state = self.todo.pop()
        return state

    def do_step(self):
        if len(self.todo) == 0:
            return None
        if self.total_done > 600:
            print("symbexec watchdog!")
            return None
        self.total_done += 1
        print('CPT', self.total_done)
        while self.todo:
            state = self.get_next_state()
            parent, ad, s = state
            self.states_done.add(state)
            self.states_var_done.add(state)

            sb = SymbolicExecutionEngine(self.lifter, dict(s))

            return parent, ad, sb
        return None
