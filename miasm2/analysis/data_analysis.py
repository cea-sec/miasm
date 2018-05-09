from miasm2.expression.expression \
    import get_expr_mem, get_list_rw, ExprId, ExprInt
from miasm2.ir.symbexec import SymbolicExecutionEngine


def get_node_name(label, i, n):
    # n_name = "%s_%d_%s"%(label.name, i, n)
    n_name = (label, i, n)
    return n_name


def intra_block_flow_raw(ir_arch, flow_graph, irb, in_nodes, out_nodes):
    """
    Create data flow for an irbloc using raw IR expressions
    """
    current_nodes = {}
    for i, assignblk in enumerate(irb):
        dict_rw = assignblk.get_rw(cst_read=True)
        current_nodes.update(out_nodes)

        # gen mem arg to mem node links
        all_mems = set()
        for node_w, nodes_r in dict_rw.iteritems():
            for n in nodes_r.union([node_w]):
                all_mems.update(get_expr_mem(n))
            if not all_mems:
                continue

            for n in all_mems:
                node_n_w = get_node_name(irb.label, i, n)
                if not n in nodes_r:
                    continue
                o_r = n.arg.get_r(mem_read=False, cst_read=True)
                for n_r in o_r:
                    if n_r in current_nodes:
                        node_n_r = current_nodes[n_r]
                    else:
                        node_n_r = get_node_name(irb.label, i, n_r)
                        current_nodes[n_r] = node_n_r
                        in_nodes[n_r] = node_n_r
                    flow_graph.add_uniq_edge(node_n_r, node_n_w)

        # gen data flow links
        for node_w, nodes_r in dict_rw.iteritems():
            for n_r in nodes_r:
                if n_r in current_nodes:
                    node_n_r = current_nodes[n_r]
                else:
                    node_n_r = get_node_name(irb.label, i, n_r)
                    current_nodes[n_r] = node_n_r
                    in_nodes[n_r] = node_n_r

                flow_graph.add_node(node_n_r)

                node_n_w = get_node_name(irb.label, i + 1, node_w)
                out_nodes[node_w] = node_n_w

                flow_graph.add_node(node_n_w)
                flow_graph.add_uniq_edge(node_n_r, node_n_w)


def intra_block_flow_symbexec(ir_arch, flow_graph, irb, in_nodes, out_nodes):
    """
    Create data flow for an irbloc using symbolic execution
    """
    current_nodes = {}

    symbols_init = dict(ir_arch.arch.regs.regs_init)

    sb = SymbolicExecutionEngine(ir_arch, dict(symbols_init))
    sb.emulbloc(irb)
    # print "*"*40
    # print irb
    # print sb.dump_id()
    # print sb.dump_mem()

    for n_w in sb.symbols:
        # print n_w
        v = sb.symbols[n_w]
        if n_w in symbols_init and symbols_init[n_w] == v:
            continue
        read_values = v.get_r(cst_read=True)
        # print n_w, v, [str(x) for x in read_values]
        node_n_w = get_node_name(irb.label, len(irb), n_w)

        for n_r in read_values:
            if n_r in current_nodes:
                node_n_r = current_nodes[n_r]
            else:
                node_n_r = get_node_name(irb.label, 0, n_r)
                current_nodes[n_r] = node_n_r
                in_nodes[n_r] = node_n_r

            out_nodes[n_w] = node_n_w
            flow_graph.add_uniq_edge(node_n_r, node_n_w)


def inter_block_flow_link(ir_arch, flow_graph, irb_in_nodes, irb_out_nodes, todo, link_exec_to_data):
    lbl, current_nodes, exec_nodes = todo
    # print 'TODO'
    # print lbl
    # print [(str(x[0]), str(x[1])) for x in current_nodes]
    current_nodes = dict(current_nodes)

    # link current nodes to bloc in_nodes
    if not lbl in ir_arch.blocks:
        print "cannot find bloc!!", lbl
        return set()
    irb = ir_arch.blocks[lbl]
    # pp(('IN', lbl, [(str(x[0]), str(x[1])) for x in current_nodes.items()]))
    to_del = set()
    for n_r, node_n_r in irb_in_nodes[irb.label].items():
        if not n_r in current_nodes:
            continue
        # print 'add link', current_nodes[n_r], node_n_r
        flow_graph.add_uniq_edge(current_nodes[n_r], node_n_r)
        to_del.add(n_r)

    # if link exec to data, all nodes depends on exec nodes
    if link_exec_to_data:
        for n_x_r in exec_nodes:
            for n_r, node_n_r in irb_in_nodes[irb.label].items():
                if not n_x_r in current_nodes:
                    continue
                if isinstance(n_r, ExprInt):
                    continue
                flow_graph.add_uniq_edge(current_nodes[n_x_r], node_n_r)

    # update current nodes using bloc out_nodes
    for n_w, node_n_w in irb_out_nodes[irb.label].items():
        current_nodes[n_w] = node_n_w

    # get nodes involved in exec flow
    x_nodes = tuple(sorted(list(irb.dst.get_r())))

    todo = set()
    for lbl_dst in ir_arch.graph.successors(irb.label):
        todo.add((lbl_dst, tuple(current_nodes.items()), x_nodes))

    # pp(('OUT', lbl, [(str(x[0]), str(x[1])) for x in current_nodes.items()]))

    return todo


def create_implicit_flow(ir_arch, flow_graph, irb_in_nodes, irb_out_ndes):

    # first fix IN/OUT
    # If a son read a node which in not in OUT, add it
    todo = set(ir_arch.blocks.keys())
    while todo:
        lbl = todo.pop()
        irb = ir_arch.blocks[lbl]
        for lbl_son in ir_arch.graph.successors(irb.label):
            if not lbl_son in ir_arch.blocks:
                print "cannot find bloc!!", lbl
                continue
            irb_son = ir_arch.blocks[lbl_son]
            for n_r in irb_in_nodes[irb_son.label]:
                if n_r in irb_out_nodes[irb.label]:
                    continue
                if not isinstance(n_r, ExprId):
                    continue

                # print "###", n_r
                # print "###", irb
                # print "###", 'OUT', [str(x) for x in irb.out_nodes]
                # print "###", irb_son
                # print "###", 'IN', [str(x) for x in irb_son.in_nodes]

                node_n_w = irb.label, len(irb), n_r
                irb_out_nodes[irb.label][n_r] = node_n_w
                if not n_r in irb_in_nodes[irb.label]:
                    irb_in_nodes[irb.label][n_r] = irb.label, 0, n_r
                node_n_r = irb_in_nodes[irb.label][n_r]
                # print "###", node_n_r
                for lbl_p in ir_arch.graph.predecessors(irb.label):
                    todo.add(lbl_p)

                flow_graph.add_uniq_edge(node_n_r, node_n_w)


def inter_block_flow(ir_arch, flow_graph, irb_0, irb_in_nodes, irb_out_nodes, link_exec_to_data=True):

    todo = set()
    done = set()
    todo.add((irb_0, (), ()))

    while todo:
        state = todo.pop()
        if state in done:
            continue
        done.add(state)
        out = inter_block_flow_link(ir_arch, flow_graph, irb_in_nodes, irb_out_nodes, state, link_exec_to_data)
        todo.update(out)


class symb_exec_func:

    """
    This algorithm will do symbolic execution on a function, trying to propagate
    states between basic blocks in order to extract inter-blocs dataflow. The
    algorithm tries to merge states from blocks with multiple parents.

    There is no real magic here, loops and complex merging will certainly fail.
    """

    def __init__(self, ir_arch):
        self.todo = set()
        self.stateby_ad = {}
        self.cpt = {}
        self.states_var_done = set()
        self.states_done = set()
        self.total_done = 0
        self.ir_arch = ir_arch

    def add_state(self, parent, ad, state):
        variables = dict(state.symbols.items())

        # get bloc dead, and remove from state
        b = self.ir_arch.get_block(ad)
        if b is None:
            raise ValueError("unknown bloc! %s" % ad)
        """
        dead = b.dead[0]
        for d in dead:
            if d in variables:
                del(variables[d])
        """
        variables = variables.items()

        s = parent, ad, tuple(sorted(variables))
        """
        state_var = s[1]
        if s in self.states_var_done:
            print 'skip state'
            return
        if not ad in self.stateby_ad:
            self.stateby_ad[ad] = set()
        self.stateby_ad[ad].add(state_var)

        """
        self.todo.add(s)

        """
        if not ad in self.cpt:
            self.cpt[ad] = 0
        """
    """
    def get_next_min(self):
        state_by_ad = {}
        for state in self.todo:
            ad = state[1]
            if not ad in state_by_ad:
                state_by_ad[ad] = []
            state_by_ad[ad].append(state)
        print "XX", [len(x) for x in state_by_ad.values()]
        state_by_ad = state_by_ad.items()
        state_by_ad.sort(key=lambda x:len(x[1]))
        state_by_ad.reverse()
        return state_by_ad.pop()[1][0]
    """

    def get_next_state(self):
        state = self.todo.pop()
        return state

    def do_step(self):
        if len(self.todo) == 0:
            return None
        if self.total_done > 600:
            print "symbexec watchdog!"
            return None
        self.total_done += 1
        print 'CPT', self.total_done
        while self.todo:
            # if self.total_done>20:
            #    self.get_next_min()
            # state = self.todo.pop()
            state = self.get_next_state()
            parent, ad, s = state
            self.states_done.add(state)
            self.states_var_done.add(state)
            # if s in self.states_var_done:
            #    print "state done"
            #    continue

            sb = SymbolicExecutionEngine(self.ir_arch, dict(s))

            return parent, ad, sb
        return None
