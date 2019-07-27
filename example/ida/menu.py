"""Implements a menu for IDA with:
- Miasm
- Miasm > Symbolic execution (icon 81, F3)
- Miasm > Dependency graph (icon 79, F4)
- Miasm > Graph IR (icon 188, F7)
- Miasm > RPYC server (icon 182, F10)
- Miasm > Type propagation (icon 38, F11)
"""

import idaapi as idaapi

from symbol_exec import symbolic_exec
from graph_ir import function_graph_ir
try:
    from rpyc_ida import serve_threaded
except ImportError:
    serve_threaded = None
from depgraph import launch_depgraph
try:
    from ctype_propagation import analyse_function
except ImportError:
    analyse_function = None

class Handler(idaapi.action_handler_t):

    def __init__(self, callback):
        """Create a Handler calling @callback when activated"""
        super(Handler, self).__init__()
        self.callback = callback

    def activate(self, ctx):
        return self.callback()

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def register(self, name, label, shortcut=None, tooltip=None, icon=-1):
        action = idaapi.action_desc_t(
            name,    # The action name. This acts like an ID and must be unique
            label,   # The action text.
            self,    # The action handler.
            shortcut,# Optional: the action shortcut
            tooltip, # Optional: the action tooltip (available in menus/toolbar)
            icon,    # Optional: the action icon (shows when in menus/toolbars)
        )
        idaapi.register_action(action)
        self.name = name
        return action

    def attach_to_menu(self, menu):
        assert hasattr(self, "name")
        idaapi.attach_action_to_menu(menu, self.name, idaapi.SETMENU_APP)

idaapi.create_menu("Miasm", "Miasm")

handler_symb = Handler(symbolic_exec)
handler_symb.register("miasm:symbexec", "Symbolic exec", shortcut="F3", icon=81)
handler_symb.attach_to_menu("Miasm/Symbolic exec")
handler_depgraph = Handler(launch_depgraph)
handler_depgraph.register("miasm:depgraph", "Dependency graph", shortcut="F4", icon=79)
handler_depgraph.attach_to_menu("Miasm/Dependency graph")

handler_graph = Handler(function_graph_ir)
handler_graph.register("miasm:graphir", "Graph IR", shortcut="F7", icon=188)
handler_graph.attach_to_menu("Miasm/Graph IR")

if serve_threaded is not None:
    handler_rpyc = Handler(serve_threaded)
    handler_rpyc.register("miasm:rpyc", "RPYC server", shortcut="F10", icon=182)
    handler_rpyc.attach_to_menu("Miasm/RPYC server")
if analyse_function is not None:
    handler_ctype = Handler(analyse_function)
    handler_ctype.register("miasm:ctype", "Type propagation", shortcut="F11",
                           icon=38)
    handler_ctype.attach_to_menu("Miasm/Type propagation")
