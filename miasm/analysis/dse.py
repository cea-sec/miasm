"""Dynamic symbolic execution module.

Offers a way to have a symbolic execution along a concrete one.
Basically, this is done through DSEEngine class, with scheme:

dse = DSEEngine(Machine("x86_32"))
dse.attach(jitter)

The DSE state can be updated through:

 - .update_state_from_concrete: update the values from the CPU, so the symbolic
   execution will be completely concrete from this point (until changes)
 - .update_state: inject information, for instance RAX = symbolic_RAX
 - .symbolize_memory: symbolize (using .memory_to_expr) memory areas (ie,
   reading from an address in one of these areas yield a symbol)

The DSE run can be instrumented through:
 - .add_handler: register an handler, modifying the state instead of the current
   execution. Can be used for stubbing external API
 - .add_lib_handler: register handlers for libraries
 - .add_instrumentation: register an handler, modifying the state but continuing
   the current execution. Can be used for logging facilities


On branch, if the decision is symbolic, one can also collect "path constraints"
and inverse them to produce new inputs potentially reaching new paths.

Basically, this is done through DSEPathConstraint. In order to produce a new
solution, one can extend this class, and override 'handle_solution' to produce a
solution which fit its needs. It could avoid computing new solution by
overriding 'produce_solution'.

If one is only interested in constraints associated to its path, the option
"produce_solution" should be set to False, to speed up emulation.
The constraints are accumulated in the .z3_cur z3.Solver object.

Here are a few remainings TODO:
 - handle endianness in check_state / atomic read: currently, but this is also
   true for others Miasm2 symbolic engines, the endianness is not take in
   account, and assumed to be Little Endian

 - too many memory dependencies in constraint tracking: in order to let z3 find
   new solution, it does need information on memory values (for instance, a
   lookup in a table with a symbolic index). The estimated possible involved
   memory location could be too large to pass to the solver (threshold named
   MAX_MEMORY_INJECT). One possible solution, not yet implemented, is to call
   the solver for reducing the possible values thanks to its accumulated
   constraints.
"""
from builtins import range
from collections import namedtuple
import warnings

try:
    import z3
except:
    z3 = None

from future.utils import viewitems

from miasm.core.utils import encode_hex, force_bytes
from miasm.expression.expression import ExprMem, ExprInt, ExprCompose, \
    ExprAssign, ExprId, ExprLoc, LocKey, canonize_to_exprloc
from miasm.core.bin_stream import bin_stream_vm
from miasm.jitter.emulatedsymbexec import EmulatedSymbExec
from miasm.expression.expression_helper import possible_values
from miasm.ir.translators import Translator
from miasm.analysis.expression_range import expr_range
from miasm.analysis.modularintervals import ModularIntervals

DriftInfo = namedtuple("DriftInfo", ["symbol", "computed", "expected"])

class DriftException(Exception):
    """Raised when the emulation drift from the reference engine"""

    def __init__(self, info):
        super(DriftException, self).__init__()
        self.info = info

    def __str__(self):
        if len(self.info) == 1:
            return "Drift of %s: %s instead of %s" % (
                self.info[0].symbol,
                self.info[0].computed,
                self.info[0].expected,
            )
        else:
            return "Drift of:\n\t" + "\n\t".join("%s: %s instead of %s" % (
                dinfo.symbol,
                dinfo.computed,
                dinfo.expected)
                                                 for dinfo in self.info)


class ESETrackModif(EmulatedSymbExec):
    """Extension of EmulatedSymbExec to be used by DSE engines

    Add the tracking of modified expressions, and the ability to symbolize
    memory areas
    """

    def __init__(self, *args, **kwargs):
        super(ESETrackModif, self).__init__(*args, **kwargs)
        self.modified_expr = set() # Expr modified since the last reset
        self.dse_memory_range = [] # List/Intervals of memory addresses to
                                   # symbolize
        self.dse_memory_to_expr = None # function(addr) -> Expr used to
                                       # symbolize

    def mem_read(self, expr_mem):
        if not expr_mem.ptr.is_int():
            return super(ESETrackModif, self).mem_read(expr_mem)
        dst_addr = int(expr_mem.ptr)

        # Split access in atomic accesses
        out = []
        for addr in range(dst_addr, dst_addr + expr_mem.size // 8):
            if addr in self.dse_memory_range:
                # Symbolize memory access
                out.append(self.dse_memory_to_expr(addr))
                continue
            atomic_access = ExprMem(ExprInt(addr, expr_mem.ptr.size), 8)
            if atomic_access in self.symbols:
                out.append( super(EmulatedSymbExec, self).mem_read(atomic_access))
            else:
                # Get concrete value
                atomic_access = ExprMem(ExprInt(addr, expr_mem.ptr.size), 8)
                out.append(super(ESETrackModif, self).mem_read(atomic_access))

        if len(out) == 1:
            # Trivial case (optimization)
            return out[0]

        # Simplify for constant merging (ex: {ExprInt(1, 8), ExprInt(2, 8)})
        return self.expr_simp(ExprCompose(*out))

    def mem_write(self, expr, data):
        # Call Symbolic mem_write (avoid side effects on vm)
        return super(EmulatedSymbExec, self).mem_write(expr, data)

    def reset_modified(self):
        """Reset modified expression tracker"""
        self.modified_expr.clear()

    def apply_change(self, dst, src):
        super(ESETrackModif, self).apply_change(dst, src)
        self.modified_expr.add(dst)


class ESENoVMSideEffects(EmulatedSymbExec):
    """
    Do EmulatedSymbExec without modifying memory
    """
    def mem_write(self, expr, data):
        return super(EmulatedSymbExec, self).mem_write(expr, data)


class DSEEngine(object):
    """Dynamic Symbolic Execution Engine

    This class aims to be overridden for each specific purpose
    """
    SYMB_ENGINE = ESETrackModif

    def __init__(self, machine, loc_db):
        self.machine = machine
        self.loc_db = loc_db
        self.handler = {} # addr -> callback(DSEEngine instance)
        self.instrumentation = {} # addr -> callback(DSEEngine instance)
        self.addr_to_cacheblocks = {} # addr -> {label -> IRBlock}
        self.lifter = self.machine.lifter(loc_db=self.loc_db) # corresponding IR
        self.ircfg = self.lifter.new_ircfg() # corresponding IR

        # Defined after attachment
        self.jitter = None # Jitload (concrete execution)
        self.symb = None # SymbolicExecutionEngine
        self.symb_concrete = None # Concrete SymbExec for path desambiguisation
        self.mdis = None # DisasmEngine

    def prepare(self):
        """Prepare the environment for attachment with a jitter"""
        # Disassembler
        self.mdis = self.machine.dis_engine(bin_stream_vm(self.jitter.vm),
                                            lines_wd=1,
                                            loc_db=self.loc_db)

        # Symbexec engine
        ## Prepare symbexec engines
        self.symb = self.SYMB_ENGINE(self.jitter.cpu, self.jitter.vm,
                                     self.lifter, {})
        self.symb.enable_emulated_simplifications()
        self.symb_concrete = ESENoVMSideEffects(
            self.jitter.cpu, self.jitter.vm,
            self.lifter, {}
        )

        ## Update registers value
        self.symb.symbols[self.lifter.IRDst] = ExprInt(
            getattr(self.jitter.cpu, self.lifter.pc.name),
            self.lifter.IRDst.size
        )

        # Activate callback on each instr
        self.jitter.jit.set_options(max_exec_per_call=1, jit_maxline=1)
        self.jitter.exec_cb = self.callback

        # Clean jit cache to avoid multi-line basic blocks already jitted
        self.jitter.jit.clear_jitted_blocks()

    def attach(self, emulator):
        """Attach the DSE to @emulator
        @emulator: jitload (or API equivalent) instance

        To attach *DURING A BREAKPOINT*, one may consider using the following snippet:

        def breakpoint(self, jitter):
            ...
            dse.attach(jitter)
            dse.update...
            ...
            # Additional call to the exec callback is necessary, as breakpoints are
            # honored AFTER exec callback
            jitter.exec_cb(jitter)

            return True

        Without it, one may encounteer a DriftException error due to a
        "desynchronization" between jitter and dse states. Indeed, on 'handle'
        call, the jitter must be one instruction AFTER the dse.
        """
        self.jitter = emulator
        self.prepare()

    def handle(self, cur_addr):
        r"""Handle destination
        @cur_addr: Expr of the next address in concrete execution
        /!\ cur_addr may be a loc_key

        In this method, self.symb is in the "just before branching" state
        """
        pass

    def add_handler(self, addr, callback):
        """Add a @callback for address @addr before any state update.
        The state IS NOT updated after returning from the callback
        @addr: int
        @callback: func(dse instance)"""
        self.handler[addr] = callback

    def add_lib_handler(self, libimp, namespace):
        """Add search for handler based on a @libimp libimp instance

        Known functions will be looked by {name}_symb or {name}_{ord}_symb in the @namespace
        """
        namespace = dict(
            (force_bytes(name), func) for name, func in viewitems(namespace)
        )

        # lambda cannot contain statement
        def default_func(dse):
            fname = libimp.fad2cname[dse.jitter.pc]
            if isinstance(fname, tuple):
                fname = b"%s_%d_symb" % (force_bytes(fname[0]), fname[1])
            else:
                fname = b"%s_symb" % force_bytes(fname)
            raise RuntimeError("Symbolic stub '%s' not found" % fname)

        for addr, fname in viewitems(libimp.fad2cname):
            if isinstance(fname, tuple):
                fname = b"%s_%d_symb" % (force_bytes(fname[0]), fname[1])
            else:
                fname = b"%s_symb" % force_bytes(fname)
            func = namespace.get(fname, None)
            if func is not None:
                self.add_handler(addr, func)
            else:
                self.add_handler(addr, default_func)

    def add_instrumentation(self, addr, callback):
        """Add a @callback for address @addr before any state update.
        The state IS updated after returning from the callback
        @addr: int
        @callback: func(dse instance)"""
        self.instrumentation[addr] = callback

    def _check_state(self):
        """Check the current state against the concrete one"""
        errors = [] # List of DriftInfo

        for symbol in self.symb.modified_expr:
            # Do not consider PC
            if symbol in [self.lifter.pc, self.lifter.IRDst]:
                continue

            # Consider only concrete values
            symb_value = self.eval_expr(symbol)
            if not symb_value.is_int():
                continue
            symb_value = int(symb_value)

            # Check computed values against real ones
            if symbol.is_id():
                if hasattr(self.jitter.cpu, symbol.name):
                    value = getattr(self.jitter.cpu, symbol.name)
                    if value != symb_value:
                        errors.append(DriftInfo(symbol, symb_value, value))
            elif symbol.is_mem() and symbol.ptr.is_int():
                value_chr = self.jitter.vm.get_mem(
                    int(symbol.ptr),
                    symbol.size // 8
                )
                exp_value = int(encode_hex(value_chr[::-1]), 16)
                if exp_value != symb_value:
                    errors.append(DriftInfo(symbol, symb_value, exp_value))

        # Check for drift, and act accordingly
        if errors:
            raise DriftException(errors)

    def callback(self, _):
        """Called before each instruction"""
        # Assert synchronization with concrete execution
        self._check_state()

        # Call callbacks associated to the current address
        cur_addr = self.jitter.pc
        if isinstance(cur_addr, LocKey):
            lbl = self.lifter.loc_db.loc_key_to_label(cur_addr)
            cur_addr = lbl.offset

        if cur_addr in self.handler:
            self.handler[cur_addr](self)
            return True

        if cur_addr in self.instrumentation:
            self.instrumentation[cur_addr](self)

        # Handle current address
        self.handle(ExprInt(cur_addr, self.lifter.IRDst.size))

        # Avoid memory issue in ExpressionSimplifier
        if len(self.symb.expr_simp.cache) > 100000:
            self.symb.expr_simp.cache.clear()

        # Get IR blocks
        if cur_addr in self.addr_to_cacheblocks:
            self.ircfg.blocks.clear()
            self.ircfg.blocks.update(self.addr_to_cacheblocks[cur_addr])
        else:

            ## Reset cache structures
            self.ircfg.blocks.clear()# = {}

            ## Update current state
            asm_block = self.mdis.dis_block(cur_addr)
            self.lifter.add_asmblock_to_ircfg(asm_block, self.ircfg)
            self.addr_to_cacheblocks[cur_addr] = dict(self.ircfg.blocks)

        # Emulate the current instruction
        self.symb.reset_modified()

        # Is the symbolic execution going (potentially) to jump on a lbl_gen?
        if len(self.ircfg.blocks) == 1:
            self.symb.run_at(self.ircfg, cur_addr)
        else:
            # Emulation could stuck in generated IR blocks
            # But concrete execution callback is not enough precise to obtain
            # the full IR blocks path
            # -> Use a fully concrete execution to get back path

            # Update the concrete execution
            self._update_state_from_concrete_symb(
                self.symb_concrete, cpu=True, mem=True
            )
            while True:

                next_addr_concrete = self.symb_concrete.run_block_at(
                    self.ircfg, cur_addr
                )
                self.symb.run_block_at(self.ircfg, cur_addr)

                if not (isinstance(next_addr_concrete, ExprLoc) and
                        self.lifter.loc_db.get_location_offset(
                            next_addr_concrete.loc_key
                        ) is None):
                    # Not a lbl_gen, exit
                    break

                # Call handle with lbl_gen state
                self.handle(next_addr_concrete)
                cur_addr = next_addr_concrete


        # At this stage, symbolic engine is one instruction after the concrete
        # engine

        return True

    def _get_gpregs(self):
        """Return a dict of regs: value from the jitter
        This version use the regs associated to the attrib (!= cpu.get_gpreg())
        """
        out = {}
        regs = self.lifter.arch.regs.attrib_to_regs[self.lifter.attrib]
        for reg in regs:
            if hasattr(self.jitter.cpu, reg.name):
                out[reg.name] = getattr(self.jitter.cpu, reg.name)
        return out

    def take_snapshot(self):
        """Return a snapshot of the current state (including jitter state)"""
        snapshot = {
            "mem": self.jitter.vm.get_all_memory(),
            "regs": self._get_gpregs(),
            "symb": self.symb.symbols.copy(),
        }
        return snapshot

    def restore_snapshot(self, snapshot, memory=True):
        """Restore a @snapshot taken with .take_snapshot
        @snapshot: .take_snapshot output
        @memory: (optional) if set, also restore the memory
        """
        # Restore memory
        if memory:
            self.jitter.vm.reset_memory_page_pool()
            self.jitter.vm.reset_code_bloc_pool()
            for addr, metadata in viewitems(snapshot["mem"]):
                self.jitter.vm.add_memory_page(
                    addr,
                    metadata["access"],
                    metadata["data"]
                )

        # Restore registers
        self.jitter.pc = snapshot["regs"][self.lifter.pc.name]
        for reg, value in viewitems(snapshot["regs"]):
            setattr(self.jitter.cpu, reg, value)

        # Reset intern elements
        self.jitter.vm.set_exception(0)
        self.jitter.cpu.set_exception(0)
        self.jitter.bs._atomic_mode = False

        # Reset symb exec
        for key, _ in list(viewitems(self.symb.symbols)):
            del self.symb.symbols[key]
        for expr, value in viewitems(snapshot["symb"]):
            self.symb.symbols[expr] = value

    def update_state(self, assignblk):
        """From this point, assume @assignblk in the symbolic execution
        @assignblk: AssignBlock/{dst -> src}
        """
        for dst, src in viewitems(assignblk):
            self.symb.apply_change(dst, src)

    def _update_state_from_concrete_symb(self, symbexec, cpu=True, mem=False):
        if mem:
            # Values will be retrieved from the concrete execution if they are
            # not present
            symbexec.symbols.symbols_mem.base_to_memarray.clear()
        if cpu:
            regs = self.lifter.arch.regs.attrib_to_regs[self.lifter.attrib]
            for reg in regs:
                if hasattr(self.jitter.cpu, reg.name):
                    value = ExprInt(getattr(self.jitter.cpu, reg.name),
                                    size=reg.size)
                    symbexec.symbols[reg] = value

    def update_state_from_concrete(self, cpu=True, mem=False):
        r"""Update the symbolic state with concrete values from the concrete
        engine

        @cpu: (optional) if set, update registers' value
        @mem: (optional) if set, update memory value

        /!\ all current states will be loss.
        This function is usually called when states are no more synchronized
        (at the beginning, returning from an unstubbed syscall, ...)
        """
        self._update_state_from_concrete_symb(self.symb, cpu, mem)

    def eval_expr(self, expr):
        """Return the evaluation of @expr:
        @expr: Expr instance"""
        return self.symb.eval_expr(expr)

    @staticmethod
    def memory_to_expr(addr):
        """Translate an address to its corresponding symbolic ID (8bits)
        @addr: int"""
        return ExprId("MEM_0x%x" % int(addr), 8)

    def symbolize_memory(self, memory_range):
        """Register a range of memory addresses to symbolize
        @memory_range: object with support of __in__ operation (intervals, list,
        ...)
        """
        self.symb.dse_memory_range = memory_range
        self.symb.dse_memory_to_expr = self.memory_to_expr


class DSEPathConstraint(DSEEngine):
    """Dynamic Symbolic Execution Engine keeping the path constraint

    Possible new "solutions" are produced along the path, by inversing concrete
    path constraint. Thus, a "solution" is a potential initial context leading
    to a new path.

    In order to produce a new solution, one can extend this class, and override
    'handle_solution' to produce a solution which fit its needs. It could avoid
    computing new solution by overriding 'produce_solution'.

    If one is only interested in constraints associated to its path, the option
    "produce_solution" should be set to False, to speed up emulation.
    The constraints are accumulated in the .z3_cur z3.Solver object.

    """

    # Maximum memory size to inject in constraints solving
    MAX_MEMORY_INJECT = 0x10000

    # Produce solution strategies
    PRODUCE_NO_SOLUTION = 0
    PRODUCE_SOLUTION_CODE_COV = 1
    PRODUCE_SOLUTION_BRANCH_COV = 2
    PRODUCE_SOLUTION_PATH_COV = 3

    def __init__(self, machine, loc_db, produce_solution=PRODUCE_SOLUTION_CODE_COV,
                 known_solutions=None,
                 **kwargs):
        """Init a DSEPathConstraint
        @machine: Machine of the targeted architecture instance
        @produce_solution: (optional) if set, new solutions will be computed"""
        super(DSEPathConstraint, self).__init__(machine, loc_db, **kwargs)

        # Dependency check
        assert z3 is not None

        # Init PathConstraint specifics structures
        self.cur_solver = z3.Solver()
        self.new_solutions = {} # solution identifier -> solution's model
        self._known_solutions = set() # set of solution identifiers
        self.z3_trans = Translator.to_language("z3")
        self._produce_solution_strategy = produce_solution
        self._previous_addr = None
        self._history = None
        if produce_solution == self.PRODUCE_SOLUTION_PATH_COV:
            self._history = [] # List of addresses in the current path

    @property
    def ir_arch(self):
        warnings.warn('DEPRECATION WARNING: use ".lifter" instead of ".ir_arch"')
        return self.lifter

    def take_snapshot(self, *args, **kwargs):
        snap = super(DSEPathConstraint, self).take_snapshot(*args, **kwargs)
        snap["new_solutions"] = {
            dst: src.copy
            for dst, src in viewitems(self.new_solutions)
        }
        snap["cur_constraints"] = self.cur_solver.assertions()
        if self._produce_solution_strategy == self.PRODUCE_SOLUTION_PATH_COV:
            snap["_history"] = list(self._history)
        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_BRANCH_COV:
            snap["_previous_addr"] = self._previous_addr
        return snap

    def restore_snapshot(self, snapshot, keep_known_solutions=True, **kwargs):
        """Restore a DSEPathConstraint snapshot
        @keep_known_solutions: if set, do not forget solutions already found.
        -> They will not appear in 'new_solutions'
        """
        super(DSEPathConstraint, self).restore_snapshot(snapshot, **kwargs)
        self.new_solutions.clear()
        self.new_solutions.update(snapshot["new_solutions"])
        self.cur_solver = z3.Solver()
        self.cur_solver.add(snapshot["cur_constraints"])
        if not keep_known_solutions:
            self._known_solutions.clear()
        if self._produce_solution_strategy == self.PRODUCE_SOLUTION_PATH_COV:
            self._history = list(snapshot["_history"])
        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_BRANCH_COV:
            self._previous_addr = snapshot["_previous_addr"]

    def _key_for_solution_strategy(self, destination):
        """Return the associated identifier for the current solution strategy"""
        if self._produce_solution_strategy == self.PRODUCE_NO_SOLUTION:
            # Never produce a solution
            return None
        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_CODE_COV:
            # Decision based on code coverage
            # -> produce a solution if the destination has never been seen
            key = destination

        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_BRANCH_COV:
            # Decision based on branch coverage
            # -> produce a solution if the current branch has never been take
            key = (self._previous_addr, destination)

        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_PATH_COV:
            # Decision based on path coverage
            # -> produce a solution if the current path has never been take
            key = tuple(self._history + [destination])
        else:
            raise ValueError("Unknown produce solution strategy")

        return key

    def produce_solution(self, destination):
        """Called to determine if a solution for @destination should be test for
        satisfiability and computed
        @destination: Expr instance of the target @destination
        """
        key = self._key_for_solution_strategy(destination)
        if key is None:
            return False
        return key not in self._known_solutions

    def handle_solution(self, model, destination):
        """Called when a new solution for destination @destination is founded
        @model: z3 model instance
        @destination: Expr instance for an addr which is not on the DSE path
        """
        key = self._key_for_solution_strategy(destination)
        assert key is not None
        self.new_solutions[key] = model
        self._known_solutions.add(key)

    def handle_correct_destination(self, destination, path_constraints):
        """[DEV] Called by handle() to update internal structures giving the
        correct destination (the concrete execution one).
        """

        # Update structure used by produce_solution()
        if self._produce_solution_strategy == self.PRODUCE_SOLUTION_PATH_COV:
            self._history.append(destination)
        elif self._produce_solution_strategy == self.PRODUCE_SOLUTION_BRANCH_COV:
            self._previous_addr = destination

        # Update current solver
        for cons in path_constraints:
            self.cur_solver.add(self.z3_trans.from_expr(cons))

    def handle(self, cur_addr):
        cur_addr = canonize_to_exprloc(self.lifter.loc_db, cur_addr)
        symb_pc = self.eval_expr(self.lifter.IRDst)
        possibilities = possible_values(symb_pc)
        cur_path_constraint = set() # path_constraint for the concrete path
        if len(possibilities) == 1:
            dst = next(iter(possibilities)).value
            dst = canonize_to_exprloc(self.lifter.loc_db, dst)
            assert dst == cur_addr
        else:
            for possibility in possibilities:
                target_addr = canonize_to_exprloc(self.lifter.loc_db, possibility.value)
                path_constraint = set() # Set of ExprAssign for the possible path

                # Get constraint associated to the possible path
                memory_to_add = ModularIntervals(symb_pc.size)
                for cons in possibility.constraints:
                    eaff = cons.to_constraint()
                    # eaff.get_r(mem_read=True) is not enough
                    # ExprAssign consider a Memory access in dst as a write
                    mem = eaff.dst.get_r(mem_read=True)
                    mem.update(eaff.src.get_r(mem_read=True))
                    for expr in mem:
                        if expr.is_mem():
                            addr_range = expr_range(expr.ptr)
                            # At upper bounds, add the size of the memory access
                            # if addr (- [a, b], then @size[addr] reachables
                            # values are in @8[a, b + size[
                            for start, stop in addr_range:
                                stop += expr.size // 8 - 1
                                full_range = ModularIntervals(
                                    symb_pc.size,
                                    [(start, stop)]
                                )
                                memory_to_add.update(full_range)
                    path_constraint.add(eaff)

                if memory_to_add.length > self.MAX_MEMORY_INJECT:
                    # TODO re-croncretize the constraint or z3-try
                    raise RuntimeError("Not implemented: too long memory area")

                # Inject memory
                for start, stop in memory_to_add:
                    for address in range(start, stop + 1):
                        expr_mem = ExprMem(ExprInt(address,
                                                   self.lifter.pc.size),
                                           8)
                        value = self.eval_expr(expr_mem)
                        if not value.is_int():
                            raise TypeError("Rely on a symbolic memory case, " \
                                            "address 0x%x" % address)
                        path_constraint.add(ExprAssign(expr_mem, value))

                if target_addr == cur_addr:
                    # Add path constraint
                    cur_path_constraint = path_constraint

                elif self.produce_solution(target_addr):
                    # Looking for a new solution
                    self.cur_solver.push()
                    for cons in path_constraint:
                        trans = self.z3_trans.from_expr(cons)
                        trans = z3.simplify(trans)
                        self.cur_solver.add(trans)

                    result = self.cur_solver.check()
                    if result == z3.sat:
                        model = self.cur_solver.model()
                        self.handle_solution(model, target_addr)
                    self.cur_solver.pop()

        self.handle_correct_destination(cur_addr, cur_path_constraint)
