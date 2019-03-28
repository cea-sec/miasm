from miasm.core.asmblock import disasmEngine, AsmBlock
from miasm.core.utils import Disasm_Exception
from miasm.arch.wasm.arch import mn_wasm
from miasm.core.asmblock import AsmConstraint, AsmCFG, AsmBlockBad
from miasm.expression.expression import ExprId, LocKey, ExprLoc
import copy
import logging

log_asmblock = logging.getLogger("asmblock")

_prev_labels = {'loop': 0, 'if': 0, 'block': 0}
LABEL_PREFIXES = {'loop': 'L', 'if': 'I', 'block':'B'}
def get_new_label(kind):
    global _prev_labels
    a = _prev_labels[kind]
    _prev_labels[kind] += 1
    return "${}{}".format(LABEL_PREFIXES[kind], a)

class WasmStruct(object):
    '''
    Defines a Wasm structure (its start and its stop)
    The possible kinds of structures are:
    'func', 'loop', 'block', 'if'
    '''
    __slots__ = ['kind', 'start_key', 'end_key',
                 'after_else_key', 'label']

    def __init__(self, loc_db, kind, start_key):
        self.kind = kind
        self.start_key = start_key
        self.end_key = None
        self.after_else_key = None
        if kind == 'func':
            self.label = None
        else:
            self.label = get_new_label(kind)

    def set_end_key(self, loc_db, key):
        if self.end_key is not None:
            raise Exception('Malformed code')
        self.end_key = key
        if self.kind == 'if' and self.after_else_key is None:
            self.after_else_key = self.end_key

    def set_after_else_key(self, loc_db, key):
        if self.kind != 'if' or self.after_else_key is not None:
            raise Exception('Malformed code')
        self.after_else_key = key

    @property
    def branch_key(self):
        if self.kind == 'loop':
            return self.start_key
        return self.end_key

    @property
    def else_key(self):
        if self.kind != 'if':
            raise Exception("No esle key in {} structure".format(self.kind))
        return self.after_else_key

class PendingBasicBlocks(object):
    '''
    Feed this object with offsets of structured instructions and basic blocks
    of a specific wasm function. It will store basic blocks and update them when needed.

    For this to work you must:
     - declare every structure pseudo-instruction you encounter
       ('loop', 'block', 'if', 'else', 'end')
     - declare function start with the dummy instruction name 'func'
     - declare every basic block you encounter
        --> blocks that are processed are those ending with
            a known (pseudo-)instruction. You MUST place such
            instructions at the end of a block and declare them here
     - all these declaration must be made in order in the body of functions

    It updates basic blocks that end with:
     - branches ('br', 'br_if', 'br_table')
     - 'if' pseudo instruction
     - 'else' pseudo instruction
    by finding their true dstflow and adding the corresponding
    location to the block's bto.
    During disassembly, please declare structured (pseudo-)instructions
    BEFORE adding a basic block if both occur at the same time
    '''
    __slots__ = ['_if_todo', '_br_todo', 'done', 'loc_db',
                 '_structs', '_todo_structs']

    def __init__(self, loc_db):
        self.loc_db = loc_db
        self._br_todo = []
        self._if_todo = []
        self.done = set()
        self._structs = []
        self._todo_structs = []

    def _add_done(self, block):
        self.done.add(block)
        block.fix_constraints()

    def structure_instr_at(self, instr, key_or_block):
        '''
        Declare a structure pseudo-instruction at a specific block or key.
        Please note that for the 'else' instruction, you have to give
        the loc key at the next instruction (else is at end of block)
        '''
        key = None
        if isinstance(key_or_block, LocKey):
            key = key_or_block
        elif isinstance(key_or_block, AsmBlock):
            key = key_or_block.loc_key

        try:
            kind = instr.name
        except AttributeError:
            kind = instr

        # If end is found, this variable is set
        pop_struct = None

        if kind in ['func', 'loop', 'block', 'if']:
            self._structs.append(WasmStruct(self.loc_db, kind, key))
            self._br_todo.append([])
            self._if_todo.append([])

        elif kind == 'else':
            self._structs[-1].set_after_else_key(self.loc_db, key)

        elif kind == 'end':
            pop_struct = self._structs.pop()
            if pop_struct.kind == 'func':
                instr.args = instr.args + ['func_idx']
            pop_struct.set_end_key(self.loc_db, key)
            br_todo = self._br_todo.pop()
            if_todo = self._if_todo.pop()

            br_key = pop_struct.branch_key
            for block in br_todo:
                block.bto.add(AsmConstraint(br_key, AsmConstraint.c_to))
                self._add_done(block)

            if len(if_todo) > 1:
                raise Exception('Malformed code')
            if if_todo != []:
                else_key = pop_struct.else_key
                if_todo[0].add_cst(else_key, AsmConstraint.c_next)
                self._add_done(if_todo[0])

        else:
            raise Exception('{} is not a structure instruction'.format(kind))

        # Insert label
        if kind != 'func':
            if pop_struct is not None: # last struct has been poped (end)
                label = pop_struct.label
            else:
                label = self._structs[-1].label
            if label is not None:
                instr.args = [label] + instr.args

        # Add done structs for update
        if pop_struct is not None:
            self._todo_structs.append(pop_struct)

    def add_block(self, block):
        name = block.lines[-1].name
        if name == 'if':
            self._if_todo[-1].append(block)

        elif name == 'else':
            if self._structs[-1].kind != 'if':
                raise Exception('Unexpected \'else\'')
            # 'else' is treated as 'br 0'
            self._br_todo[-1].append(block)

        elif name in ['br', 'br_if']:
            arg = int(block.lines[-1].getdstflow(self.loc_db))
            if arg >= len(self._br_todo):
                raise Exception('Bad br')
            self._br_todo[-1-arg].append(block)
            label = self._structs[-1-arg].label
            if label is not None:
                block.lines[-1].args = [ExprId(label, 0)]


        elif name == 'br_table':
            args =  [int(i) for i in block.lines[-1].getdstflow(self.loc_db)]
            for i in range(len(args)):
                arg = args[i]
                if arg >= len(self._br_todo):
                    raise Exception('Bad br')
                self._br_todo[-1-arg].append(block)
                label = self._structs[-1-arg].label
                if label is not None:
                    block.lines[-1].args[i] = ExprId(label, 0)

        elif name == 'return':
            self._br_todo[0].append(block)

        else:
            self._add_done(block)

    @property
    def is_done(self):
        return len(self._structs) == 0

    def update_loc_names(self):
        if not self.is_done:
            raise Exception("Please wait end of function to update locs")
        for s in self._todo_structs:
            if s.label is None:
                continue
            self.loc_db.add_location_name(s.branch_key, s.label)
        self._todo_structs = []


class dis_wasm(disasmEngine):
    attrib = None

    def __init__(self, wasm_cont=None, **kwargs):
        self.cont = wasm_cont
        super(dis_wasm, self).__init__(mn_wasm, self.attrib, None, **kwargs)

    def dis_multiblock(self):
        raise NotImplementedError("Use dis_func_body to disassemble a function body")

    def dis_instr(self, bs, offset):
        try:
            instr = self.arch.dis(bs, self.attrib, offset)
            error = None
        except Disasm_Exception as e:
            log_asmblock.warning(e)
            instr = None
            error = AsmBlockBad.ERROR_CANNOT_DISASM
        except IOError as e:
            log_asmblock.warning(e)
            instr = None
            error = AsmBlockBad.ERROR_IO
        return instr, error

    def get_func_name(self, idx):
        '''Returns the name of the function number @idx'''
        func_name = self.cont._executable.functions[idx].name
        if func_name is None:
            func_name = ""
        else:
            func_name = ' ' + func_name
            #func_name = "_function_{}".format(func_idx)
        return "<fn#{}{}>".format(idx, func_name)

    def dis_func(self, func_idx, blocks=None):
        '''
        Disassembles a wasm function's body.
        Works sorta like the vanilla dis_multiblock except that it:
        - takes a function index @func_idx as a parameter
        - disassembles every instruction in function body
        - ignores self.dont_dis
        '''
        #log_asmblock.info("dis block all")
        func = self.cont._executable.functions[func_idx]

        # Get func name or create it
        func_name = self.get_func_name(func_idx)

        if func.is_imported:
            res = AsmCFG(self.loc_db)
            res.add_block(AsmBlock(self.loc_db.get_or_create_name_location(func_name)))
            return res

        # Get func body
        bs = func.code.body
        cur_offset = 0
        cur_block = AsmBlock(self.loc_db.get_or_create_name_location(func_name))

        pending_blocks = PendingBasicBlocks(self.loc_db)
        pending_blocks.structure_instr_at('func', cur_block)

        block_cpt = 0
        after_else = False
        prebuilt_key = None

        ## Block loop ##
        while not pending_blocks.is_done:
            # Start new block
            block_cpt += 1
            lines_cpt = 0
            if block_cpt != 1: # Not first block of the function
                if prebuilt_key is not None:
                    cur_block = AsmBlock(prebuilt_key)
                    prebuilt_key = None
                else:
                    cur_block = AsmBlock(self.loc_db.add_location())

            # Check block watchdog
            if self.blocs_wd is not None and block_cpt > self.blocs_wd:
                log_asmblock.debug("blocks watchdog reached at %X in function #%X", int(cur_offset), func_idx)
                break

            ## Instruction loop ##
            while not pending_blocks.is_done:

                lines_cpt += 1
                # Check line watchdog
                if self.lines_wd is not None and lines_cpt > self.lines_wd:
                    log_asmblock.debug("lines watchdog reached at %X", int(cur_offset))
                    break

                # Try to disassemble instruction
                instr, error = self.dis_instr(bs, cur_offset)

                if instr is None:
                    log_asmblock.warning("cannot disasm at %X", int(cur_offset))
                    raise Exception("Disasm error: {}".format(error))

                log_asmblock.debug("dis at %X in function #%X", int(cur_offset), func_idx)
                log_asmblock.debug(instr)
                log_asmblock.debug(instr.args)

                # Stop block in case of 'end' or 'loop'
                # -> forces the creation of a location (maybe useless for some 'end's)
                if instr.name in ['end', 'loop'] and lines_cpt > 1:
                    prebuilt_key = self.loc_db.add_location()
                    cur_block.add_cst(prebuilt_key, AsmConstraint.c_next)
                    break


                # Add instr to block
                cur_block.addline(instr)

                # Hide function index in 'return' instructions
                if instr.name == 'return':
                    instr.args.append(func_idx)

                # Declare structure pseudo-instructions
                if instr.is_structure:
                    if instr.name == 'else':
                        prebuilt_key = self.loc_db.add_location()
                        pending_blocks.structure_instr_at(instr, prebuilt_key)
                    else:
                        pending_blocks.structure_instr_at(instr, cur_block)

                if instr.is_subcall():
                    call_key = self.loc_db.get_or_create_name_location(
                        self.get_func_name(int(instr.getdstflow(None))))
                    cur_block.bto.add(AsmConstraint(call_key, AsmConstraint.c_to))

                # Increment offset
                cur_offset += instr.l

                if not instr.breakflow():
                    continue

                if instr.splitflow() and not (instr.is_subcall() and self.dontdis_retcall):
                    if prebuilt_key is None:
                        prebuilt_key = self.loc_db.add_location()
                    # 'if' branches alter execution flow when condition is not true
                    if instr.name == 'if':
                        cur_block.bto.add(AsmConstraint(prebuilt_key, AsmConstraint.c_to))
                    else:
                        cur_block.add_cst(prebuilt_key, AsmConstraint.c_next)

                break

            # Register current block
            pending_blocks.add_block(cur_block)

        pending_blocks.update_loc_names()

        blocks = AsmCFG(self.loc_db)
        for block in pending_blocks.done:
            blocks.add_block(block)

        for block in blocks.blocks:
            for instr in block.lines:
                for i in range(len(instr.args)):
                    if isinstance(instr.args[i], str):
                        if instr.args[i] == 'func_idx':
                            instr.args[i] = func_idx
                        else:
                            lk = self.loc_db.get_name_location(instr.args[i])
                            if lk is None:
                                raise Exception("Not supposed to happen")
                            instr.args[i] = ExprLoc(lk, 32)

        return blocks
