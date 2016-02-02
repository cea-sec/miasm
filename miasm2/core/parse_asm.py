#!/usr/bin/env python
#-*- coding:utf-8 -*-
import re

import miasm2.expression.expression as m2_expr
import miasm2.core.asmbloc as asmbloc
from miasm2.core.cpu import gen_base_expr, parse_ast
from miasm2.core.cpu import instruction

declarator = {'byte': 8,
              'word': 16,
              'dword': 32,
              'qword': 64,
              'long': 32,
              }

size2pck = {8: 'B',
            16: 'H',
            32: 'I',
            64: 'Q',
            }

EMPTY_RE = re.compile(r'\s*$')
COMMENT_RE = re.compile(r'\s*;\S*')
LOCAL_LABEL_RE = re.compile(r'\s*(\.L\S+)\s*:')
DIRECTIVE_START_RE = re.compile(r'\s*\.')
DIRECTIVE_RE = re.compile(r'\s*\.(\S+)')
LABEL_RE = re.compile(r'\s*(\S+)\s*:')
FORGET_LABEL_RE = re.compile(r'\s*\.LF[BE]\d\s*:')


class Directive(object):

    """Stand for Directive"""

    pass

class DirectiveAlign(Directive):

    """Stand for alignment representation"""

    def __init__(self, alignment=1):
        self.alignment = alignment

    def __str__(self):
        return "Alignment %s" % self.alignment


class DirectiveSplit(Directive):

    """Stand for alignment representation"""

    pass


class DirectiveDontSplit(Directive):

    """Stand for alignment representation"""

    pass


def guess_next_new_label(symbol_pool):
    """Generate a new label
    @symbol_pool: the asm_symbol_pool instance"""
    i = 0
    gen_name = "loc_%.8X"
    while True:
        name = gen_name % i
        label = symbol_pool.getby_name(name)
        if label is None:
            return symbol_pool.add_label(name)
        i += 1


def replace_expr_labels(expr, symbol_pool, replace_id):
    """Create asm_label of the expression @expr in the @symbol_pool
    Update @replace_id"""

    if not (isinstance(expr, m2_expr.ExprId) and
            isinstance(expr.name, asmbloc.asm_label)):
        return expr

    old_lbl = expr.name
    new_lbl = symbol_pool.getby_name_create(old_lbl.name)
    replace_id[expr] = m2_expr.ExprId(new_lbl, expr.size)
    return replace_id[expr]


def replace_orphan_labels(instr, symbol_pool):
    """Link orphan labels used by @instr to the @symbol_pool"""

    for i, arg in enumerate(instr.args):
        replace_id = {}
        arg.visit(lambda e: replace_expr_labels(e,
                                                symbol_pool,
                                                replace_id))
        instr.args[i] = instr.args[i].replace_expr(replace_id)


STATE_NO_BLOC = 0
STATE_IN_BLOC = 1


def parse_txt(mnemo, attrib, txt, symbol_pool=None):
    """Parse an assembly listing. Returns a couple (blocks, symbol_pool), where
    blocks is a list of asm_bloc and symbol_pool the associated asm_symbol_pool

    @mnemo: architecture used
    @attrib: architecture attribute
    @txt: assembly listing
    @symbol_pool: (optional) the asm_symbol_pool instance used to handle labels
    of the listing

    """

    if symbol_pool is None:
        symbol_pool = asmbloc.asm_symbol_pool()

    C_NEXT = asmbloc.asm_constraint.c_next
    C_TO = asmbloc.asm_constraint.c_to

    lines = []
    # parse each line
    for line in txt.split('\n'):
        # empty
        if EMPTY_RE.match(line):
            continue
        # comment
        if COMMENT_RE.match(line):
            continue
        # labels to forget
        if FORGET_LABEL_RE.match(line):
            continue
        # label beginning with .L
        match_re = LABEL_RE.match(line)
        if match_re:
            label_name = match_re.group(1)
            label = symbol_pool.getby_name_create(label_name)
            lines.append(label)
            continue
        # directive
        if DIRECTIVE_START_RE.match(line):
            match_re = DIRECTIVE_RE.match(line)
            directive = match_re.group(1)
            if directive in ['text', 'data', 'bss']:
                continue
            if directive in ['string', 'ascii']:
                # XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"') + 1:line.rfind(r'"')]
                raw = raw.decode('string_escape')
                if directive == 'string':
                    raw += "\x00"
                lines.append(asmbloc.asm_raw(raw))
                continue
            if directive == 'ustring':
                # XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"') + 1:line.rfind(r'"')] + "\x00"
                raw = raw.decode('string_escape')
                raw = "".join([string + '\x00' for string in raw])
                lines.append(asmbloc.asm_raw(raw))
                continue
            if directive in declarator:
                data_raw = line[match_re.end():].split(' ', 1)[1]
                data_raw = data_raw.split(',')
                size = declarator[directive]
                expr_list = []

                # parser
                base_expr = gen_base_expr()[2]
                my_var_parser = parse_ast(lambda x: m2_expr.ExprId(x, size),
                                          lambda x:
                                              m2_expr.ExprInt(x, size))
                base_expr.setParseAction(my_var_parser)

                for element in data_raw:
                    element = element.strip()
                    element_expr = base_expr.parseString(element)[0]
                    expr_list.append(element_expr.canonize())

                raw_data = asmbloc.asm_raw(expr_list)
                raw_data.element_size = size
                lines.append(raw_data)
                continue
            if directive == 'comm':
                # TODO
                continue
            if directive == 'split':  # custom command
                lines.append(DirectiveSplit())
                continue
            if directive == 'dontsplit':  # custom command
                lines.append(DirectiveDontSplit())
                continue
            if directive == "align":
                align_value = int(line[match_re.end():], 0)
                lines.append(DirectiveAlign(align_value))
                continue
            if directive in ['file', 'intel_syntax', 'globl', 'local',
                             'type', 'size', 'align', 'ident', 'section']:
                continue
            if directive[0:4] == 'cfi_':
                continue

            raise ValueError("unknown directive %s" % str(directive))

        # label
        match_re = LABEL_RE.match(line)
        if match_re:
            label_name = match_re.group(1)
            label = symbol_pool.getby_name_create(label_name)
            lines.append(label)
            continue

        # code
        if ';' in line:
            line = line[:line.find(';')]
        line = line.strip(' ').strip('\t')
        instr = mnemo.fromstring(line, attrib)

        # replace orphan asm_label with labels from symbol_pool
        replace_orphan_labels(instr, symbol_pool)

        if instr.dstflow():
            instr.dstflow2label(symbol_pool)
        lines.append(instr)

    asmbloc.log_asmbloc.info("___pre asm oki___")
    # make blocks

    cur_block = None
    state = STATE_NO_BLOC
    i = 0
    blocks = asmbloc.AsmCFG()
    block_to_nlink = None
    delayslot = 0
    while i < len(lines):
        if delayslot:
            delayslot -= 1
            if delayslot == 0:
                state = STATE_NO_BLOC
        line = lines[i]
        # no current block
        if state == STATE_NO_BLOC:
            if isinstance(line, DirectiveDontSplit):
                block_to_nlink = cur_block
                i += 1
                continue
            elif isinstance(line, DirectiveSplit):
                block_to_nlink = None
                i += 1
                continue
            elif not isinstance(line, asmbloc.asm_label):
                # First line must be a label. If it's not the case, generate
                # it.
                label = guess_next_new_label(symbol_pool)
                cur_block = asmbloc.asm_bloc(label, alignment=mnemo.alignment)
            else:
                cur_block = asmbloc.asm_bloc(line, alignment=mnemo.alignment)
                i += 1
            # Generate the current bloc
            blocks.add_node(cur_block)
            state = STATE_IN_BLOC
            if block_to_nlink:
                block_to_nlink.addto(
                    asmbloc.asm_constraint(cur_block.label,
                                           C_NEXT))
            block_to_nlink = None
            continue

        # in block
        elif state == STATE_IN_BLOC:
            if isinstance(line, DirectiveSplit):
                state = STATE_NO_BLOC
                block_to_nlink = None
            elif isinstance(line, DirectiveDontSplit):
                state = STATE_NO_BLOC
                block_to_nlink = cur_block
            elif isinstance(line, DirectiveAlign):
                cur_block.alignment = line.alignment
            elif isinstance(line, asmbloc.asm_raw):
                cur_block.addline(line)
                block_to_nlink = cur_block
            elif isinstance(line, asmbloc.asm_label):
                if block_to_nlink:
                    cur_block.addto(
                        asmbloc.asm_constraint(line, C_NEXT))
                    block_to_nlink = None
                state = STATE_NO_BLOC
                continue
            # instruction
            elif isinstance(line, instruction):
                cur_block.addline(line)
                block_to_nlink = cur_block
                if not line.breakflow():
                    i += 1
                    continue
                if delayslot:
                    raise RuntimeError("Cannot have breakflow in delayslot")
                if line.dstflow():
                    for dst in line.getdstflow(symbol_pool):
                        if not isinstance(dst, m2_expr.ExprId):
                            continue
                        if dst in mnemo.regs.all_regs_ids:
                            continue
                        cur_block.addto(asmbloc.asm_constraint(dst.name, C_TO))

                if not line.splitflow():
                    block_to_nlink = None

                delayslot = line.delayslot + 1
            else:
                raise RuntimeError("unknown class %s" % line.__class__)
        i += 1

    for block in blocks:
        # Fix multiple constraints
        block.fix_constraints()

        # Log block
        asmbloc.log_asmbloc.info(block)
    return blocks, symbol_pool
