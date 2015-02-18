#!/usr/bin/env python
#-*- coding:utf-8 -*-
import re

import miasm2.expression.expression as m2_expr
import miasm2.core.asmbloc as asmbloc
from miasm2.core.cpu import gen_base_expr, parse_ast

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


def guess_next_new_label(symbol_pool, gen_label_index=0):
    i = 0
    gen_name = "loc_%.8X"
    while True:
        name = gen_name % i
        l = symbol_pool.getby_name(name)
        if l is None:
            return symbol_pool.add_label(name)
        i += 1


def parse_txt(mnemo, attrib, txt, symbol_pool=None, gen_label_index=0):
    if symbol_pool is None:
        symbol_pool = asmbloc.asm_symbol_pool()

    lines_text = []
    lines_data = []
    lines_bss = []

    C_NEXT = asmbloc.asm_constraint.c_next
    C_TO = asmbloc.asm_constraint.c_to

    lines = lines_text
    # parse each line
    for line in txt.split('\n'):
        # empty
        if re.match(r'\s*$', line):
            continue
        # comment
        if re.match(r'\s*;\S*', line):
            continue
        # labels to forget
        r = re.match(r'\s*\.LF[BE]\d\s*:', line)
        if r:
            continue
        # label beginning with .L
        r = re.match(r'\s*(\.L\S+)\s*:', line)
        if r:
            l = r.groups()[0]
            l = symbol_pool.getby_name_create(l)
            lines.append(l)
            continue
        # directive
        if re.match(r'\s*\.', line):
            r = re.match(r'\s*\.(\S+)', line)
            directive = r.groups()[0]
            if directive == 'text':
                lines = lines_text
                continue
            if directive == 'data':
                lines = lines_data
                continue
            if directive == 'bss':
                lines = lines_bss
                continue
            if directive in ['string', 'ascii']:
                # XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"') + 1:line.rfind(r"'")]
                raw = raw.decode('string_escape')
                if directive == 'string':
                    raw += "\x00"
                lines.append(asmbloc.asm_raw(raw))
                continue
            if directive == 'ustring':
                # XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"') + 1:line.rfind(r"'")] + "\x00"
                raw = raw.decode('string_escape')
                raw = "".join([string + '\x00' for string in raw])
                lines.append(asmbloc.asm_raw(raw))
                continue
            if directive in declarator:
                data_raw = line[r.end():].split(' ', 1)[1]
                data_raw = data_raw.split(',')
                size = declarator[directive]
                data_int = []

                # parser
                base_expr = gen_base_expr()[2]
                my_var_parser = parse_ast(lambda x: m2_expr.ExprId(x, size),
                                          lambda x:
                                              m2_expr.ExprInt_fromsize(size, x))
                base_expr.setParseAction(my_var_parser)

                for b in data_raw:
                    b = b.strip()
                    x = base_expr.parseString(b)[0]
                    data_int.append(x.canonize())

                raw = data_int
                x = asmbloc.asm_raw(raw)
                x.element_size = size
                lines.append(x)
                continue
            if directive == 'comm':
                # TODO
                continue
            if directive == 'split':  # custom command
                x = asmbloc.asm_raw()
                x.split = True
                lines.append(x)
                continue
            if directive == 'dontsplit':  # custom command
                lines.append(asmbloc.asm_raw(line.strip()))
                continue
            if directive in ['file', 'intel_syntax', 'globl', 'local',
                             'type', 'size', 'align', 'ident', 'section']:
                continue
            if directive[0:4] == 'cfi_':
                continue

            raise ValueError("unknown directive %s" % str(directive))

        # label
        r = re.match(r'\s*(\S+)\s*:', line)
        if r:
            l = r.groups()[0]
            l = symbol_pool.getby_name_create(l)
            lines.append(l)
            continue

        # code
        if ';' in line:
            line = line[:line.find(';')]
        line = line.strip(' ').strip('\t')
        instr = mnemo.fromstring(line, attrib)
        if instr.dstflow():
            instr.dstflow2label(symbol_pool)
        lines.append(instr)

    asmbloc.log_asmbloc.info("___pre asm oki___")
    # make blocs

    blocs_sections = []
    bloc_num = 0
    b = None
    for lines in [lines_text, lines_data, lines_bss]:
        state = 0
        i = 0
        blocs = []
        blocs_sections.append(blocs)
        bloc_to_nlink = None
        block_may_link = False
        while i < len(lines):
            # no current bloc
            if state == 0:
                if not isinstance(lines[i], asmbloc.asm_label):
                    l = guess_next_new_label(symbol_pool)
                    lines[i:i] = [l]
                else:
                    l = lines[i]
                    b = asmbloc.asm_bloc(l)
                    b.bloc_num = bloc_num
                    bloc_num += 1
                    blocs.append(b)
                    state = 1
                    i += 1
                    if bloc_to_nlink:
                        bloc_to_nlink.addto(asmbloc.asm_constraint(b.label,
                                                                   C_NEXT))
                        bloc_to_nlink = None

            # in bloc
            elif state == 1:
                if isinstance(lines[i], asmbloc.asm_raw):
                    if hasattr(lines[i], 'split'):
                        state = 0
                        block_may_link = False
                        i += 1
                    else:
                        state = 1
                        block_may_link = True
                        b.addline(lines[i])
                        i += 1
                # asmbloc.asm_label
                elif isinstance(lines[i], asmbloc.asm_label):
                    if block_may_link:
                        b.addto(
                            asmbloc.asm_constraint(lines[i], C_NEXT))
                        block_may_link = False
                    state = 0
                # instruction
                else:
                    b.addline(lines[i])
                    if lines[i].dstflow():
                        for x in lines[i].getdstflow(symbol_pool):
                            if not isinstance(x, m2_expr.ExprId):
                                continue
                            if x in mnemo.regs.all_regs_ids:
                                continue
                            b.addto(asmbloc.asm_constraint(x, C_TO))

                        # TODO XXX redo this really

                        if not lines[i].breakflow() and i + 1 < len(lines):
                            if isinstance(lines[i + 1], asmbloc.asm_label):
                                l = lines[i + 1]
                            else:
                                l = guess_next_new_label(symbol_pool)
                                lines[i + 1:i + 1] = [l]
                        else:
                            state = 0

                        if lines[i].splitflow():
                            bloc_to_nlink = b
                    if not lines[i].breakflow() or lines[i].splitflow():
                        block_may_link = True
                    else:
                        block_may_link = False

                    i += 1

    for block in blocs_sections[0]:
        asmbloc.log_asmbloc.info(block)

    return blocs_sections, symbol_pool
