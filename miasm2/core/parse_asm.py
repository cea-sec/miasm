#!/usr/bin/env python
#-*- coding:utf-8 -*-

import re
import struct
import miasm2.expression.expression as m2_expr
from miasm2.core.asmbloc import *
from miasm2.core.utils import pck
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
        symbol_pool = asm_symbol_pool()

    lines_text = []
    lines_data = []
    lines_bss = []

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
                lines.append(asm_raw(raw))
                continue
            if directive == 'ustring':
                # XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"') + 1:line.rfind(r"'")] + "\x00"
                raw = raw.decode('string_escape')
                raw = "".join(map(lambda x: x + '\x00', raw))
                lines.append(asm_raw(raw))
                continue
            if directive in declarator:
                data_raw = line[r.end():].split(' ', 1)[1]
                data_raw = data_raw.split(',')
                size = declarator[directive]
                data_int = []
                has_symb = False

                # parser
                variable, operand, base_expr = gen_base_expr()
                my_var_parser = parse_ast(lambda x:m2_expr.ExprId(x, size),
                                          lambda x:m2_expr.ExprInt_fromsize(size, x))
                base_expr.setParseAction(my_var_parser)

                for b in data_raw:
                    b = b.strip()
                    x = base_expr.parseString(b)[0]
                    data_int.append(x.canonize())
                p = size2pck[size]
                raw = data_int
                x = asm_raw(raw)
                x.element_size = size
                lines.append(x)
                continue
            if directive == 'comm':
                # TODO
                continue
            if directive == 'split':  # custom command
                x = asm_raw()
                x.split = True
                lines.append(x)
                continue
            if directive == 'dontsplit':  # custom command
                lines.append(asm_raw(line.strip()))
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

    log_asmbloc.info("___pre asm oki___")
    # make blocs
    # gen_label_index = 0

    blocs_sections = []
    bloc_num = 0
    for lines in [lines_text, lines_data, lines_bss]:
        state = 0
        i = 0
        blocs = []
        blocs_sections.append(blocs)
        bloc_to_nlink = None
        block_may_link = False
        while i < len(lines):
            # print 'DEAL', lines[i], state
            # no current bloc
            if state == 0:
                if not isinstance(lines[i], asm_label):
                    l = guess_next_new_label(symbol_pool)
                    lines[i:i] = [l]
                else:
                    l = lines[i]
                    b = asm_bloc(l)
                    b.bloc_num = bloc_num
                    bloc_num += 1
                    blocs.append(b)
                    state = 1
                    i += 1
                    if bloc_to_nlink:
                        # print 'nlink!'
                        bloc_to_nlink.addto(
                            asm_constraint(b.label, asm_constraint.c_next))
                        bloc_to_nlink = None

            # in bloc
            elif state == 1:
                # asm_raw
                if isinstance(lines[i], asm_raw):
                    if hasattr(lines[i], 'split'):
                        state = 0
                        block_may_link = False
                        i += 1
                    else: #if lines[i].raw.startswith('.dontsplit'):
                        # raw asm are link by default
                        # print 'dontsplit'
                        state = 1
                        block_may_link = True
                        b.addline(lines[i])
                        i += 1
                    """
                    else:
                        b.addline(lines[i])
                        i += 1
                    """
                # asm_label
                elif isinstance(lines[i], asm_label):
                    if block_may_link:
                        # print 'nlink!'
                        b.addto(
                            asm_constraint(lines[i], asm_constraint.c_next))
                        block_may_link = False
                    state = 0
                # instruction
                else:
                    b.addline(lines[i])
                    if lines[i].dstflow():
                        '''
                        mydst = lines[i].args
                        if len(mydst)==1 and mnemo.get_symbols(mydst[0]):
                            arg = dict(mydst[0])
                            symbs = mnemo.get_symbols(arg)
                            """
                            TODO XXX redo this (as many miasm parts)
                            """
                            l = symbs[0][0]
                            lines[i].setdstflow([l])
                            b.addto(asm_constraint(l, asm_constraint.c_to))
                        '''
                        for x in lines[i].getdstflow(symbol_pool):
                            if not isinstance(x, m2_expr.ExprId):
                                continue
                            if x in mnemo.regs.all_regs_ids:
                                continue
                            b.addto(asm_constraint(x, asm_constraint.c_to))

                        # TODO XXX redo this really

                        if not lines[i].breakflow() and i + 1 < len(lines):
                            if isinstance(lines[i + 1], asm_label):
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

    for b in blocs_sections[0]:
        log_asmbloc.info(b)

    return blocs_sections, symbol_pool
