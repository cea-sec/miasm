#
# Copyright (C) 2011 EADS France, Fabrice Desclaux <fabrice.desclaux@eads.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
from miasm.core.asmbloc import *
from shlex import shlex


declarator = {'byte':'B', 'long':'I'}
def guess_next_new_label(symbol_pool, gen_label_index = 0):
    i = 0
    while True:
        l = asm_label(i)
        i+=1
        if not l.name in symbol_pool.s:
            return l
        
    
def parse_txt(mnemo, txt, symbol_pool = None, gen_label_index = 0):
    if symbol_pool == None:
        symbol_pool = asm_symbol_pool()

    lines_text = []
    lines_data = []
    lines_bss  = []

    lines=lines_text
    #parse each line
    for line in txt.split('\n'):
        #empty
        if re.match(r'\s*$', line):
            continue
        #comment
        if re.match(r'\s*;\S*', line):
            continue
        #directive
        if re.match(r'\s*\.', line):
            r =  re.match(r'\s*\.(\S+)', line)
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
                #XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"')+1:line.rfind(r"'")]
                if directive == 'string':
                    raw+="\x00"
                lines.append(asm_raw(raw))
                continue
            if directive == 'ustring':
                #XXX HACK
                line = line.replace(r'\n', '\n').replace(r'\r', '\r')
                raw = line[line.find(r'"')+1:line.rfind(r"'")]+"\x00"
                raw = "".join(map(lambda x:x+'\x00', raw))
                lines.append(asm_raw(raw))
                continue
            if directive in declarator:
                data_raw = [x for x in shlex(line[r.end():]) if not x in ',']
                data_int = []
                for b in data_raw:
                    if re.search(r'0x', b):
                        data_int.append(int(b, 16))
                    else:
                        data_int.append(int(b))
                raw = reduce(lambda x,y:x+struct.pack(declarator[directive], y), data_int, "")
                lines.append(asm_raw(raw))
                continue
            if directive == 'split': #custom command
                lines.append(asm_raw(line.strip()))
                continue
            
            raise "unknown directive %s"%str(directive)
        
        #label
        r = re.match(r'\s*(\S+)\s*:', line)
        if r:
            l = r.groups()[0]
            l = symbol_pool.getby_name_create(l)
            lines.append(l)
            continue
        
        #code
        if ';' in line:
            line = line[:line.find(';')]
        prefix, name, args = mnemo.parse_mnemo(line)
        #print prefix, name, args
        args = [mnemo.parse_address(a) for a in args]
        #pool symbols
        for a in args:

            if mnemo.has_symb(a):
                symbs = mnemo.get_symbols(a)
                symbs_dct = {}
                for s, count in symbs:
                    if isinstance(s, asm_label):
                        continue
                    l = symbol_pool.getby_name_create(s)
                    symbs_dct[s] = l
                mnemo.names2symbols(a, symbs_dct)




        if mnemo.rebuilt_inst:
            candidates=dict([[len(x),x] for x in mnemo.asm(line)])
            if not candidates:
                raise ValueError('cannot asm %s'%str(line))
            c = candidates[min(candidates.keys())]
            c+=mnemo.prefix2hex(prefix)
            instr = mnemo.dis(c)
        else:
            instr = mnemo.asm_instr(line)
        instr.arg = args
        lines.append(instr)

    log_asmbloc.info( "___pre asm oki___")
    #make blocs
    #gen_label_index = 0


    
    all_blocs_sections = []
    bloc_num = 0
    for lines in [lines_text, lines_data, lines_bss]:
        state = 0
        i = 0
        all_blocs = []
        all_blocs_sections.append(all_blocs)

        bloc_to_nlink = None
        block_may_link = False
        while i <len(lines):
            #no current bloc
            if state == 0:
                if not isinstance(lines[i], asm_label):
                    l = guess_next_new_label(symbol_pool)
                    symbol_pool.add(l)
                    lines[i:i] = [l]
                else:
                    l = lines[i]
                    b = asm_bloc(l)
                    b.bloc_num = bloc_num
                    bloc_num+=1
                    all_blocs.append(b)
                    state = 1
                    i+=1
                    if bloc_to_nlink:
                        bloc_to_nlink.addto(asm_constraint(b.label, asm_constraint.c_next))
                        bloc_to_nlink = None
                
            #in bloc
            elif state == 1:
                #asm_raw
                if isinstance(lines[i], asm_raw):
                    if lines[i].raw.startswith('.split'):
                        state = 0
                        block_may_link = False
                        i+=1
                    else:
                        b.addline(lines[i])
                        i+=1
                #asm_label
                elif isinstance(lines[i], asm_label):
                    if block_may_link:
                        b.addto(asm_constraint(lines[i], asm_constraint.c_next))
                        block_may_link = False
                    state = 0
                #instruction
                else:
                    b.addline(lines[i])
                    if lines[i].dstflow():
                        mydst = lines[i].arg

                        if len(mydst)==1 and mnemo.get_symbols(mydst[0]):
                            arg = dict(mydst[0])
                            symbs = mnemo.get_symbols(arg)
                            """
                            TODO XXX redo this (as many miasm parts)
                            """
                            l = symbs[0][0]
                            lines[i].setdstflow([l])
                            b.addto(asm_constraint(l, asm_constraint.c_to))
                            
                        # TODO XXX redo this really

                        if not lines[i].breakflow() and i+1 < len(lines):
                            if isinstance(lines[i+1], asm_label):
                                l = lines[i+1]
                            else:
                                l = guess_next_new_label(symbol_pool)
                                symbol_pool.add(l)
                                lines[i+1:i+1] = [l]
                        else:
                            state = 0

                        if lines[i].splitflow():
                            bloc_to_nlink = b
                    if not lines[i].breakflow() or lines[i].splitflow():
                        block_may_link = True
                    else:
                        block_may_link = False
                            
                    
                    i+=1        
    
    
                        
    
    for b in all_blocs_sections[0]:
        log_asmbloc.info( b)

    return all_blocs_sections, symbol_pool
