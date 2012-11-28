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
from miasm.arch.ia32_reg import x86_afs
from miasm.tools.modint import uint1, uint8, uint16, uint32, uint64, int8, int16, int32, int64

def dict_add(a, b):
    tmp = dict(a)
    for k in b:
        #special case
        if k == x86_afs.symb:
            if k in tmp:
                tmp[k] = dict_add(tmp[k], b[k])
            else:
                tmp[k] = dict(b[k])
            continue
        #normal case
        if k in tmp:
            tmp[k]+=b[k]
        else:
            tmp[k] = b[k]
        if tmp[k]==0:
            del(tmp[k])
    return tmp

def dict_sub(a, b):
    tmp = dict(a)
    for k in b:
        #special case
        if k == x86_afs.symb:
            if k in tmp:
                tmp[k] = dict_sub(tmp[k], b[k])
            else:
                tmp[k] = dict({},b[k])
            continue
        #normal case
        if k in tmp:
            tmp[k]-=b[k]
        else:
            tmp[k] = -b[k]
        if tmp[k]==0:
            del(tmp[k])
    return tmp

def dict_mul(a, b):
    if a.keys() == [x86_afs.imm]:
        ret = {}
        for k in b:
            if k == x86_afs.symb:
                ret[k] = dict_mul({x86_afs.imm:a[x86_afs.imm]}, b[k])
            else:
                ret[k] = a[x86_afs.imm]*b[k]
        return ret
    if b.keys() == [x86_afs.imm]:
        ret = {}
        for k in a:
            if k == x86_afs.symb:
                ret[k] = dict_mul({x86_afs.imm:b[x86_afs.imm]}, a[k])
            else:
                ret[k] = b[x86_afs.imm]*a[k]
        return ret

    raise 'bad dict mul %s'%(str(a)+str(b))

keywords = ("BYTE", "WORD", "DWORD", "QWORD", "SINGLE", "DOUBLE", "TBYTE",
            "ES", "CS", "SS", "DS", "FS", "GS",
            "PTR", "OFFSET", "FLAT")


tokens = keywords +(
    'NUMBER',
    'PLUS','MINUS','TIMES','DIVIDE',
    'LPAREN','RPAREN','LBRA','RBRA', 'COLON',
    'NAME',
    )

# Tokens

t_PLUS    = r'\+'
t_MINUS   = r'-'
t_TIMES   = r'\*'
t_DIVIDE  = r'/'
t_LPAREN  = r'\('
t_RPAREN  = r'\)'
t_LBRA  = r'\['
t_RBRA  = r'\]'
t_COLON    = r':'

def t_NAME(t):
    r'\.L[A-Z]*[0-9]+|[a-zA-Z_][a-zA-Z0-9_.]*'
    if t.value.upper() in keywords:
        t.type = t.value.upper()
        t.value = t.value.lower()
    return t



def t_NUMBER(t):
    r'((((0x)|(0X))[0-9a-fA-F]+)|(\d+))'
    try:
        if t.value.startswith("0x") or t.value.startswith("0X"):
            t.value = int(t.value, 16)
        else:
            t.value = int(t.value)
    except ValueError:
        print("Integer value too large %d", t.value)
        t.value = 0
    return t

# Ignored characters
t_ignore = " \t"

def t_newline(t):
    r'\n+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)


# Build the lexer
import ply.lex as lex
lex.lex()


precedence = (
    ('left','PLUS','MINUS'),
    ('left','TIMES','DIVIDE'),
    ('right','UMINUS'),
    )

def p_expression_1(t):
    '''expression : '''
    return {}
def p_expression_2(t):
    '''expression : expression PLUS expression
                  | expression MINUS expression
                  | expression TIMES expression
                  | expression DIVIDE expression'''

    if t[2] == '+':
        t[0] = dict_add(t[1], t[3])
    elif t[2] == '-':
        t[0] = dict_sub(t[1], t[3])
    elif t[2] == '*':
        t[0] = dict_mul(t[1], t[3])
    elif t[2] == '/':
        raise 'bad op'
    else:
        raise 'bad op'


def p_expression_3(t):
    '''expression : LPAREN expression RPAREN'''
    t[0] = t[2]

def p_expression_4(t):
    '''expression : OFFSET FLAT COLON expression '''
    t[0] = t[4]

def p_expression_5(t):
    '''expression : MINUS expression  %prec UMINUS'''
    t[0] = dict([[k,-t[2][k]] for k in t[2]])

def p_expression_6(t):
    '''expression :  NUMBER'''
    t[0] = {x86_afs.imm:int(int32(uint32(int(t[1]))))}

def p_expression_8st(t):
    '''expression : NAME LPAREN NUMBER RPAREN'''
    t[0] = t[1] + "%d"%t[3]
    t[0] ={x86_afs.reg_dict[t[0]]:1, x86_afs.size : x86_afs.f32}

#"[@?_a-zA-Z\.$][?\.a-zA-Z0-9_@$]*"
def p_expression_8(t):
    '''expression : NAME'''
    if t[1] == 'st':
        t[1] = 'st0'
    if t[1] in x86_afs.reg_list32:
        size = x86_afs.u32
    elif t[1] in x86_afs.reg_list16:
        size = x86_afs.u16
    elif t[1] in x86_afs.reg_list8:
        size = x86_afs.u08
    elif t[1] in x86_afs.reg_flt:
        size = x86_afs.f32
    elif t[1] in x86_afs.reg_dr:
        size = x86_afs.u32
    elif t[1] in x86_afs.reg_cr:
        size = x86_afs.u32
    elif t[1] in x86_afs.reg_sg:
        size = x86_afs.u32


    else:
        #raise 'bad reg size'
        t[0] = {x86_afs.symb:{t[1]:1}}
        return
    t[0] ={x86_afs.reg_dict[t[1]]:1, x86_afs.size : size}

def p_PTRSIZE(t):
    '''PTRSIZE : BYTE
               | WORD
               | DWORD
               | QWORD
               | SINGLE
               | DOUBLE
               | TBYTE
                 '''
    t[0] = t[1]

def p_PTRMEM(t):
    '''PTRMEM : PTR'''
    t[0] = t[1]







def p_OPTSEG(t):
    '''OPTSEG :  ES
               | CS
               | SS
               | DS
               | FS
               | GS
                 '''
    t[0] = t[1]

def p_opt_seg_colon_1(t):
    '''opt_seg_colon : OPTSEG COLON '''
    t[0] = {x86_afs.segm:x86_afs.reg_sg.index(t[1])}

def p_opt_seg_1(t):
    '''opt_seg : OPTSEG '''
    t[0] ={x86_afs.reg_dict[t[1]]:1, x86_afs.size : x86_afs.u32}

def p_expression_9(t):
    '''expression : PTRSIZE PTRMEM expression '''
    size = t[1]
    if size=='byte':
        t[3][x86_afs.ad] = x86_afs.u08
    elif size == 'word':
        t[3][x86_afs.ad] = x86_afs.u16
    elif size == 'dword':
        t[3][x86_afs.ad] = x86_afs.u32
    elif size == 'qword':
        t[3][x86_afs.ad] = x86_afs.f64
    elif size == 'single':
        t[3][x86_afs.ad] = x86_afs.f32
    elif size == 'double':
        t[3][x86_afs.ad] = x86_afs.f64
    else:
        raise 'bad address size'
    t[0] = t[3]

def p_expression_10(t):
    '''expression : LBRA expression RBRA '''
    if not x86_afs.ad in t[2]:
        t[2][x86_afs.ad] = x86_afs.u32
    t[0] = t[2]

def p_expression_10a(t):
    '''expression : opt_seg_colon expression '''
    t[2].update(t[1])
    t[0] = t[2]

def p_expression_11(t):
    '''expression : opt_seg'''
    t[0] = t[1]

def parse_ad(a):
    tmp_dict = {}
    l = yacc.parse(a)

    if not x86_afs.ad in l:
        l[x86_afs.ad] = False
    else:
        l[x86_afs.size] = l[x86_afs.ad]

    if not x86_afs.size in l:
        l[x86_afs.size] = x86_afs.u32



    return l

import ply.yacc as yacc
yacc.yacc()

def ad_to_generic(a):

    #opt imm
    out = []
    to_add = []
    #generic ad size
    if a[x86_afs.ad]:
        a[x86_afs.ad] = True


        #imm can always be encoded in u32
        to_add.append({x86_afs.imm:x86_afs.u32})

        if  x86_afs.imm in a:
            if a[x86_afs.imm] >=0 and a[x86_afs.imm] <=0xFF:
                to_add.append({x86_afs.imm:x86_afs.u08})
            if a[x86_afs.imm] >=-128 and a[x86_afs.imm] <128:
                to_add.append({x86_afs.imm:x86_afs.s08})
        else:
            to_add.append({x86_afs.imm:x86_afs.u08})
            to_add.append({x86_afs.imm:x86_afs.s08})


    if not x86_afs.imm in a:
        out.append(a)
    else:
        i = a[x86_afs.imm]
        if i<128 and i >= -128:
            to_add.append({x86_afs.imm:x86_afs.s08})
        if i<=0xFF and i >=0 :
            to_add.append({x86_afs.imm:x86_afs.u08})

    for kv in to_add:
        tmp = dict(a)
        tmp.update(kv)
        out.append(tmp)

    out_unik = []
    for o in out:
        if not o in out_unik:
            out_unik.append(o)

    return out_unik


