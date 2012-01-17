#!/usr/bin/env python
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
from miasm.tools.pe_helper import *
from elfesteem import *
from miasm.core import bin_stream
from miasm.arch.ia32_sem import *
from miasm.core import asmbloc
from miasm.core import parse_asm
import re
import sys


class hooks():
    def name2str(self, n):
        return "str_%s"%n
    
    def __init__(self, in_str, symbol_pool, gen_data_log_code = True):
        self.in_str = in_str
        self.all_bloc = [[]]
        self.symbol_pool = symbol_pool
        if gen_data_log_code:
            self.all_bloc, self.symbol_pool = parse_asm.parse_txt(x86mnemo,'''
        
        f_name:
        .string "out.txt"
        f_handle:
        .long 0x0
        my_critic_sec:
        .long 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        write_ret:
        .long 0xDEADBEEF
        mtick:
        .long 0xdeadbeef
        
        
        log_name_data_len:
            push    ebp
            mov     ebp, esp
            pushad
        
        
        
            mov eax, [f_handle]
            test eax, eax
            jnz write_file_2
            ;; create log file
            push 0
            push 0x80
            push 4
            push 0
            push 1
            push 4
            lea ebx, [f_name]
            push ebx
            call [CreateFileA]
            mov [f_handle], eax
        
            ;; create lock
            push my_critic_sec
            call [InitializeCriticalSection]
            
        write_file_2:
            ;; lock
            push my_critic_sec
            call [EnterCriticalSection]
        
            
            ;; write log name
            push [ebp+8]
            call [lstrlenA]
            inc eax
        
            push 0
            lea ebx, [write_ret]
            push ebx
            push eax
            push [ebp+8]
            push [f_handle]
            call [WriteFile]
        

            ;; write tickcount
            call [GetTickCount]
            mov [mtick], eax
            push 0
            lea ebx, [write_ret]
            push ebx
            push 4
            lea ebx, [mtick]
            push ebx
            push [f_handle]
            call [WriteFile]
            
        
            ;; write data size
            push 0
            lea ebx, [write_ret]
            push ebx
            push 4
            lea ebx, [ebp+0x10]
            push ebx
            push [f_handle]
            call [WriteFile]
        
        
            ;;write data
            push 0
            lea ebx, [write_ret]
            push ebx
            push [ebp+0x10]
            push [ebp+0xc]
            push [f_handle]
            call [WriteFile]
        
            ;; unlock
            push my_critic_sec
            call [LeaveCriticalSection]
        
        
            popad
            mov esp, ebp
            pop ebp
            ret 0xc
        
        ''', symbol_pool = symbol_pool)
            
    
    def add_hook(self, hook_ad, args_to_hook = {}, vars_decl = [], func_code = "", post_hook = ""):
        wrapper_name = "wrapper_%.8X"%hook_ad
        wrapper_log_name = "wrapper_log_%.8X"%hook_ad
        patch_name = "patch_%.8X"%hook_ad
        patch_end_name = "patch_end_%.8X"%hook_ad
        
        log_name = "log_%.8X"%hook_ad

        string_decl = []
        to_hook = args_to_hook.keys()
        to_hook.sort()

        for s in to_hook:
            if s.endswith('DONT_LOG'):
                continue
            string_decl.append('%s:\n.string "%s"'%(self.name2str(s), s))
        string_decl = "\n".join(string_decl)
        

        lines, total_bytes = asmbloc.steal_bytes(self.in_str, x86_mn, hook_ad, 5)
        erased_asm = "\n".join([str(l) for l in lines])
        print 'stolen lines'
        print erased_asm

        self.symbol_pool.getby_name_create(patch_name).offset = hook_ad
        self.symbol_pool.getby_name_create(patch_end_name).offset = hook_ad+total_bytes


        asm_s = '''
%s:
    call %s
'''%(wrapper_name, wrapper_log_name)+erased_asm+"\n"+post_hook+"\n"+'''
    jmp %s'''%(patch_end_name)+'''
%s:
    ;;int 3
    pushad
    pushfd
    '''%wrapper_log_name

        for s in to_hook[::-1]:
            asm_s += args_to_hook[s][1]
        asm_s +='''
    call    %s
    popfd
    popad
    ret
'''%(log_name)+string_decl+'\n'+'\n'.join(vars_decl)+'''
%s:
    push ebp
    mov ebp, esp
    
'''%(log_name)
        asm_s += func_code +'\n'

        for i, c in enumerate(to_hook):
            len_howto, arg_asm = args_to_hook[c]
            if type(len_howto) in [int, long]:
                asm_s += '''
    push %d
    '''%(len_howto)
            elif isinstance(len_howto, str):
                asm_s += len_howto

            if not c.endswith('DONT_LOG'):
                asm_s += '''
    push [ebp+%d]
    push %s
    call log_name_data_len
        '''%(8+4*i, self.name2str(c))


        asm_s +="""
    pop     ebp
    ret     %d
    
    """%(len(to_hook)*4)

        asm_s +="""
        %s:
        jmp %s
        %s:
        .split
        """%(patch_name, wrapper_name, patch_end_name)
    
        #print asm_s

        all_bloc, self.symbol_pool = parse_asm.parse_txt(x86mnemo,asm_s, symbol_pool = self.symbol_pool)
        self.all_bloc[0] += all_bloc[0]
        return log_name
        
    

        
