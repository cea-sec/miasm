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
class afs_desc:
    def __init__(self):

        self.noad = "no_ad"
        self.ad = "ad"

        self.ad8 = "ad8"
        self.ad16 = "ad16"
        self.ad32 = "ad32"
        self.segm = "segm"

        self.size = "size"

        self.symb = "symb__intern__"

        self.imm = "imm"
        self.s08 = "s08"
        self.u08 = "u08"
        self.u16 = "u16"
        self.s16 = "s16"
        self.u32 = "u32"
        self.s32 = "s32"
        self.s32 = "s32"
        self.s64 = "s64"
        self.u64 = "u64"

        self.f32 = "f32"
        self.f64 = "f64"
        self.fpu = "fpu"
        
        self.im1 = "im1"
        self.im3 = "im3"
        self.ims = "ims"
        self.mim = "mim"

        self.size_seg = "size_seg"

        self.dict_size = {self.imm:'imm',
                          self.s08:'b',
                          self.u08:'B',
                          self.s16:'h',
                          self.u16:'H',
                          self.s32:'i',
                          self.u32:'I',
                          }
                          

        
        self.r_eax = "eax"
        self.r_ecx = "ecx"
        self.r_edx = "edx"
        self.r_ebx = "ebx"
        self.r_esp = "esp"
        self.r_ebp = "ebp"
        self.r_esi = "esi"
        self.r_edi = "edi"
        
        self.r_dr0 = "dr0"
        self.r_dr1 = "dr1"
        self.r_dr2 = "dr2"
        self.r_dr3 = "dr3"
        self.r_dr4 = "dr4"
        self.r_dr5 = "dr5"
        self.r_dr6 = "dr6"
        self.r_dr7 = "dr7"
        
        self.r_cr0 = "cr0"
        self.r_cr1 = "cr1"
        self.r_cr2 = "cr2"
        self.r_cr3 = "cr3"
        self.r_cr4 = "cr4"
        self.r_cr5 = "cr5"
        self.r_cr6 = "cr6"
        self.r_cr7 = "cr7"
        
        self.r_ax = "ax"
        self.r_cx = "cx"
        self.r_dx = "dx"
        self.r_bx = "bx"
        self.r_sp = "sp"
        self.r_bp = "bp"
        self.r_si = "si"
        self.r_di = "di"
             
        self.r_al = "al"
        self.r_cl = "cl"
        self.r_dl = "dl"
        self.r_bl = "bl"
        self.r_ah = "ah"
        self.r_ch = "ch"
        self.r_dh = "dh"
        self.r_bh = "bh"


        self.r_es = "es"
        self.r_cs = "cs"
        self.r_ss = "ss"
        self.r_ds = "ds"
        self.r_fs = "fs"
        self.r_gs = "gs"

        self.reg_list8 =[self.r_al,  self.r_cl,  self.r_dl,  self.r_bl,
                         self.r_ah,  self.r_ch,  self.r_dh,  self.r_bh]
        self.reg_list16=[self.r_ax,  self.r_cx,  self.r_dx,  self.r_bx,
                         self.r_sp,  self.r_bp,  self.r_si,  self.r_di]
        self.reg_list32=[self.r_eax, self.r_ecx, self.r_edx, self.r_ebx,
                         self.r_esp, self.r_ebp, self.r_esi, self.r_edi]
  
        self.reg_dr=     [self.r_dr0, self.r_dr1, self.r_dr2, self.r_dr3,
                          self.r_dr4, self.r_dr5, self.r_dr6, self.r_dr7]

        self.reg_cr=     [self.r_cr0, self.r_cr1, self.r_cr2, self.r_cr3,
                          self.r_cr4, self.r_cr5, self.r_cr6, self.r_cr7]

        self.reg_sg=     [self.r_es,  self.r_cs,  self.r_ss,  self.r_ds,
                         self.r_fs,  self.r_gs,   None,       None]

        self.reg_flt =  ["st%d"%i for i in range(8)]

        self.reg_mmx =  ["mm%d"%i for i in range(8)]

        self.reg_dict = {}
        for i in range(8):
            self.reg_dict[self.reg_list8[i]] = i
        for i in range(8):
            self.reg_dict[self.reg_list16[i]] = i
        for i in range(8):
            self.reg_dict[self.reg_list32[i]] = i
        for i in range(8):
            self.reg_dict[self.reg_flt[i]] = i
        for i in range(8):
            self.reg_dict[self.reg_cr[i]] = i+0x100
        for i in range(8):
            self.reg_dict[self.reg_dr[i]] = i+0x200
        for i in range(8):
            self.reg_dict[self.reg_sg[i]] = i+0x400
            
        

        self.x86_prefix = [0xF0, 0xF2, 0xF3,
                           0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65,
                           0x66, 
                           0x67]
        

x86_afs = afs_desc()
