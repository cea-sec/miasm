#! /usr/bin/env python
#-*- coding:utf-8 -*-
"""ELF loader: ARM BE8 images must map to a machine that decodes
little-endian instructions, not to plain "armb" (regression for issue #1576).
"""
import unittest
import struct
import io
import logging

from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

logging.getLogger('cpuhelper').setLevel(logging.ERROR)

ENTRY = 0x400000
FLAGS_BE8 = 0x05800200   # EABI v5 | EF_ARM_BE8
FLAGS_BE32 = 0x05000200  # EABI v5

CODE = [
    0xE3A00012,  # mov  r0, #0x12
    0xE2800030,  # add  r0, r0, #0x30
    0xE3A01005,  # mov  r1, #5
    0xE0020190,  # mul  r2, r0, r1
    0xE0211202,  # eor  r1, r1, r2, lsl #4
]
EXPECTED = ["MOV", "ADD", "MOV", "MUL", "EOR"]


def make_elf(be8: bool) -> bytes:
    endian = "<" if be8 else ">"
    text = b"".join(struct.pack(endian + "I", w) for w in CODE)
    off_text = 0x1000
    hdr = (b"\x7fELF" + bytes([1, 2, 1, 0]) + b"\x00" * 8   # ELFCLASS32, MSB, SYSV
           + struct.pack(">H", 2)         # ET_EXEC
           + struct.pack(">H", 40)        # EM_ARM
           + struct.pack(">I", 1)         # e_version
           + struct.pack(">I", ENTRY)     # e_entry
           + struct.pack(">I", 52)        # e_phoff
           + struct.pack(">I", 0)         # e_shoff
           + struct.pack(">I", FLAGS_BE8 if be8 else FLAGS_BE32)
           + struct.pack(">H", 52)        # e_ehsize
           + struct.pack(">H", 32)        # e_phentsize
           + struct.pack(">H", 1)         # e_phnum
           + struct.pack(">H", 40)        # e_shentsize
           + struct.pack(">H", 0)         # e_shnum
           + struct.pack(">H", 0))        # e_shstrndx
    ph = (struct.pack(">I", 1)            # PT_LOAD
          + struct.pack(">I", off_text)   # p_offset
          + struct.pack(">I", ENTRY)      # p_vaddr
          + struct.pack(">I", ENTRY)      # p_paddr
          + struct.pack(">I", len(text))  # p_filesz
          + struct.pack(">I", len(text))  # p_memsz
          + struct.pack(">I", 5)          # PF_R | PF_X
          + struct.pack(">I", 0x1000))    # p_align
    img = hdr + ph + b"\x00" * (off_text - 52 - 32) + text
    assert len(img) == off_text + len(text)
    return img


def load(raw: bytes):
    ldb = LocationDB()
    return Container.from_stream(io.BytesIO(raw), ldb), ldb


def dis_insns(container, ldb):
    mach = Machine(container.arch)
    mdis = mach.dis_engine(container.bin_stream, loc_db=ldb)
    mdis.dont_dis = [ENTRY + len(CODE) * 4]
    cfg = mdis.dis_multiblock(ENTRY)
    lines = []
    for b in sorted(cfg.blocks,
                    key=lambda b: b.lines[0].offset if b.lines else -1):
        lines.extend(b.lines)
    return [l.name.upper() for l in lines[:len(CODE)]]


class TestElfBe8(unittest.TestCase):
    def test_be8_maps_to_armbe8_and_decodes(self):
        cont, ldb = load(make_elf(be8=True))
        self.assertEqual(cont.arch, "armbe8")
        self.assertEqual(dis_insns(cont, ldb), EXPECTED)

    def test_be32_control_stays_armb_and_decodes(self):
        cont, ldb = load(make_elf(be8=False))
        self.assertEqual(cont.arch, "armb")
        self.assertEqual(dis_insns(cont, ldb), EXPECTED)


if __name__ == "__main__":
    unittest.main()
