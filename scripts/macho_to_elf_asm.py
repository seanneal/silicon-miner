#!/usr/bin/env python3
"""Adapt Apple Mach-O asm syntax to GNU as ELF.

Textual only: @PAGE/@PAGEOFF, the const section name, and the Mach-O
leading underscore on the three exported hash-path symbols. Instructions
are unchanged. The Mac build assembles sha256d_mine.s directly; this
exists so a Linux VM can assemble and run that same hash path under
qemu-aarch64 (Apple Silicon H/s are not measured here).
"""
import re
import sys

def main() -> None:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: macho_to_elf_asm.py IN.s OUT.s\n")
        sys.exit(2)
    src = open(sys.argv[1], encoding="utf-8").read()
    src = src.replace(".section __TEXT,__const", ".section .rodata")
    src = re.sub(r"(\w+)@PAGEOFF", r":lo12:\1", src)
    src = re.sub(r"(\w+)@PAGE", r"\1", src)
    for name in (
        "sha256_compress",
        "sha256d_genesis_selftest",
        "sha256d_mine_midstate",
    ):
        src = src.replace("_" + name, name)
    open(sys.argv[2], "w", encoding="utf-8").write(src)

if __name__ == "__main__":
    main()
