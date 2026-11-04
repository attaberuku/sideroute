#!/usr/bin/env python3
"""Renders the SVGs in this folder to multi-size .ico files (PNG entries). Needs rsvg-convert."""
import struct, subprocess, sys
from pathlib import Path

here = Path(__file__).resolve().parent

def ico(svg: str, sizes: list[int], out: str) -> None:
    pngs = [subprocess.run(["rsvg-convert", "-w", str(s), "-h", str(s), str(here / svg)],
                           check=True, capture_output=True).stdout for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    entries, data = b"", b""
    for s, p in zip(sizes, pngs):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(p), offset + len(data))
        data += p
    (here / out).write_bytes(head + entries + data)

ico("app.svg", [16, 20, 24, 32, 40, 48, 64, 256], "app.ico")
for state in ("off", "on", "warn"):
    ico(f"tray-{state}.svg", [16, 20, 24, 32, 40, 48], f"tray-{state}.ico")
