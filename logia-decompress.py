#!/usr/bin/env python3
from pathlib import Path

data = Path("logia-cups-output.bin").read_bytes()
header, rest = data.split(b"\n", 1)
graphic = rest.split(b"^XA", 1)[0].decode("ascii").strip()

parts = header.split(b",")
total_bytes = int(parts[1])
bytes_per_row = int(parts[2])
row_width = bytes_per_row * 2
expected_rows = total_bytes // bytes_per_row

rows = []
current = ""
count = 0

for char in graphic:
    if char in "\r\n":
        continue

    if char == ":":
        if not rows or current or count:
            raise ValueError("Unexpected repeated-row marker")
        rows.append(rows[-1])
        continue

    if char == ",":
        current += "0" * (row_width - len(current))
        rows.append(current)
        current = ""
        count = 0
        continue

    if "g" <= char <= "z":
        count += (ord(char) - ord("g") + 1) * 20
        continue

    if "G" <= char <= "Y":
        count += ord(char) - ord("G") + 1
        continue

    if char in "0123456789ABCDEF":
        current += char * (count or 1)
        count = 0

        if len(current) == row_width:
            rows.append(current)
            current = ""
        elif len(current) > row_width:
            raise ValueError(f"Row exceeds {row_width} characters")
        continue

    raise ValueError(f"Unknown compression character: {char!r}")

if current:
    raise ValueError("Incomplete final row")

if len(rows) != expected_rows:
    raise ValueError(
        f"Expected {expected_rows} rows, decoded {len(rows)}"
    )

raw_hex = "".join(rows).encode("ascii")

zpl = (
    b"^XA\n"
    b"^PW1200\n"
    b"^LL1800\n"
    b"^FO0,0\n"
    + f"^GFA,{total_bytes},{total_bytes},{bytes_per_row},".encode()
    + raw_hex
    + b"\n^FS\n^PQ1\n^XZ\n"
)

Path("logia-uncompressed.zpl").write_bytes(zpl)

print(f"Decoded rows: {len(rows)}")
print(f"Uncompressed bytes: {len(raw_hex) // 2}")
print(f"Created logia-uncompressed.zpl ({len(zpl)} bytes)")
