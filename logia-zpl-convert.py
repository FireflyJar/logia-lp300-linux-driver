#!/usr/bin/env python3
import sys
import base64
import zlib


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def convert(data):
    header, rest = data.split(b"\n", 1)

    if not header.startswith(b"~DGR:CUPS.GRF,"):
        raise ValueError("Unsupported CUPS graphic header")

    graphic = rest.split(b"^XA", 1)[0].decode("ascii").strip()

    parts = header.split(b",")
    total_bytes = int(parts[1])
    bytes_per_row = int(parts[2])

    if total_bytes <= 0 or bytes_per_row <= 0:
        raise ValueError("Invalid graphic dimensions")
    if total_bytes % bytes_per_row:
        raise ValueError("Incomplete graphic rows")

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
            if len(current) > row_width:
                raise ValueError("Row too long")
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
                raise ValueError("Row exceeds expected width")
            continue

        raise ValueError(f"Unknown compression character: {char!r}")

    if current or count:
        raise ValueError("Incomplete final row")

    if len(rows) != expected_rows:
        raise ValueError(
            f"Expected {expected_rows} rows, decoded {len(rows)}"
        )

    raw = bytes.fromhex("".join(rows))

    if len(raw) != total_bytes:
        raise ValueError("Incorrect decoded graphic size")

    compressed = zlib.compress(raw, level=9)
    encoded = base64.b64encode(compressed)
    checksum = f"{crc16(encoded):04X}".encode()

    width = bytes_per_row * 8
    height = expected_rows

    return (
        b"\x1f\x1b\x1a\x01\x03\x01\x00"
        + b"^MN^XA^LH0,0^MMT"
        + f"^PW{width}^LS0^POI^LL{height}\n".encode()
        + b"^FO0,0,0\n"
        + f"^GFA,{total_bytes},{total_bytes},{bytes_per_row},:Z64:".encode()
        + encoded
        + b":" + checksum
        + b"\r\n^PQ1^XZ\n\r"
    )


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(convert(sys.stdin.buffer.read()))
    except (ValueError, IndexError, UnicodeError) as exc:
        print(f"Conversion failed: {exc}", file=sys.stderr)
        sys.exit(1)
