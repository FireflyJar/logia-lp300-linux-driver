# Logia LOGLP300 Linux Printer Driver

A community-developed Linux CUPS driver for the Logia LOGLP300 USB label printer.

## Status

Successfully tested on Fedora 44 with 4x6-inch labels at 300 DPI.

The driver prints PDF documents through CUPS without requiring Windows.

## How it works

1. CUPS converts the document into Zebra ZPL graphics.
2. A Python converter transforms the graphics into Z64-compressed ZPL.
3. A custom CUPS backend automatically discovers the connected Logia USB printer.
4. The backend sends the converted print data to the printer.

The printer may identify itself as ESC/POS despite accepting Z64-compressed ZPL.

## Requirements

- Linux with CUPS
- CUPS Zebra ZPL printer driver
- Python 3
- USB-connected Logia LOGLP300 printer
- Root privileges for installation

## Installation

Clone the repository:

    git clone https://github.com/FireflyJar/printer-driver-analysis.git
    cd printer-driver-analysis

Install the printer:

    sudo ./install.sh

The installer creates a CUPS printer queue named `logia-zpl`.

The installer refuses to overwrite an existing queue with the same name.

## Printing

Print a 4x6-inch PDF label:

    lp -d logia-zpl -o media=w288h432 -o Resolution=300dpi label.pdf

You can also select the printer from applications that support CUPS printing.

## Development

The portable installer and automatic USB discovery were developed and tested on Fedora 44.

Project files:

- `install.sh` - Fedora installation script
- `logiausb` - CUPS USB backend
- `logia-zpl-convert.py` - Z64 graphics converter
- `logia-decompress.py` - ZPL graphics decompression utility

## Limitations

- Tested with one LOGLP300 printer on Fedora 44.
- Other Linux distributions have not been verified.
- Automatic discovery currently expects the USB printer name `Logia Printer`.
- The driver uses a legacy CUPS PPD, which CUPS has deprecated.
- Printing has been verified with 4x6-inch PDF labels; other sizes require testing.

## License

License not yet selected.
