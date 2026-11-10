# LogiaRender printer output analysis

## Scope and method

This report records the static analysis findings from the REA/Ghidra session
for `LogiaRender.DLL` and the read-only inspection of `Logiadpi.xpd`. The
original DLL and XPD were not executed or modified.

| Artifact | Identity |
|---|---|
| `LogiaRender.DLL` | x64 PE; SHA-256 `43b97212c4d6c047f0bb86d1896fca84da84b80e756e7d8d5e9df2bc1cba08e5` |
| `Logiadpi.xpd` | 1,955 bytes; SHA-256 `9617007045c6ce9fc379a7bb0047056fc26936bc20dd56d9765a50ad44acc0ca` |
| Analysis provider | Ghidra 12.2, through REA |

Pseudocode references below identify decompiler output, not original source.
Evidence IDs refer to retained REA observations from this investigation.
Static references establish what the analyzed image contains, not what a
particular Windows installation executed or sent to a printer.

## Executive finding

**Confirmed statically for the supplied XPD:** `DrvEnablePDEV`
(`FUN_180005068`, `0x180005068`) compares the XPD profile label at file offset
`0x4c` with a four-entry profile table. The XPD contains UTF-16LE `ZPL` at that
offset. The matching table row contains the function pointer
`0x18000af98` (`FUN_18000af98`), the ZPL-style serializer. That row is copied
into the PDEV so `DrvSendPage` (`FUN_18000a250`, `0x18000a250`) can call it
through the pointer at PDEV offset `+0x6e8`.

The same table contains `0x18000a790` (`FUN_18000a790`), a TSPL-style
serializer, in its `TSPL` row. It is not the selected row for the supplied XPD.
This establishes the static selection logic and the value encoded in this XPD;
it does not prove which data-file path a particular live Windows installation
returns to the driver.

The DLL also has a separate `DrvEscape`/`WritePrinter` route that forwards a
length-prefixed caller buffer. No conclusion that this route emits either
serializer's commands is warranted.

## Profile table and XPD selection

### XPD observations

- The file begins with `TRPH`; the initial header bytes include
  `54 52 50 48 c0 00 00 00 23 01 00 00`.
- The profile label is at file offset `0x4c`: bytes
  `5a 00 50 00 4c 00 00 00`, i.e. UTF-16LE `ZPL` followed by NUL.
- The file contains 16 fixed-stride media records, followed by a JSON settings
  object beginning at offset `0x680`.
- The JSON includes:

  ```json
  {
    "Advanced": {
      "Density": {"Min": 0, "Max": 15, "Value": 65288},
      "Speed": {"Min": 2, "Max": 4, "Value": 65282},
      "PrintMode": {"Value": 1},
      "SavePaper": {"Mode": 2}
    }
  }
  ```

- These are observed stored values. The session did not establish the units or
  runtime interpretation of the raw Density and Speed values.
- `PrintMode: 1` is present in the XPD JSON. The observed serializer-selection
  code compares the profile label at offset `0x4c`; it does not branch on this
  JSON `PrintMode` value.

### `DrvEnablePDEV` selection logic

`FUN_180005068` (`0x180005068`) obtains a driver data-file path from the
`DRIVER_INFO` structure returned by `GetPrinterDriverW`, reads/parses the
configuration through `FUN_18000b620` (`0x18000b620`), and stores the parsed
configuration pointer at `PDEV+0x610`.

The relevant assembly in `FUN_180005068` is:

- `0x1800051f2`: loads the table base `0x1800144c0`.
- `0x1800051f9`: advances the parsed configuration pointer to `+0x4c`.
- `0x1800051ff–0x180005228`: compares the UTF-16 profile label against the
  candidate profile strings.
- `0x18000522f–0x180005236`: advances across up to four entries spaced
  `0xc0` bytes apart.
- `0x180005238–0x180005253`: computes the matching row and copies `0xc0` bytes
  to `PDEV+0x648`.

The four profile rows are confirmed by their UTF-16 strings and the pointer
stored at row offset `+0xa0`:

| Table row label | Row base | Callback slot | Stored value |
|---|---:|---:|---:|
| `DUMMY` | `0x1800144c0` | `0x180014560` | null |
| `ESC/POS` | `0x180014580` | `0x180014620` | null |
| `TSPL` | `0x180014640` | `0x1800146e0` | `0x18000a790` |
| `ZPL` | `0x180014700` | `0x1800147a0` | `0x18000af98` |

Each row is `0xc0` bytes; the callback slot is `0xa0` bytes into its row.
The copied destination is `PDEV+0x648`, so the callback slot becomes
`PDEV+0x6e8`.

**Selection result:** the supplied label `ZPL` matches the fourth row, so
`PDEV+0x6e8` is initialized from that row as `0x18000af98`. `TSPL` maps to
`0x18000a790`, but its row is not selected by this XPD label.

### Relevant evidence

- `DrvEnablePDEV` assembly and loop: `ev_4540e58747876a15bb917cd58702634369d556802bd1d20c980e9a06c96172e2`
- `DrvEnablePDEV` pseudocode (REA batch result): `ev_0297248a5efb3f6715a9143956788e1c616accc695b1265ece7f7bbbd32452d4`
- Configuration parsing function `FUN_18000b620`: `ev_0637a97613b16d56d29df9dd8e4979a63660339c858b885265b3f9a2b37f90ee`
- Profile label/table bytes:
  - DUMMY: `ev_8d69e89ba794efb5a06e1169e1318843cc7ed05cd9dda170521a5222b988075a`
  - ESC/POS: `ev_8b3b91dff715136d54a6f985613a61b29179b07f794e670f540e0132cd7ccae3`
  - TSPL: `ev_3fde73dbd66ce63dd1fd85aa5836950e18a29b8e155b3436a21940479f9b2372`
  - ZPL: `ev_d296b51ebf14efaf081a0303775e988308183936d330c6046e8128f14e60403d`
- Callback slot bytes:
  - DUMMY: `ev_0eb1847091e99ff58d8ec061bb20f9ccc5a8c86909112e9c3899a474cdc0a290`
  - ESC/POS: `ev_f6e971dfcded9c4f8185fd0b09db3ac1232a70861a9078764ae455c05f34c45b`
  - TSPL: `ev_10bc20c9de406778684cdafa78b4b12ebdc818adbb94a0210207a1494d0a7f90`
  - ZPL: `ev_d529f37800d8963eb58ba8749ebac68d2ca8357ac67f61b1afb561d0d9c84e80`
- XPD bytes and JSON were read directly from the file without modifying it.

## Callback use in `DrvSendPage`

`FUN_18000a250` (`0x18000a250`, callback-table entry `iFunc 0x20`,
`DrvSendPage`) loads the callback at `0x18000a5ba`:

```asm
0x18000a5ba: MOV RAX, qword ptr [RBX + 0x6e8]
```

After checking the pointer and preparing arguments, it calls through `RAX` at
`0x18000a5d6`. The Windows x64 argument registers and stack slot are set up
before the indirect call. The five arguments correspond to:

1. `RCX`: PDEV
2. `RDX`: raster/buffer pointer
3. `R8D`: byte count
4. `R9D`: additional value
5. `[RSP+0x20]`: fifth argument

Both serializer functions have five-argument shapes compatible with this
callsite:

```c
FUN_18000a790(longlong pdev, void *data, ulonglong size,
              undefined8 arg4, uint arg5)
FUN_18000af98(longlong pdev, longlong data, uint size,
              undefined8 arg4, uint arg5)
```

The profile table supplies the exact targets; argument-shape compatibility is
corroborating evidence, not the basis for identifying the selected function.

The complete loaded-image byte search for a direct `+0x6e8` memory operand
found the read at `0x18000a5ba`. `DrvEnablePDEV` initializes this slot as part
of the 0xc0-byte row copy at `0x180005238–0x180005253`; no separate direct
store instruction to `PDEV+0x6e8` was found in the searched initialized
segments. Thus the pointer's source is the selected static table row, itself
selected by the XPD's profile string.

Evidence:

- `DrvSendPage` pseudocode: `ev_24b152673016eeee51e1bcdf9b0fdc072de907f98e698488fe0c0e3e62ef2769`
- `DrvSendPage` assembly: `ev_a83ab10b8eee3de642574f5893674b91eb837936d6c37f77f9c3a4a60f85f84a`
- Exact `PDEV+0x6e8` read search: `ev_6788ce251e0c84bdd32971eee76a291bcc5d95903e837964aeaac1248dba43c4`
- `PDEV+0x648` copy-destination search, finding `0x18000523b`: `ev_2839e69077d1da377f8d0f8bf56c93724533dca693b264ea554ea158bdca3916`
- Previously captured indirect call and unresolved-target records:
  `ev_4354acb33d16ccc0754ff2ddc1229a862354a6404c3e0f28179ffeefc3bf2661`,
  `ev_acc9d3f84cd3c8e77603c4e4de5e7f22ef3f2838d96c8219d348314bcde19fda`.
  The unresolved-target result was from before tracing the initializer/table;
  the later table evidence resolves the static callback value for this XPD.

## Serializer behavior

### Selected ZPL-style serializer: `FUN_18000af98`

`FUN_18000af98` (`0x18000af98`) appends output to the buffer descriptor at
`PDEV+0x688` through the common appender `FUN_18000a700` (`0x18000a700`).
Its pseudocode constructs:

- `^GFA,%d,%d,%d,` prefix
- `:Z64:` marker
- Base64-encoded image bytes
- Four hexadecimal checksum characters, followed by CR/LF
- `^PQ1^XZ\n\r` trailer

`FUN_18000ae74` (`0x18000ae74`) implements the Base64 conversion used by the
serializer. The literal command sequence is observed in the decompilation.
Exact runtime numeric values in the formatted header were not established:
the decompiler shows multiple `%d` placeholders but only one explicit
formatted argument. Do not infer the final dimensions or byte counts from
those format strings alone.

Evidence:

- ZPL serializer pseudocode: `ev_666699a54e38effd949e7ea56997bb0722e280538d307571483140d9b283600d`
- Base64 helper pseudocode: `ev_10461806c93252f0cb0977c2e4388f21ec8887d40679014c7b1433276bb480ca`
- ZPL row pointer bytes show `0x18000af98`: `ev_d529f37800d8963eb58ba8749ebac68d2ca8357ac67f61b1afb561d0d9c84e80`

`FUN_18000ab88` (`0x18000ab88`) is a separate ZPL-style setup emitter.
It appends settings such as `^XA`, `^LH`, `^PW`, `^LL`, `^PR`, `~SD`, and
other `^FO`/label commands to a buffer at `param_1+0x40`, not the page buffer
at `PDEV+0x688`. Its presence is supporting evidence for the ZPL profile, but
its setup buffer is not itself the callback output.

Evidence: `ev_0bb88d9afd6d2c2c977da45d79c546985ad04b600eae679a910888855c5ffa36`

### Alternate TSPL-style serializer: `FUN_18000a790`

`FUN_18000a790` (`0x18000a790`) appends:

- `BITMAP 0,0,%d,%d,1,`
- the supplied raster bytes
- `\r\nPRINT 1,1\r\n`

to the same `PDEV+0x688` output-buffer descriptor. As with ZPL, runtime
formatted dimensions are not established by the available decompilation.
Its table row is selected by profile string `TSPL`; it is not selected by
the supplied XPD's `ZPL` string.

Evidence:

- TSPL serializer pseudocode: `ev_495ec5f07efb6d62bf94e38e2c4334dcc242c897c09501d57166c8c16b6f0b7f`
- TSPL row pointer bytes: `ev_10bc20c9de406778684cdafa78b4b12ebdc818adbb94a0210207a1494d0a7f90`

`FUN_18000a8a4` (`0x18000a8a4`) is a separate TSPL-style setup emitter that
includes `SIZE`, `GAP`, `REFERENCE`, `SPEED`, `DENSITY`, `SET ...`, and `CLS`
commands. Like the ZPL setup emitter, it appends to `param_1+0x40`, separate
from the page buffer.

Evidence: `ev_cfea853b11fa2230bbde6c16940d46f5374782e87a99786215096382d772588a`

### Shared appender and reachability evidence

`FUN_18000a700` (`0x18000a700`) appends bytes and expands the output allocation
as needed. Its observed direct callers include the TSPL and ZPL serializers
and their setup emitters. Ghidra did not find direct code callers to
`FUN_18000a790` or `FUN_18000af98`; the earlier reference results pointed to
runtime-function metadata (`.pdata`). The profile table's function-pointer
entries explain how these functions are reached indirectly.

Evidence:

- Appender pseudocode: `ev_7386bf74cfda631690a9411e044abb392e7f45684846bca0b6d63adcec9b9ecf`
- Appender caller inventory: `ev_aa9ceacd32fa412fed13d14b4c416d027a971f50c8e3a634a5e91bd20a750ed8`
- Earlier direct-caller results for A790 and AF98:
  `ev_9c121932457a690116cab3646dff918e40ba1595d3affbce48622aec68b2e339`,
  `ev_47f5f65682e8eecfd7249f02c0ff40148c6dc78fa4f63e21833633d3dfda655b`

## Raster and output paths

### `DrvSendPage` output

`FUN_18000a250` creates/converts a page raster, optionally applies image
conversion or overlay routines, invokes the selected callback when there is
image data, then writes the buffer at `PDEV+0x688` with its length at
`PDEV+0x690` through `WritePrinter`. The writer sends 0x1000-byte chunks and
then any tail, and afterward releases/clears the buffer. With this XPD, the
static callback selected by initialization is the ZPL serializer at
`0x18000af98`.

### 1-bpp conversion findings

- `FUN_1800072c0` (`0x1800072c0`) allocates 1-bit output with
  `4 * ceil(width/32)` bytes per row, i.e. DWORD-aligned scanlines.
- Mode 2 calls `FUN_180007060` (`0x180007060`), which uses an 8x8 ordered
  threshold matrix on grayscale samples and sets packed bits MSB-first
  (`0x80 >> (x & 7)`).
- `FUN_1800097a8` (`0x1800097a8`) loads/scales images, handles multiple source
  bit depths, and in its overlay path reverses row order.

These are mode-specific conversion facts. The session did not establish the
final width, height, orientation, or exact raster byte layout for every
`DrvSendPage` invocation, nor resolve the ZPL header's runtime numeric values.

Evidence:

- `FUN_1800072c0`: `ev_fbde27ceee8e2849fa14a14eecae176b3889817f838802b3494fd2c5ad34ec73`
- `FUN_180007060`: `ev_1ad844df5405ca4785a0f72cc76135af47b93762d95ea6262a97c70f897656bb`
- `FUN_1800097a8`: `ev_d9bd9355884f3205c8a3e9cf7e16f9d228ee42f72c401905db8ad63e6610f8fb`

### Separate `DrvEscape` path

`FUN_18000b44c` (`0x18000b44c`, callback-table entry `iFunc 0x18`,
`DrvEscape`) handles selector `0x13` by validating a 16-bit length prefix
and writing exactly the following payload bytes with `WritePrinter`. It
adds no serializer header or trailer; the bytes are caller-supplied. Its
success condition checks that the reported write count matches the requested
payload length.

Evidence: `ev_f2bb07fd911808d704a40624e87cf4d945c6f6b50a9ab8c040746f2f6b1293a3`

## Other relevant DDI table entries

`DrvEnableDriver` (`0x180004fa0`) provides the callback table beginning at
`0x180004a20`. The relevant and previously mapped `iFunc` entries are:

| `iFunc` | Likely Windows DDI | Function address |
|---:|---|---:|
| `0x00` | `DrvEnablePDEV` | `0x180005068` |
| `0x01` | `DrvCompletePDEV` | `0x18000530c` |
| `0x02` | `DrvDisablePDEV` | `0x180005318` |
| `0x03` | `DrvEnableSurface` | `0x180005380` |
| `0x04` | `DrvDisableSurface` | `0x180005418` |
| `0x07` | `DrvResetPDEV` | `0x1800052bc` |
| `0x08` | `DrvDisableDriver` | `0x180005028` |
| `0x0c` | `DrvRealizeBrush` | `0x180008b6c` |
| `0x0d` | `DrvDitherColor` | `0x180007b18` |
| `0x12` | `DrvBitBlt` | `0x180007350` |
| `0x13` | `DrvCopyBits` | `0x180008b88` |
| `0x14` | `DrvStretchBlt` | `0x180006d08` |
| `0x17` | `DrvTextOut` | `0x18000b2f8` |
| `0x18` | `DrvEscape` | `0x18000b44c` |
| `0x20` | `DrvSendPage` | `0x18000a250` |
| `0x21` | `DrvStartPage` | `0x180008e08` |
| `0x22` | likely `DrvEndDoc` | `0x18000a6f0` |
| `0x23` | `DrvStartDoc` | `0x18000a6bc` |

Names are inferred by mapping observed `iFunc` values to Windows printer DDI
indices; many DLL functions have autogenerated names.

Evidence:

- Callback-table bytes: `ev_74229c68df8869693249fc57dc8efd07fc510d2858b5568f455232db14880e6d`
- `DrvEnableDriver` pseudocode: `ev_7c1b9de0549346882e6c0ba4aa7f86b6ad255967545603d2a2c40a8275f6ac58`

## Confirmed findings versus assumptions

### Confirmed by static artifact evidence

- The target DLL is the x64 PE identified above; the XPD has the size and
  digest listed above.
- The supplied XPD contains `ZPL` at offset `0x4c` and `PrintMode: 1` in its
  JSON settings.
- `DrvEnablePDEV` compares the profile label against a four-row table and
  copies the matching 0xc0-byte record to `PDEV+0x648`.
- The copied record's callback slot is at `PDEV+0x6e8`.
- The `ZPL` row stores `0x18000af98`; the `TSPL` row stores `0x18000a790`.
- `DrvSendPage` reads the callback at `PDEV+0x6e8` and calls it indirectly.
- Therefore, applying the observed selection logic to the supplied XPD
  selects `FUN_18000af98` (ZPL-style), not `FUN_18000a790` (TSPL-style).
- Both candidate serializers append to the page-output buffer at `PDEV+0x688`.
- The serializer pseudocode contains the ZPL-style and TSPL-style byte/text
  sequences documented above.
- `DrvEscape` selector `0x13` is a distinct raw-payload `WritePrinter` path.
- The noted mode-2 raster conversion uses 1-bpp packed output and DWORD row
  alignment.

### Not established / assumptions to avoid

- No live Windows execution or printer capture was performed. It is not
  confirmed which path a particular installation's `GetPrinterDriverW`
  result resolves to, whether it loads this exact XPD, or what bytes the
  printer physically receives.
- `PrintMode: 1` was not shown to select the serializer; profile string
  matching is the observed selector.
- No units or runtime meanings were derived for the raw XPD Density and Speed
  values.
- Numeric fields and exact raster dimensions in the formatted ZPL/TSPL
  headers remain unresolved; the decompiler's format strings and recovered
  arguments are insufficient to claim exact emitted numbers.
- The final raster's width, height, row orientation, and bit polarity for all
  runtime modes were not fully established.
- The presence of command literals alone would not prove output selection;
  here selection for this supplied XPD is supported by the initializer's
  table lookup and stored function pointer, not just by strings.

## Unresolved questions and possible next steps

No additional analysis was performed to answer these questions in this
report-writing step:

1. Confirm, in a controlled environment, that the target Windows installation
   returns this exact `Logiadpi.xpd` path from `GetPrinterDriverW`; do not infer
   runtime behavior from the static file alone.
2. If exact transmitted bytes are needed, collect an authorized spooler or
   printer-port capture and compare it with the ZPL serializer's output.
3. Resolve the runtime values passed to the ZPL formatter and their relationship
   to `DrvSendPage`'s raster dimensions and stride.
4. Trace all image modes through `FUN_180008e9c`, conversions, and final
   callback arguments to establish dimensions, row ordering, and polarity for
   each mode.
5. Clarify the semantics/units of XPD Density, Speed, and `PrintMode` using
   their consuming code or authoritative configuration documentation.
6. Determine whether an ESC/POS row is populated in another XPD variant; in
   the supplied image the observed ESC/POS callback slot is null.

The Ghidra session was closed after the analysis. Original files remain
unmodified.
