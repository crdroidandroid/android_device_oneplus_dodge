# Frida bring-up probes (apsfixup)

These are **bring-up / diagnostic** scripts used to find and prove the APS turbo P010 bug before
translating it into the native `libapsfixup.so`. They are **not** shipped in the build — they run
on a dev device with `frida-server` (root) attached to the camera app:

```
adb shell setenforce 0
frida -U -n com.oplus.camera -l <probe>.js > out.txt
# (some OnePlus builds name the process "Camera": frida -U -n Camera -l <probe>.js)
```

All are **native-only** (no Java `.implementation` hooks — that crashes this ART) and use the
Frida-17 instance API (`Process.findModuleByName(m).findExportByName(...)`, NOT the removed static
`Module.findExportByName`).

## Recommended porting workflow

When porting to a new OnePlus device / after a camera blob OTA, use them in this order:

1. **`op_qnn_init_probe.js`** — first, make sure the turbo path even runs. It flags `/odm` dlopen
   failures (the namespace bug) and whether `ARC_Turbo_RAW_InitQNN` is reached. If you see
   `[dlopen FAIL] … not accessible for the namespace clns-shared-…`, fix `public.libraries.txt`
   before anything else (the turbo/DSP path is gated until those `/odm` libs resolve).
2. **`op_chroma_repair.js`** — the reference fix. If it makes Auto photos sharp + correctly
   colored, the bug is the same and the native lib will work with matching offsets. This is the
   single most important probe — it *is* the fix, in JS.
3. **`op_outstruct_dump.js` / `op_planelayout_probe.js` / `op_bufferfill_probe.js`** — only if the
   struct field offsets differ on the new blob and you need to re-derive `+0x40/+0x48/+0x60/+0x64`.

See `../PORTING.md` for the static (readelf/capstone) offset re-derivation.

## Probe reference

| script | hooks | what it shows / does |
|---|---|---|
| `op_chroma_repair.js` | `ARC_Turbo_RAW_Process` (libarcsoft_turbo_raw), `p010LSB2MSBNeon` (libAlgoProcess) | **The runtime fix.** Repairs the output struct chroma ptr (`luma+⅔·buf`) + pitch (`=Y stride`), and clamps the P010 conversion (`w5` so `w4·w5·1.5==buffer`). Also dumps the struct. Make Auto photos sharp = bug confirmed. |
| `op_qnn_init_probe.js` | `dlopen`/`android_dlopen_ext`, `ARC_Turbo_RAW_InitQNN`, fastrpc `ioctl` | Finds `/odm` dlopen/namespace failures and whether QNN/DSP init is reached. Diagnoses the "turbo never runs → soft" gate. |
| `op_outstruct_dump.js` | `turboHdrProcessV2` (libAlgoInterface) | Raw dump of the output struct (`AlgoProcessData+0x4f8`) to identify luma/chroma/pitch field offsets. |
| `op_planelayout_probe.js` | `APSGrallocUtils::getPlaneLayout`, `camApsBufferLockPlanes` (libAlgoProcess) | Dumps the gralloc-reported Y/UV plane addresses + strides — shows the bad P010 plane layout at the source. |
| `op_bufferfill_probe.js` | the `[AlgoProcessData+0xa8]` vtable call sites in `turboRawProcess` | Pinpoints which call writes the garbage chroma into the output struct (before/after compare). |
| `op_force_align.js` | `libAlgoProcess+0x5c76f4` (the alignment-config reader) | Diagnostic: force the `mOutputAlignmentStride/Scanline` members. (Historical — proved these are NOT the chroma driver; kept as a worked example of struct-member forcing.) |

## Notes

- Offsets inside these scripts are pinned to the dodge blobs (libAlgoProcess `db5afd2a…`,
  libAlgoInterface `a81b2d71…`). On a new blob, update them the same way as the native lib
  (`readelf -r`, capstone) — each script documents its offsets in a header comment.
- `op_chroma_repair.js` is the authoritative reference for the fix arithmetic; if you change the
  native `apsfixup.cpp`, keep it in sync (or vice-versa).
