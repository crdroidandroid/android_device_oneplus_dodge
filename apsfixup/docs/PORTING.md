# libapsfixup — porting / blob-update guide

`libapsfixup.so` fixes the OnePlus APS "turbo" soft/green/crash bug on ports where the device's
gralloc reports a wrong plane layout for the full-res **P010 (10-bit)** snapshot output buffer.
The ArcSoft/Algo blobs are byte-identical to stock, so they faithfully consume the bad layout
and produce a garbage chroma plane. The fix corrects three things at runtime, by **GOT
redirection only** (no code patching, no execmem/execmod):

1. **chroma plane pointer** — `plane[1] (UV) = luma + Yplane_size` (was `align_up(luma,0)` = 4GB garbage)
2. **chroma stride** — `pitch[1] = pitch[0]` (was `0`)
3. **P010 LSB→MSB conversion length** — `w5` set so `w4*w5*1.5 == buffer` (was an uninitialized stride)

Most of the logic is **geometry-derived and portable** (works on any 4:2:0 P010 buffer); only a
handful of **offsets are pinned to specific blob BuildIds** and must be re-derived for a new
device or a camera-blob OTA.

---

## What is portable vs. what must be re-pinned

**Portable (do NOT need to change):**
- The chroma offset = `2/3 * mapping_size` (Y plane of a 4:2:0 P010 buffer), page aligned.
- `pitch[1] = pitch[0]`.
- The conversion fix `w5 = (2/3 * avail) / w4` (makes the loop's `w4*w5*1.5` span exactly the buffer).
- The repair scan (find a `0x76..` valid ptr immediately followed by a `0x77..`-garbage ptr).
- The naked-asm trampoline for `ARC_Turbo_RAW_Process` (it has stack args; a C wrapper drops them).
- The `dlsym` symbol name `"ARC_Turbo_RAW_Process"`.

**Pinned per blob (`apsfixup.cpp` constants):**
| constant | what it is | lib |
|---|---|---|
| `P010_FUNC_OFF` | `APSFormatConverterNeon::p010LSB2MSBNeon` | libAlgoProcess.so |
| `P010_GOT_OFF`  | that function's `R_AARCH64_JUMP_SLOT` GOT entry | libAlgoProcess.so |
| `DLSYM_GOT_OFF` | the `dlsym@LIBC` `R_AARCH64_JUMP_SLOT` GOT entry | libAlgoInterface.so |

Plus the **output-struct field offsets** in `repair_struct()` (`+0x40` luma, `+0x48` chroma,
`+0x60` pitch[0], `+0x64` pitch[1]) — these are the ArcSoft ASVL output struct and are usually
stable across OnePlus devices, but **verify** them (see step 4).

---

## Re-derive the offsets (per device / per blob)

You need the two blobs from the target firmware:
`/odm/lib64/libAlgoProcess.so` and `/odm/lib64/libAlgoInterface.so`.
Tools: `readelf`, `nm`, and Python `capstone` (`pip install capstone`).

### 1. `P010_FUNC_OFF` and `P010_GOT_OFF` (libAlgoProcess.so)

```bash
# function offset — it appears in tombstones as APSFormatConverterNeon::p010LSB2MSBNeon, and is
# a JUMP_SLOT relocation target. The reloc gives BOTH the GOT slot and the function offset:
readelf -r libAlgoProcess.so | grep -i p010LSB2MSBNeon
#   <GOT_OFF>  ....JUMP_SL  <FUNC_OFF>  _ZN22APSFormatConverterNeon...p010LSB2MSBNeon + 0
# -> left column  = P010_GOT_OFF
# -> symbol value = P010_FUNC_OFF
```
If the symbol is stripped, find it via the log string `"p010LSB2MSB, w: %u, h: %u, rowS: %u, colS: %u"`
and its call site (`bl` to a PLT stub `adrp x16; ldr x17,[x16,#N]; br x17` — the GOT slot is that page+N).

Sanity-check the conversion math is unchanged (loop length = `w4*w5*1.5`):
```python
# disassemble the function and confirm: mul w8,w4,w5 ; add w9,w8,w8,lsl#1 ; lsr w9,#5 ; ldr q0,[x..],#0x10 ; shl v0.8h,#6
```
If that pattern changed, the `w5 = (2/3*avail)/w4` formula may need re-deriving.

### 2. `DLSYM_GOT_OFF` (libAlgoInterface.so)

```bash
# confirm ARC is resolved by dlsym (string + dlsym import + a "find ARC_... failed dlerror" log):
strings -a libAlgoInterface.so | grep -x ARC_Turbo_RAW_Process
readelf -r libAlgoInterface.so | grep -i 'dlsym@LIBC'
#   <GOT_OFF>  ....JUMP_SL  0  dlsym@LIBC + 0   -> DLSYM_GOT_OFF
```
If `ARC_Turbo_RAW_Process` is NOT dlsym'd in this blob (e.g. it became a real DT_NEEDED import),
GOT-hook libAlgoInterface's import of it directly instead of dlsym.

### 3. Confirm BIND_NOW (both libs)

```bash
readelf -d libAlgoProcess.so   | grep -iE 'BIND_NOW|FLAGS'
readelf -d libAlgoInterface.so | grep -iE 'BIND_NOW|FLAGS'
```
GOT redirection relies on the slots being resolved at load. All OnePlus camera blobs seen so far
are BIND_NOW. If a blob is lazy, hook earlier or resolve the slot first.

### 4. Verify the output-struct layout (recommended, with Frida)

The bring-up Frida probes are in [`frida/`](frida/) — see [`frida/README.md`](frida/README.md)
for the full set and the recommended order. Run `frida/op_outstruct_dump.js` (or
`op_planelayout_probe.js`) to dump the struct and confirm the field offsets in the output struct:

```
#   +0x40 = luma (valid 0x76.. ptr)   +0x48 = chroma (0x77..-garbage)
#   +0x60 = pitch[0] (Y stride)       +0x64 = pitch[1] (==0, the bug)
```
If those offsets differ, update `repair_struct()` (and the `+0x40==off` pitch special-case)
accordingly. **`frida/op_chroma_repair.js` is the reference fix** — it implements the exact same
three corrections as `apsfixup.cpp`, in JS; when it makes photos sharp on the new device, the
native lib will too with the matching offsets.

---

## Update + build + verify

1. Edit the three constants (and struct offsets if step 4 found differences) in `apsfixup.cpp`.
2. Update the `DT_NEEDED`: `extract-files.py` already does `.add_needed('libapsfixup.so')` on
   `libAlgoProcess.so` (uses `prebuilts/extract-tools/.../patchelf-0_18`).
3. Make sure `libapsfixup.so` is resolvable by the camera namespace: it is a `/odm` lib that
   `libAlgoProcess` DT_NEEDEDs, and OnePlus camera app namespaces cannot resolve `/odm` libs by
   name — so add `libapsfixup.so` to `vendor/etc/public.libraries.txt` (we do this via a
   `.add_line_if_missing()` fixup). The same list must expose the ArcSoft/QNN dlopen targets.
4. Soong namespace: the blob namespace (`vendor/<oem>/<device>`) must `import` the namespace that
   defines `libapsfixup` (here `device/oneplus/dodge`) — add it to `namespace_imports`.
5. `m libapsfixup`, flash (or push `libapsfixup.so` + the patched `libAlgoProcess.so` +
   `public.libraries.txt`, `restorecon` to `same_process_hal_file` for the `/odm` libs, reboot).
6. Verify:
   ```
   adb logcat -s apsfixup    # take one Auto photo
   ```
   Expect, in order:
   ```
   libapsfixup loaded (pid ...)
   GOT-hooked p010 (real=...)
   GOT-hooked dlsym in libAlgoInterface (real=...)
   interposing ARC_Turbo_RAW_Process (real=...)
   chroma fix: luma=... -> ... (ysize=0x1800000)
   p010 fix: avail=... w4=... w5 <garbage>-><height>
   ```
   The lib also logs `GOT[p010]=... expected ...` if the GOT slot value doesn't match
   `base+P010_FUNC_OFF` — that warning means **the offsets drifted** (re-run the steps above).

---

## Notes / assumptions

- Buffer is 4:2:0 semiplanar P010 → `Yplane = 2/3 * total`. If a device uses a different snapshot
  format (e.g. NV12 8-bit, or a tiled/UBWC layout), the `2/3` ratio and the contiguous-plane
  assumption must be revisited.
- The fix only engages when the chroma plane is actually garbage (the repair scan is a no-op on
  correct buffers), so shipping it is safe even on a build where the underlying bug is absent.
- Offsets here are for: libAlgoProcess `BuildId db5afd2a31f4cb3b85b593b2f3383d43`, libAlgoInterface
  `BuildId a81b2d7129a5cf28c91ffd49445ea88f` (OnePlus 13 / dodge, sm8750). Verify BuildIds with
  `readelf -n <lib> | grep -i 'build id'` before assuming the constants apply.
