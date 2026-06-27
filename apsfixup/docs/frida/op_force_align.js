// op_force_align.js — CONFIRM + FIX the Auto soft-photo root cause.
//
// ROOT CAUSE (RE-proven): libAlgoProcess fn @ +0x5c76f4 reads the OnePlus vendor tag
// com.oplus.aps.platform.output.alignment (2-int array). The port's HAL doesn't emit it, so
// the code falls to the default at +0x5c7908: `stp wzr, wzr, [x19,#0x14]` => sets
// mOutputAlignmentStride=0, mOutputAlignmentScanline=0 (members [obj+0x14]/[obj+0x18]).
// That 0 makes the chroma-plane align_up() produce a 4GB-garbage pointer => sharp luma,
// green/garbage chroma, crash, soft Auto photos.
//
// This hook lets the function run, then OVERWRITES [obj+0x14]/[obj+0x18] with non-zero
// alignment so align_up() behaves. Light: fires once per capture (NOT per frame) -> won't
// hang like the plane-dump probe.
//
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_force_align.js > ~/sparkos/frida_force.txt
//   >>> take ONE Auto photo, check: does it still crash? is the saved photo sharp+correct color? <<<
//
// CALIBRATION: STRIDE_ALIGN / SCANLINE_ALIGN below. Start at 1 (identity = use the natural
// pre-aligned plane offset). If it no longer 4GB-crashes => ROOT CAUSE CONFIRMED. If colors
// are shifted/wrong, the buffer expects a real alignment: try 64, then 256, then 512, then
// 4096 (edit the two consts, re-run, re-shoot). The value that yields a clean photo is the
// number the port must emit in the com.oplus.aps.platform.output.alignment tag.
'use strict';

var STRIDE_ALIGN   = 256;   // [obj+0x14] mOutputAlignmentStride   (edit + re-run to calibrate)
var SCANLINE_ALIGN = 32;   // [obj+0x18] mOutputAlignmentScanline

var OFF = 0x5c76f4;       // alignment-reader function
var logged = 0;

function arm(){
  var m = Process.findModuleByName('libAlgoProcess.so');
  if (!m) return false;
  Interceptor.attach(m.base.add(OFF), {
    onEnter: function(a){ this.obj = a[0]; },
    onLeave: function(r){
      try {
        var o = this.obj; if (!o || o.isNull()) return;
        var oldS = o.add(0x14).readU32();
        var oldL = o.add(0x18).readU32();
        o.add(0x14).writeU32(STRIDE_ALIGN);
        o.add(0x18).writeU32(SCANLINE_ALIGN);
        if (logged < 4) {
          logged++;
          console.log('[force-align] obj=' + o +
            '  was {stride=' + oldS + ', scanline=' + oldL + '}' +
            '  -> {stride=' + STRIDE_ALIGN + ', scanline=' + SCANLINE_ALIGN + '}' +
            (oldS===0 && oldL===0 ? '   <<< was the 0/0 BUG default' : ''));
        }
      } catch(e){ console.log('[force-align] err ' + e); }
    }
  });
  console.log('[*] hooked alignment-reader @ ' + m.base.add(OFF) +
    '  forcing stride=' + STRIDE_ALIGN + ' scanline=' + SCANLINE_ALIGN);
  return true;
}

var poll = setInterval(function(){ if (arm()) clearInterval(poll); }, 150);
console.log('[*] op_force_align loaded (self-arming). Take ONE Auto photo.');
