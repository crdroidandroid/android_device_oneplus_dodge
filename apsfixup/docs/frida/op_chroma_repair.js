// op_chroma_repair.js — repair the garbage chroma plane at ARC_Turbo_RAW_Process entry, so the
// turbo write lands in the real UV plane => sharp Auto photo (proof toward the permanent patch).
//
// At ARC_Turbo_RAW_Process(handle, s1, s2, s3, ...) the buffer structs (x1/x2/x3) have a
// luma/chroma plane pair: valid 0x76.. ptr at +N, then garbage 0x77.. ptr at +N+8. We replace
// the garbage chroma with luma + Y-plane-size. Y = 2/3 of the buffer mapping (4:2:0 semiplanar,
// holds for NV12 and P010).  CHROMA_NUM/CHROMA_DEN let us calibrate the fraction if needed.
//
// ARC_Turbo_RAW_Process @ libarcsoft_turbo_raw.so + 0x1e45c
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_chroma_repair.js > ~/sparkos/frida_repair.txt
//   >>> take ONE Auto photo — does it complete + look SHARP with correct colors? <<<
'use strict';
var CHROMA_NUM = 2, CHROMA_DEN = 3;   // chroma offset = mapping_size * NUM/DEN  (calibrate)

function hx(p){ return p ? ('0x'+p.toString(16)) : '0x0'; }
function isBuf(v){ try{ var hi=parseInt(v.shr(32).toString()); if(hi<0x70||hi>0x7f) return false;
  return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))>=0; }catch(e){return false;} }
function isGarbage(v){ try{ if(v.isNull())return false; var hi=parseInt(v.shr(32).toString());
  if(hi<0x70||hi>0x7f) return false; return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))<0; }catch(e){return false;} }

function repairStruct(name, base){
  if(!base || base.isNull()) return;
  try { if(Process.findRangeByAddress(base)===null) return; } catch(e){ return; }
  for (var off=0; off<0x80; off+=8){
    var luma, chroma;
    try { luma = base.add(off).readPointer(); chroma = base.add(off+8).readPointer(); } catch(e){ break; }
    if (isBuf(luma) && isGarbage(chroma)){
      var rng=null; try{ rng=Process.findRangeByAddress(luma); }catch(e){}
      if(!rng){ console.log('  ['+name+'] +0x'+off.toString(16)+' luma='+hx(luma)+' chroma='+hx(chroma)+'  (no mapping, skip)'); continue; }
      // bytes from luma to end of its mapping; Y plane = avail * NUM/DEN (4:2:0 semiplanar)
      var lumaOff = luma.sub(rng.base).toUInt32();             // offset of luma within mapping
      var avail = rng.size - lumaOff;                          // bytes available from luma
      var ysize = Math.floor(avail * CHROMA_NUM / CHROMA_DEN);
      ysize = Math.floor(ysize / 4096) * 4096;                 // page align
      var newChroma = luma.add(ysize);
      base.add(off+8).writePointer(newChroma);
      console.log('  ['+name+'] +0x'+off.toString(16)+'  luma='+hx(luma)
        +'  chroma '+hx(chroma)+' -> '+hx(newChroma)+'   (map '+hx(rng.base)+' size 0x'+rng.size.toString(16)+', Ysize 0x'+ysize.toString(16)+')');
      // FIX THE GREEN: chroma pitch (pitch[k]) is 0; set it = Y pitch. Plane[k] at off, plane[0]
      // at 0x40 => k=(off-0x40)/8+1 for the chroma; pitch base = 0x60, pitch[k] at 0x60+k*4.
      if (off === 0x40){
        var yPitch = base.add(0x60).readU32();
        var cur = base.add(0x64).readU32();
        if (yPitch>0 && cur===0){ base.add(0x64).writeU32(yPitch);
          console.log('    + chroma pitch[1] @+0x64: '+cur+' -> '+yPitch+' (= Y stride)'); }
      }
    }
  }
}

var done=0;
function arm(){
  var p; try{ var m=Process.findModuleByName('libarcsoft_turbo_raw.so'); if(!m) return false; p=m.base.add(0x1e45c);}catch(e){return false;}
  Interceptor.attach(p, {
    onEnter: function(a){
      if(done>6) return; done++;
      console.log('\n=== ARC_Turbo_RAW_Process  tid='+Process.getCurrentThreadId()+'  (NUM/DEN='+CHROMA_NUM+'/'+CHROMA_DEN+') ===');
      // full dump of x2 (the output struct) so we can see plane ptrs AND pitch/stride ints
      try {
        var b=a[2];
        if (b && !b.isNull() && Process.findRangeByAddress(b)){
          console.log('  --- x2 struct @'+hx(b)+' (raw) ---');
          for (var o=0;o<0x90;o+=8){
            var pp=b.add(o).readPointer();
            var i0=b.add(o).readU32(), i1=b.add(o+4).readU32();
            console.log('    +0x'+o.toString(16)+' = '+hx(pp)+'   ints{'+i0+', '+i1+'}');
          }
        }
      } catch(e){ console.log('  dump err '+e); }
      repairStruct('x1', a[1]);
      repairStruct('x2', a[2]);
      repairStruct('x3', a[3]);
    }
  });
  console.log('[*] hooked ARC_Turbo_RAW_Process @ '+hx(p)+' — take ONE Auto photo.');
  return true;
}
// hook the REAL p010LSB2MSBNeon (libAlgoProcess+0x4bd934) and CLAMP its length so it converts
// exactly the buffer (Y+UV) without overrunning. Signature: (u16* dst, u16* src, w2,w3,w4,w5);
// per RE the processed count = arg4*arg5. We cap arg5 so arg4*arg5 == buffer u16 elements.
var convArmed=false, convN=0;
function armConv(){
  if(convArmed) return;
  var m=Process.findModuleByName('libAlgoProcess.so'); if(!m) return;
  try{
    Interceptor.attach(m.base.add(0x4bd934), {
      onEnter:function(a){
        var src=a[1];
        var w2=a[2].toUInt32(), w3=a[3].toUInt32(), w4=a[4].toUInt32(), w5=a[5].toUInt32();
        var rng=null; try{ rng=Process.findRangeByAddress(src); }catch(e){}
        if(!rng){ if(convN<6){convN++;console.log('  [p010conv] src='+hx(src)+' (no map) w2='+w2+' w3='+w3+' w4='+w4+' w5='+w5);} return; }
        // p010LSB2MSBNeon(dst, src, width=w2, height=w3, dstStride=w4, srcStride=w5).
        // BUGS on port: w3=Y-height only (green chroma); w5=garbage srcStride (shear/overrun).
        // FIX: height must span Y+UV = avail/dstStride rows; srcStride must equal dstStride.
        var avail = rng.size - src.sub(rng.base).toUInt32();   // bytes from src to end of mapping
        // p010LSB2MSBNeon processes (w4*w5*1.5) bytes (the loop count = (w4*w5*3)>>5, x16B).
        // For EXACTLY the buffer (Y+UV) we need w4*w5 == avail*2/3. The loop ignores w2/w3.
        if (w4>0){
          var targetProd = Math.floor(avail * 2 / 3);          // stride*height (Y-plane bytes) = 0x1800000
          var newW5 = Math.floor(targetProd / w4);             // = height (3072) when w4=stride(8192)
          if (newW5>0 && w5 !== newW5){
            a[5] = ptr(newW5);                                 // w4*w5*1.5 == buffer  -> full Y+UV, no overrun
            if(convN<8){convN++;console.log('  [p010 FIX] src='+hx(src)+' avail=0x'+avail.toString(16)
              +' w4='+w4+'  w5 '+w5+'->'+newW5+'  (bytes 0x'+(w4*newW5*3/2).toString(16)+' == buffer)');}
          } else if(convN<8){convN++;console.log('  [p010 ok] w4='+w4+' w5='+w5+' bytes=0x'+(w4*w5*3/2).toString(16));}
        }
      }
    });
    convArmed=true;
    console.log('[*] hooked p010LSB2MSBNeon @ '+hx(m.base.add(0x4bd934))+' (clamp to buffer)');
  }catch(e){ console.log('[conv hook err] '+e); }
}
var poll=setInterval(function(){ var a=arm(); armConv(); if(a&&convArmed) clearInterval(poll); }, 150);
console.log('[*] op_chroma_repair loaded.');
