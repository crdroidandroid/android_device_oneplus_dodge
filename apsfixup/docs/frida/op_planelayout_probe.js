// op_planelayout_probe.js — catch the EXACT field that makes the chroma plane 4GB-garbage.
//
// libAlgoProcess builds the buffer plane layout (Y/UV addrs + strides) via its gralloc wrapper,
// then hands it up; libAlgoInterface uses it and the chroma plane comes out = align_up(luma,4GB).
// Hook the producers and dump the per-plane addresses + strides AT PRODUCTION:
//   APSGrallocUtils::getPlaneLayout(void*,void*,void*&,void*&)  libAlgoProcess+0x120d54
//   camApsBufferLockPlanes(...)                                 libAlgoProcess+0x1c28e8
// For each: dump x0..x6, and scan every pointer arg's memory for:
//   - a LUMA/CHROMA pair (valid 0x76.. ptr at +N, 0x77..-garbage ptr at +N+8)  <-- the bug, in situ
//   - plausible stride/scanline int32 fields (100..20000) near the planes
// Whichever value sits where the chroma offset should be (a 0, or a garbage scanline/colStride)
// is the port-side field to fix.
//
// NATIVE, Frida-17 instance API. Namespace-fixed turbo-ON build.
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_planelayout_probe.js > ~/sparkos/frida_plane.txt
//   >>> take ONE Auto photo (flat) <<<
'use strict';
function hx(p){ return p ? ('0x'+p.toString(16)) : '0x0'; }
// REAL garbage chroma signature (from the crash dst 0x7700001000): high32 is a POINTER-band
// value 0x70..0x7f AND low32 is tiny (<0x100000). This rejects packed-int32 pairs like
// 0x78000000001 ({1,1920}) whose high32 (0x780) is NOT a pointer band.
function isGarbage(v){ try{ if(v.isNull())return false; const hi=parseInt(v.shr(32).toString());
  if(hi<0x70||hi>0x7f) return false;
  return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))<0; }catch(e){return false;} }
function isBuf(v){ try{ const hi=parseInt(v.shr(32).toString()); if(hi<0x70||hi>0x7f)return false;
  return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))>=0; }catch(e){return false;} }
// precise align_up(luma,4GB) test: chroma_high == luma_high+1 and chroma_low tiny
function isAlignUpChroma(luma,chroma){ try{ if(!isBuf(luma)) return false;
  if(!chroma.shr(32).equals(luma.shr(32).add(1))) return false;
  return chroma.and(ptr('0xffffffff')).compare(ptr('0x100000'))<0; }catch(e){return false;} }
function readable(v){ try{ return !v.isNull() && Process.findRangeByAddress(v)!==null; }catch(e){return false;} }
function i32(p,o){ try{ return p.add(o).readS32(); }catch(e){ return null; } }

// dump a region: flag plane ptrs, luma/chroma pairs, and small-int (stride/scanline) fields
function dumpRegion(label, p, words){
  if(!readable(p)) return;
  console.log('    '+label+' @'+hx(p)+':');
  for(let i=0;i<words;i++){
    let v; try{ v=p.add(i*8).readPointer(); }catch(e){ break; }
    const off=i*8;
    let nxt=null; try{ nxt=p.add(off+8).readPointer(); }catch(e){}
    if(isBuf(v) && nxt && isAlignUpChroma(v,nxt)){
      const so=i32(p,off+8+8), so2=i32(p,off+8+0xc);   // ints right after the chroma slot
      console.log('      +0x'+off.toString(16)+' luma='+hx(v)+'  +0x'+(off+8).toString(16)
        +' chroma='+hx(nxt)+'   <<<<< REAL BUG: chroma=align_up(luma,4GB)  [next ints: '+so+','+so2+']');
    }
    else if(isBuf(v) && nxt && isGarbage(nxt))
      console.log('      +0x'+off.toString(16)+' luma='+hx(v)+'  +0x'+(off+8).toString(16)+' chroma='+hx(nxt)+'   <<<<< chroma garbage');
    else if(isBuf(v))  console.log('      +0x'+off.toString(16)+' = '+hx(v)+'   (buf ptr)');
    else if(isGarbage(v)) console.log('      +0x'+off.toString(16)+' = '+hx(v)+'   <<<<< GARBAGE ptr (ptr-band hi, tiny lo)');
    else {
      // int32 pair: maybe stride/scanline
      const a=i32(p,off), b=i32(p,off+4);
      if(a!==null && ((a>=64&&a<=30000)||(b>=64&&b<=30000)))
        console.log('      +0x'+off.toString(16)+' int32 = '+a+' , '+b+'   (stride/scanline/offset?)');
    }
  }
}

let counts={};
function gate(n){ counts[n]=(counts[n]||0)+1; return counts[n]<=4; }

function hookFn(addr,name,nargs){
  Interceptor.attach(addr,{
    onEnter(a){ this.go=gate(name); if(!this.go) return; this.a=[]; for(let i=0;i<nargs;i++) this.a.push(a[i]);
      console.log('\n===== '+name+' (enter) tid='+Process.getCurrentThreadId()+' =====');
      for(let i=0;i<nargs;i++) console.log('  x'+i+' = '+hx(this.a[i])+(isGarbage(this.a[i])?'  GARBAGE':(isBuf(this.a[i])?'  (buf)':'')));
      for(let i=0;i<nargs;i++) if(readable(this.a[i])) dumpRegion('x'+i, this.a[i], 24);
    },
    onLeave(r){ if(!this.go) return;
      console.log('  -- '+name+' (leave) ret='+hx(r)+' --');
      // out-params written during call: re-scan pointer args, and deref void** out refs
      for(let i=0;i<this.a.length;i++){
        const ai=this.a[i]; if(!readable(ai)) continue;
        dumpRegion('x'+i+'(post)', ai, 24);
        // if x_i is a void** out-ref, follow it
        try{ const inner=ai.readPointer(); if(readable(inner) && inner.compare(ai)!==0) dumpRegion('*x'+i, inner, 16); }catch(e){}
      }
    }
  });
  console.log('[+] hooked '+name+' @ '+hx(addr));
}

let done=false;
function arm(){
  if(done) return;
  const m=Process.findModuleByName('libAlgoProcess.so'); if(!m) return;
  hookFn(m.base.add(0x120d54),'APSGrallocUtils::getPlaneLayout',5);
  hookFn(m.base.add(0x1c28e8),'camApsBufferLockPlanes',6);
  done=true;
  console.log('[*] armed — take ONE Auto photo. Look for the LUMA/CHROMA line + the stride/scanline near it.');
}
const poll=setInterval(function(){ arm(); if(done) clearInterval(poll); },150);
console.log('[*] op_planelayout_probe loaded (self-arming, libAlgoProcess).');
