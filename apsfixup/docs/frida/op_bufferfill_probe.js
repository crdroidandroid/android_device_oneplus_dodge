// op_bufferfill_probe.js — find the EXACT function that writes the garbage chroma plane.
//
// In libAlgoInterface::turboRawProcess the output ASVL struct = AlgoProcessData(x19)+0x4f8
// (luma @+0x40, chroma @+0x48). Its planes are filled by a vtable call [x19+0xa8] at two
// sites (0x1c478f0, 0x1c47ad8). This hooks each site, logging:
//   * the TARGET function of the vtable call (module+offset)  -> the code to RE/patch next
//   * luma/chroma in the output struct BEFORE and AFTER the call -> which call writes garbage
//
// Run on the namespace-fixed turbo-ON build, WITHOUT op_force_align (let it run natural / 0,0).
// It will still crash after these logs (the garbage write is later) — the lines we need print
// first.
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_bufferfill_probe.js > ~/sparkos/frida_bf.txt
//   >>> take ONE Auto photo <<<
'use strict';

function hx(p){ return p ? ('0x'+p.toString(16)) : '0x0'; }
function modOff(p){
  try { var m=Process.findModuleByAddress(p);
    return m ? (m.name + '+0x' + p.sub(m.base).toString(16)) : (hx(p)+' (unknown module)'); }
  catch(e){ return hx(p); }
}
// the align_up(luma,0) garbage signature: hi word in pointer band 0x70..0x7f, tiny low32
function isGarbage(v){
  try { if(v.isNull()) return false; var hi=parseInt(v.shr(32).toString());
    if(hi<0x70||hi>0x7f) return false;
    return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))<0; } catch(e){ return false; }
}
function rdp(p){ try { return p.readPointer(); } catch(e){ return ptr(0); } }

var SITES=[0x1c478f0, 0x1c47ad8];   // blr [x19+0xa8] sites in turboRawProcess
var seen=0;

function dumpOut(tag, x19){
  try {
    var out = x19.add(0x4f8);
    var luma = rdp(out.add(0x40));
    var chroma = rdp(out.add(0x48));
    console.log('    '+tag+': luma='+hx(luma)+'  chroma='+hx(chroma)
      + (isGarbage(chroma) ? '   <<<<< CHROMA GARBAGE' : ''));
    return isGarbage(chroma);
  } catch(e){ console.log('    '+tag+' err '+e); return false; }
}

function arm(){
  var m = Process.findModuleByName('libAlgoInterface.so');
  if (!m) return false;
  SITES.forEach(function(off, idx){
    var site = m.base.add(off);
    // BEFORE: at the blr, x8 = target fn, x19 = AlgoProcessData
    Interceptor.attach(site, {
      onEnter: function(){
        if (seen > 12) return;
        seen++;
        var x19 = this.context.x19;
        var x8  = this.context.x8;
        console.log('\n=== site#'+idx+' @libAlgoInterface+'+hx(off)
          + '  vtable target = ' + modOff(x8) + '   tid='+Process.getCurrentThreadId());
        console.log('    AlgoProcessData(x19)='+hx(x19)+'  outStruct='+hx(x19.add(0x4f8)));
        this.x19 = x19;
        dumpOut('BEFORE', x19);
      }
    });
    // AFTER: instruction right after the blr
    Interceptor.attach(site.add(4), {
      onEnter: function(){
        if (seen > 12) return;
        try {
          var x19 = this.context.x19;
          if (dumpOut('AFTER ', x19))
            console.log('    ^^^ this vtable call WROTE the garbage chroma — RE its target above.');
        } catch(e){}
      }
    });
  });
  console.log('[*] hooked buffer-fill sites (0x1c478f0, 0x1c47ad8). Take ONE Auto photo.');
  return true;
}

var poll=setInterval(function(){ if(arm()) clearInterval(poll); }, 150);
console.log('[*] op_bufferfill_probe loaded (self-arming).');
