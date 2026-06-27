// op_outstruct_dump.js — Phase 1 of the chroma repair. Dump the turbo OUTPUT buffer struct
// (AlgoProcessData+0x4f8) at turboHdrProcessV2 entry so we can identify luma(+0x40),
// chroma(+0x48), and the stride/height/format fields -> compute the correct chroma offset.
//
// turboHdrProcessV2(AlgoProcessData* x0) @ libAlgoInterface+0x1c24b6c
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_outstruct_dump.js > ~/sparkos/frida_out.txt
//   >>> take ONE Auto photo (it will crash after; the dump prints first) <<<
'use strict';
function hx(p){ return p ? ('0x'+p.toString(16)) : '0x0'; }
function isGarbage(v){ try{ if(v.isNull())return false; var hi=parseInt(v.shr(32).toString());
  if(hi<0x70||hi>0x7f) return false; return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))<0; }catch(e){return false;} }
function isBuf(v){ try{ var hi=parseInt(v.shr(32).toString()); if(hi<0x70||hi>0x7f) return false;
  return v.and(ptr('0xffffffff')).compare(ptr('0x100000'))>=0; }catch(e){return false;} }

var OFF = 0x1c24b6c;   // turboHdrProcessV2
var done = 0;

function arm(){
  var m = Process.findModuleByName('libAlgoInterface.so'); if(!m) return false;
  Interceptor.attach(m.base.add(OFF), {
    onEnter: function(a){
      if (done > 3) return; done++;
      var apd = a[0];
      var out = apd.add(0x4f8);
      console.log('\n=== turboHdrProcessV2  AlgoProcessData='+hx(apd)+'  outStruct='+hx(out)+'  tid='+Process.getCurrentThreadId());
      for (var i=0;i<0x12;i++){
        var off=i*8;
        try{
          var p=out.add(off).readPointer();
          var lo=out.add(off).readU32();
          var hi=out.add(off+4).readU32();
          var tag='';
          if (isBuf(p)) tag=' <-- BUF PTR';
          else if (isGarbage(p)) tag=' <-- GARBAGE (chroma?)';
          else if ((lo>0 && lo<30000) || (hi>0 && hi<30000)) tag=' (ints: '+lo+', '+hi+'  <- stride/height?)';
          console.log('  +0x'+off.toString(16)+' = '+hx(p)+tag);
        }catch(e){ console.log('  +0x'+off.toString(16)+' <unreadable>'); }
      }
      console.log('  (luma should be at +0x40, chroma at +0x48; note which nearby ints look like stride & height)');
    }
  });
  console.log('[*] hooked turboHdrProcessV2 @ '+hx(m.base.add(OFF))+' — take ONE Auto photo.');
  return true;
}
var poll=setInterval(function(){ if(arm()) clearInterval(poll); }, 150);
console.log('[*] op_outstruct_dump loaded.');
