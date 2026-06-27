// op_qnn_init_probe.js — THE decisive final test.
//
// Hypothesis (external reviewer #2, never instrumented): on the port, ArcSoft's HTP/QNN
// runtime init FAILS, so turbo silently falls back to a CPU path whose allocator yields the
// 4GB-aligned garbage dst. Static check already proved the QNN libs + DSP skel are PRESENT
// at the same paths as stock (libQnnHtp.so @ /odm/lib64, libarc_htp_driver_skel.so @
// /odm/lib/rfsa/adsp). So the ONLY open question is the RUNTIME result of InitQNN.
//
// This probe answers three things in ONE capture, all NATIVE (no Java hooks):
//   (1) Is ARC_Turbo_RAW_InitQNN CALLED, and what does it RETURN?
//          ret == 0 (MOK)  -> QNN init SUCCEEDS  => CPU-fallback theory is DEAD; the garbage
//                              dst is computed on the HTP/working path (back to descriptor bug)
//          ret != 0        -> QNN init FAILS     => smoking gun: CPU fallback -> garbage dst
//          never called    -> turbo never reaches QNN init (wrong path selected upstream)
//   (2) Does ANY libQnn*/skel/cdsp dlopen FAIL? (android_dlopen_ext/dlopen returning NULL)
//          a NULL return on a QNN/HTP/skel path is the concrete reason InitQNN would fail.
//   (3) Does the turbo buffer ever get FastRPC-mapped into the DSP SMMU? (ioctl 'R' nr 6/10)
//          if QNN works there should be DSP map ops; if absent, buffer never reaches the DSP.
//
// LIGHT: no INVOKE hook, no hexdump (that's what bogged earlier runs). dlopen logging is
// filtered to QNN/HTP/arcsoft/cdsp/skel names only.
//
// USAGE — run on the TURBO-ON build (d1bb5e10; InitQNN only runs when turbo executes):
//   adb shell setenforce 0
//   frida -U -n com.oplus.camera -l ~/sparkos/op_qnn_init_probe.js > ~/sparkos/frida_qnn.txt
//   >>> HDR OFF, point at a plain evenly-lit wall, take ONE Auto/Photo photo <<<
//   (flat non-HDR scene so turbo COMPLETES instead of hitting the §2a crash mid-init)
//   If it still crashes before the verdict, the InitQNN onLeave line below will already have
//   printed — that line alone is the answer.
'use strict';

function hx(p){ return p ? ('0x'+p.toString(16)) : '0x0'; }
function MB(n){ return (n/(1024*1024)).toFixed(2)+' MB'; }
function u64(p,off){ try { return p.add(off).readU64(); } catch(e){ return ptr(0); } }
function s32(p,off){ try { return p.add(off).readS32(); } catch(e){ return -999; } }
function n64(v){ try { return Number(v); } catch(e){ return 0; } }

// Frida 17 removed the static Module.findExportByName(mod, sym). Resolve via the instance
// method (works in 17) with global/old-API fallbacks so the hooks ACTUALLY install.
function resolveExport(modName, sym){
  try { const m = Process.findModuleByName(modName); if (m && m.findExportByName){ const a=m.findExportByName(sym); if(a) return a; } } catch(e){}
  try { if (Module.getGlobalExportByName){ const a=Module.getGlobalExportByName(sym); if(a) return a; } } catch(e){}
  try { if (Module.findGlobalExportByName){ const a=Module.findGlobalExportByName(sym); if(a) return a; } } catch(e){}
  try { if (Module.findExportByName){ const a=Module.findExportByName(modName, sym); if(a) return a; } } catch(e){}  // old API
  return null;
}

function vaTag(p){
  try {
    const lo = p.and(ptr('0xffffffff'));
    if (lo.isNull()) return '   <<< 4GB-ALIGNED (low32=0) = garbage/translation signature';
    const hi = parseInt(p.shr(32).toString());
    if (lo.compare(ptr('0x10000')) < 0) return '   <<< low32 tiny (0x'+lo.toString(16)+') = truncated-pointer signature';
    if (hi >= 0x70 && hi <= 0x74) return '   (valid camera band)';
  } catch(e){}
  return '';
}

// ---- (1) ARC_Turbo_RAW_InitQNN / UnInitQNN return value ----------------------------------
function hookByName(sym, isInit){
  // resolve across all loaded modules (symbol lives in libarcsoft_turbo_raw.so, loaded lazily)
  const addr = resolveExport('libarcsoft_turbo_raw.so', sym);
  if (!addr) { return false; }   // quiet: the 200ms poller keeps retrying until the lib loads
  Interceptor.attach(addr, {
    onEnter(a){ this.t = Date.now(); },
    onLeave(r){
      const ret = r.toInt32();
      console.log('\n############################################################');
      console.log('## '+sym+'  RETURNED  ret=' + ret + '  (' + hx(r) + ')'
                  + '   tid=' + Process.getCurrentThreadId());
      if (isInit) {
        if (ret === 0)
          console.log('## VERDICT: ret==0 => QNN/HTP init SUCCEEDED on the port.');
        else
          console.log('## VERDICT: ret!=0 => QNN/HTP init FAILED  => CPU-FALLBACK path = the bug.');
      }
      console.log('############################################################\n');
    }
  });
  console.log('[+] hooked ' + sym + ' @ ' + hx(addr));
  return true;
}

let initHooked = false, uninitHooked = false;
function tryHookQnn(){
  if (!initHooked)  initHooked  = hookByName('ARC_Turbo_RAW_InitQNN', true);
  if (!uninitHooked) uninitHooked = hookByName('ARC_Turbo_RAW_UnInitQNN', false);
}

// ---- (2) dlopen failures on QNN/HTP/arcsoft/cdsp/skel paths -------------------------------
function isInteresting(name){
  if (!name) return false;
  return /qnn|htp|arcsoft|cdsp|skel|libAlgo|turbo/i.test(name);
}
function hookDlopen(sym){
  const p = resolveExport('libdl.so', sym);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(a){ try { this.name = a[0].isNull() ? '<null>' : a[0].readCString(); } catch(e){ this.name = '?'; } },
    onLeave(r){
      const interesting = isInteresting(this.name);
      // when a QNN/HTP lib gets loaded, (re)try resolving InitQNN
      if (interesting && !r.isNull()) tryHookQnn();
      if (r.isNull() && interesting) {
        console.log('\n[dlopen FAIL] '+sym+'("'+this.name+'") -> NULL');
        try { const de = resolveExport('libdl.so','dlerror');
              if (de){ const msg = new NativeFunction(de,'pointer',[])(); if(!msg.isNull()) console.log('   dlerror: '+msg.readCString()); } } catch(e){}
        console.log('   ^^^ a failed QNN/HTP/skel load is a concrete reason InitQNN would fail.\n');
      } else if (interesting) {
        console.log('[dlopen ok] '+this.name);
      }
    }
  });
}

// ---- (3) fastrpc DSP map ops (nr 6 MMAP / nr 10 MEM_MAP / nr 1 ALLOC) ---------------------
function hookIoctl(){
  const p = resolveExport('libc.so','ioctl');
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(a){
      this.nr = -1;
      const req = (a[1].toUInt32 ? a[1].toUInt32() : (a[1].toInt32()>>>0));
      if (((req>>>8)&0xff) !== 0x52) return;            // not fastrpc 'R'
      const nr = req & 0xff;
      if (nr!==1 && nr!==6 && nr!==10) return;          // ALLOC/MMAP/MEM_MAP only (no INVOKE)
      this.nr = nr; this.argp = a[2];
      if (nr===6){ this.fd=s32(this.argp,0); this.size=u64(this.argp,16); this.vin=u64(this.argp,8); }
      else if (nr===10){ this.fd=s32(this.argp,4); this.size=u64(this.argp,24); this.vin=u64(this.argp,16); }
      else { this.size=u64(this.argp,8); }
    },
    onLeave(r){
      if (this.nr < 0) return;
      if (this.nr === 1){
        const fd = s32(this.argp,0);
        console.log('[fastrpc ALLOC_DMA_BUFF] '+MB(n64(this.size))+' -> fd='+fd+' ret='+r.toInt32()
          + (n64(this.size)>=16*1024*1024 ? '   <<< BIG' : ''));
        return;
      }
      const vout = u64(this.argp, this.nr===6?24:32);
      const nm = (this.nr===6)?'MMAP':'MEM_MAP';
      console.log('[fastrpc '+nm+' -> DSP] fd='+this.fd+' '+MB(n64(this.size))
        +' vaddrin='+hx(this.vin)+' vaddrout='+hx(vout)+vaTag(vout)+'  ret='+r.toInt32()
        +'  tid='+Process.getCurrentThreadId());
    }
  });
  console.log('[+] hooked ioctl (fastrpc ALLOC/MMAP/MEM_MAP only)');
}

console.log('[*] op_qnn_init_probe loaded. Run on TURBO-ON build; shoot a FLAT non-HDR scene.');
hookDlopen('android_dlopen_ext');
hookDlopen('dlopen');
hookIoctl();
tryHookQnn();   // in case the turbo lib is already loaded at attach time

// SELF-ARMING: poll every 200ms and hook InitQNN the instant libarcsoft_turbo_raw.so loads,
// no matter HOW it loads (dlopen, preload, dlmopen, linker namespace). Announces once when
// the lib first appears, stops polling once both symbols are hooked.
let announced = false;
const poll = setInterval(function(){
  if (!announced) {
    let m = null; try { m = Process.findModuleByName('libarcsoft_turbo_raw.so'); } catch(e){}
    if (m) { announced = true; console.log('[*] libarcsoft_turbo_raw.so now loaded @ '+hx(m.base)+' — arming InitQNN hook'); }
  }
  tryHookQnn();
  if (initHooked && uninitHooked) { clearInterval(poll); console.log('[*] InitQNN + UnInitQNN hooked; poller stopped.'); }
}, 200);

console.log('[*] watching for ARC_Turbo_RAW_InitQNN return + QNN/HTP dlopen failures + DSP map ops (self-arming poll active).');
