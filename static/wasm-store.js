(() => {
  'use strict';
  const CATALOG = 'https://raw.githubusercontent.com/aa-proxy/wasm-catalog-registry/main/';
  const MAX = 16 * 1024 * 1024;
  const TTL = 30 * 60 * 1000;
  const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,122}\.wasm$/;
  const COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
  const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$/;
  let hooks=[], listLoaded=false, busy=false, catalog=[], catalogAt=0, catalogPromise=null;
  const detailCache = new Map();
  const $ = id => document.getElementById(id);
  function status(message,failed=false){$('wasm-store-status').textContent=message;$('wasm-store-status').classList.toggle('is-error',failed);}
  async function request(url,options) {
    const response=await fetch(url,options);
    if(!response.ok)throw new Error(`${response.status} ${await response.text().then(s=>s.slice(0,200))}`);
    return response;
  }
  function setBusy(b){busy=b;for(const node of document.querySelectorAll('#wasm-store-page button, #wasm-hook-file'))node.disabled=b;}
  function validateFilename(name) {if(!FILE_NAME.test(name)||name.length>128)throw new Error('Invalid WASM filename. Use ASCII letters, digits, ., - and _.');}
  function validateEntry(e) {
    return e && typeof e==='object' && COMPONENT.test(e.id||'') && VERSION.test(e.version||'') && FILE_NAME.test(e.filename||'') &&
      typeof e.name==='string' && typeof e.sha256==='string' && /^[0-9a-f]{64}$/i.test(e.sha256) &&
      Number.isInteger(e.size_bytes) && e.size_bytes>=8 && e.size_bytes<=MAX;
  }
  function asText(value){return typeof value==='string'?value:'';}
  function textNode(tag,cls,content){const n=document.createElement(tag);if(cls)n.className=cls;n.textContent=content;return n;}
  function action(label,callback,kind='secondary'){
    const b=document.createElement('button');b.type='button';b.className=kind;b.textContent=label;
    b.addEventListener('click',callback);return b;
  }
  function moduleCard(title,meta,description) {
    const card=document.createElement('li');card.className='wasm-module-card';
    const main=document.createElement('div');main.className='wasm-module-info';
    main.append(textNode('strong',null,title),textNode('span','wasm-module-meta',meta));
    if(description)main.append(textNode('p','wasm-module-description',description));
    const buttons=document.createElement('div');buttons.className='wasm-module-actions';
    card.append(main,buttons);
    return {card,main,buttons};
  }
  async function listHooks(render=true){
    const res=await request('/wasm-hooks',{cache:'no-store'});
    const data=await res.json();
    if(!Array.isArray(data))throw new Error('Invalid /wasm-hooks response');
    hooks=data;listLoaded=true;if(render)renderInstalled();return data;
  }
  function renderInstalled(){
    const list=$('wasm-hook-list');list.replaceChildren();
    $('wasm-installed-count').textContent=`${hooks.length} installed`;
    if(!hooks.length){list.append(textNode('li','tool-empty','No WASM modules installed. Upload one here or choose Discover.'));return;}
    for(const hook of hooks){
      const {card,buttons}=moduleCard(hook.name,`${Number(hook.size||0).toLocaleString()} bytes · ${hook.error?'Error':hook.loaded?'Loaded':'Pending'}`,asText(hook.error));
      if(hook.error)card.classList.add('is-error');
      buttons.append(action('Delete',async()=>{
        if(!confirm(`Delete ${hook.name}? The module will be unloaded.`))return;
        setBusy(true);try {await request(`/wasm-hooks/${encodeURIComponent(hook.name)}`,{method:'DELETE'});await listHooks();status(`${hook.name} deleted.`);}
        catch(e){status(`Delete failed: ${e.message}`,true);}finally{setBusy(false);}
      },'outline'));
      list.append(card);
    }
  }
  function renderCatalog(){
    const list=$('wasm-catalog-list');list.replaceChildren();
    const query=$('wasm-catalog-search').value.trim().toLowerCase();
    const matching=catalog.filter(e=>[e.name,e.id,e.category,e.author,e.description].some(v=>asText(v).toLowerCase().includes(query)));
    if(!matching.length){list.append(textNode('div','tool-empty',catalog.length?'No matching modules.':'No modules published yet.'));return;}
    for(const entry of matching){
      const installed=hooks.find(h=>h.name===entry.filename);
      const match=installed && typeof installed.sha256==='string' && installed.sha256.toLowerCase()===entry.sha256.toLowerCase();
      const versionStatus=installed?(match?' · Up to date':' · Installed (version unknown or different)'):'';
      const {card,main,buttons}=moduleCard(entry.name,`${asText(entry.category)||'Other'} · v${entry.version} · ${entry.author||'Unknown author'}${versionStatus}`,asText(entry.description));
      const details=action('Details',()=>detailsFor(entry,card,details),'secondary');
      buttons.append(details);
      if(!match){buttons.append(action(installed?'Replace / update':'Install',()=>installEntry(entry,!!installed),'outline'));}
      list.append(card);
    }
  }
  async function detailsFor(entry,card,button){
    const old=card.querySelector('.wasm-module-details');
    if(old){old.remove();button.textContent='Details';return;}
    button.disabled=true;
    try{
      let data=detailCache.get(entry.id);
      if(!data){
        const res=await request(`${CATALOG}modules/${encodeURIComponent(entry.id)}/info.json`,{cache:'no-store'});
        data=await res.json();
        if(!data || data.id!==entry.id)throw new Error('Invalid module metadata');
        detailCache.set(entry.id,data);
      }
      const box=document.createElement('div');box.className='wasm-module-details';
      box.append(textNode('p',null,asText(data.description) || asText(entry.description)));
      if(Array.isArray(data.capabilities) && data.capabilities.length)box.append(textNode('p','wasm-module-meta',`Capabilities: ${data.capabilities.join(', ')}`));
      if(Array.isArray(data.releases))for(const rel of data.releases.slice(0,4)){
        box.append(textNode('p','wasm-module-meta',`v${rel.version||'?'}: ${rel.changelog||'No changelog'}`));
      }
      if(typeof data.source_url==='string' && /^https:\/\//.test(data.source_url)){
        const a=document.createElement('a');a.href=data.source_url;a.target='_blank';a.rel='noopener noreferrer';a.textContent='Source code';box.append(a);
      }
      card.append(box);button.textContent='Hide details';
    }catch(e){status(`Unable to load details: ${e.message}`,true);}finally{button.disabled=false;}
  }
  async function fetchCatalog(force=false){
    if(catalogPromise)return catalogPromise;
    if(!force && catalogAt && Date.now()-catalogAt<TTL){renderCatalog();return;}
    status('Loading WASM catalog…');
    catalogPromise=(async()=>{
      try {
        const response=await request(`${CATALOG}catalog.json`,{cache:force?'no-store':'default'});
        const raw=await response.json();
        if(raw.schema_version!==2||!Array.isArray(raw.scripts)||raw.scripts.length>200)throw new Error('Unsupported catalog format');
        const valid=raw.scripts.filter(validateEntry);
        catalog=valid;catalogAt=Date.now();
        status(valid.length?`${valid.length} modules found. Select Details or Install.`:'The official catalog is currently empty. Local upload still works.');
        renderCatalog();
      }catch(e){status(`Online catalog unavailable: ${e.message}. Installed modules still work.`,true);}
      finally{catalogPromise=null;}
    })();
    return catalogPromise;
  }
  // Match Rust src/wasm_hooks_web.rs::validate_magic and Android WasmImport:
  // WASM core modules and WASM components share the four-byte `\0asm` magic.
  // The four bytes after it vary by binary format (for components: 0d 00 01 00).
  // The runtime performs the full validation after upload.
  function validHeader(bytes){return bytes.length>=8 && [0,97,115,109].every((b,i)=>bytes[i]===b);}
  // Portable SHA-256 for HTTP installations where window.crypto.subtle is unavailable.
  // Input is capped at 16 MiB, so processing on the UI thread is acceptable here.
  function sha256Fallback(bytes){
    const k=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    const h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const padded=new Uint8Array(Math.ceil((bytes.length+9)/64)*64);padded.set(bytes);padded[bytes.length]=0x80;
    const bitLength=bytes.length*8;
    const view=new DataView(padded.buffer);view.setUint32(padded.length-8,Math.floor(bitLength/0x100000000));view.setUint32(padded.length-4,bitLength>>>0);
    const w=new Uint32Array(64), rot=(x,n)=>((x>>>n)|(x<<(32-n)))>>>0;
    for(let offset=0;offset<padded.length;offset+=64){
      for(let i=0;i<16;i++)w[i]=view.getUint32(offset+i*4);
      for(let i=16;i<64;i++){const s0=rot(w[i-15],7)^rot(w[i-15],18)^(w[i-15]>>>3);const s1=rot(w[i-2],17)^rot(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}
      let [a,b,c,d,e,f,g,z]=h;
      for(let i=0;i<64;i++){const s1=rot(e,6)^rot(e,11)^rot(e,25);const ch=(e&f)^((~e)&g);const temp1=(z+s1+ch+k[i]+w[i])>>>0;const s0=rot(a,2)^rot(a,13)^rot(a,22);const maj=(a&b)^(a&c)^(b&c);const temp2=(s0+maj)>>>0;
        z=g;g=f;f=e;e=(d+temp1)>>>0;d=c;c=b;b=a;a=(temp1+temp2)>>>0;
      }
      for(const [i,x] of [a,b,c,d,e,f,g,z].entries())h[i]=(h[i]+x)>>>0;
    }
    return Array.from(h,n=>n.toString(16).padStart(8,'0')).join('');
  }
  async function hash(bytes){
    if(globalThis.crypto?.subtle){const data=await crypto.subtle.digest('SHA-256',bytes);return Array.from(new Uint8Array(data),n=>n.toString(16).padStart(2,'0')).join('');}
    return sha256Fallback(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  }
  async function uploadBytes(name,bytes){
    validateFilename(name);
    if(bytes.byteLength<8||bytes.byteLength>MAX||!validHeader(new Uint8Array(bytes.slice(0,8))))throw new Error('Invalid WebAssembly header or size exceeds 16 MiB.');
    await request(`/wasm-hooks/${encodeURIComponent(name)}`,{method:'PUT',body:bytes});
    status(`${name} uploaded. Checking runtime load status…`);
    for(let i=0;i<15;i++){
      await new Promise(resolve=>setTimeout(resolve,500));
      const rows=await listHooks(false);
      const hook=rows.find(h=>h.name===name);
      if(hook && (hook.loaded||hook.error)){
        renderInstalled();
        status(hook.error?`${name}: ${hook.error}`:`${name} installed and loaded.`,!!hook.error);
        return;
      }
    }
    renderInstalled();status(`${name} uploaded; runtime still pending. Refresh Installed later.`);
  }
  async function installEntry(entry,installed){
    if(busy)return;
    if(installed&&!confirm(`Replace ${entry.filename} with ${entry.name} v${entry.version}?`))return;
    setBusy(true);status(`Downloading ${entry.name} v${entry.version}…`);
    try{
      const url=`${CATALOG}modules/${encodeURIComponent(entry.id)}/${encodeURIComponent(entry.id)}-${encodeURIComponent(entry.version)}.wasm`;
      const response=await request(url,{cache:'no-store'});
      const declared=Number(response.headers.get('content-length')||'0');
      if(declared>MAX)throw new Error('Remote WASM too large');
      const bytes=await response.arrayBuffer();
      if(bytes.byteLength!==entry.size_bytes)throw new Error('Size does not match catalog');
      if(!validHeader(new Uint8Array(bytes.slice(0,8))))throw new Error('Invalid WASM header');
      status('Verifying SHA-256…');
      const digest=await hash(bytes);
      if(digest!==entry.sha256.toLowerCase())throw new Error('SHA-256 mismatch. Not installing.');
      // If the caller didn't already know it's installed, refresh before PUT to prevent accidental replacement.
      if(!installed){await listHooks(false);if(hooks.some(h=>h.name===entry.filename)&&!confirm(`${entry.filename} is now installed. Replace it?`))return;}
      await uploadBytes(entry.filename,bytes);
      renderCatalog();
    }catch(e){status(`Installation failed: ${e.message}`,true);}finally{setBusy(false);}
  }
  async function localUpload(event){
    event.preventDefault();if(busy)return;
    const file=$('wasm-hook-file').files[0];if(!file)return;
    try{validateFilename(file.name);}catch(e){status(e.message,true);return;}
    if(file.size<8||file.size>MAX){status('WASM must be 8 bytes–16 MiB.',true);return;}
    // Preflight the current directory to avoid silently overwriting a file added elsewhere.
    try{await listHooks(false);}catch(e){status(`Cannot check existing hooks: ${e.message}`,true);return;}
    const existing=hooks.some(h=>h.name===file.name);
    if(existing&&!confirm(`Replace existing ${file.name}?`))return;
    setBusy(true);
    try{await uploadBytes(file.name,await file.arrayBuffer());$('wasm-hook-file').value='';$('wasm-selected-file').textContent='No file selected';renderCatalog();}
    catch(e){status(`Upload failed: ${e.message}`,true);}finally{setBusy(false);}
  }
  async function onEnter(){
    if(!listLoaded){try{await listHooks();status('Installed modules loaded.');}catch(e){status(`Cannot load installed modules: ${e.message}`,true);}}
  }
  function selectTab(tab){
    $('wasm-installed-pane').hidden=tab!=='installed';$('wasm-discover-pane').hidden=tab!=='discover';
    for(const id of ['installed','discover']){
      const btn=$(`wasm-tab-${id}`), active=id===tab;
      btn.classList.toggle('is-active',active);btn.setAttribute('aria-selected',String(active));
    }
    if(tab==='discover')fetchCatalog();else onEnter();
  }
  document.addEventListener('DOMContentLoaded',()=>{
    $('wasm-tab-installed').addEventListener('click',()=>selectTab('installed'));
    $('wasm-tab-discover').addEventListener('click',()=>selectTab('discover'));
    $('wasm-catalog-refresh').addEventListener('click',()=>fetchCatalog(true));
    $('wasm-catalog-search').addEventListener('input',renderCatalog);
    $('wasm-hook-refresh').addEventListener('click',async()=>{try{await listHooks();status('Installed list refreshed.');renderCatalog();}catch(e){status(e.message,true);}});
    $('wasm-hook-file').addEventListener('change',event=>{
      const file=event.target.files?.[0];
      $('wasm-selected-file').textContent=file?file.name:'No file selected';
      $('wasm-selected-file').title=file?.name||'';
    });
    $('wasm-hook-form').addEventListener('submit',localUpload);
    document.addEventListener('dashboard-page',e=>{if(e.detail.page==='wasm-store')onEnter();});
    if(window.location.hash.includes('wasm-store'))onEnter();
  });
  // Expose the pure hash helper for opt-in local verification tests; no host APIs.
  if(typeof window!=='undefined')window.__wasmStoreHashForTest=sha256Fallback;
})();
