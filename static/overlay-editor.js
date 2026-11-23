(() => {
  'use strict';
  const defaults = {telemetry: {text: '<b>RPM: 2500</b>\n<font color="#DCF6FF">30/45 °C</font>', anchor_horizontal: 'right', anchor_vertical: 'bottom', offset_x_px: 105, offset_y_px: 12, box_opacity_percent: 0, box_border_px: 0, text_rgb: [255,255,255]}, temperature: {text: '<font color="#00DFFF">❄ 0028</font>\n<font color="#00DFFF">🌡 50/40°C</font>', anchor_horizontal:'right',anchor_vertical:'bottom',offset_x_px:200,offset_y_px:10,box_opacity_percent:0,box_border_px:0}, dtc: {text: '<b><font color="#FF3333">⚠ DTC ALERT [MIL ON]</font></b><br>P0100: Air Flow Circuit<br>P0171: System Too Lean', anchor_horizontal:'right',anchor_vertical:'bottom',offset_x_px:25,offset_y_px:8,box_opacity_percent:75,box_bg_rgb:[12,12,18],box_border_px:2,box_border_rgb:[245,44,55],max_display_lines:6}};
  const config = [
    ['x','offset_x_px',0,8192,100], ['y','offset_y_px',0,8192,9], ['scale','text_scale',1,128,2],
    ['opacity','box_opacity_percent',0,100,0], ['padding-x','box_padding_x_px',0,2048,12],
    ['padding-y','box_padding_y_px',0,2048,9], ['border','box_border_px',0,40,0],
    ['linespace','line_spacing_px',0,100,6], ['charspace','char_spacing_px',0,100,1]
  ];
  const colors = [['color-text','text_rgb',[245,250,255]], ['color-bg','box_bg_rgb',[16,22,32]], ['color-border','box_border_rgb',[0,200,255]]];
  let loaded = null, dirty = false, loading = false, saving = false;
  const el = id => document.getElementById('overlay-'+id);
  const clamp = (x,min,max) => Math.min(max, Math.max(min,x));
  const number = (str,min,max,fallback) => str.trim() === '' || !/^\d+$/.test(str) ? fallback : clamp(Number(str),min,max);
  const rgba = (v, fallback) => Array.isArray(v) && v.length === 3 ? v.map(x=>clamp(Number(x)||0,0,255)) : fallback;
  const toHex = a => '#'+a.map(n=>clamp(n|0,0,255).toString(16).padStart(2,'0')).join('');
  const fromHex = s => [1,3,5].map(i=>parseInt(s.slice(i,i+2),16));
  const label = (message, fail=false) => { el('status').textContent=message; el('status').classList.toggle('is-error',fail); };
  function values() {
    if (!loaded) return null;
    const o = {...loaded.overlay, text:el('text').value, font_path:el('font').value};
    for (const [id,key,min,max,fallback] of config) {
      const old = (id === 'x' || id === 'y') && o[key] == null ? (id === 'x'?o.box_margin_right_px:o.box_margin_bottom_px) : o[key];
      o[key] = number(el(id).value,min,max,Number.isFinite(Number(old)) ? Number(old) : fallback);
    }
    for (const [id,key] of colors) o[key] = fromHex(el(id).value);
    const active = document.querySelector('.overlay-anchor-grid button[aria-pressed="true"]');
    if (active) [o.anchor_horizontal,o.anchor_vertical] = active.dataset.anchor.split(',');
    return { enabled:el('enabled').checked, overlay:o };
  }
  function populate(response) {
    loaded = response;
    const o = response.overlay;
    el('enabled').checked = response.enabled;
    el('text').value = o.text || '';
    el('font').value = o.font_path || '';
    for (const [id,key,, ,fallback] of config) {
      const legacy = id === 'x' ? o.box_margin_right_px : o.box_margin_bottom_px;
      el(id).value = o[key] ?? legacy ?? fallback;
    }
    for (const [id,key,fallback] of colors) el(id).value = toHex(rgba(o[key],fallback));
    chooseAnchor(o.anchor_horizontal || 'right', o.anchor_vertical || 'bottom');
    el('path').textContent = `Overlay file: ${response.text_path || '(unknown)'}${(response.text_path || '').startsWith('/dev/shm/') ? ' · RAM-backed: changes are lost on reboot.' : ''}`;
    dirty = false;
    render();
  }
  function chooseAnchor(horizontal,vertical) {
    for (const btn of el('anchor-grid').querySelectorAll('button')) {
      const match = btn.dataset.anchor === `${horizontal},${vertical}`;
      btn.setAttribute('aria-pressed',String(match)); btn.classList.toggle('is-selected',match);
    }
  }
  async function fetchOverlay(force=false) {
    if (loading || saving || (loaded && !force)) return;
    loading=true; label('Loading overlay configuration…');
    try {
      const res=await fetch('/overlay',{cache:'no-store'});
      if(!res.ok) throw new Error(`GET /overlay: ${res.status} ${await res.text()}`);
      populate(await res.json()); label('Ready. Changes are local until you save.');
    } catch(e) {label(e.message,true);} finally{loading=false;}
  }
  function buildText(raw) {
    // Parse markup, then rebuild only an explicit subset. Never inject arbitrary saved HTML.
    const parsed = new DOMParser().parseFromString(raw,'text/html');
    const root = document.createDocumentFragment();
    const allowed = new Set(['B','STRONG','I','EM','U','FONT','SPAN','MARK','BR']);
    function append(node,dest,depth) {
      if (depth > 20) return;
      if(node.nodeType === Node.TEXT_NODE) {
        dest.appendChild(document.createTextNode(node.nodeValue.replace(/\{\{([A-Za-z0-9_]+)(?::\d+)?\}\}/g,(_,key)=>({battery_level_percentage:'85',speed:'42',rpm:'2500',temperature:'40'}[key.toLowerCase()] || `[${key}]`))));
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        let span;
        if (node.tagName === 'BR') {dest.appendChild(document.createElement('br'));return;}
        if(allowed.has(node.tagName)) {
          span=document.createElement(['B','STRONG','I','EM','U','MARK'].includes(node.tagName) ? node.tagName.toLowerCase() : 'span');
          if(node.tagName === 'FONT') { const c=node.getAttribute('color'); if(c && /^#[a-fA-F0-9]{6}$/.test(c))span.style.color=c; }
          if(node.tagName === 'SPAN') {
            const style=node.getAttribute('style') || '';
            for(const decl of style.split(';')) {
              const [k,v] = decl.split(':').map(a=>a?.trim().toLowerCase());
              if(!v)continue;
              if(k==='color' && /^#[a-f0-9]{6}$/.test(v))span.style.color=v;
              if(k==='background-color' && /^#[a-f0-9]{6}$/.test(v))span.style.backgroundColor=v;
              if(k==='font-weight' && (v==='bold'||v==='700'))span.style.fontWeight='bold';
              if(k==='font-style' && v==='italic')span.style.fontStyle='italic';
            }
          }
        } else span=document.createDocumentFragment();
        for(const child of node.childNodes)append(child,span,depth+1);
        dest.appendChild(span);
      }
    }
    for(const child of parsed.body.childNodes)append(child,root,0);
    return root;
  }
  // Vector-only local Android Auto sample. Drawn by the browser; never touches the video pipeline.
  function drawSampleScreen() {
    const canvas = el('preview-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const W=1280, H=720;
    if(canvas.width !== W || canvas.height !== H){canvas.width=W;canvas.height=H;}
    ctx.clearRect(0,0,W,H);
    const rect=(x,y,w,h,c)=>{ctx.fillStyle=c;ctx.fillRect(x,y,w,h);};
    const pathRound=(x,y,w,h,r)=>{r=Math.min(r,w/2,h/2);ctx.beginPath();ctx.moveTo(x+r,y);ctx.lineTo(x+w-r,y);ctx.arcTo(x+w,y,x+w,y+r,r);ctx.lineTo(x+w,y+h-r);ctx.arcTo(x+w,y+h,x+w-r,y+h,r);ctx.lineTo(x+r,y+h);ctx.arcTo(x,y+h,x,y+h-r,r);ctx.lineTo(x,y+r);ctx.arcTo(x,y,x+r,y,r);ctx.closePath();};
    const round=(x,y,w,h,r,c)=>{pathRound(x,y,w,h,r);ctx.fillStyle=c;ctx.fill();};
    const stroke=(x,y,w,h,r,c,line=2)=>{pathRound(x,y,w,h,r);ctx.strokeStyle=c;ctx.lineWidth=line;ctx.stroke();};
    const label=(s,x,y,size=24,color='#e9f0f7',weight=500)=>{ctx.fillStyle=color;ctx.font=`${weight} ${size}px system-ui, -apple-system, sans-serif`;ctx.fillText(s,x,y);};
    const line=(pts,color,width=2)=>{ctx.beginPath();ctx.moveTo(pts[0][0],pts[0][1]);for(const p of pts.slice(1))ctx.lineTo(p[0],p[1]);ctx.strokeStyle=color;ctx.lineWidth=width;ctx.lineCap='round';ctx.lineJoin='round';ctx.stroke();};
    const disc=(x,y,r,c)=>{ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);ctx.fillStyle=c;ctx.fill();};
    const gradient=(x,y,w,h,c1,c2)=>{const g=ctx.createLinearGradient(x,y,x+w,y+h);g.addColorStop(0,c1);g.addColorStop(1,c2);return g;};
    // App window and schematic road map; road lines are deliberately decorative.
    rect(0,0,W,H,'#070d16');
    round(17,17,806,601,23,gradient(17,17,806,601,'#172c40','#0e1b2a'));
    ctx.save();pathRound(17,17,806,601,23);ctx.clip();
    const roads=[[[75,15],[155,170],[208,340],[195,618]],[[315,0],[351,100],[308,240],[370,390],[333,618]],[[497,18],[455,156],[500,310],[485,610]],[[675,25],[622,180],[687,336],[640,618]],[[20,205],[215,240],[425,223],[790,268]],[[10,420],[260,460],[480,419],[826,475]],[[65,580],[295,530],[565,560],[812,540]]];
    roads.forEach((p,i)=>line(p,i%2?'#2d4358':'#263e51',i%2?5:3));
    line([[560,5],[570,175],[540,285],[555,384],[520,500],[534,615]],'#075d9e',29);
    line([[560,5],[570,175],[540,285],[555,384],[520,500],[534,615]],'#159cf3',11);
    line([[560,5],[570,175],[540,285],[555,384],[520,500],[534,615]],'#55d5ff',3);
    ctx.restore();
    // Navigation banner.
    round(45,42,480,117,18,gradient(45,42,480,117,'#006b5a','#005047'));
    label('↰',66,111,54,'#d6fff5',650);label('400 m',133,88,26,'#ddfff8',650);
    label('Coastal Highway',133,127,29,'#ffffff',650);
    // Navigation indicator.
    disc(535,381,39,'#1868e9');
    ctx.beginPath();ctx.moveTo(535,347);ctx.lineTo(515,400);ctx.lineTo(535,389);ctx.lineTo(555,400);ctx.closePath();ctx.fillStyle='#f9ffff';ctx.fill();
    round(44,461,354,110,17,'rgba(11,20,32,0.92)');stroke(44,461,354,110,17,'#395263',2);
    label('23 min',67,505,30,'#d4d576',700);label(' · 9.4 mi',176,505,27,'#dbe5f0',500);
    label('ETA 12:58',67,541,25,'#9eafc2',500);
    // Right dashboard widgets: compact music section and a softly colored cover.
    round(841,17,421,260,22,'#242830');
    label('Now playing',867,59,21,'#b6c6d4',550);
    round(870,81,105,105,13,gradient(870,81,105,105,'#234969','#695b86'));
    disc(922,134,33,'#102a41a0');disc(922,134,12,'#b6dbe3');
    label('Iris',998,121,34,'#f3f4f7',650);label('The Goo Goo Dolls',998,160,21,'#aebac7');
    round(869,205,359,5,3,'#505d68');round(869,205,154,5,3,'#91d8df');
    disc(1023,207,8,'#e0f1f4');
    label('1:06',869,241,18,'#9baebb');label('4:49',1179,241,18,'#9baebb');
    round(841,292,421,326,22,gradient(841,292,421,326,'#262f40','#293b50'));
    label('Music & media',869,334,22,'#e5ecf0',600);
    round(869,353,363,162,16,gradient(869,353,363,162,'#175365','#19334d'));
    // Abstract album-like shapes, all Canvas primitives.
    ctx.save();pathRound(869,353,363,162,16);ctx.clip();
    disc(1168,392,90,'rgba(73,176,176,0.12)');disc(1092,485,99,'rgba(76,123,174,0.29)');
    line([[897,468],[951,426],[1003,449],[1059,397],[1137,432],[1202,373]],'rgba(120,208,203,0.52)',6);
    ctx.restore();
    label('Playlist mix',891,402,25,'#f0f8fa',650);label('Available on your phone',891,436,19,'#d6e5e6',450);
    label('◀◀',898,569,31,'#dbeaf6');disc(1054,556,35,'#b6eaf1');
    ctx.beginPath();ctx.moveTo(1047,540);ctx.lineTo(1047,572);ctx.lineTo(1069,556);ctx.closePath();ctx.fillStyle='#0e2a39';ctx.fill();
    label('▶▶',1171,569,31,'#dbeaf6');
    // Dark Android Auto style bottom dock, separate from the overlay layer.
    rect(0,620,W,100,'#070a0d');line([[0,620],[1280,620]],'#27343e',2);
    round(31,638,61,61,22,'#263542');label('▦',46,679,32,'#e4eef7',600);
    round(112,638,61,61,22,'#213c46');label('♪',131,680,33,'#8de8e2',600);
    round(189,638,61,61,22,'#283749');label('☎',204,677,29,'#deecf5');
    label('Android Auto · Preview',284,680,23,'#a4bac7',500);
    label('5G  ▮  12:45',1079,680,24,'#dce9f3',500);
  }
  function render() {
    const v=values(); if(!v)return;
    const o=v.overlay, box=el('preview-box'), frame=el('preview-frame');
    box.replaceChildren(buildText(o.text));
    box.hidden = !o.text.trim();
    el('preview-guide').hidden = !el('preview-guides').checked;
    box.classList.toggle('show-bounds', el('preview-bounds').checked);
    const width=frame.clientWidth || 400, factor=width/1280;
    const horizontal=o.anchor_horizontal, vertical=o.anchor_vertical;
    box.style.left=horizontal==='left' ? `${o.offset_x_px/1280*100}%` : horizontal==='center'?'50%':'auto';
    box.style.right=horizontal==='right' ? `${o.offset_x_px/1280*100}%` : 'auto';
    box.style.top=vertical==='top' ? `${o.offset_y_px/720*100}%` : vertical==='center'?'50%':'auto';
    box.style.bottom=vertical==='bottom' ? `${o.offset_y_px/720*100}%` : 'auto';
    box.style.transform=`translate(${horizontal==='center'?'-50%':'0'},${vertical==='center'?'-50%':'0'})`;
    box.style.padding=`${Math.round(o.box_padding_y_px*factor)}px ${Math.round(o.box_padding_x_px*factor)}px`;
    box.style.border=`${Math.max(0,Math.round(o.box_border_px*factor))}px solid ${toHex(rgba(o.box_border_rgb,[0,200,255]))}`;
    const [r,g,b]=rgba(o.box_bg_rgb,[16,22,32]);
    box.style.backgroundColor=`rgba(${r},${g},${b},${o.box_opacity_percent/100})`;
    box.style.color=toHex(rgba(o.text_rgb,[245,250,255]));
    box.style.fontSize=`${clamp(Math.round((o.font_path?(o.text_scale<=4?o.text_scale*12:o.text_scale):o.text_scale*8)*factor),9,27)}px`;
    box.style.lineHeight=`${1+o.line_spacing_px/30}`;
    box.style.letterSpacing=`${o.char_spacing_px*factor}px`;
  }
  async function save() {
    if(!loaded||saving)return;
    saving=true; el('save').disabled=true;label('Saving overlay…');
    try {
      const payload=values();
      // Keep the numeric text box editable while focused; normalize only at save.
      for(const [id,key,min,max,fallback] of config) el(id).value=number(el(id).value,min,max,fallback);
      const res=await fetch('/overlay',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      if(!res.ok)throw new Error(`PUT /overlay: ${res.status} ${await res.text()}`);
      const originalEnabled=loaded.enabled;
      populate(await res.json());
      label(originalEnabled!==loaded.enabled?'Saved. Reconnect Android Auto to apply enable/disable.':'Overlay saved. Text and appearance updates are polled live.');
    } catch(e){label(e.message,true);} finally{saving=false;el('save').disabled=false;}
  }
  document.addEventListener('DOMContentLoaded',()=>{
    drawSampleScreen();
    for (const id of ['preview-guides','preview-bounds']) el(id).addEventListener('change',render);
    for(const btn of el('anchor-grid').querySelectorAll('button'))btn.addEventListener('click',()=>{chooseAnchor(...btn.dataset.anchor.split(','));dirty=true;render();});
    for(const name of ['enabled','text','font',...config.map(v=>v[0]),...colors.map(v=>v[0])]){
      el(name).addEventListener('input',()=>{dirty=true;render();});
    }
    // Keep numeric controls empty while editing; fill with 1 only when focus leaves.
    for(const [id] of config)el(id).addEventListener('blur',()=>{
      if(el(id).value.trim()===''){el(id).value='1';dirty=true;render();}
    });
    el('save').addEventListener('click', save);
    el('reload').addEventListener('click',()=>{if(dirty&&!confirm('Discard unsaved overlay changes?'))return;fetchOverlay(true);});
    for(const btn of document.querySelectorAll('[data-overlay-preset]'))btn.addEventListener('click',()=>{
      if(!loaded)return;
      const preset=defaults[btn.dataset.overlayPreset];
      const v={...values().overlay,...preset};
      populate({...loaded,enabled:el('enabled').checked,overlay:v});dirty=true;
      label('Template applied to preview. Click Save overlay to publish.');
    });
    document.addEventListener('dashboard-page',event=>{if(event.detail.page==='overlay'){fetchOverlay();render();}});
    window.addEventListener('resize',()=>{if(!el('preview-frame').closest('[hidden]'))render();});
    if(window.location.hash.includes('overlay'))fetchOverlay();
  });
})();
