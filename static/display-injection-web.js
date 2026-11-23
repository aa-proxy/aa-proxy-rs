/* Display Injection web UI, ported from Companion's DisplayInjectionScreen and models.
 * All mutations use existing aa-proxy-rs routes; no alternate file writer.
 */
(() => {
  'use strict';
  const BASE = '/display-injection';
  const CLUSTER = 'DISPLAY_TYPE_CLUSTER';
  const AUX = 'DISPLAY_TYPE_AUXILIARY';
  const NAV = 'KEYCODE_NAVIGATION';
  const $ = id => document.getElementById(id);
  const KEYS = ['top', 'bottom', 'left', 'right'];
  const DEFAULTS = {
    cluster: {id:'',name:'Cluster 1',enabled:true,display_type:CLUSTER,
      codec_resolution:'VIDEO_1920x1080',frame_rate:'VIDEO_FPS_60',initial_content_keycode:null,
      width_margin:270,height_margin:344,content_insets:null,stable_content_insets:null,
      density:180,viewing_distance:100,touch_width:1280,touch_height:720,
      input_touchscreen:false,input_source:true},
    auxiliary: n => ({id:'',name:`Auxiliary ${n}`,enabled:true,display_type:AUX,
      codec_resolution:'VIDEO_1280x720',frame_rate:'VIDEO_FPS_30',initial_content_keycode:NAV,
      width_margin:0,height_margin:0,content_insets:null,stable_content_insets:null,
      density:160,viewing_distance:300,touch_width:1280,touch_height:720,
      input_touchscreen:false,input_source:true})
  };
  let state = {enabled:true,displays:[],file:'',requires_reconnect:true,display_id_mode:'auto_max_plus_one'};
  let media = [];
  let active = null, deleting = null, busy = false, loaded = false;
  const status = (message, bad=false) => {
    const el=$('di-status'); if (!el) return;
    el.textContent=message||'';
    el.classList.toggle('di-error',!!bad);
  };
  const showError = message => { const e=$('di-editor-error');e.textContent=message;e.hidden=!message; };
  async function request(url, method='GET', payload=null) {
    const options={method,headers:{Accept:'application/json'},cache:'no-store'};
    if(payload!==null){options.headers['Content-Type']='application/json';options.body=JSON.stringify(payload);}
    let response;
    try{response=await fetch(url,options);}catch(e){throw new Error(`Network: ${e.message}`);}
    const raw=await response.text();
    let data;
    try{data=raw?JSON.parse(raw):{};}catch(_){throw new Error(`Invalid JSON response (HTTP ${response.status})`);}
    if(!response.ok)throw new Error(data.message||data.error||`HTTP ${response.status}`);
    return data;
  }
  const label = value => String(value||'').replace(/^DISPLAY_TYPE_|^VIDEO_|^KEYCODE_/,'').replace(/_/g,' ');
  const int = (n, defaultValue=0) => Number.isFinite(Number(n))?Number(n):defaultValue;
  const summarize = insets => {
    const i=insets||{};
    return `L${int(i.left)} R${int(i.right)} T${int(i.top)} B${int(i.bottom)}`;
  };
  function node(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
  function button(text,fn,cls='secondary'){
    const e=node('button','',text);e.type='button';if(cls)e.className=cls;e.addEventListener('click',fn);return e;
  }
  function spec(parent,text){parent.append(node('div','',text));}
  function card(profile){
    const el=node('div','di-card');
    const top=node('div','di-card-head');
    const names=node('div'); names.append(node('strong','',profile.name||profile.id));names.append(node('small','di-id',profile.id));
    top.append(names,node('span','di-chip-status'+(profile.enabled?'':' di-off'),profile.enabled?'Enabled':'Disabled'));
    el.append(top);
    const details=node('div','di-specs');
    [
      `Type: ${label(profile.display_type)}`,
      `Resolution: ${label(profile.codec_resolution)} · ${label(profile.frame_rate)}`,
      `Density: ${profile.density} · Viewing distance: ${profile.viewing_distance}`,
      `Margins: ${profile.width_margin} × ${profile.height_margin}`,
      `Content insets: ${summarize(profile.content_insets)}`,
      `Stable content insets: ${summarize(profile.stable_content_insets)}`,
      `Touch: ${profile.input_touchscreen?'Enabled':'Disabled'} · ${profile.touch_width} × ${profile.touch_height}`,
      profile.display_type===AUX?`Initial content: ${label(profile.initial_content_keycode||NAV)} · Input source: Required`:`Input source: ${profile.input_source?'Enabled':'Disabled'}`
    ].forEach(line=>spec(details,line));
    el.append(details);
    const actions=node('div','di-card-actions');
    const endpoint=media.find(x=>x.inject_display_id===profile.id && String(x.kind).toLowerCase()==='video');
    const view=button('View',()=>viewMedia(profile,endpoint),'secondary');
    view.disabled=!endpoint;view.title=endpoint?'View media tap details':'No media tap for this display';
    actions.append(button('Edit',()=>openEditor(profile)),button('Remove',()=>confirmRemove(profile),'secondary'),view);
    el.append(actions);
    return el;
  }
  function render(){
    const clusters=state.displays.filter(p=>p.display_type===CLUSTER);
    const aux=state.displays.filter(p=>p.display_type===AUX);
    $('di-master-enable').checked=!!state.enabled;
    $('di-config-path').textContent=state.file?`Configuration: ${state.file} · IDs: ${state.display_id_mode}`:'';
    const c=$('di-cluster');c.replaceChildren();
    if(clusters.length)c.append(card(clusters[0]));
    else{const e=node('div','di-empty');e.append(node('p','','No Cluster display added.'));
      e.append(button('+ Add Cluster',()=>openEditor({...DEFAULTS.cluster})));c.append(e);}
    const a=$('di-aux-list');a.replaceChildren();
    if(aux.length)aux.forEach(p=>a.append(card(p)));
    else a.append(node('p','di-empty','No Auxiliary displays. Add one or more AUX displays.'));
    $('di-add-aux').disabled=busy;
  }
  async function refresh(clearMessage=true){
    if(clearMessage)status('Loading Display Injection…');
    try{
      const [result,taps]=await Promise.all([request(BASE),request('/media-taps').catch(()=>({endpoints:[]}))]);
      if(!Array.isArray(result.displays))throw new Error('Missing displays list');
      state=result;media=Array.isArray(taps.endpoints)?taps.endpoints:[];
      render();loaded=true;
      if(clearMessage)status(result.requires_reconnect?'Changes require a new AA session.':'Configuration loaded.');
    }catch(e){status(`Cannot load Display Injection: ${e.message}`,true);}
  }
  async function mutate(url,method,data,success){
    if(busy)return;
    busy=true;status('Saving…');
    try{const result=await request(url,method,data);state=result;status(success||'Saved. Reconnect Android Auto to apply.');return true;}
    catch(e){status(`Save failed: ${e.message}`,true);return false;}
    finally{
      // Refresh after releasing the mutation lock. Rendering while busy=true
      // leaves Add AUX disabled until a manual Refresh (also after DELETE).
      busy=false;
      render();
    }
  }
  const form=()=> $('di-editor-form');
  const field=name=>form().elements.namedItem(name);
  const setField=(key,value)=>{field(key).value=value==null?'':String(value);};
  function choice(name,value){
    const group=form().querySelector(`[data-choice="${name}"]`);
    group.dataset.selected=value||'';
    group.querySelectorAll('[data-choice-value]').forEach(b=>{
      const pressed=b.dataset.choiceValue===value;b.setAttribute('aria-pressed',pressed?'true':'false');
    });
  }
  function setInsets(prefix,i){KEYS.forEach(k=>setField(`${prefix}.${k}`,i?.[k]));}
  function equalInsets(a,b){return KEYS.every(k=>String(a?.[k]??'')===String(b?.[k]??''));}
  function getInsets(prefix){
    const vals=Object.fromEntries(KEYS.map(k=>[k,field(`${prefix}.${k}`).value.trim()]));
    if(KEYS.every(k=>!vals[k]))return null;
    const result={};
    // Companion returns null unless all four inset values are supplied.
    if(KEYS.some(k=>!vals[k]))return null;
    for(const k of KEYS) result[k]=parseNumber(vals[k],`${prefix}.${k}`,0);
    return result;
  }
  function parseNumber(value,label,defaultValue){
    const raw=String(value).trim();
    if(raw==='')return defaultValue;
    if(!/^\d+$/.test(raw))throw new Error(`${label} must be a nonnegative integer`);
    const n=Number(raw);
    if(!Number.isSafeInteger(n) || n>2147483647)throw new Error(`${label} is out of range`);
    return n;
  }
  function showModal(id){$(id).hidden=false;document.body.classList.add('di-modal-open');}
  function closeModal(id){$(id).hidden=true;if(!document.querySelector('.di-modal-overlay:not([hidden])'))document.body.classList.remove('di-modal-open');}
  function openEditor(profile){
    active=JSON.parse(JSON.stringify(profile));showError('');
    $('di-editor-heading').textContent=(active.id?'Edit ':'Add ')+(active.display_type===CLUSTER?'Cluster': 'Auxiliary');
    const f=form();f.reset();field('enabled').checked=!!active.enabled;
    setField('name',active.name);
    choice('codec_resolution',active.codec_resolution);
    choice('frame_rate',active.frame_rate);
    choice('initial_content_keycode',active.initial_content_keycode||NAV);
    $('di-initial-content-group').hidden=active.display_type!==AUX;
    setField('width_margin',active.width_margin);
    setField('height_margin',active.height_margin);
    setInsets('content_insets',active.content_insets);setInsets('stable_content_insets',active.stable_content_insets);
    const keep=equalInsets(active.content_insets,active.stable_content_insets);
    field('stable_same').checked=keep;$('di-stable-insets').hidden=keep;
    setField('density',active.density);setField('viewing_distance',active.viewing_distance);
    setField('touch_width',active.touch_width);setField('touch_height',active.touch_height);
    field('input_touchscreen').checked=!!active.input_touchscreen;
    field('input_source').checked=active.display_type===AUX?true:!!active.input_source;
    field('input_source').disabled=active.display_type===AUX;
    $('di-input-source-hint').textContent=active.display_type===AUX?'Required for AUX':'Optional for Cluster';
    $('di-editor-save').disabled=false;
    updateVisual();showModal('di-editor-overlay');$('di-editor-x').focus();
  }
  function readEditor(){
    const f=form();
    const p={...active};
    p.enabled=field('enabled').checked;
    p.name=field('name').value.trim()||active.name;
    p.codec_resolution=f.querySelector('[data-choice="codec_resolution"]').dataset.selected;
    p.frame_rate=f.querySelector('[data-choice="frame_rate"]').dataset.selected;
    p.initial_content_keycode=p.display_type===AUX?f.querySelector('[data-choice="initial_content_keycode"]').dataset.selected||NAV:null;
    for(const key of ['width_margin','height_margin','density','viewing_distance','touch_width','touch_height']){
      p[key]=parseNumber(field(key).value,key,({density:160,viewing_distance:300,touch_width:1280,touch_height:720})[key]||0);
    }
    p.content_insets=getInsets('content_insets');
    p.stable_content_insets=field('stable_same').checked?p.content_insets:getInsets('stable_content_insets');
    p.input_touchscreen=field('input_touchscreen').checked;
    p.input_source=p.display_type===AUX?true:field('input_source').checked;
    return p;
  }
  async function submitEditor(ev){
    ev.preventDefault();if(busy||!active)return;
    let profile;
    try{profile=readEditor();}catch(e){showError(e.message);return;}
    $('di-editor-save').disabled=true;
    const existing=!!profile.id;
    const url=existing?`${BASE}/displays/${encodeURIComponent(profile.id)}`:`${BASE}/displays`;
    const ok=await mutate(url,existing?'PUT':'POST',profile,`${profile.name} saved. Reconnect Android Auto to apply.`);
    if(ok){closeModal('di-editor-overlay');active=null;}
    else $('di-editor-save').disabled=false;
  }
  function confirmRemove(profile){deleting=profile;$('di-confirm-heading').textContent=`Remove ${profile.name||profile.id}?`;
    showModal('di-confirm-overlay');}
  async function remove(){if(!deleting)return;const profile=deleting;
    const ok=await mutate(`${BASE}/displays/${encodeURIComponent(profile.id)}`,'DELETE',null,`${profile.name||profile.id} removed.`);
    if(ok){deleting=null;closeModal('di-confirm-overlay');}
  }
  function viewMedia(profile,endpoint){
    if(!endpoint)return;
    $('di-media-title').textContent=`Media tap: ${profile.name||profile.id}`;
    const data=$('di-media-details');data.replaceChildren();
    ['endpoint_id','label','kind','port','direct_port','inject_display_id'].forEach(k=>{
      data.append(node('p','',`${k}: ${endpoint[k]??'—'}`));
    });showModal('di-media-overlay');
  }
  function updateVisual(){
    // Decorative visualization only; no video decode. Scale margin/inset rulers proportionally.
    const preview=$('di-geometry-preview');if(!preview)return;
    const data=active||DEFAULTS.cluster;
    const resolution=form().querySelector('[data-choice="codec_resolution"]').dataset.selected||data.codec_resolution;
    const dims=resolution==='VIDEO_800x480'?[800,480]:resolution==='VIDEO_1920x1080'?[1920,1080]:[1280,720];
    const w=dims[0],h=dims[1];
    const inp=k=>parseInt(field(k).value,10)||0;
    const widthMargin=Math.min(inp('width_margin'),w/2),heightMargin=Math.min(inp('height_margin'),h/2);
    const l=Math.min(inp('content_insets.left'),w/2),r=Math.min(inp('content_insets.right'),w/2);
    const t=Math.min(inp('content_insets.top'),h/2),b=Math.min(inp('content_insets.bottom'),h/2);
    const safe=$('di-preview-safe');
    safe.style.left=`${(widthMargin+l)*100/w}%`;safe.style.right=`${(widthMargin+r)*100/w}%`;
    safe.style.top=`${(heightMargin+t)*100/h}%`;safe.style.bottom=`${(heightMargin+b)*100/h}%`;
    $('di-preview-label').textContent=`${w} × ${h} · ${data.display_type===CLUSTER?'Cluster':'Auxiliary'} · sample preview`;
  }
  function init(){
    if(!$('display-injection-page'))return;
    $('di-refresh').addEventListener('click',()=>refresh());
    $('di-add-aux').addEventListener('click',()=>openEditor(DEFAULTS.auxiliary(state.displays.filter(p=>p.display_type===AUX).length+1)));
    $('di-master-enable').addEventListener('change',async ev=>{
      const value=ev.target.checked;
      const ok=await mutate(BASE,'PUT',{enabled:value},'Display Injection setting saved. Reconnect Android Auto.');
      if(!ok)ev.target.checked=!value;
    });
    document.querySelectorAll('#di-editor-form [data-choice-value]').forEach(b=>b.addEventListener('click',()=>{
      choice(b.closest('[data-choice]').dataset.choice,b.dataset.choiceValue);updateVisual();
    }));
    field('stable_same').addEventListener('change',e=>{$('di-stable-insets').hidden=e.target.checked;});
    form().addEventListener('input',updateVisual);
    form().addEventListener('submit',submitEditor);
    $('di-editor-x').addEventListener('click',()=>closeModal('di-editor-overlay'));
    $('di-editor-cancel').addEventListener('click',()=>closeModal('di-editor-overlay'));
    $('di-confirm-cancel').addEventListener('click',()=>closeModal('di-confirm-overlay'));
    $('di-confirm-remove').addEventListener('click',remove);
    $('di-media-close').addEventListener('click',()=>closeModal('di-media-overlay'));
    for(const id of ['di-editor-overlay','di-confirm-overlay','di-media-overlay']){
      $(id).addEventListener('click',e=>{if(e.target===$(id))closeModal(id);});
    }
    document.addEventListener('keydown',e=>{if(e.key==='Escape'){
      for(const id of ['di-editor-overlay','di-confirm-overlay','di-media-overlay'])if(!$(id).hidden){closeModal(id);break;}
    }});
    document.addEventListener('dashboard-page',e=>{
      if(e.detail?.page==='display-injection' && !loaded)refresh();
    });
    if(window.location.hash.replace(/^#\/?/,'')==='display-injection')refresh();
  }
  document.addEventListener('DOMContentLoaded',init);
  // Read-only entry points for smoke tests and other dashboard pages.
  window.DisplayInjectionWeb={refresh,defaults:DEFAULTS};
})();
