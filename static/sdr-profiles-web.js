/* SDR UI Profiles: web parity with Companion's Global / File / Vehicle / Phone view.
 * All writes use existing /sdr-ui/profiles/:vehicle_id endpoints. No new server API.
 */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const edges = ['top', 'bottom', 'left', 'right'];
  const insetTypes = [
    ['margins', 'Margins'],
    ['content_insets', 'Content insets'],
    ['stable_content_insets', 'Stable content insets']
  ];
  const state = { current: null, file: null, vehicle: null, vehicleId: null, phoneId: null, busy: false };
  const clone = obj => JSON.parse(JSON.stringify(obj));
  const text = (value, fallback='Unknown') => typeof value === 'string' && value.trim() ? value : fallback;
  function element(tag, className, value) {
    const el = document.createElement(tag);
    if(className) el.className = className;
    if(value !== undefined) el.textContent = value;
    return el;
  }
  function button(label, callback, className) {
    const el=element('button',className,label);el.type='button';el.addEventListener('click',callback);return el;
  }
  function chip(name, flag) {
    const el=element('span','sdr-status-chip',`${flag === null ? '○' : flag ? '✓' : '–'} ${name}`);
    el.dataset.state=flag === null ? 'unknown' : flag ? 'yes' : 'no';
    return el;
  }
  async function request(path, options) {
    const res=await fetch(path, {...options,cache:'no-store'});
    const raw=await res.text();
    let data=null;
    try {data=raw ? JSON.parse(raw) : null;}catch(_){/* error text from backend */}
    if (!res.ok) throw new Error(data?.message || raw.slice(0,200) || `HTTP ${res.status}`);
    return data;
  }
  function feedback(message, fail=false) {
    const el=$('sdr-detail-message');
    if(el){el.textContent=message;el.style.color=fail?'#ff8993':'#8de0d2';}
    if (typeof window.showSnackbar === 'function') window.showSnackbar(message,fail?'error':'success');
  }
  function currentSummary() {
    const c=state.current, f=state.file;
    const identity=$('sdr-identity'), chips=$('sdr-status-chips'), location=$('sdr-profile-path'), captured=$('sdr-status-captured');
    if(!identity||!chips||!location||!captured)return;
    identity.replaceChildren();chips.replaceChildren();
    if(c){
      captured.textContent=`Captured ${text(c.detected_at,'recently')}`;
      identity.textContent=`${text(c.vehicle_name,c.vehicle_id)} · Phone: ${text(c.phone?.name)} · ${c.patch_applied ? `Patch applied (${c.patch_count || 0})` : 'No patch applied'}`;
    }else{
      captured.textContent='No captured ServiceDiscoveryResponse';
      identity.textContent='Current SDR capture is unavailable. Saved profiles can still be edited below.';
    }
    chips.append(
      chip('Global',c ? !!c.global_enabled : null),
      chip('File',c ? !!c.file_enabled : (f ? !!f.profiles?.enabled : null)),
      chip('Vehicle',c ? !!c.vehicle_profile_enabled : null),
      chip('Phone',c ? !!c.phone_profile_enabled : null)
    );
    location.textContent=`Profile file: ${c?.profile_file || f?.profile_file || '(not available)'}`;
  }
  async function refreshStatus() {
    try {state.current=await request('/sdr-ui/current');}
    catch(e){state.current=null;}
    currentSummary();
  }
  function onListLoaded(response) {state.file=response;currentSummary();}
  async function open(vehicleId) {
    if(!vehicleId || state.busy)return;
    state.vehicleId=vehicleId;
    state.phoneId=null;
    const panel=$('sdr-profile-detail');
    panel.hidden=false;panel.textContent='Loading vehicle profile…';
    try {
      state.vehicle=await request(`/sdr-ui/profiles/${encodeURIComponent(vehicleId)}`);
      draw();
      panel.scrollIntoView({behavior:'smooth',block:'nearest'});
    }catch(e){panel.textContent=`Could not load vehicle profile: ${e.message}`;}
  }
  function close() {state.vehicleId=null;state.vehicle=null;state.phoneId=null;$('sdr-profile-detail').hidden=true;}
  async function refreshProfile() {
    if(!state.vehicleId)return;
    state.vehicle=await request(`/sdr-ui/profiles/${encodeURIComponent(state.vehicleId)}`);
    if(state.phoneId&&!state.vehicle.phones?.some(p=>p.id===state.phoneId))state.phoneId=null;
    draw();
    // Refresh the existing installed profiles view without reloading the page.
    $('sdr-refresh-profiles')?.click();
  }
  async function updateProfile(mutator) {
    if(state.busy||!state.vehicleId)return;
    state.busy=true;
    try{
      // Always re-read to avoid overwriting edits made in another page/tab.
      const fresh=await request(`/sdr-ui/profiles/${encodeURIComponent(state.vehicleId)}`);
      const updated=clone(fresh);
      mutator(updated);
      const result=await request(`/sdr-ui/profiles/${encodeURIComponent(state.vehicleId)}`,{
        method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(updated)
      });
      state.vehicle=result.profile || updated;
      feedback('Profile saved. SDR geometry normally applies on the next Android Auto connection.');
      draw();$('sdr-refresh-profiles')?.click();
    }catch(e){feedback(`Save failed: ${e.message}`,true);}
    finally{state.busy=false;}
  }
  function switchRow(title, detail, checked, handler) {
    const row=element('label','sdr-scope-switch');
    const content=element('span');
    content.append(element('strong','',title),element('small','sdr-detail-sub',detail));
    const toggle=document.createElement('input');toggle.type='checkbox';toggle.checked=!!checked;
    toggle.setAttribute('aria-label',title);
    toggle.addEventListener('change',()=>handler(toggle.checked));
    row.append(content,toggle);return row;
  }
  function showInfo(vehicle) {
    const inf=vehicle.info||{};
    const entries=[['Make',inf.make],['Model',inf.model],['Year',inf.year],['Display',inf.display_name],
       ['Head unit',[inf.head_unit_make,inf.head_unit_model].filter(Boolean).join(' ')],['Software',inf.head_unit_software_version],['Driver position',inf.driver_position]];
    const found=entries.filter(([,v])=>v);
    if(!found.length)return element('div','sdr-detail-sub','No vehicle identity metadata supplied.');
    const p=element('p','sdr-detail-sub',found.map(([k,v])=>`${k}: ${v}`).join(' · '));return p;
  }
  function draw() {
    const panel=$('sdr-profile-detail'), v=state.vehicle;
    if(!v||!panel)return;
    panel.replaceChildren();
    const head=element('div','sdr-detail-head');
    const group=element('div');
    group.append(element('h3','',`Vehicle: ${text(v.name,v.id)}`), element('div','sdr-detail-sub',v.id||''));
    head.append(group,button('Close editor',close,'secondary'));panel.append(head);
    panel.append(showInfo(v));
    const current=state.current?.vehicle_id===v.id ? state.current : null;
    if(current)panel.append(element('div','sdr-detail-note',`Current connection: ${current.patch_applied?'patch applied':'patch not applied'} · ${current.patch_count||0} modifications`));
    panel.append(switchRow('Vehicle profile',v.enabled?'Applied to all phones unless a phone override takes priority':'Saved, but vehicle override is disabled',v.enabled,
      checked=>updateProfile(p=>{p.enabled=checked;})));
    const phones=Array.isArray(v.phones)?v.phones:[];
    panel.append(element('h4','','Edit target'));
    panel.append(element('p','sdr-detail-sub','Choose vehicle defaults or a specific phone. Settings are saved to that target only.'));
    const targets=element('div','sdr-targets');
    const vehicleTarget=button('Vehicle default',()=>{state.phoneId=null;draw();});
    vehicleTarget.setAttribute('aria-pressed',String(state.phoneId===null));targets.append(vehicleTarget);
    for(const p of phones){
      const target=button(`📱 ${text(p.name,p.id)}`,()=>{state.phoneId=p.id;draw();});
      target.setAttribute('aria-pressed',String(state.phoneId===p.id));targets.append(target);
    }
    panel.append(targets);
    const phone=phones.find(p=>p.id===state.phoneId);
    if(phone){
      const hint=phone.info?.bt_mac_masked || 'Phone override';
      panel.append(switchRow(`Phone: ${text(phone.name,phone.id)}`,hint,phone.enabled,
        checked=>updateProfile(p=>{const target=p.phones?.find(x=>x.id===phone.id);if(target)target.enabled=checked;})));
      if(!(phone.displays?.length)){
        const section=element('div','sdr-detail-note','This phone has no display override yet.');
        section.append(button('Copy vehicle values to phone',()=>updateProfile(p=>{
          const target=p.phones?.find(x=>x.id===phone.id);
          if(!target || target.displays?.length)return;
          target.displays=clone(p.displays||[]);target.enabled=true;
        })));
        panel.append(section);
      }
    }
    const displays=(phone || v).displays||[];
    panel.append(element('h4','',`Displays (${displays.length})`));
    if(!displays.length)panel.append(element('p','sdr-detail-sub','No video configurations for this target. Capture SDR first, or copy vehicle values into this phone override.'));
    const list=element('div','sdr-video-list');
    displays.forEach((d, di)=>{
      const videos=Array.isArray(d.video_configs)?d.video_configs:[];
      videos.forEach((cfg,vi)=>{
        const card=element('div','sdr-video-row');
        const meta=element('div');meta.append(element('strong','',`${text(d.display_type,'Display')} · ${text(cfg.codec_resolution,'Video')}`));
        const formatted=insetTypes.map(([key,title])=>{
          const i=cfg[key]||{};
          return `${title}: L ${i.left??0} · R ${i.right??0} · T ${i.top??0} · B ${i.bottom??0}`;
        });
        meta.append(element('small','',`Display ID ${d.display_id??'?'} · ${cfg.enabled!==false?'Enabled':'Disabled'} · Density ${cfg.density??'default'} / ${cfg.real_density??'default'}`));
        for(const line of formatted)meta.append(element('small','',line));
        card.append(meta,button('Edit geometry',()=>editVideo(di,vi),'secondary'));list.append(card);
      });
    });
    panel.append(list);
    panel.append(element('p','sdr-detail-note','Each save updates the selected vehicle profile through PUT /sdr-ui/profiles/:vehicle_id. Global and File flags are displayed above, but configured separately. Changes to handshake layout normally require reconnecting the phone.'));
    const status=element('div','', '');status.id='sdr-detail-message';status.setAttribute('role','status');panel.append(status);
  }
  function parseSize(value) {
    const m=/(\d+)x(\d+)/.exec(value||'');
    return m ? {width:Number(m[1]),height:Number(m[2])} : {width:1920,height:1080};
  }
  function numberInput(name,value,max,allowNull=false) {
    const label=document.createElement('label');label.textContent=name;
    const input=document.createElement('input');input.type='number';input.inputMode='numeric';
    input.min='0';input.max=String(max);input.step='1';input.value=value==null?'':String(value);
    input.dataset.optional=String(allowNull);label.append(input);return [label,input];
  }
  function editVideo(displayIndex,videoIndex) {
    const v=state.vehicle;
    const phone=(v.phones||[]).find(p=>p.id===state.phoneId);
    const config=(phone||v).displays?.[displayIndex]?.video_configs?.[videoIndex];
    if(!config)return;
    const dlg=$('sdr-video-edit-dialog');dlg.replaceChildren();
    const size=parseSize(config.codec_resolution);
    const head=element('h3','',`${text(config.codec_resolution,'Video')} · Geometry`);
    dlg.append(head,element('p','sdr-detail-sub','Edit only the values you need. Existing unknown fields are preserved.'));
    const enabled=switchRow('Apply this video config','Disabled configurations are ignored.',config.enabled!==false,()=>{});
    // This toggle is included in the dialog's Save action (not saved immediately).
    dlg.append(enabled);
    const fields={}, inputMap={};
    const diagram=element('div','sdr-diagram');const safe=element('div','safe');diagram.append(safe);dlg.append(diagram);
    const syncDiagram=()=>{
      const group=fields.margins||{};
      const px=edge=>Math.max(0,Number(group[edge]?.value)||0);
      safe.style.top=`${Math.min(48,px('top')/size.height*100)}%`;
      safe.style.bottom=`${Math.min(48,px('bottom')/size.height*100)}%`;
      safe.style.left=`${Math.min(48,px('left')/size.width*100)}%`;
      safe.style.right=`${Math.min(48,px('right')/size.width*100)}%`;
    };
    const groups={};
    for(const [key,title] of insetTypes){
      const fieldset=document.createElement('fieldset');const legend=document.createElement('legend');legend.textContent=title;fieldset.append(legend);
      const grid=element('div','sdr-form-grid'), originals=config[key]||{};
      const inputs={};
      for(const edge of edges){
        const max=['left','right'].includes(edge)?Math.max(0,size.width):Math.max(0,size.height);
        const [lbl,input]=numberInput(edge[0].toUpperCase()+edge.slice(1),originals[edge],max,true);
        input.addEventListener('input',syncDiagram);
        inputs[edge]=input;grid.append(lbl);
      }
      fields[key]=inputs;groups[key]=fieldset;fieldset.append(grid);dlg.append(fieldset);
    }
    const stableRow=element('label','sdr-scope-switch');
    const stableCheck=document.createElement('input');stableCheck.type='checkbox';
    const same=(a,b)=>edges.every(e=>(a?.[e]??0)===(b?.[e]??0));
    stableCheck.checked=same(config.stable_content_insets,config.content_insets);
    stableCheck.addEventListener('change',()=>{groups.stable_content_insets.hidden=stableCheck.checked;});
    stableRow.append(element('span','', 'Keep stable insets same as content'),stableCheck);
    dlg.insertBefore(stableRow,groups.stable_content_insets);
    groups.stable_content_insets.hidden=stableCheck.checked;
    const adv=document.createElement('fieldset');const legend=document.createElement('legend');legend.textContent='Advanced scaling';adv.append(legend);
    const grid=element('div','sdr-form-grid');
    for(const [key,label] of [['density','Density'],['real_density','Real density']]){
      const [lbl,input]=numberInput(label,config[key],65535,true);inputMap[key]=input;grid.append(lbl);
    }
    adv.append(grid);dlg.append(adv);
    const actions=element('div','sdr-dialog-actions');
    const cancel=button('Cancel',()=>dlg.close(),'secondary');
    const save=button('Save video config',async ()=>{
      const invalid=[];
      const parse=(input,label)=>{
        const raw=input.value.trim();if(!raw)return null;
        const n=Number(raw),max=Number(input.max);
        if(!Number.isSafeInteger(n)||n<0||n>max){invalid.push(`${label} must be 0–${max}`);return null;}
        return n;
      };
      const result=clone(config);
      const activeEnabled=enabled.querySelector('input[type=checkbox]');
      result.enabled=activeEnabled.checked;
      for(const [key,title] of insetTypes){
        const next={...(config[key]||{})};
        for(const edge of edges){
          const n=parse(fields[key][edge],`${title} ${edge}`);
          if(n===null)delete next[edge];else next[edge]=n;
        }
        result[key]=Object.keys(next).length?next:null;
      }
      if(stableCheck.checked)result.stable_content_insets=clone(result.content_insets);
      for(const key of ['density','real_density'])result[key]=parse(inputMap[key],key);
      if(invalid.length){feedback(invalid.join('; '),true);return;}
      save.disabled=true;
      dlg.close();
      await updateProfile(profile=>{
        const target=state.phoneId?(profile.phones||[]).find(p=>p.id===state.phoneId):profile;
        const video=target?.displays?.[displayIndex]?.video_configs?.[videoIndex];
        if(!video)throw new Error('This video config changed; reload the profile before saving.');
        Object.assign(video,result);
      });
    });
    actions.append(cancel,save);dlg.append(actions);
    dlg.addEventListener('click', e=>{if(e.target===dlg)dlg.close();},{once:true});
    syncDiagram();dlg.showModal();
  }
  function init() {
    const dlg=$('sdr-video-edit-dialog');if(!dlg)return;
    $('sdr-refresh-current')?.addEventListener('click',refreshStatus);
    document.addEventListener('dashboard-page',e=>{if(e.detail?.page==='sdr-ui')refreshStatus();});
    if(location.hash.includes('sdr-ui'))refreshStatus();
  }
  window.SdrProfilesWeb={refreshStatus,onListLoaded,open,close};
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);
  else init();
})();
