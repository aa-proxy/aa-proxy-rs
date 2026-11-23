/* Read-only ServiceDiscoveryResponse viewer with a persisted last-capture fallback.
 * API: GET /service-discovery-response (already present in aa-proxy-rs).
 * No writes to SDR settings. No polling or new Rust endpoint.
 */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let current = null;
  let loading = false;
  const serviceTypes = {
    sensorSourceService:'Sensor Source', mediaSinkService:'Media Sink',
    inputSourceService:'Input Source', mediaSourceService:'Media Source',
    bluetoothService:'Bluetooth', radioService:'Radio',
    navigationStatusService:'Navigation Status',
    mediaPlaybackService:'Media Playback Status', phoneStatusService:'Phone Status',
    mediaBrowserService:'Media Browser', vendorExtensionService:'Vendor Extension',
    genericNotificationService:'Generic Notification', wifiProjectionService:'Wi-Fi Projection'
  };
  const labels = {
    vehicleId:'Vehicle ID', headUnitMake:'Head Unit Make',
    headUnitModel:'Head Unit Model', headUnitSoftwareBuild:'Head Unit Software Build',
    headUnitSoftwareVersion:'Head Unit Software Version',
    headunitInfo:'Head Unit Info', uiConfig:'UI Config', uiTheme:'UI Theme',
    codecResolution:'Codec Resolution', videoCodecType:'Video Codec Type',
    audioConfigs:'Audio Configurations', videoConfigs:'Video Configurations',
    displayId:'Display ID', isSecondary:'Secondary Display',
    supportedEvConnectorTypes:'Supported EV Connector Types',
    pixelAspectRatioE4:'Pixel Aspect Ratio E4',
    wifiProjectionService:'Wi-Fi Projection', carWifiBssid:'Car Wi-Fi BSSID',
    rds:'RDS', data:'Data (Base64)', id:'Service ID',
  };
  const name = key => labels[key] || key.replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/^./,c=>c.toUpperCase());
  const node = (tag,className,content) => {
    const el = document.createElement(tag);
    if (className) el.className=className;
    if (content !== undefined) el.textContent=String(content);
    return el;
  };
  const plainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
  const present = v => v !== null && v !== undefined && !(typeof v==='string' && v.trim()==='');
  const scalar = (key,value) => {
    if(typeof value === 'boolean') return value?'Yes':'No';
    if(key==='data' && typeof value === 'string' && value.length>80) return `Base64 · ${value.length} characters`;
    if(typeof value==='string' && value.length>320) return `${value.slice(0,320)}… (${value.length} chars, full value in raw JSON)`;
    if(Array.isArray(value) && value.every(v=>!plainObject(v) && !Array.isArray(v))) {
      const items=value.slice(0,24).map(String);
      return items.join(', ')+(value.length>24?` · +${value.length-24} more`:'');
    }
    return String(value);
  };
  function attributes(data, exclusions = []) {
    const dl=node('dl','sdr-info-data');
    for (const [key,value] of Object.entries(data || {})) {
      if(exclusions.includes(key) || !present(value) || plainObject(value) || (Array.isArray(value) && value.some(v=>plainObject(v)||Array.isArray(v))))continue;
      dl.append(node('dt','',name(key)),node('dd','',scalar(key,value)));
    }
    return dl;
  }
  function tree(data, parent, depth=0) {
    if(!plainObject(data) || depth>6)return;
    const attrs=attributes(data);if(attrs.children.length)parent.append(attrs);
    for(const [key,val] of Object.entries(data)) {
      if(!present(val))continue;
      if(plainObject(val)) {
        const section=node('section','sdr-info-subsection');
        section.append(node('h4','',name(key)));
        tree(val,section,depth+1);parent.append(section);
      }else if(Array.isArray(val) && val.some(v=>plainObject(v)||Array.isArray(v))) {
        const section=node('section','sdr-info-subsection');
        section.append(node('h4','',`${name(key)} (${val.length})`));
        val.forEach((item,i)=>{
          if(i>=60)return;
          const sub=node('section','sdr-info-subsection');
          sub.append(node('h4','',`${name(key).replace(/s$/,'')} #${i+1}`));
          if(plainObject(item))tree(item,sub,depth+1);
          else sub.append(node('p','',scalar(key,item)));
          section.append(sub);
        });
        if(val.length>60)section.append(node('p','',`+${val.length-60} more entries in raw JSON`));
        parent.append(section);
      }
    }
  }
  const card = title => {
    const c=node('section','sdr-info-card');c.append(node('h3','',title));return c;
  };
  function render(data) {
    const container=$('sdr-info-sections');container.replaceChildren();
    const overview=card('Vehicle / Head Unit');
    const keys=['displayName','make','model','year','vehicleId','driverPosition','headUnitMake','headUnitModel','headUnitSoftwareBuild','headUnitSoftwareVersion','canPlayNativeMediaDuringVr','sessionConfiguration','probeForSupport'];
    const view=Object.fromEntries(keys.filter(k=>present(data[k])).map(k=>[k,data[k]]));
    const attrs=attributes(view);
    if(attrs.children.length)overview.append(attrs);
    else overview.append(node('p','sdr-detail-sub','No vehicle identity fields in the last capture.'));
    container.append(overview);
    if(plainObject(data.connectionConfiguration)) {
      const c=card('Connection Configuration');tree(data.connectionConfiguration,c);container.append(c);
    }
    if(plainObject(data.headunitInfo)) {
      const c=card('Head Unit Info');tree(data.headunitInfo,c);container.append(c);
    }
    const services=Array.isArray(data.services)?data.services:[];
    const c=card(`Services (${services.length})`);
    if(!services.length)c.append(node('p','sdr-detail-sub','No services in this response.'));
    for(const [index,service] of services.entries()) {
      const types=Object.entries(serviceTypes).filter(([key])=>plainObject(service?.[key]));
      const title=`${index+1}. ${types.map(([,v])=>v).join(' + ') || 'Unknown Service'}${present(service?.id)?` · ID ${service.id}`:''}`;
      const details=node('details','sdr-info-service');
      const summary=node('summary','',title);details.append(summary);
      if(types.length)for(const [key,label] of types) {
        const section=node('section','sdr-info-subsection');section.append(node('h4','',label));
        tree(service[key],section);details.append(section);
      }
      else tree(service,details);
      c.append(details);
    }
    container.append(c);
    $('sdr-info-raw').textContent=JSON.stringify(data,null,2);
    $('sdr-info-actions').hidden=false;
    $('sdr-info-raw-panel').hidden=false;
  }
  async function load() {
    if(loading)return;
    loading=true;const button=$('sdr-info-refresh');button.disabled=true;
    const status=$('sdr-info-status');status.classList.remove('is-error');
    status.textContent='Loading ServiceDiscoveryResponse…';
    try {
      const res=await fetch('/service-discovery-response',{cache:'no-store'});
      if(res.status===404)throw new Error('No ServiceDiscoveryResponse captured. Connect Android Auto with MITM enabled, then refresh.');
      if(!res.ok)throw new Error(`HTTP ${res.status}`);
      const data=await res.json();
      if(!plainObject(data))throw new Error('Unexpected SDR response format');
      current=data;render(data);
      const source=res.headers.get('x-sdr-source');
      const sourceLabel=source==='disk'?'Last saved SDR (from disk)':'Last captured SDR';
      status.textContent=`${sourceLabel} · ${Array.isArray(data.services)?data.services.length:0} service(s)`;
    }catch(e){
      status.textContent=`SDR Info unavailable: ${e.message}`;
      status.classList.add('is-error');
      if(!current){$('sdr-info-actions').hidden=true;$('sdr-info-raw-panel').hidden=true;$('sdr-info-sections').replaceChildren();}
    }finally{loading=false;button.disabled=false;}
  }
  async function copyJson() {
    if(!current)return;
    const json=JSON.stringify(current,null,2);
    const status=$('sdr-info-status');
    try{
      if(navigator.clipboard && window.isSecureContext)await navigator.clipboard.writeText(json);
      else{
        const ta=node('textarea');ta.value=json;ta.style.position='fixed';ta.style.left='-99999px';document.body.append(ta);ta.select();
        const ok=document.execCommand('copy');ta.remove();if(!ok)throw new Error('Clipboard unavailable');
      }
      status.textContent='SDR JSON copied.';
    }catch(e){status.textContent=`Copy failed: ${e.message}. Use Save JSON instead.`;status.classList.add('is-error');}
  }
  function downloadJson() {
    if(!current)return;
    const blob=new Blob([JSON.stringify(current,null,2)],{type:'application/json'});
    const url=URL.createObjectURL(blob);
    const anchor=node('a');anchor.href=url;anchor.download='service-discovery-response.json';document.body.append(anchor);anchor.click();anchor.remove();
    // The download is initiated synchronously. Revoke later, not before it starts.
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  function init() {
    if(!$('sdr-info-page'))return;
    $('sdr-info-refresh').addEventListener('click',load);
    $('sdr-info-copy').addEventListener('click',copyJson);
    $('sdr-info-download').addEventListener('click',downloadJson);
    document.addEventListener('dashboard-page', e=>{if(e.detail?.page==='sdr-info')load();});
    if(window.location.hash.includes('sdr-info'))load();
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);
  else init();
})();
