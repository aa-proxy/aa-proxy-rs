(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const IDENT = /^[a-z0-9_-]{1,48}$/;
  const MAX_FIELDS = 32;
  let fields = [], observed = new Map(), lastGenerated = '';
  let lastPreviewStates = ''; // redraw only when the freshness badge changes
  const sampleField = (kind = 'api', label = 'New field', source = 'custom', key = 'value', sample = '', unit = '', fallback = '—') => ({
    kind, label, source, key, sample, unit, fallback, decimals: '0', color: '#bfeff4'
  });
  // Empty by default: never suggest that mock telemetry is real live data.
  // Users opt into explicit example values with 'Load OBD example'.
  fields = [];

  // The preview-only values are never interpreted as markup. Overlay editor
  // inserts them using textContent/TextNodes, so external telemetry cannot inject HTML.
  const dataKey = field => field.kind === 'api'
    ? `ws.overlay.${field.source}.${field.key}`
    : `ws.${field.source}.${field.key}`;
  function fieldState(field) {
    if (field.kind === 'static') return {kind:'static', text:'STATIC TEXT'};
    if (field.kind === 'legacy') return field.sample.trim()
      ? {kind:'sample', text:'SAMPLE · preview only'}
      : {kind:'waiting', text:'EXISTING WS · not monitored'};
    const entry = observed.get(dataKey(field));
    if (entry) return Date.now() < entry.expiresAt
      ? {kind:'live', text:'LIVE · last refresh'}
      : {kind:'stale', text:'STALE · fallback shown'};
    return field.sample.trim()
      ? {kind:'sample', text:'SAMPLE · preview only'}
      : {kind:'waiting', text:'WAITING FOR LIVE DATA'};
  }
  window.aaOverlayDynamic = {
    previewValue(name) {
      const entry = observed.get(name);
      if (entry) return Date.now() < entry.expiresAt ? entry.value : undefined;
      for (const field of fields) {
        if (field.kind === 'static') continue;
        if (dataKey(field) === name && field.sample.trim() !== '') return field.sample;
      }
      return undefined;
    }
  };
  function refreshFieldStatuses() {
    const states = fields.map(f => fieldState(f));
    const fingerprint = states.map(s => s.kind).join('|');
    document.querySelectorAll('#dynamic-fields [data-field-status]').forEach((node,i) => {
      if (!states[i]) return;
      node.textContent = states[i].text;
      node.dataset.state = states[i].kind;
    });
    if (fingerprint !== lastPreviewStates) {
      lastPreviewStates = fingerprint;
      document.dispatchEvent(new Event('overlay-dynamic-preview'));
    }
  }

  function status(message, error = false) {
    const el = $('dynamic-validation');
    el.textContent = message;
    el.classList.toggle('is-error', error);
  }
  function dataStatus(message, error = false) {
    const el = $('dynamic-data-status');
    el.textContent = message;
    el.classList.toggle('is-error', error);
  }
  function tag(name, attrs, value) {
    const node = document.createElement(name);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    if (value !== undefined) node.textContent = String(value);
    return node;
  }
  function fieldInput(field, name, type = 'text', options = null) {
    const outer = tag('label', {}, name === 'kind' ? 'Type' : ({label:'Label',source:'Source ID',key:'Field key',sample:'Test value (optional)',unit:'Unit / suffix',fallback:'Fallback',decimals:'Decimals',color:'Color'}[name] || name));
    let node;
    if (options) {
      node = tag('select');
      for (const [value, title] of options) {
        const option = tag('option', {value}, title);
        node.appendChild(option);
      }
      node.value = field[name];
    } else {
      const attrs = {type, autocomplete:'off'};
      if (name === 'color') attrs.type = 'color';
      if (name === 'source' || name === 'key') attrs.maxlength = '48';
      if (name === 'label') attrs.maxlength = '80';
      if (name === 'fallback' || name === 'unit') attrs.maxlength = '80';
      if (name === 'sample') { attrs.maxlength = '256'; attrs.placeholder = 'Blank = no sample data'; }
      if (name === 'decimals') { attrs.type = 'number'; attrs.min = '0'; attrs.max = '6'; }
      node = tag('input', attrs);
      node.value = field[name];
    }
    if (name === 'source' || name === 'key') outer.classList.add('dynamic-source-only');
    node.addEventListener('input', () => {
      field[name] = node.value;
      // Do not re-render an input while editing (preserves the cursor and empty value).
      updateExamples();
      if (name === 'sample' || name === 'source' || name === 'key') { refreshFieldStatuses(); document.dispatchEvent(new Event('overlay-dynamic-preview')); }
    });
    if (name === 'kind') node.addEventListener('change', () => {
      field.kind = node.value;
      renderFields();
      updateExamples();
    });
    outer.appendChild(node);
    return outer;
  }
  function renderFields() {
    const host = $('dynamic-fields');
    host.replaceChildren();
    fields.forEach((field, i) => {
      const card = tag('article', {class:'dynamic-field'});
      if (field.kind === 'static') card.classList.add('is-static');
      const head = tag('div', {class:'dynamic-field-head'});
      head.append(tag('strong', {}, `Field ${i + 1}`));
      const actions = tag('div', {class:'tool-actions'});
      const buttons = [['↑','Move up', i > 0, -1], ['↓','Move down', i < fields.length - 1, 1]];
      for (const [txt, hint, enabled, direction] of buttons) {
        const button = tag('button', {type:'button',class:'secondary outline',title:hint,'aria-label':hint}, txt);
        button.disabled = !enabled;
        button.addEventListener('click', () => {
          const target = i + direction;
          [fields[i], fields[target]] = [fields[target], fields[i]];
          renderFields(); updateExamples();
        });
        actions.append(button);
      }
      const remove = tag('button', {type:'button',class:'secondary outline',title:'Remove field','aria-label':'Remove field'}, '×');
      remove.addEventListener('click', () => { fields.splice(i, 1); renderFields(); updateExamples(); });
      actions.append(remove);
      head.append(tag('span', {class:'dynamic-field-status', 'data-field-status':'', 'aria-label':'Preview data status'}, 'WAITING FOR LIVE DATA'));
      head.append(actions);
      const grid = tag('div',{class:'dynamic-field-grid'});
      grid.append(
        fieldInput(field,'kind','text',[['api','Dynamic REST / WS'],['legacy','Existing WS topic'],['static','Static text']]),
        fieldInput(field,'label'), fieldInput(field,'source'), fieldInput(field,'key'),
        fieldInput(field,'sample'), fieldInput(field,'decimals'), fieldInput(field,'unit'),
        fieldInput(field,'fallback'), fieldInput(field,'color')
      );
      card.append(head,grid);
      card.append(tag('small', {class:'dynamic-field-hint'}, 'Test value is optional and only used locally for preview or Send example. It is not a default live value.'));
      host.append(card);
    });
    if (!fields.length) host.append(tag('p',{class:'tool-footnote'},'No fields added yet. Select Add field to start blank, or Load OBD example for explicitly marked sample values.'));
    lastPreviewStates = '';
    refreshFieldStatuses();
  }
  const escapeMarkup = value => String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  function layoutText() {
    if (!fields.length) throw new Error('Add at least one field.');
    const lines = fields.map((field, index) => {
      const label = field.label.trim();
      if (!label || label.length > 80) throw new Error(`Field ${index + 1}: label is required (max 80 chars).`);
      if (!/^#[0-9a-fA-F]{6}$/.test(field.color)) throw new Error(`Field ${index + 1}: invalid color.`);
      let variable;
      if (field.kind === 'static') variable = escapeMarkup(field.sample);
      else {
        if (!IDENT.test(field.source) || !IDENT.test(field.key)) throw new Error(`Field ${index + 1}: source and key must be lowercase letters, digits, _ or - (1–48 chars).`);
        const decimals = Number(field.decimals);
        if (!Number.isInteger(decimals) || decimals < 0 || decimals > 6) throw new Error(`Field ${index + 1}: decimals must be 0–6.`);
        const key = field.kind === 'api' ? `ws.overlay.${field.source}.${field.key}` : `ws.${field.source}.${field.key}`;
        // Fallback cannot contain `}}` or `|`, because they are template separators.
        const fallback = field.fallback.trim();
        if (fallback.includes('}}') || fallback.includes('|') || fallback.includes('<')) throw new Error(`Field ${index + 1}: fallback contains unsupported characters.`);
        variable = `{{${key}:${decimals} | ${fallback || '—'}}}`;
      }
      const line = `${escapeMarkup(label)}: ${variable}${escapeMarkup(field.unit)}`;
      return `<font color="${field.color}">${line}</font>`;
    });
    const result = lines.join('\n');
    if (new TextEncoder().encode(result).length > 8192) throw new Error('Generated text exceeds the 8192-byte overlay limit.');
    return result;
  }
  // Example snippets use JSON null as an explicit placeholder when a field
  // has no user-supplied test value. The Send test button never sends blanks.
  function batches(includeEmpty = false) {
    const sources = new Map();
    for (const field of fields) {
      if (field.kind !== 'api' || !IDENT.test(field.source) || !IDENT.test(field.key)) continue;
      const raw = field.sample.trim();
      if (!includeEmpty && raw === '') continue;
      if (!sources.has(field.source)) sources.set(field.source, {});
      const n = Number(raw);
      sources.get(field.source)[field.key] = raw === '' ? null : Number.isFinite(n) ? n : raw;
    }
    return [...sources].map(([source, values]) => ({source, values, ttl_ms: readTtl()}));
  }
  function readTtl() {
    const n = Number($('dynamic-ttl').value);
    return Number.isInteger(n) && n >= 250 && n <= 60000 ? n : 3000;
  }
  // Quote arbitrary JSON safely for POSIX shells (including apostrophes).
  const shellQuote = text => "'" + text.replace(/'/g, "'\\''") + "'";
  function snippets() {
    const batch = batches(true);
    if (!batch.length) return {rest:'# Add a Dynamic REST/WS field first.', ws:'// Add a Dynamic REST/WS field first.'};
    const rest = '# EXAMPLE: replace null with real sensor values before sending.\n# Fields omitted from future requests keep their own TTL.\n' + batch.map(b => `curl -X POST 'http://DEVICE_IP/overlay/data' \\\n  -H 'Content-Type: application/json' \\\n  -H 'Authorization: Bearer YOUR_TOKEN' \\\n  -d ${shellQuote(JSON.stringify(b))}`).join('\n\n');
    const ws = `// EXAMPLE: replace null with real sensor values before sending.\n// Partial updates merge; each field has its own TTL.\nconst socket = new WebSocket('ws://DEVICE_IP/ws/overlay');\nsocket.addEventListener('message', ({data}) => {\n  const message = JSON.parse(data);\n  if (message.type === 'authenticated') {\n${batch.map(b => `    socket.send(JSON.stringify({type:'update', ...${JSON.stringify(b)}}));`).join('\n')}\n  }\n});\nsocket.addEventListener('open', () => {\n  socket.send(JSON.stringify({type:'auth',token:'YOUR_TOKEN'}));\n});`;
    return {rest,ws};
  }
  function updateExamples() {
    const {rest,ws} = snippets();
    $('dynamic-rest-example').textContent = rest;
    $('dynamic-ws-example').textContent = ws;
  }
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
      else {
        const ta = tag('textarea',{readonly:'readonly'});
        ta.value = text; ta.style.position = 'fixed';ta.style.left = '-9999px';
        document.body.append(ta);ta.select();
        if (!document.execCommand('copy')) throw new Error('Clipboard is unavailable');
        ta.remove();
      }
      status('Example copied. Replace DEVICE_IP and YOUR_TOKEN with your values.');
    } catch (err) { status(`Copy failed: ${err.message}. Select the example to copy manually.`,true); }
  }
  async function sendSample() {
    const token = $('dynamic-token').value;
    if (token.length < 16) return dataStatus('Enter the configured OVERLAY_DATA_TOKEN first.',true);
    const batch = batches();
    if (!batch.length) return dataStatus('Enter at least one explicit Test value first. Blank values are never sent.',true);
    dataStatus(`Sending ${batch.length} source(s)…`);
    try {
      for (const message of batch) {
        const res = await fetch('/overlay/data', {
          method:'POST', cache:'no-store',
          headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'},
          body:JSON.stringify(message)
        });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
      }
      dataStatus('REST test accepted. Values expire after the configured TTL.');
      await refreshData();
    } catch (err) { dataStatus(`Data API: ${err.message}`,true); }
  }
  async function refreshData() {
    const token = $('dynamic-token').value;
    if (token.length < 16) return dataStatus('Enter the configured OVERLAY_DATA_TOKEN first.',true);
    try {
      const res = await fetch('/overlay/data', {cache:'no-store',headers:{'Authorization':`Bearer ${token}`}});
      if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
      const data = await res.json();
      observed = new Map();
      const summary = [];
      const time = Date.now();
      for (const entry of data.sources || []) {
        const statuses = entry.fields || {};
        const active = Object.entries(entry.values || {});
        const freshCount = active.length;
        summary.push(`${entry.source}: ${freshCount} live field(s)${Object.keys(statuses).length > freshCount ? ', some stale' : ''}`);
        for (const [key, meta] of Object.entries(statuses)) {
          const remaining = Math.max(0, Number(meta.ttl_ms) - Number(meta.age_ms));
          observed.set(`ws.overlay.${entry.source}.${key}`, {
            value: (entry.values || {})[key],
            expiresAt: meta.fresh ? time + remaining : 0
          });
        }
        // Read older V9 servers gracefully (without per-field status).
        if (!Object.keys(statuses).length && entry.fresh) {
          for (const [key,value] of active) {
            observed.set(`ws.overlay.${entry.source}.${key}`, {
              value, expiresAt: time + Math.max(0, Number(entry.ttl_ms) - Number(entry.age_ms))
            });
          }
        }
      }
      dataStatus(summary.length ? summary.join(' · ') : 'No dynamic sources received yet.');
      refreshFieldStatuses();
      document.dispatchEvent(new Event('overlay-dynamic-preview'));
    } catch(err) {dataStatus(`Data API: ${err.message}`,true);}
  }
  // Reconstruct Builder rows from the normal saved overlay text, without
  // adding unknown keys to the legacy JSON schema. Hand-authored texts are
  // left intact and are never overwritten automatically.
  function restoreGeneratedLayout(text) {
    const lines = String(text || '').trim().split(/\r?\n/).filter(Boolean);
    if (!lines.length || lines.length > MAX_FIELDS) return;
    const parsed = [];
    const decode = value => value.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
    for (const line of lines) {
      const outer = line.match(/^<font color="(#[0-9a-fA-F]{6})">([^<>]*?)<\/font>$/);
      if (!outer) return;
      const color = outer[1];
      const separator = outer[2].indexOf(': ');
      if (separator < 1) return;
      const label = decode(outer[2].slice(0,separator));
      const content = outer[2].slice(separator+2);
      const dynamic = content.match(/^\{\{ws\.(overlay\.)?([a-z0-9_-]+)\.([a-z0-9_-]+):([0-6]) \| ([^{}|<>]*)\}\}([^<>]*)$/);
      if (dynamic) {
        const [,overlayPrefix,source,key,decimals,fallback,unit] = dynamic;
        parsed.push({kind:overlayPrefix ? 'api' : 'legacy',label,source,key,decimals,fallback,unit:decode(unit),sample:'',color});
      } else {
        parsed.push({kind:'static',label,source:'custom',key:'value',decimals:'0',fallback:'—',unit:'',sample:decode(content),color});
      }
    }
    fields = parsed;
    lastGenerated = text;
    renderFields(); updateExamples();
    status(`Restored ${fields.length} editable dynamic field(s) from overlay.json.`);
  }
  document.addEventListener('overlay-config-loaded', e => restoreGeneratedLayout(e.detail.text));
  document.addEventListener('DOMContentLoaded', () => {
    renderFields(); updateExamples();
    $('dynamic-help-open').addEventListener('click', () => {
      const dialog = $('dynamic-help-dialog');
      if (typeof dialog.showModal === 'function') dialog.showModal();
      else dialog.setAttribute('open', '');
    });
    $('dynamic-help-close').addEventListener('click', () => {
      const dialog = $('dynamic-help-dialog');
      if (typeof dialog.close === 'function') dialog.close();
      else dialog.removeAttribute('open');
    });
    $('dynamic-help-dialog').addEventListener('click', event => {
      if (event.target === $('dynamic-help-dialog')) $('dynamic-help-close').click();
    });
    window.setInterval(refreshFieldStatuses, 1000);
    $('dynamic-add-field').addEventListener('click', () => {
      if (fields.length >= MAX_FIELDS) return status('Maximum 32 fields per layout.',true);
      fields.push(sampleField('api', 'New value', 'custom', `field_${fields.length+1}`, ''));
      renderFields();updateExamples();
    });
    $('dynamic-example-fields').addEventListener('click', () => {
      if (fields.length && !confirm('Replace the current Builder rows? This will not modify the saved overlay.')) return;
      fields = [
        sampleField('api','RPM','obd','rpm','2500',' rpm'),
        sampleField('api','Coolant','obd','coolant_temp_c','86',' °C'),
        sampleField('api','Fuel','obd','fuel_level_pct','68',' %')
      ];
      renderFields(); updateExamples(); status('OBD sample fields loaded locally. Generate text to preview.');
    });
    $('dynamic-generate').addEventListener('click', () => {
      try {
        const value = layoutText();
        const input = $('overlay-text');
        if (input.value.trim() && input.value !== lastGenerated && !confirm('Replace the current overlay text? Existing layout changes will be kept in the editor until Save.')) return;
        input.value = value;
        lastGenerated = value;
        input.dispatchEvent(new Event('input',{bubbles:true}));
        status('Layout generated locally. Review the preview, then select Save overlay to write overlay.json.');
      } catch(err) {status(err.message,true);}
    });
    $('dynamic-test').addEventListener('click',sendSample);
    $('dynamic-refresh').addEventListener('click',refreshData);
    $('dynamic-ttl').addEventListener('input',updateExamples);
    $('dynamic-copy-rest').addEventListener('click',()=>copyText(snippets().rest));
    $('dynamic-copy-ws').addEventListener('click',()=>copyText(snippets().ws));
  });
})();
