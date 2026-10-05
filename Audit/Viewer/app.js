(() => {
  'use strict';

  const state = { report:null, module:null, rows:[], filtered:[], page:1, pageSize:25 };
  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const arr = value => Array.isArray(value) ? value : (value == null ? [] : [value]);
  const isObject = value => value && typeof value === 'object' && !Array.isArray(value);

  function toast(message){ const el=$('toast'); el.textContent=message; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2200); }
  function prettyKey(key){ return String(key).replace(/([a-z])([A-Z])/g,'$1 $2').replace(/_/g,' ').replace(/^./,c=>c.toUpperCase()); }
  function formatValue(v){
    if(v === null || v === undefined || v === '') return '<span class="cell-muted">—</span>';
    if(typeof v === 'boolean') return v ? '<span class="badge good">Oui</span>' : '<span class="badge">Non</span>';
    if(v instanceof Date) return esc(v.toLocaleString('fr-FR'));
    if(typeof v === 'object') return '<span class="cell-muted">'+esc(JSON.stringify(v))+'</span>';
    const s=String(v);
    if(/^\\d{4}-\\d{2}-\\d{2}T/.test(s)){ const d=new Date(s); if(!isNaN(d)) return esc(d.toLocaleString('fr-FR')); }
    return esc(s);
  }
  function results(){ return state.report?.Results || {}; }
  function rowsFor(key){
    const v=results()[key];
    if(Array.isArray(v)) return v;
    if(v && typeof v === 'object') return [v];
    return [];
  }
  function totalObjects(){
    return Object.values(results()).reduce((n,v)=>n+(Array.isArray(v)?v.length:(v&&typeof v==='object'?1:0)),0);
  }
  function moduleLabel(key){ return prettyKey(key); }

  function loadReport(data){
    if(!data || typeof data !== 'object' || !data.Results) throw new Error('Ce fichier ne ressemble pas à un rapport AD-Audit.json.');
    state.report=data; state.module=null;
    $('emptyState').hidden=true; $('app').hidden=false;
    renderNav(); showDashboard();
    toast('Rapport chargé');
  }

  function renderNav(){
    const nav=$('moduleNav');
    const entries=Object.entries(results());
    nav.innerHTML='<button class="nav-item active" data-view="dashboard">⌂ <span>Tableau de bord</span></button>'+
      entries.map(([key,v])=>{
        const count=Array.isArray(v)?v.length:1;
        return '<button class="nav-item" data-module="'+esc(key)+'">'+esc(moduleLabel(key))+' <span class="nav-count">'+count+'</span></button>';
      }).join('');
    nav.querySelectorAll('.nav-item').forEach(btn=>btn.addEventListener('click',()=>{
      nav.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active')); btn.classList.add('active');
      if(btn.dataset.view==='dashboard') showDashboard(); else showTable(btn.dataset.module);
    }));
  }

  function setView(id){
    document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
    $(id).classList.add('active');
  }

  function showDashboard(){
    setView('dashboard');
    const r=results(), entries=Object.entries(r);
    const findings=Array.isArray(state.report.Findings)?state.report.Findings:[];
    const high=findings.filter(x=>String(x.Severity).toLowerCase()==='high').length;
    const medium=findings.filter(x=>String(x.Severity).toLowerCase()==='medium').length;
    $('dashboard').innerHTML =
      '<div class="page-head"><div><h2>Tableau de bord</h2><p>Vue synthétique du rapport chargé.</p></div></div>'+
      '<div class="grid">'+
        stat('Domaine',state.report.Domain||'—','')+
        stat('Modules',entries.length,'modules présents')+
        stat('Objets audités',totalObjects(),'éléments collectés')+
        stat('Findings',findings.length,high+' critiques · '+medium+' moyens')+
      '</div>'+
      '<div class="panels">'+
        '<div class="panel"><div class="panel-head">Informations du rapport</div><div class="panel-body">'+
          detailList({Version:state.report.Version,StartedAt:state.report.StartedAt,FinishedAt:state.report.FinishedAt,ReadOnly:state.report.ReadOnly})+
        '</div></div>'+
        '<div class="panel"><div class="panel-head">Modules disponibles</div><div class="panel-body">'+
          entries.map(([k,v])=>'<div class="finding"><div class="finding-title">'+esc(moduleLabel(k))+'</div><div class="finding-meta">'+(Array.isArray(v)?v.length+' éléments':'1 objet')+'</div></div>').join('')+
        '</div></div>'+
      '</div>'+
      '<div class="panel" style="margin-top:16px"><div class="panel-head">Findings</div><div class="panel-body">'+
        (findings.length?findings.slice(0,30).map(findingHtml).join(''):'<span class="cell-muted">Aucun finding dans ce rapport.</span>')+
      '</div></div>';
  }

  function stat(label,value,sub){return '<div class="card"><div class="stat-label">'+esc(label)+'</div><div class="stat-value">'+esc(value)+'</div><div class="stat-sub">'+esc(sub)+'</div></div>'}
  function detailList(obj){return '<div class="detail-grid">'+Object.entries(obj).map(([k,v])=>'<div class="detail-item"><div class="detail-key">'+esc(prettyKey(k))+'</div><div class="detail-value">'+formatValue(v)+'</div></div>').join('')+'</div>'}
  function findingHtml(f){
    const sev=String(f.Severity||'Info').toLowerCase();
    return '<div class="finding '+esc(sev)+'"><div class="finding-title">'+esc(f.Title||'Finding')+'</div><div class="finding-meta">'+esc(f.Severity||'Info')+' · '+esc(f.Category||'')+' · '+esc(f.Object||'')+'</div><div class="finding-detail">'+esc(f.Details||'')+(f.Recommendation?'<br><strong>Recommandation :</strong> '+esc(f.Recommendation):'')+'</div></div>';
  }

  function showTable(module){
    state.module=module; state.rows=rowsFor(module); state.page=1;
    setView('tableView');
    renderTable();
  }

  function renderTable(){
    const rows=state.rows;
    const columns=rows.length ? Object.keys(rows[0]) : [];
    $('tableView').innerHTML=
      '<div class="page-head"><div><h2>'+esc(moduleLabel(state.module))+'</h2><p>'+rows.length+' élément(s) collecté(s).</p></div></div>'+
      '<div class="toolbar"><input id="tableSearch" class="search" placeholder="Rechercher dans ce module…"><select id="pageSize"><option value="25">25 lignes</option><option value="50">50 lignes</option><option value="100">100 lignes</option><option value="250">250 lignes</option></select></div>'+
      '<div class="table-wrap">'+
      (columns.length?'<table><thead><tr>'+columns.map(c=>'<th>'+esc(prettyKey(c))+'</th>').join('')+'</tr></thead><tbody id="tableBody"></tbody></table>':'<div class="panel-body">Aucune donnée exploitable dans ce module.</div>')+
      '</div><div class="pagination"><span id="pageInfo"></span><div class="pager"><button id="prevPage">‹</button><button id="nextPage">›</button></div></div>';
    if(columns.length){
      $('tableSearch').addEventListener('input',()=>{state.page=1;applyFilter()});
      $('pageSize').addEventListener('change',e=>{state.pageSize=Number(e.target.value);state.page=1;applyFilter()});
      $('prevPage').addEventListener('click',()=>{if(state.page>1){state.page--;renderBody(columns)}});
      $('nextPage').addEventListener('click',()=>{if(state.page<Math.ceil(state.filtered.length/state.pageSize)){state.page++;renderBody(columns)}});
      applyFilter();
    }
  }

  function applyFilter(){
    const q=($('tableSearch')?.value||'').toLowerCase().trim();
    state.filtered=!q?state.rows:state.rows.filter(row=>Object.values(row).some(v=>String(v??'').toLowerCase().includes(q)));
    renderBody(state.rows.length?Object.keys(state.rows[0]):[]);
  }

  function renderBody(columns){
    const start=(state.page-1)*state.pageSize, pageRows=state.filtered.slice(start,start+state.pageSize);
    $('tableBody').innerHTML=pageRows.map((row,i)=>
      '<tr data-index="'+(start+i)+'">'+columns.map(c=>'<td>'+formatValue(row[c])+'</td>').join('')+'</tr>'
    ).join('');
    $('tableBody').querySelectorAll('tr').forEach(tr=>tr.addEventListener('dblclick',()=>showDetail(state.filtered[Number(tr.dataset.index)])));
    $('pageInfo').textContent=state.filtered.length+' résultat(s) · page '+state.page+' / '+Math.max(1,Math.ceil(state.filtered.length/state.pageSize));
  }

  function showDetail(row){
    setView('detailView');
    $('detailView').innerHTML='<div class="page-head"><div><h2>Détail</h2><p>Objet sélectionné dans « '+esc(moduleLabel(state.module))+' ».</p></div><button id="backBtn" class="button">← Retour</button></div>'+
      '<div class="panel"><div class="panel-body">'+detailList(row)+'</div></div>'+
      '<div class="panel" style="margin-top:16px"><div class="panel-head">JSON brut</div><div class="panel-body"><pre class="json">'+esc(JSON.stringify(row,null,2))+'</pre></div></div>';
    $('backBtn').addEventListener('click',()=>showTable(state.module));
  }

  function handleFile(file){
    if(!file)return;
    const reader=new FileReader();
    reader.onload=()=>{try{loadReport(JSON.parse(reader.result))}catch(e){toast('Erreur : '+e.message)}};
    reader.onerror=()=>toast('Impossible de lire le fichier.');
    reader.readAsText(file);
  }

  $('fileInput').addEventListener('change',e=>handleFile(e.target.files[0]));
  $('emptyFileInput').addEventListener('change',e=>handleFile(e.target.files[0]));
  $('resetBtn').addEventListener('click',()=>{
    state.report=null; $('app').hidden=true; $('emptyState').hidden=false; $('moduleNav').innerHTML='';
    $('fileInput').value=''; $('emptyFileInput').value='';
  });
})();