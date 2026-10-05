(() => {
  'use strict';

  const state = {
    report: null,
    module: null,
    rows: [],
    filtered: [],
    page: 1,
    pageSize: 25,
    scoring: true
  };

  const $ = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const arr = value => Array.isArray(value) ? value : (value == null ? [] : [value]);
  const num = value => {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  };
  const lower = value => String(value ?? '').toLowerCase();
  const bool = value => value === true || lower(value) === 'true' || lower(value) === 'oui';
  const isObject = value => value && typeof value === 'object' && !Array.isArray(value);

  /*
   * Scoring is deliberately client-side.
   * The PowerShell collector remains read-only and only collects evidence.
   * No score is written back to AD or to the source JSON.
   *
   * Philosophy:
   * - 100 = no detected weakness in the audited scope.
   * - penalties are bounded per category to avoid one noisy population destroying the score.
   * - a score is never presented without coverage information.
   * - rules only evaluate fields actually present in the report.
   */
  const SCORE_RULES = [
    {
      id:'USR-001', category:'Comptes', module:'Users', severity:'high', weight:8, maxHits:10,
      test:r=>bool(r.PasswordNeverExpires) && bool(r.Enabled),
      title:'Compte actif avec mot de passe n’expirant jamais',
      recommendation:'Réduire les exceptions et appliquer une politique de mot de passe adaptée. Pour les comptes de service, privilégier les comptes de service managés lorsque possible.'
    },
    {
      id:'USR-002', category:'Comptes', module:'Users', severity:'high', weight:7, maxHits:10,
      test:r=>bool(r.PasswordNotRequired) && bool(r.Enabled),
      title:'Compte actif sans exigence de mot de passe',
      recommendation:'Exiger un mot de passe robuste ou utiliser un mécanisme d’authentification adapté au type de compte.'
    },
    {
      id:'USR-003', category:'Comptes', module:'Users', severity:'medium', weight:4, maxHits:20,
      test:r=>bool(r.DoesNotRequirePreAuth) && bool(r.Enabled),
      title:'Compte actif sans pré-authentification Kerberos',
      recommendation:'Réactiver la pré-authentification Kerberos sauf besoin métier explicitement documenté.'
    },
    {
      id:'USR-004', category:'Comptes', module:'Users', severity:'medium', weight:3, maxHits:20,
      test:r=>bool(r.TrustedForDelegation) && bool(r.Enabled),
      title:'Compte utilisateur autorisé à la délégation non contrainte',
      recommendation:'Limiter la délégation aux seuls comptes et scénarios qui l’exigent.'
    },
    {
      id:'USR-005', category:'Comptes', module:'Users', severity:'medium', weight:3, maxHits:15,
      test:r=>bool(r.TrustedToAuthForDelegation) && bool(r.Enabled),
      title:'Compte utilisateur autorisé à la délégation contrainte avec transition',
      recommendation:'Vérifier précisément les usages de protocol transition et réduire les délégations inutiles.'
    },
    {
      id:'USR-006', category:'Comptes', module:'Users', severity:'medium', weight:2, maxHits:20,
      test:r=>bool(r.IsPrivileged) && bool(r.Enabled) && bool(r.PasswordNeverExpires),
      title:'Compte privilégié actif avec mot de passe permanent',
      recommendation:'Séparer les comptes d’administration et appliquer une politique de rotation adaptée.'
    },
    {
      id:'USR-007', category:'Comptes', module:'Users', severity:'low', weight:1, maxHits:30,
      test:r=>bool(r.Enabled) && r.LastLogonDate && daysSince(r.LastLogonDate) > 180,
      title:'Compte actif sans connexion depuis plus de 180 jours',
      recommendation:'Vérifier le besoin métier puis désactiver ou supprimer les comptes réellement obsolètes.'
    },
    {
      id:'GRP-001', category:'Privilèges', module:'Groups', severity:'high', weight:8, maxHits:10,
      test:r=>bool(r.IsPrivileged) && num(r.MemberCount) > 0,
      title:'Groupe privilégié contenant des membres',
      recommendation:'Revoir les membres, privilégier les groupes d’administration dédiés et appliquer une logique de moindre privilège.'
    },
    {
      id:'CMP-001', category:'Postes', module:'Computers', severity:'medium', weight:3, maxHits:20,
      test:r=>bool(r.Enabled) && bool(r.Stale),
      title:'Ordinateur actif considéré comme obsolète',
      recommendation:'Vérifier l’inventaire, l’activité réelle du poste et retirer les objets AD devenus inutiles.'
    },
    {
      id:'CMP-002', category:'Postes', module:'Computers', severity:'high', weight:7, maxHits:10,
      test:r=>bool(r.Enabled) && bool(r.TrustedForDelegation),
      title:'Ordinateur actif en délégation non contrainte',
      recommendation:'Supprimer la délégation non contrainte lorsqu’elle n’est pas strictement nécessaire.'
    },
    {
      id:'CMP-003', category:'Postes', module:'Computers', severity:'medium', weight:3, maxHits:20,
      test:r=>bool(r.Enabled) && !hasLapsEvidence(r),
      title:'Aucune preuve de LAPS sur l’ordinateur',
      recommendation:'Déployer Windows LAPS ou une solution équivalente et vérifier les ACL de lecture du secret.'
    },
    {
      id:'KER-001', category:'Kerberos', module:'Kerberos', severity:'critical', weight:18, maxHits:10,
      test:r=>bool(r.DoesNotRequirePreAuth) && bool(r.Enabled),
      title:'Compte Kerberos potentiellement AS-REP roastable',
      recommendation:'Réactiver la pré-authentification Kerberos sauf exception documentée.'
    },
    {
      id:'KER-002', category:'Kerberos', module:'Kerberos', severity:'critical', weight:18, maxHits:10,
      test:r=>bool(r.TrustedForDelegation) && bool(r.Enabled),
      title:'Délégation Kerberos non contrainte détectée',
      recommendation:'Supprimer la délégation non contrainte ou isoler strictement le scénario qui l’impose.'
    },
    {
      id:'KER-003', category:'Kerberos', module:'Kerberos', severity:'high', weight:8, maxHits:15,
      test:r=>arr(r.AllowedToDelegateTo).length > 0 || arr(r.MsDSAllowedToDelegateTo).length > 0,
      title:'Délégation Kerberos contrainte configurée',
      recommendation:'Vérifier que chaque SPN cible est indispensable et que le périmètre est minimal.'
    },
    {
      id:'KER-004', category:'Kerberos', module:'Kerberos', severity:'high', weight:10, maxHits:10,
      test:r=>hasRBCD(r),
      title:'Délégation contrainte basée sur les ressources détectée',
      recommendation:'Identifier les principaux autorisés dans msDS-AllowedToActOnBehalfOfOtherIdentity et vérifier qu’ils sont légitimes.'
    },
    {
      id:'DOM-001', category:'Domaine', module:'Domain', severity:'high', weight:8, maxHits:1,
      test:r=>num(firstDefined(r.MinimumPasswordLength, r.MinPasswordLength)) !== null && num(firstDefined(r.MinimumPasswordLength, r.MinPasswordLength)) < 12,
      title:'Longueur minimale de mot de passe faible',
      recommendation:'Viser au minimum 12 caractères, en cohérence avec la politique de sécurité de l’organisation.'
    },
    {
      id:'DOM-002', category:'Domaine', module:'Domain', severity:'medium', weight:4, maxHits:1,
      test:r=>num(firstDefined(r.PasswordHistoryCount, r.PasswordHistoryLength)) !== null && num(firstDefined(r.PasswordHistoryCount, r.PasswordHistoryLength)) < 10,
      title:'Historique de mots de passe faible',
      recommendation:'Augmenter l’historique pour empêcher la réutilisation rapide des anciens secrets.'
    },
    {
      id:'DOM-003', category:'Domaine', module:'Domain', severity:'high', weight:8, maxHits:1,
      test:r=>num(firstDefined(r.LockoutThreshold, r.AccountLockoutThreshold)) === 0,
      title:'Verrouillage de compte désactivé',
      recommendation:'Définir une politique de verrouillage adaptée au risque et aux contraintes opérationnelles.'
    },
    {
      id:'PW-001', category:'Authentification', module:'PasswordPolicies', severity:'high', weight:8, maxHits:5,
      test:r=>num(firstDefined(r.MinPasswordLength, r.MinimumPasswordLength)) !== null && num(firstDefined(r.MinPasswordLength, r.MinimumPasswordLength)) < 12,
      title:'Politique de mot de passe trop courte',
      recommendation:'Augmenter la longueur minimale et vérifier les éventuelles politiques fines applicables.'
    },
    {
      id:'PW-002', category:'Authentification', module:'PasswordPolicies', severity:'high', weight:7, maxHits:5,
      test:r=>num(r.LockoutThreshold) === 0,
      title:'Seuil de verrouillage désactivé',
      recommendation:'Définir un seuil cohérent avec la protection contre le password spraying.'
    },
    {
      id:'LAPS-001', category:'Postes', module:'LAPS', severity:'high', weight:10, maxHits:10,
      test:r=>bool(r.Enabled) && !hasLapsEvidence(r),
      title:'Aucune preuve de mot de passe LAPS présent',
      recommendation:'Déployer Windows LAPS et vérifier la délégation des droits de lecture/gestion.'
    },
    {
      id:'LAPS-002', category:'Postes', module:'LAPS', severity:'medium', weight:4, maxHits:10,
      test:r=>hasLapsEvidence(r) && lapsExpired(r),
      title:'Secret LAPS potentiellement expiré',
      recommendation:'Vérifier le renouvellement LAPS et l’état du poste concerné.'
    },
    {
      id:'GPO-001', category:'GPO', module:'GPOAnalysis', severity:'high', weight:8, maxHits:10,
      test:r=>containsFlag(r,['UAC','RDP','SMB1','Defender','SensitivePrivilege']) && bool(r.SecurityConcern),
      title:'Configuration GPO signalée comme sensible',
      recommendation:'Examiner la configuration exacte dans le rapport GPO avant de conclure à une faiblesse.'
    },
    {
      id:'ADCS-001', category:'AD CS', module:'ADCS', severity:'high', weight:10, maxHits:10,
      test:r=>hasRiskyAdcsFlags(r),
      title:'Configuration AD CS potentiellement sensible',
      recommendation:'Analyser les templates, EKU, droits d’enrôlement et paramètres de sujet avant de valider le risque.'
    },
    {
      id:'RB-001', category:'Résilience', module:'RecycleBin', severity:'medium', weight:5, maxHits:1,
      test:r=>r.Enabled === false || (r.EnabledScopes && arr(r.EnabledScopes).length === 0),
      title:'Corbeille Active Directory non activée ou non confirmée',
      recommendation:'Activer la Corbeille AD si les contraintes de niveau fonctionnel le permettent.'
    },
    {
      id:'HEALTH-001', category:'Réplication', module:'Health', severity:'critical', weight:15, maxHits:10,
      test:r=>num(r.LastReplicationResult) !== null && num(r.LastReplicationResult) !== 0,
      title:'Erreur de réplication détectée',
      recommendation:'Investiguer les erreurs de réplication avant toute opération de correction ou de nettoyage.'
    },
    {
      id:'HEALTH-002', category:'Réplication', module:'Health', severity:'high', weight:8, maxHits:10,
      test:r=>num(r.ConsecutiveReplicationFailures) > 0,
      title:'Échecs de réplication consécutifs',
      recommendation:'Identifier le partenaire concerné et contrôler DNS, RPC, connectivité, SYSVOL et état NTDS.'
    }
  ];

  function firstDefined(...values){ return values.find(v => v !== undefined && v !== null && v !== ''); }

  function daysSince(value){
    const d=new Date(value);
    if(Number.isNaN(d.getTime())) return -1;
    return Math.floor((Date.now()-d.getTime())/86400000);
  }

  function hasLapsEvidence(r){
    const keys=['LapsPasswordExpirationTime','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime','msLAPS-PasswordExpirationTimeComputed'];
    return keys.some(k=>r[k] !== undefined && r[k] !== null && r[k] !== '');
  }

  function lapsExpired(r){
    const v=firstDefined(r.LapsPasswordExpirationTime,r['msLAPS-PasswordExpirationTime'],r['ms-Mcs-AdmPwdExpirationTime']);
    if(!v) return false;
    const n=num(v);
    if(n !== null && n > 100000000000000) {
      const d=new Date(n/10000-11644473600000);
      return !Number.isNaN(d.getTime()) && d.getTime() < Date.now();
    }
    const d=new Date(v);
    return !Number.isNaN(d.getTime()) && d.getTime() < Date.now();
  }

  function hasRBCD(r){
    return ['msDS-AllowedToActOnBehalfOfOtherIdentity','AllowedToActOnBehalfOfOtherIdentity','RBCD'].some(k=>{
      const v=r[k];
      return v !== undefined && v !== null && String(v).trim() !== '';
    });
  }

  function containsFlag(r, flags){
    const text=JSON.stringify(r).toLowerCase();
    return flags.some(f=>text.includes(String(f).toLowerCase()));
  }

  function hasRiskyAdcsFlags(r){
    const text=JSON.stringify(r).toLowerCase();
    return ['enrolleesupplies','enrollee supplies subject','managerapproval','authorizedsignatures','anypurpose','clientauthentication'].some(x=>text.includes(x));
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

  function moduleLabel(key){ return String(key).replace(/([a-z])([A-Z])/g,'$1 $2').replace(/_/g,' ').replace(/^./,c=>c.toUpperCase()); }

  function severityLabel(s){
    return ({critical:'Critique',high:'Élevé',medium:'Moyen',low:'Faible',info:'Info'})[lower(s)] || s || 'Info';
  }

  function scoreClass(score){
    if(score >= 90) return 'excellent';
    if(score >= 75) return 'good';
    if(score >= 60) return 'medium';
    if(score >= 40) return 'poor';
    return 'critical';
  }

  function scoreLabel(score){
    if(score >= 90) return 'Excellent';
    if(score >= 75) return 'Bon';
    if(score >= 60) return 'Moyen';
    if(score >= 40) return 'Faible';
    return 'Critique';
  }

  function moduleCoverage(){
    const expected=SCORE_RULES.map(r=>r.module).filter((v,i,a)=>a.indexOf(v)===i);
    const present=expected.filter(m=>Object.prototype.hasOwnProperty.call(results(),m));
    return expected.length ? Math.round((present.length/expected.length)*100) : 0;
  }

  function calculateScore(){
    const findings=Array.isArray(state.report?.Findings)?state.report.Findings:[];
    const evidence=[];
    const categories={};
    const byRule={};

    const addEvidence=(rule,row,penalty)=>{
      if(!categories[rule.category]) categories[rule.category]={penalty:0,hits:0,highlights:[]};
      categories[rule.category].hits++;
      categories[rule.category].penalty=Math.min(categories[rule.category].penalty, categoryCap(rule.category));
      const before=categories[rule.category].penalty;
      const allowed=Math.max(0,Math.min(rule.weight,categoryCap(rule.category)-before));
      if(allowed<=0) return;
      categories[rule.category].penalty+=allowed;
      const item={
        id:rule.id, category:rule.category, severity:rule.severity, penalty:allowed,
        title:rule.title, recommendation:rule.recommendation,
        object:objectLabel(row), evidence:buildEvidence(rule,row)
      };
      evidence.push(item);
      byRule[rule.id]=(byRule[rule.id]||0)+1;
      categories[rule.category].highlights.push(item);
    };

    for(const rule of SCORE_RULES){
      const rows=rowsFor(rule.module);
      let hits=0;
      for(const row of rows){
        let matched=false;
        try { matched=rule.test(row); } catch(_) { matched=false; }
        if(matched){
          hits++;
          if(hits<=rule.maxHits) addEvidence(rule,row,rule.weight);
        }
      }
    }

    /*
     * Existing collector findings are treated as secondary evidence.
     * Only findings not already represented by a scoring rule add a small
     * bounded penalty. This prevents double-counting.
     */
    for(const f of findings){
      const sev=lower(f.Severity);
      const title=lower(f.Title);
      const already=evidence.some(e=>lower(e.title)===title || lower(e.object)===lower(f.Object) && lower(e.category)===lower(f.Category));
      if(already) continue;
      const p=sev==='critical'?10:sev==='high'?7:sev==='medium'?4:sev==='low'?1:0;
      if(!p) continue;
      const category=f.Category || 'Autres';
      if(!categories[category]) categories[category]={penalty:0,hits:0,highlights:[]};
      const cap=categoryCap(category);
      const allowed=Math.max(0,Math.min(p,cap-categories[category].penalty));
      if(allowed<=0) continue;
      categories[category].penalty+=allowed;
      const item={
        id:'FINDING',category,severity:sev,penalty:allowed,
        title:f.Title||'Finding',recommendation:f.Recommendation||'Examiner et corriger la cause du finding.',
        object:f.Object||'—',evidence:f.Details||'Finding produit par le collecteur.'
      };
      evidence.push(item);
      categories[category].hits++;
      categories[category].highlights.push(item);
    }

    const totalPenalty=Object.values(categories).reduce((n,c)=>n+c.penalty,0);
    const score=Math.max(0,Math.min(100,100-totalPenalty));
    const categoryRows=Object.entries(categories).map(([category,v])=>{
      const max=categoryCap(category);
      const s=Math.max(0,Math.round(100-(v.penalty/max)*100));
      return {category,score:s,penalty:v.penalty,hits:v.hits,items:v.highlights};
    }).sort((a,b)=>a.score-b.score);

    const auditedModules=Object.keys(results());
    const expected=SCORE_RULES.map(r=>r.module).filter((v,i,a)=>a.indexOf(v)===i);
    const coverage=expected.length?Math.round(auditedModules.filter(m=>expected.includes(m)).length/expected.length*100):0;

    return {score,label:scoreLabel(score),className:scoreClass(score),penalty:totalPenalty,coverage,evidence,categoryRows,byRule};
  }

  function categoryCap(category){
    const caps={
      'Comptes':20,'Privilèges':18,'Postes':18,'Kerberos':25,'Domaine':15,
      'Authentification':15,'GPO':15,'AD CS':15,'Résilience':10,'Réplication':20
    };
    return caps[category] || 12;
  }

  function objectLabel(row){
    return row?.SamAccountName || row?.Name || row?.DisplayName || row?.DNSHostName || row?.DistinguishedName || row?.DN || 'Objet AD';
  }

  function buildEvidence(rule,row){
    const fields={
      'USR-001':['SamAccountName','PasswordNeverExpires','Enabled'],
      'USR-002':['SamAccountName','PasswordNotRequired','Enabled'],
      'USR-003':['SamAccountName','DoesNotRequirePreAuth','Enabled'],
      'USR-004':['SamAccountName','TrustedForDelegation','Enabled'],
      'USR-005':['SamAccountName','TrustedToAuthForDelegation','Enabled'],
      'USR-006':['SamAccountName','IsPrivileged','PasswordNeverExpires'],
      'USR-007':['SamAccountName','LastLogonDate'],
      'GRP-001':['Name','IsPrivileged','MemberCount'],
      'CMP-001':['Name','Enabled','Stale','LastLogonDate'],
      'CMP-002':['Name','Enabled','TrustedForDelegation'],
      'CMP-003':['Name','Enabled','LapsPasswordExpirationTime','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'],
      'KER-001':['SamAccountName','DoesNotRequirePreAuth','Enabled'],
      'KER-002':['SamAccountName','Name','TrustedForDelegation'],
      'KER-003':['SamAccountName','AllowedToDelegateTo','msDS-AllowedToDelegateTo'],
      'KER-004':['Name','msDS-AllowedToActOnBehalfOfOtherIdentity'],
      'DOM-001':['MinimumPasswordLength','MinPasswordLength'],
      'DOM-002':['PasswordHistoryCount','PasswordHistoryLength'],
      'DOM-003':['LockoutThreshold','AccountLockoutThreshold'],
      'PW-001':['Name','MinPasswordLength','MinimumPasswordLength'],
      'PW-002':['Name','LockoutThreshold'],
      'LAPS-001':['Name','Enabled'],
      'LAPS-002':['Name','LapsPasswordExpirationTime','msLAPS-PasswordExpirationTime'],
      'GPO-001':['DisplayName','GpoStatus','SecurityConcern'],
      'ADCS-001':['DisplayName','certificateTemplates','msPKI-Certificate-Name-Flag'],
      'RB-001':['Enabled','EnabledScopes'],
      'HEALTH-001':['Server','Partner','LastReplicationResult'],
      'HEALTH-002':['Server','Partner','ConsecutiveReplicationFailures']
    };
    const wanted=fields[rule.id]||Object.keys(row||{}).slice(0,6);
    const out={};
    for(const k of wanted) if(row && row[k] !== undefined && row[k] !== null && row[k] !== '') out[k]=row[k];
    return Object.keys(out).length?out:'Règle déclenchée à partir des données collectées.';
  }

  function topRecommendations(score){
    return score.evidence.slice().sort((a,b)=>{
      const order={critical:4,high:3,medium:2,low:1,info:0};
      return (order[b.severity]||0)-(order[a.severity]||0) || b.penalty-a.penalty;
    }).slice(0,8);
  }

  function toast(message){ const el=$('toast'); el.textContent=message; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2200); }

  function formatValue(v){
    if(v === null || v === undefined || v === '') return '<span class="cell-muted">—</span>';
    if(typeof v === 'boolean') return v ? '<span class="badge good">Oui</span>' : '<span class="badge">Non</span>';
    if(v instanceof Date) return esc(v.toLocaleString('fr-FR'));
    if(typeof v === 'object') return '<span class="cell-muted">'+esc(JSON.stringify(v))+'</span>';
    const s=String(v);
    if(/^\d{4}-\d{2}-\d{2}T/.test(s)){ const d=new Date(s); if(!isNaN(d)) return esc(d.toLocaleString('fr-FR')); }
    return esc(s);
  }

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
      '<button class="nav-item score-nav" data-view="score">◉ <span>Analyse & score</span></button>'+
      entries.map(([key,v])=>{
        const count=Array.isArray(v)?v.length:1;
        return '<button class="nav-item" data-module="'+esc(key)+'">'+esc(moduleLabel(key))+' <span class="nav-count">'+count+'</span></button>';
      }).join('');
    nav.querySelectorAll('.nav-item').forEach(btn=>btn.addEventListener('click',()=>{
      nav.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active')); btn.classList.add('active');
      if(btn.dataset.view==='dashboard') showDashboard();
      else if(btn.dataset.view==='score') showScore();
      else showTable(btn.dataset.module);
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
    const high=findings.filter(x=>['high','critical'].includes(lower(x.Severity))).length;
    const medium=findings.filter(x=>lower(x.Severity)==='medium').length;
    const score=state.scoring?calculateScore():null;
    $('dashboard').innerHTML =
      '<div class="page-head"><div><h2>Tableau de bord</h2><p>Vue synthétique du rapport chargé.</p></div><div class="toolbar-inline"><button id="scoreToggle" class="button '+(state.scoring?'primary':'')+'">Analyse '+(state.scoring?'activée':'désactivée')+'</button></div></div>'+
      (score ? scoreHero(score) : '')+
      '<div class="grid">'+
        stat('Domaine',state.report.Domain||'—','')+
        stat('Modules',entries.length,'modules présents')+
        stat('Objets audités',totalObjects(),'éléments collectés')+
        stat('Findings',findings.length,high+' élevés/critiques · '+medium+' moyens')+
      '</div>'+
      '<div class="panels">'+
        '<div class="panel"><div class="panel-head">Informations du rapport</div><div class="panel-body">'+
          detailList({Version:state.report.Version,StartedAt:state.report.StartedAt,FinishedAt:state.report.FinishedAt,ReadOnly:state.report.ReadOnly,SelectedModules:state.report.SelectedModules})+
        '</div></div>'+
        '<div class="panel"><div class="panel-head">Modules disponibles</div><div class="panel-body">'+
          entries.map(([k,v])=>'<div class="finding"><div class="finding-title">'+esc(moduleLabel(k))+'</div><div class="finding-meta">'+(Array.isArray(v)?v.length+' éléments':'1 objet')+'</div></div>').join('')+
        '</div></div>'+
      '</div>'+
      '<div class="panel" style="margin-top:16px"><div class="panel-head">Findings du collecteur</div><div class="panel-body">'+
        (findings.length?findings.slice(0,30).map(findingHtml).join(''):'<span class="cell-muted">Aucun finding dans ce rapport.</span>')+
      '</div></div>';
    $('scoreToggle').addEventListener('click',()=>{state.scoring=!state.scoring;showDashboard()});
  }

  function scoreHero(score){
    const top=topRecommendations(score);
    return '<div class="score-layout">'+
      '<div class="score-card '+esc(score.className)+'">'+
        '<div class="score-kicker">SCORE D’ANALYSE</div><div class="score-number">'+score.score+'</div><div class="score-max">/ 100</div>'+
        '<div class="score-label">'+esc(score.label)+'</div>'+
        '<div class="score-meter"><span style="width:'+score.score+'%"></span></div>'+
        '<div class="score-foot"><span>'+score.penalty+' points de pénalité détectés</span><span>Couverture '+score.coverage+'%</span></div>'+
      '</div>'+
      '<div class="panel score-side"><div class="panel-head">Priorités détectées</div><div class="panel-body">'+
        (top.length?top.slice(0,5).map(scoreItemHtml).join(''):'<span class="cell-muted">Aucune faiblesse détectée par les règles disponibles.</span>')+
      '</div></div>'+
    '</div>';
  }

  function scoreItemHtml(item){
    return '<div class="score-item '+esc(item.severity)+'"><div><span class="severity-dot"></span><strong>'+esc(item.title)+'</strong></div><div class="finding-meta">'+esc(severityLabel(item.severity))+' · -'+item.penalty+' · '+esc(item.object)+'</div></div>';
  }

  function showScore(){
    setView('scoreView');
    const score=calculateScore();
    const cats=score.categoryRows;
    const top=topRecommendations(score);
    $('scoreView').innerHTML=
      '<div class="page-head"><div><h2>Analyse & score</h2><p>Analyse locale des données du rapport. Aucun score n’est écrit dans le fichier source.</p></div><button id="scoreToggle2" class="button '+(state.scoring?'primary':'')+'">Analyse '+(state.scoring?'activée':'désactivée')+'</button></div>'+
      '<div class="score-layout">'+
        '<div class="score-card '+esc(score.className)+'"><div class="score-kicker">SCORE GLOBAL</div><div class="score-number">'+score.score+'</div><div class="score-max">/ 100</div><div class="score-label">'+esc(score.label)+'</div><div class="score-meter"><span style="width:'+score.score+'%"></span></div><div class="score-foot"><span>-'+score.penalty+' points</span><span>Couverture '+score.coverage+'%</span></div></div>'+
        '<div class="panel"><div class="panel-head">Interprétation</div><div class="panel-body"><p class="score-explain">Le score mesure uniquement les faiblesses détectables dans les modules présents. Il ne constitue pas une certification de sécurité.</p><div class="legend"><span><b>90–100</b> Excellent</span><span><b>75–89</b> Bon</span><span><b>60–74</b> Moyen</span><span><b>40–59</b> Faible</span><span><b>0–39</b> Critique</span></div></div></div>'+
      '</div>'+
      '<div class="panel score-panel"><div class="panel-head">Scores par domaine</div><div class="panel-body score-categories">'+
        (cats.length?cats.map(categoryHtml).join(''):'<span class="cell-muted">Aucune catégorie évaluée.</span>')+
      '</div></div>'+
      '<div class="panels">'+
        '<div class="panel"><div class="panel-head">Top recommandations</div><div class="panel-body">'+(top.length?top.map(recommendationHtml).join(''):'<span class="cell-muted">Aucune recommandation.</span>')+'</div></div>'+
        '<div class="panel"><div class="panel-head">Méthodologie</div><div class="panel-body"><ul class="method"><li>Le collecteur PowerShell reste en lecture seule.</li><li>Chaque règle utilise uniquement les données présentes dans le JSON.</li><li>Les pénalités sont plafonnées par domaine pour éviter un biais lié au volume.</li><li>Les findings existants peuvent compléter l’analyse sans être comptés deux fois lorsqu’une règle équivalente existe.</li><li>Les éléments non audités ne sont pas considérés comme conformes : ils réduisent la couverture.</li></ul></div></div>'+
      '</div>'+
      '<div class="panel score-panel"><div class="panel-head">Détail des éléments ayant un impact</div><div class="panel-body">'+
        (score.evidence.length?score.evidence.map(recommendationHtml).join(''):'<span class="cell-muted">Aucun élément.</span>')+
      '</div></div>';

    $('scoreToggle2').addEventListener('click',()=>{state.scoring=!state.scoring;showDashboard()});
  }

  function categoryHtml(c){
    const cls=scoreClass(c.score);
    return '<div class="category-row"><div class="category-title"><strong>'+esc(c.category)+'</strong><span>'+c.hits+' élément(s) · -'+c.penalty+'</span></div><div class="category-bar"><span class="'+cls+'" style="width:'+c.score+'%"></span></div><div class="category-score '+cls+'">'+c.score+'</div></div>';
  }

  function recommendationHtml(item){
    return '<div class="recommendation '+esc(item.severity)+'"><div class="recommendation-head"><span class="severity-pill '+esc(item.severity)+'">'+esc(severityLabel(item.severity))+'</span><strong>'+esc(item.title)+'</strong><span class="penalty">-'+item.penalty+'</span></div><div class="finding-meta">'+esc(item.category)+' · '+esc(item.object)+'</div><div class="recommendation-text"><strong>Recommandation :</strong> '+esc(item.recommendation)+'</div><details><summary>Voir la preuve</summary><pre class="evidence">'+esc(typeof item.evidence==='object'?JSON.stringify(item.evidence,null,2):item.evidence)+'</pre></details></div>';
  }

  function stat(label,value,sub){return '<div class="card"><div class="stat-label">'+esc(label)+'</div><div class="stat-value">'+esc(value)+'</div><div class="stat-sub">'+esc(sub)+'</div></div>'}
  function detailList(obj){return '<div class="detail-grid">'+Object.entries(obj).map(([k,v])=>'<div class="detail-item"><div class="detail-key">'+esc(moduleLabel(k))+'</div><div class="detail-value">'+formatValue(v)+'</div></div>').join('')+'</div>'}
  function findingHtml(f){
    const sev=String(f.Severity||'Info').toLowerCase();
    return '<div class="finding '+esc(sev)+'"><div class="finding-title">'+esc(f.Title||'Finding')+'</div><div class="finding-meta">'+esc(severityLabel(f.Severity||'Info'))+' · '+esc(f.Category||'')+' · '+esc(f.Object||'')+'</div><div class="finding-detail">'+esc(f.Details||'')+(f.Recommendation?'<br><strong>Recommandation :</strong> '+esc(f.Recommendation):'')+'</div></div>';
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
      (columns.length?'<table><thead><tr>'+columns.map(c=>'<th>'+esc(moduleLabel(c))+'</th>').join('')+'</tr></thead><tbody id="tableBody"></tbody></table>':'<div class="panel-body">Aucune donnée exploitable dans ce module.</div>')+
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