import React, { useEffect, useRef, useState } from 'react';
import { AppState, FlatList, Platform, Pressable, SafeAreaView, ScrollView, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { StatusBar } from 'expo-status-bar';
import {loadSavedCaseVersion,type SavedCaseVersion} from './savedCases';
import {FILTER_VALUES,reportQuery,fixedReviewRequest,type ReportFilters} from './reportFilters';
import { exportReport } from './exportReport';
import {moduleProgressText,type ModuleProgress} from './moduleProgress';
import { buildLabRequest, DISPOSABLE_POST_EXAMPLE, type LabModule } from './labPolicy';

type Scan = {api_cases:string[];cleanup_status:string;cleanup_attempted:number;directory_cases:string[];module_progress:Partial<Record<LabModule,ModuleProgress>>;progress_available:boolean;id:string; status:string; attempted:number; planned:number; error:string|null; modules:LabModule[]; custom_cases:unknown[]; retest_of:string|null};
type Finding = {id:string; path:string; status_code:number; summary:string; module:LabModule; severity:string; confidence:string; review_state:string; review_note:string;review_retest_id:string|null;reviewed_at:string|null; evidence?:{rule_id?:string; remediation?:string}};
const moduleLabels:Record<LabModule,string>={directories:'Directories · 3 resources + random missing-path control',vhosts:'Virtual hosts · 3 control/candidate requests',api:'API fixture · 6 two-actor ownership checks',parameters:'Parameter signals · 6 harmless marker checks',custom:'Custom cases · bounded declarative GET/lab POST checks',subdomains:'DNS fixture · 3 local control/candidate queries'};
const moduleBudgets:Record<LabModule,number>={directories:4,vhosts:3,api:6,parameters:6,custom:0,subdomains:3};
const terminal = new Set(['completed','cancelled','failed','timed_out','interrupted']);

export default function App() {
  const [base, setBase] = useState('');
  const [token, setToken] = useState('');
  const [connected, setConnected] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [savedCases,setSavedCases]=useState<SavedCaseVersion[]>([]);
  const [caseName,setCaseName]=useState('My fixture cases');
  const [caseSource,setCaseSource]=useState('');
  const [moreCases,setMoreCases]=useState(false);
  const [customText,setCustomText]=useState('[{"path":"/health","method":"GET","params":{},"expect_status":200,"contains":"fixture"}]');
  const [modules, setModules] = useState<LabModule[]>(['directories']);
  const [apiCases,setApiCases]=useState<string[]>([]);
  const [directoryCases,setDirectoryCases]=useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<Scan|null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tab, setTab] = useState<'run'|'history'|'report'>('run');
  const [report,setReport]=useState<{summary:string;partial:boolean;limitations:string;totals:Record<string,unknown>;findings:Finding[];unfiltered_findings:number;filters:ReportFilters}|null>(null);
  const [filters,setFilters]=useState<ReportFilters>({});
  const [reviewNote,setReviewNote]=useState('');
  const [reviewRetest,setReviewRetest]=useState('');
  const [snapshot,setSnapshot]=useState('');
  const [comparison,setComparison]=useState('');
  const pendingKey = useRef<string|null>(null);
  const active = useRef(true);
  const inFlight = useRef(false);

  useEffect(() => {
    if (Platform.OS !== 'web') {
      Promise.all([SecureStore.getItemAsync('apiBase'), SecureStore.getItemAsync('apiToken')])
        .then(([url,key]) => {if(url)setBase(url);if(key)setToken(key);})
        .catch(() => setError('Saved connection could not be loaded. Enter it again.'));
    }
    const subscription = AppState.addEventListener('change', state => {active.current = state === 'active';});
    return () => subscription.remove();
  }, []);

  async function request(path:string, options:RequestInit = {},format:'json'|'text'='json') {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(base.replace(/\/$/,'') + path, {...options, signal:controller.signal,
        headers: {'Content-Type':'application/json', Authorization:`Bearer ${token}`, ...options.headers}});
      if (!response.ok) {
        if (response.status === 401) {setConnected(false);throw new Error('Connection token was rejected.');}
        throw new Error(`API request failed (${response.status}). Check the backend and retry.`);
      }
      return format==='text'?await response.text():await response.json();
    } finally {clearTimeout(timer);}
  }

  async function refresh(id?:string) {
    if(inFlight.current)return;
    inFlight.current = true;
    try {
      const list:Scan[] = await request('/v1/scans'); setScans(list);
      if (id) {
        const detail:Scan = await request(`/v1/scans/${id}`); setSelected(detail);
        setFindings(await request(`/v1/scans/${id}/findings`));
      }
      setError('');
    } finally {inFlight.current = false;}
  }

  useEffect(() => {
    if(!connected || !selected || terminal.has(selected.status))return;
    const timer = setInterval(() => {
      if(active.current) refresh(selected.id).catch(() => setError('Backend unreachable. Scan state is unknown until connection returns.'));
    },2000);
    return () => clearInterval(timer);
  },[connected, selected?.id, selected?.status, base, token]);

  async function action(fn:()=>Promise<void>) {
    setBusy(true);setError('');
    try {await fn();} catch(e) {setError(e instanceof Error ? e.message : 'Could not complete the request.');}
    finally {setBusy(false);}
  }

  async function loadCases(afterId?:string){
    const page:SavedCaseVersion[]=await request('/v1/custom-cases'+(afterId?'?after_id='+encodeURIComponent(afterId):''));
    setSavedCases(current=>afterId?[...current,...page.filter(row=>!current.some(old=>old.id===row.id))]:page);setMoreCases(page.length===50);
  }
  async function saveCases(){
    let cases:unknown;try{cases=JSON.parse(customText);}catch{throw new Error('Custom cases must be a JSON array.');}
    if(!Array.isArray(cases))throw new Error('Custom cases must be a JSON array.');
    const row:SavedCaseVersion=await request('/v1/custom-cases',{method:'POST',body:JSON.stringify({name:caseName,cases})});
    setCaseSource(row.name+' · '+row.version.slice(0,12));await loadCases();
  }
  async function connect() {
    await action(async () => {
      let url:URL;try {url = new URL(base);} catch {throw new Error('Enter a complete HTTPS API address.');}
      if(url.protocol !== 'https:' && !(Platform.OS==='web' && url.hostname==='localhost' && url.protocol==='http:'))
        throw new Error('Use HTTPS for your API connection.');
      if(url.username || url.password || url.search || url.hash || !token.trim())throw new Error('Check the API address and connection token.');
      await request('/v1/targets');await refresh();await loadCases();
      if(Platform.OS!=='web') {await SecureStore.setItemAsync('apiBase',base);await SecureStore.setItemAsync('apiToken',token);}
      setConnected(true);
    });
  }

  async function start() {
    await action(async () => {
      let cases:unknown[]=[];
      if(modules.includes('custom')){let value:unknown;try{value=JSON.parse(customText);}catch{throw new Error('Custom cases must be a JSON array.');}if(!Array.isArray(value))throw new Error('Custom cases must be a JSON array.');cases=value;}
      const body = buildLabRequest(authorized, modules,cases,directoryCases,apiCases);
      if(!pendingKey.current)pendingKey.current = `mobile-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const row:Scan = await request('/v1/scans',{method:'POST',headers:{'Idempotency-Key':pendingKey.current},body:JSON.stringify(body)});
      pendingKey.current = null; setAuthorized(false);
      setTab('run');await refresh(row.id);
    });
  }

  async function openReport(nextFilters:ReportFilters=filters) {
    if(!selected)throw new Error('Choose a run first.');
    setReport(await request(`/v1/scans/${selected.id}/report.json${reportQuery(nextFilters)}`));setFilters(nextFilters);setSnapshot('');setComparison('');setTab('report');
  }
  async function retest() {
    if(!selected || !authorized)throw new Error('Confirm new authorization before this retest.');
    if(!pendingKey.current)pendingKey.current=`mobile-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const body={...buildLabRequest(authorized,selected.modules,selected.custom_cases,selected.directory_cases,selected.api_cases),retest_of:selected.id};
    const row:Scan=await request('/v1/scans',{method:'POST',headers:{'Idempotency-Key':pendingKey.current},body:JSON.stringify(body)});
    pendingKey.current=null;setAuthorized(false);setComparison('');setReport(null);setTab('run');await refresh(row.id);
  }

  return <SafeAreaView style={s.safe}><StatusBar style="light"/><ScrollView contentContainerStyle={s.page} keyboardShouldPersistTaps="handled">
    <View style={s.brand}><View style={s.mark}/><Text style={s.brandName}>FUZZCORE</Text><Text style={s.tag}>LAB EDITION</Text></View>
    <Text style={s.title}>A clear view of{ '\n' }your test surface.</Text>
    <Text style={s.intro}>Controlled discovery. Real evidence. No vulnerability claims without review.</Text>
    <View style={s.notice}><Text style={s.noticeTitle}>Authorized lab targets only</Text><Text style={s.body}>This build supports fixed-lab directory/vhost discovery and synthetic API ownership, harmless parameter signals and declarative custom cases. DNS discovery stays inside the local fixture. Reports and exports describe only these bounded fixture checks.</Text></View>
    {!connected ? <View style={s.card}>
      <Text style={s.heading}>Connect your backend</Text><Text style={s.body}>Your APK controls a separate server. The server must be running and reachable from this device.</Text>
      <Text style={s.label}>API ADDRESS</Text><TextInput style={s.input} value={base} onChangeText={setBase} placeholder="https://your-development-api" placeholderTextColor="#81909f" autoCapitalize="none" autoCorrect={false} keyboardType="url" accessibilityLabel="API address"/>
      <Text style={s.label}>CONNECTION TOKEN</Text><TextInput style={s.input} value={token} onChangeText={setToken} placeholder="Provided by your lab administrator" placeholderTextColor="#81909f" autoCapitalize="none" autoCorrect={false} secureTextEntry accessibilityLabel="Connection token"/>
      <Pressable disabled={busy} onPress={connect} style={[s.button,busy&&s.disabled]} accessibilityRole="button"><Text style={s.buttonText}>{busy?'Connecting…':'Connect to lab'}</Text></Pressable>
      <Text style={s.foot}>Token stored in device secure storage after connection. Web preview keeps it in memory only.</Text>
    </View> : <>
      <View style={s.tabs}>{(['run','history','report'] as const).map(t=><Pressable key={t} onPress={()=>t==='report'?action(openReport):setTab(t)} style={[s.tab,tab===t&&s.tabOn]} accessibilityRole="tab" accessibilityState={{selected:tab===t}}><Text style={s.tabText}>{t==='run'?'Run a scan':t==='history'?'History':'Report'}</Text></Pressable>)}</View>
      {tab==='run' ? <View style={s.card}>
        <Text style={s.label}>APPROVED TARGET</Text><Text style={s.heading}>FuzzCore fixture lab</Text><Text style={s.body}>One fixture destination · 2 requests/sec maximum · no redirects</Text>
        {(['directories','vhosts','api','parameters','custom','subdomains'] as const).map(module => <View key={module} style={s.notice}><Text style={s.body}>{moduleLabels[module]}</Text><Switch value={modules.includes(module)} disabled={busy || !!pendingKey.current || (!!selected && !terminal.has(selected.status))} accessibilityLabel={`Select ${module} module`} onValueChange={enabled=>{setModules(current=>enabled?[...current,module]:current.filter(m=>m!==module));if(module==='directories'&&!enabled)setDirectoryCases([]);if(module==='api'&&!enabled)setApiCases([]);setAuthorized(false);}}/></View>)}
        {modules.includes('api')&&<View style={s.notice}><Text style={s.body}>Include curated API inventory: 4 additional read-only lab requests, a random missing control and named public/protected/hidden fixture routes. Header-presence and isolated HTTP metadata are informational, not proof about production HTTPS or vulnerabilities. Off by default. No arbitrary endpoint import or follow-up targets.</Text><Switch accessibilityLabel="Include curated API inventory checks" value={apiCases.includes('inventory-v1')} disabled={busy||!!pendingKey.current||!!selected&&!terminal.has(selected.status)} onValueChange={enabled=>{setApiCases(enabled?['inventory-v1']:[]);setAuthorized(false);}}/></View>}
        {modules.includes('directories')&&<View style={s.notice}><Text style={s.body}>Include synthetic file canary: 3 additional read-only lab requests. Symbolic fixture data only, no host file reads or inclusion. Off by default.</Text><Switch accessibilityLabel="Include synthetic file canary checks" value={directoryCases.includes('canary-v1')} disabled={busy || !!pendingKey.current || (!!selected && !terminal.has(selected.status))} onValueChange={enabled=>{setDirectoryCases(current=>enabled?[...current.filter(c=>c!=='canary-v1'),'canary-v1']:current.filter(c=>c!=='canary-v1'));setAuthorized(false);}}/></View>}
        {modules.includes('directories')&&<View style={s.notice}><Text style={s.body}>Include benign temporary upload: fixed harmless text in memory only. Create, read, delete and verify absence, plus 2 reserved cleanup requests for operator recovery. Cleanup continues after cancellation; unresolved cleanup blocks new uploads. 5-minute fixture expiry is a fallback, not proof of deletion. No executable files or host filesystem writes. Off by default.</Text><Switch accessibilityLabel="Include benign upload cleanup checks" value={directoryCases.includes('upload-v1')} disabled={busy || !!pendingKey.current || (!!selected && !terminal.has(selected.status))} onValueChange={enabled=>{setDirectoryCases(current=>enabled?[...current.filter(c=>c!=='upload-v1'),'upload-v1']:current.filter(c=>c!=='upload-v1'));setAuthorized(false);}}/></View>}
        {modules.includes('custom') && <><Text style={s.label}>CUSTOM CASES JSON · MAXIMUM 3</Text><Text style={s.body}>GET: /health, /api/status, /custom-fixture. POST: /custom-disposable only, with one harmless marker and no retained data. Optional expected status, literal text and content-type/x-fixture-mode header checks. No code or arbitrary URLs.</Text><TextInput multiline style={[s.input,{minHeight:130}]} value={customText} editable={!busy && !pendingKey.current && (!selected || terminal.has(selected.status))} onChangeText={text=>{setCustomText(text);setCaseSource('Edited copy, save to create a new immutable version.');setAuthorized(false);}} accessibilityLabel="Custom cases JSON" autoCapitalize="none" autoCorrect={false} maxLength={2000}/><Pressable disabled={busy || !!pendingKey.current || (!!selected && !terminal.has(selected.status))} style={s.secondary} accessibilityRole="button" onPress={()=>{setCustomText(JSON.stringify([DISPOSABLE_POST_EXAMPLE],null,2));setCaseSource('Unsaved disposable POST example.');setAuthorized(false);}}><Text style={s.link}>Use disposable POST example</Text></Pressable></>}
        {modules.includes('custom')&&<View style={s.notice}><Text style={s.heading}>Saved case versions</Text><Text style={s.body}>Saving or loading never starts a scan. Versions are immutable. Loading copies the cases into this editor and requires fresh authorization; later edits do not change past runs.</Text><TextInput style={s.input} accessibilityLabel="Saved case name" value={caseName} onChangeText={setCaseName} maxLength={80} editable={!busy}/><Pressable style={s.secondary} accessibilityRole="button" disabled={busy||!!pendingKey.current||!!selected&&!terminal.has(selected.status)} onPress={()=>action(saveCases)}><Text style={s.link}>Save immutable case version</Text></Pressable><Pressable style={s.secondary} accessibilityRole="button" disabled={busy} onPress={()=>action(()=>loadCases())}><Text style={s.link}>Refresh saved versions</Text></Pressable>{!!caseSource&&<Text style={s.foot}>Editor source: {caseSource}</Text>}{savedCases.length===0?<Text style={s.body}>No saved versions. Save the validated cases above to reuse them.</Text>:savedCases.map(value=><View key={value.id} style={s.finding}><Text style={s.path}>{value.name}</Text><Text style={s.foot}>{value.version.slice(0,12)} · {value.cases.length} cases · {value.created_at}</Text><Pressable style={s.secondary} accessibilityLabel={`Load saved version ${value.id}`} accessibilityRole="button" disabled={busy||!!pendingKey.current||!!selected&&!terminal.has(selected.status)} onPress={()=>action(async()=>{const row:SavedCaseVersion=await request('/v1/custom-cases/'+value.id);const loaded=loadSavedCaseVersion(row);setCustomText(loaded.text);setCaseSource(loaded.source);setCaseName(row.name);setAuthorized(loaded.authorized);})}><Text style={s.link}>Load version into editor</Text></Pressable></View>)}{moreCases&&<Pressable style={s.secondary} accessibilityRole="button" disabled={busy} onPress={()=>action(()=>loadCases(savedCases[savedCases.length-1]?.id))}><Text style={s.link}>Load older versions</Text></Pressable>}</View>}
        <Text style={s.foot}>{modules.reduce((total,module)=>total+moduleBudgets[module],0)+directoryCases.reduce((total,caseId)=>total+(caseId==='upload-v1'?6:3),0)+4*apiCases.length} maximum budget including selected cleanup reserves, plus up to 3 selected custom cases. Every case shares the same request budget. Virtual-host differences are discoveries. API proof applies only to the deliberately seeded synthetic lab.</Text>
        <View style={s.notice}><Text style={s.body}>I am authorized to test this fixed fixture lab. This confirmation does not permit other targets.</Text><Switch value={authorized} onValueChange={setAuthorized} disabled={busy} accessibilityLabel="Confirm authorization for this lab scan" /></View>
        <Pressable disabled={!authorized || !modules.length || busy || (!!selected && !terminal.has(selected.status))} style={[s.button,(!authorized || !modules.length || busy || (!!selected && !terminal.has(selected.status)))&&s.disabled]} onPress={start} accessibilityRole="button"><Text style={s.buttonText}>{busy?'Working…':'Start lab scan'}</Text></Pressable>
        {selected && <><View style={s.divider}/><Text style={s.label}>LATEST RUN</Text><Text style={s.status}>{selected.status.replace('_',' ')}</Text><Text style={s.body}>{selected.attempted} / {selected.planned} checks attempted</Text>
          {selected.directory_cases.includes('upload-v1')&&<Text style={selected.cleanup_status==='unverified'||selected.cleanup_status==='pending'?s.error:s.body}>Upload cleanup: {selected.cleanup_status.replaceAll('_',' ')} · {selected.cleanup_attempted}/4 cleanup attempts. Expiry alone is not verified cleanup.</Text>}
          <Text style={s.heading}>Module progress</Text><Text style={s.foot}>Completed means a check returned a response, not that its target is safe. Attempted includes a request still in flight or failed.</Text>{selected.progress_available?selected.modules.map(module=><View key={module} style={s.finding} accessibilityLabel={`${module} progress`}><Text style={s.path}>{module.replaceAll('_',' ')}</Text><Text style={s.body}>{moduleProgressText(selected.module_progress[module])}</Text></View>):<Text style={s.body}>{moduleProgressText(undefined)}</Text>}
          {!!selected.error && <Text style={s.error}>{selected.error.replaceAll('_',' ')}</Text>}
          {!terminal.has(selected.status) && <Pressable disabled={busy} style={s.secondary} onPress={()=>action(async()=>{await request(`/v1/scans/${selected.id}/cancel`,{method:'POST'});await refresh(selected.id);})} accessibilityRole="button"><Text style={s.link}>Cancel scan</Text></Pressable>}
          <Text style={s.heading}>Discoveries</Text>{findings.length===0?<Text style={s.body}>No resources recorded for this run yet.</Text>:findings.map(f=><View key={f.id} style={s.finding}><Text style={s.path}>{f.path} <Text style={s.code}>{f.status_code}</Text></Text><Text style={s.foot}>{f.module} · {f.severity} · {f.confidence} · {f.evidence?.rule_id || 'resource-status-v1'}</Text><Text style={s.body}>{f.summary}</Text>{!!f.evidence?.remediation && <Text style={s.body}>Fix: {f.evidence.remediation}</Text>}</View>)}
        </>}
      </View> : tab==='history' ? <View style={s.card}><Text style={s.heading}>Recent runs</Text>{scans.length===0?<Text style={s.body}>No scans yet. Start a lab scan to see it here.</Text>:scans.map(row=><Pressable key={row.id} style={s.finding} onPress={()=>action(async()=>{await refresh(row.id);setTab('run');})} accessibilityRole="button"><Text style={s.path}>{row.status} · {row.attempted}/{row.planned}</Text><Text style={s.foot}>{row.id.slice(0,8)}</Text></Pressable>)}</View> : <View style={s.card}><Text style={s.heading}>Run report</Text>{!report?<Text style={s.body}>Select a run in History, then open Report.</Text>:<>
        <View style={s.notice}><Text style={s.heading}>Report filters</Text><Text style={s.body}>Filters apply to this view, both exports and new snapshots. They do not change scan scope or the full stored results. {report.unfiltered_findings} unfiltered observations.</Text>{(Object.keys(FILTER_VALUES) as (keyof typeof FILTER_VALUES)[]).map(key=><Pressable key={key} disabled={busy} style={s.secondary} accessibilityRole="button" accessibilityLabel={`Report filter ${key}: ${filters[key]||'all'}`} onPress={()=>action(async()=>{const options:readonly string[]=FILTER_VALUES[key];const current=filters[key];const next=current?options[options.indexOf(current)+1]:options[0];const value={...filters};if(next)value[key]=next;else delete value[key];await openReport(value);})}><Text style={s.link}>{key.replaceAll('_',' ')}: {filters[key]||'all'} · next</Text></Pressable>)}<Pressable disabled={busy} style={s.secondary} accessibilityRole="button" onPress={()=>action(()=>openReport({}))}><Text style={s.link}>Clear report filters</Text></Pressable></View>
        <Text style={s.body}>{report.summary}</Text><Text style={s.error}>{report.partial?'Partial or in-progress run. Results are incomplete.':'Completed bounded fixture run, not an exhaustive assessment.'}</Text><Text style={s.body}>{report.limitations}</Text>
        <Text selectable style={s.foot}>{JSON.stringify(report.totals,null,2)}</Text>
        <Pressable disabled={busy} style={s.button} onPress={()=>action(async()=>{if(!selected)return;const value=await request(`/v1/scans/${selected.id}/report.json${reportQuery(filters)}`);await exportReport(selected.id,'json',JSON.stringify(value,null,2));})} accessibilityRole="button"><Text style={s.buttonText}>Export JSON</Text></Pressable>
        <Pressable disabled={busy} style={s.secondary} onPress={()=>action(async()=>{if(!selected)return;const value=await request(`/v1/scans/${selected.id}/report.html${reportQuery(filters)}`,{},'text');await exportReport(selected.id,'html',value);})} accessibilityRole="button"><Text style={s.link}>Export printable HTML</Text></Pressable>
        <Pressable disabled={busy} style={s.secondary} onPress={()=>action(async()=>{if(!selected)return;const value=await request(`/v1/scans/${selected.id}/report-snapshots${reportQuery(filters)}`,{method:'POST'});setSnapshot(value.id);})} accessibilityRole="button"><Text style={s.link}>Save immutable snapshot</Text></Pressable>{!!snapshot&&<Text selectable style={s.foot}>Saved snapshot: {snapshot}</Text>}
        <Text style={s.heading}>Review findings</Text><Text style={s.body}>A fixed review is your manual decision, only after a completed same-scope linked retest did not observe that fingerprint. It does not prove source changes or target security. Enter your note and retest ID, then choose the specific finding.</Text><TextInput style={[s.input,{minHeight:90}]} multiline accessibilityLabel="Manual fixed review note" value={reviewNote} onChangeText={setReviewNote} maxLength={500}/><TextInput style={s.input} accessibilityLabel="Completed linked retest ID" value={reviewRetest} onChangeText={setReviewRetest} maxLength={64} autoCapitalize="none" autoCorrect={false}/>{report.findings.length===0&&<Text style={s.body}>No findings match these filters. This is not a security certificate.</Text>}{report.findings.map(f=><View key={f.id} style={s.finding}><Text style={s.path}>{f.path}</Text><Text style={s.body}>{f.review_state} · {f.severity} · {f.confidence}</Text>{!!f.reviewed_at&&<Text style={s.foot}>Reviewed: {f.reviewed_at} · {f.review_note}{f.review_retest_id?' · Linked retest: '+f.review_retest_id:''}</Text>}{(['open','acknowledged','retest_requested'] as const).map(state=><Pressable key={state} disabled={busy} style={s.secondary} accessibilityRole="button" onPress={()=>action(async()=>{if(!selected)return;await request(`/v1/scans/${selected.id}/findings/${f.id}/review`,{method:'PATCH',body:JSON.stringify({state})});await refresh(selected.id);await openReport();})}><Text style={s.link}>{state.replaceAll('_',' ')}</Text></Pressable>)}<Pressable disabled={busy||!reviewNote.trim()||!reviewRetest.trim()} style={s.secondary} accessibilityRole="button" accessibilityLabel={`Mark finding ${f.id} fixed after manual retest review`} onPress={()=>action(async()=>{if(!selected)return;await request(`/v1/scans/${selected.id}/findings/${f.id}/review`,{method:'PATCH',body:JSON.stringify(fixedReviewRequest(reviewNote,reviewRetest))});await refresh(selected.id);await openReport();})}><Text style={s.link}>Mark fixed after my retest review</Text></Pressable></View>)}
        {!!selected&&terminal.has(selected.status)&&<><Text style={s.body}>After a manual fixture change, retest the same module/case snapshot. Confirm fresh authorization on Run a scan first. A missing result is not automatically fixed.</Text><Pressable disabled={busy||!authorized} style={[s.button,(!authorized||busy)&&s.disabled]} onPress={()=>action(retest)} accessibilityRole="button"><Text style={s.buttonText}>Retest same scope</Text></Pressable></>}
        {!!selected?.retest_of&&terminal.has(selected.status)&&<Pressable disabled={busy} style={s.secondary} accessibilityRole="button" onPress={()=>action(async()=>{if(selected)setComparison(JSON.stringify(await request(`/v1/scans/${selected.id}/retest-comparison`),null,2));})}><Text style={s.link}>Compare linked retest</Text></Pressable>}{!!comparison&&<Text selectable style={s.foot}>{comparison}</Text>}
      </>}</View>}
      <Pressable disabled={busy} onPress={()=>action(async()=>refresh(selected?.id))} style={s.secondary} accessibilityRole="button"><Text style={s.link}>Refresh status</Text></Pressable>
      <Pressable onPress={()=>action(async()=>{setConnected(false);setAuthorized(false);pendingKey.current=null;setToken('');setSavedCases([]);setCaseSource('');setMoreCases(false);setSelected(null);setReport(null);setFilters({});setReviewNote('');setReviewRetest('');setSnapshot('');setComparison('');setFindings([]);setScans([]);if(Platform.OS!=='web')await SecureStore.deleteItemAsync('apiToken');})} style={s.secondary} accessibilityRole="button"><Text style={s.muted}>Disconnect and remove token</Text></Pressable>
    </>}
    {!!error && <View style={s.errorBox} accessibilityRole="alert"><Text style={s.error}>{error}</Text></View>}
    <Text style={s.footer}>LAB / DEVELOPMENT BUILD{ '\n' }Finding a resource does not prove it is vulnerable.</Text>
  </ScrollView></SafeAreaView>;
}

const s = StyleSheet.create({
 safe:{flex:1,backgroundColor:'#0c1420'},page:{padding:24,paddingTop:40,paddingBottom:44,maxWidth:760,width:'100%',alignSelf:'center',gap:18},brand:{flexDirection:'row',alignItems:'center',gap:10,flexWrap:'wrap'},mark:{height:20,width:8,backgroundColor:'#65e0c3',borderRadius:3},brandName:{color:'#f5f8fa',fontWeight:'800',fontSize:16,letterSpacing:2},tag:{color:'#65e0c3',fontSize:10,letterSpacing:1,marginLeft:'auto'},title:{color:'#f5f8fa',fontWeight:'700',fontSize:34,lineHeight:41,marginTop:12},intro:{color:'#aebdca',fontSize:16,lineHeight:25},notice:{borderLeftWidth:3,borderLeftColor:'#65e0c3',padding:15,backgroundColor:'#122733',gap:7},noticeTitle:{color:'#8eecd7',fontSize:14,fontWeight:'700'},body:{color:'#afc0cd',fontSize:14,lineHeight:23},card:{backgroundColor:'#152131',padding:20,borderRadius:18,borderWidth:1,borderColor:'#263749',gap:12},heading:{color:'#f5f8fa',fontSize:21,fontWeight:'700',marginTop:3},label:{color:'#86a3b7',fontSize:10,fontWeight:'700',letterSpacing:1.4,marginTop:9},input:{minHeight:50,borderRadius:8,borderWidth:1,borderColor:'#384b61',padding:12,color:'#f5f8fa',fontSize:14,backgroundColor:'#0d1927'},button:{backgroundColor:'#65e0c3',borderRadius:8,paddingVertical:16,alignItems:'center',marginTop:8,minHeight:50},buttonText:{fontWeight:'700',fontSize:15,color:'#08291f'},disabled:{opacity:.4},foot:{color:'#8295a8',fontSize:11,lineHeight:18},footer:{color:'#748a9d',fontSize:10,lineHeight:20,letterSpacing:.6,textAlign:'center',marginTop:14},tabs:{flexDirection:'row',gap:10},tab:{padding:13,borderRadius:8,backgroundColor:'#152131',flex:1,alignItems:'center'},tabOn:{borderWidth:1,borderColor:'#65e0c3'},tabText:{color:'#d8e8ec',fontSize:14},divider:{height:1,backgroundColor:'#304356',marginVertical:10},status:{color:'#65e0c3',fontSize:26,fontWeight:'600',textTransform:'capitalize'},secondary:{minHeight:46,justifyContent:'center',alignItems:'center',padding:10},link:{color:'#65e0c3',fontWeight:'600',fontSize:14},muted:{color:'#8295a8',fontSize:13},finding:{paddingVertical:14,borderBottomWidth:1,borderBottomColor:'#2a3b4c',gap:7},path:{color:'#f5f8fa',fontSize:15,fontWeight:'600'},code:{color:'#65e0c3'},errorBox:{padding:16,borderRadius:8,backgroundColor:'#38212b'},error:{color:'#ffb8c6',fontSize:14,lineHeight:22}
});
