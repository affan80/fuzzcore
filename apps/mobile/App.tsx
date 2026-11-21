import React, { useEffect, useRef, useState } from 'react';
import { AppState, FlatList, Platform, Pressable, SafeAreaView, ScrollView, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { StatusBar } from 'expo-status-bar';
import { buildLabRequest, type LabModule } from './labPolicy';

type Scan = {id:string; status:string; attempted:number; planned:number; error:string|null; modules:LabModule[]};
type Finding = {id:string; path:string; status_code:number; summary:string; module:LabModule; evidence?:{rule_id?:string}};
const terminal = new Set(['completed','cancelled','failed','timed_out','interrupted']);

export default function App() {
  const [base, setBase] = useState('');
  const [token, setToken] = useState('');
  const [connected, setConnected] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [modules, setModules] = useState<LabModule[]>(['directories']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<Scan|null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tab, setTab] = useState<'run'|'history'>('run');
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

  async function request(path:string, options:RequestInit = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(base.replace(/\/$/,'') + path, {...options, signal:controller.signal,
        headers: {'Content-Type':'application/json', Authorization:`Bearer ${token}`, ...options.headers}});
      if (!response.ok) {
        if (response.status === 401) {setConnected(false);throw new Error('Connection token was rejected.');}
        throw new Error(`API request failed (${response.status}). Check the backend and retry.`);
      }
      return await response.json();
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

  async function connect() {
    await action(async () => {
      let url:URL;try {url = new URL(base);} catch {throw new Error('Enter a complete HTTPS API address.');}
      if(url.protocol !== 'https:' && !(Platform.OS==='web' && url.hostname==='localhost' && url.protocol==='http:'))
        throw new Error('Use HTTPS for your API connection.');
      if(url.username || url.password || url.search || url.hash || !token.trim())throw new Error('Check the API address and connection token.');
      await request('/v1/targets');await refresh();
      if(Platform.OS!=='web') {await SecureStore.setItemAsync('apiBase',base);await SecureStore.setItemAsync('apiToken',token);}
      setConnected(true);
    });
  }

  async function start() {
    await action(async () => {
      const body = buildLabRequest(authorized, modules);
      if(!pendingKey.current)pendingKey.current = `mobile-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const row:Scan = await request('/v1/scans',{method:'POST',headers:{'Idempotency-Key':pendingKey.current},body:JSON.stringify(body)});
      pendingKey.current = null; setAuthorized(false);
      setTab('run');await refresh(row.id);
    });
  }

  return <SafeAreaView style={s.safe}><StatusBar style="light"/><ScrollView contentContainerStyle={s.page} keyboardShouldPersistTaps="handled">
    <View style={s.brand}><View style={s.mark}/><Text style={s.brandName}>FUZZCORE</Text><Text style={s.tag}>LAB EDITION</Text></View>
    <Text style={s.title}>A clear view of{ '\n' }your test surface.</Text>
    <Text style={s.intro}>Controlled discovery. Real evidence. No vulnerability claims without review.</Text>
    <View style={s.notice}><Text style={s.noticeTitle}>Authorized lab targets only</Text><Text style={s.body}>This build supports fixed-lab directory and virtual-host discovery. API, parameter, custom and DNS modules and report export are not available yet.</Text></View>
    {!connected ? <View style={s.card}>
      <Text style={s.heading}>Connect your backend</Text><Text style={s.body}>Your APK controls a separate server. The server must be running and reachable from this device.</Text>
      <Text style={s.label}>API ADDRESS</Text><TextInput style={s.input} value={base} onChangeText={setBase} placeholder="https://your-development-api" placeholderTextColor="#81909f" autoCapitalize="none" autoCorrect={false} keyboardType="url" accessibilityLabel="API address"/>
      <Text style={s.label}>CONNECTION TOKEN</Text><TextInput style={s.input} value={token} onChangeText={setToken} placeholder="Provided by your lab administrator" placeholderTextColor="#81909f" autoCapitalize="none" autoCorrect={false} secureTextEntry accessibilityLabel="Connection token"/>
      <Pressable disabled={busy} onPress={connect} style={[s.button,busy&&s.disabled]} accessibilityRole="button"><Text style={s.buttonText}>{busy?'Connecting…':'Connect to lab'}</Text></Pressable>
      <Text style={s.foot}>Token stored in device secure storage after connection. Web preview keeps it in memory only.</Text>
    </View> : <>
      <View style={s.tabs}>{(['run','history'] as const).map(t=><Pressable key={t} onPress={()=>setTab(t)} style={[s.tab,tab===t&&s.tabOn]} accessibilityRole="tab" accessibilityState={{selected:tab===t}}><Text style={s.tabText}>{t==='run'?'Run a scan':'History'}</Text></Pressable>)}</View>
      {tab==='run' ? <View style={s.card}>
        <Text style={s.label}>APPROVED TARGET</Text><Text style={s.heading}>FuzzCore fixture lab</Text><Text style={s.body}>One fixture destination · 2 requests/sec maximum · no redirects</Text>
        {(['directories','vhosts'] as const).map(module => <View key={module} style={s.notice}><Text style={s.body}>{module==='directories'?'Directory discovery · 4 fixed paths':'Virtual hosts · default, random control, seeded host'}</Text><Switch value={modules.includes(module)} disabled={busy || (!!selected && !terminal.has(selected.status))} accessibilityLabel={`Select ${module} module`} onValueChange={enabled=>{setModules(current=>enabled?[...current,module]:current.filter(m=>m!==module));setAuthorized(false);}}/></View>)}
        <Text style={s.foot}>{(modules.includes('directories')?4:0)+(modules.includes('vhosts')?3:0)} total requests across selected modules. Virtual-host differences are discoveries, not proof of isolation failure.</Text>
        <View style={s.notice}><Text style={s.body}>I am authorized to test this fixed fixture lab. This confirmation does not permit other targets.</Text><Switch value={authorized} onValueChange={setAuthorized} disabled={busy} accessibilityLabel="Confirm authorization for this lab scan" /></View>
        <Pressable disabled={!authorized || !modules.length || busy || (!!selected && !terminal.has(selected.status))} style={[s.button,(!authorized || !modules.length || busy || (!!selected && !terminal.has(selected.status)))&&s.disabled]} onPress={start} accessibilityRole="button"><Text style={s.buttonText}>{busy?'Working…':'Start lab scan'}</Text></Pressable>
        {selected && <><View style={s.divider}/><Text style={s.label}>LATEST RUN</Text><Text style={s.status}>{selected.status.replace('_',' ')}</Text><Text style={s.body}>{selected.attempted} / {selected.planned} checks attempted</Text>
          {!!selected.error && <Text style={s.error}>{selected.error.replaceAll('_',' ')}</Text>}
          {!terminal.has(selected.status) && <Pressable disabled={busy} style={s.secondary} onPress={()=>action(async()=>{await request(`/v1/scans/${selected.id}/cancel`,{method:'POST'});await refresh(selected.id);})} accessibilityRole="button"><Text style={s.link}>Cancel scan</Text></Pressable>}
          <Text style={s.heading}>Discoveries</Text>{findings.length===0?<Text style={s.body}>No resources recorded for this run yet.</Text>:findings.map(f=><View key={f.id} style={s.finding}><Text style={s.path}>{f.path} <Text style={s.code}>{f.status_code}</Text></Text><Text style={s.foot}>{f.module} · informational · {f.evidence?.rule_id || 'resource-status-v1'}</Text><Text style={s.body}>{f.summary}</Text></View>)}
        </>}
      </View> : <View style={s.card}><Text style={s.heading}>Recent runs</Text>{scans.length===0?<Text style={s.body}>No scans yet. Start a lab scan to see it here.</Text>:scans.map(row=><Pressable key={row.id} style={s.finding} onPress={()=>action(async()=>{await refresh(row.id);setTab('run');})} accessibilityRole="button"><Text style={s.path}>{row.status} · {row.attempted}/{row.planned}</Text><Text style={s.foot}>{row.id.slice(0,8)}</Text></Pressable>)}</View>}
      <Pressable disabled={busy} onPress={()=>action(async()=>refresh(selected?.id))} style={s.secondary} accessibilityRole="button"><Text style={s.link}>Refresh status</Text></Pressable>
      <Pressable onPress={()=>action(async()=>{setConnected(false);setAuthorized(false);setToken('');setSelected(null);setFindings([]);setScans([]);if(Platform.OS!=='web')await SecureStore.deleteItemAsync('apiToken');})} style={s.secondary} accessibilityRole="button"><Text style={s.muted}>Disconnect and remove token</Text></Pressable>
    </>}
    {!!error && <View style={s.errorBox} accessibilityRole="alert"><Text style={s.error}>{error}</Text></View>}
    <Text style={s.footer}>LAB / DEVELOPMENT BUILD{ '\n' }Finding a resource does not prove it is vulnerable.</Text>
  </ScrollView></SafeAreaView>;
}

const s = StyleSheet.create({
 safe:{flex:1,backgroundColor:'#0c1420'},page:{padding:24,paddingTop:40,paddingBottom:44,maxWidth:760,width:'100%',alignSelf:'center',gap:18},brand:{flexDirection:'row',alignItems:'center',gap:10,flexWrap:'wrap'},mark:{height:20,width:8,backgroundColor:'#65e0c3',borderRadius:3},brandName:{color:'#f5f8fa',fontWeight:'800',fontSize:16,letterSpacing:2},tag:{color:'#65e0c3',fontSize:10,letterSpacing:1,marginLeft:'auto'},title:{color:'#f5f8fa',fontWeight:'700',fontSize:34,lineHeight:41,marginTop:12},intro:{color:'#aebdca',fontSize:16,lineHeight:25},notice:{borderLeftWidth:3,borderLeftColor:'#65e0c3',padding:15,backgroundColor:'#122733',gap:7},noticeTitle:{color:'#8eecd7',fontSize:14,fontWeight:'700'},body:{color:'#afc0cd',fontSize:14,lineHeight:23},card:{backgroundColor:'#152131',padding:20,borderRadius:18,borderWidth:1,borderColor:'#263749',gap:12},heading:{color:'#f5f8fa',fontSize:21,fontWeight:'700',marginTop:3},label:{color:'#86a3b7',fontSize:10,fontWeight:'700',letterSpacing:1.4,marginTop:9},input:{minHeight:50,borderRadius:8,borderWidth:1,borderColor:'#384b61',padding:12,color:'#f5f8fa',fontSize:14,backgroundColor:'#0d1927'},button:{backgroundColor:'#65e0c3',borderRadius:8,paddingVertical:16,alignItems:'center',marginTop:8,minHeight:50},buttonText:{fontWeight:'700',fontSize:15,color:'#08291f'},disabled:{opacity:.4},foot:{color:'#8295a8',fontSize:11,lineHeight:18},footer:{color:'#748a9d',fontSize:10,lineHeight:20,letterSpacing:.6,textAlign:'center',marginTop:14},tabs:{flexDirection:'row',gap:10},tab:{padding:13,borderRadius:8,backgroundColor:'#152131',flex:1,alignItems:'center'},tabOn:{borderWidth:1,borderColor:'#65e0c3'},tabText:{color:'#d8e8ec',fontSize:14},divider:{height:1,backgroundColor:'#304356',marginVertical:10},status:{color:'#65e0c3',fontSize:26,fontWeight:'600',textTransform:'capitalize'},secondary:{minHeight:46,justifyContent:'center',alignItems:'center',padding:10},link:{color:'#65e0c3',fontWeight:'600',fontSize:14},muted:{color:'#8295a8',fontSize:13},finding:{paddingVertical:14,borderBottomWidth:1,borderBottomColor:'#2a3b4c',gap:7},path:{color:'#f5f8fa',fontSize:15,fontWeight:'600'},code:{color:'#65e0c3'},errorBox:{padding:16,borderRadius:8,backgroundColor:'#38212b'},error:{color:'#ffb8c6',fontSize:14,lineHeight:22}
});
