// Public community-maintained directory snapshots, not official authorization feeds.
export const FEEDS=Object.freeze({hackerone:'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json',bugcrowd:'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json'});
const discoveryHost=/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
function hostSuggestion(raw){
 if(typeof raw!=='string'||raw.length>2048)return null;
 const text=raw.trim().toLowerCase();if(discoveryHost.test(text))return text;
 try{const u=new URL(text);if(u.protocol!=='https:'||u.username||u.password||u.port||u.pathname!=='/'||u.search||u.hash||!discoveryHost.test(u.hostname))return null;return u.hostname;}catch{return null;}
}
export function normalizeDiscovery(data,source,retrievedAt=new Date().toISOString()){
 if(!FEEDS[source])throw new Error('Unknown directory source.');
 if(!Array.isArray(data)||data.length>10000)throw new Error('Unsupported directory schema or size.');
 const expected=source==='hackerone'?'hackerone.com':'bugcrowd.com',result=[],seen=new Set();
 for(const raw of data){
  if(!raw||typeof raw.name!=='string'||raw.name.length>300||!raw.targets||!Array.isArray(raw.targets.in_scope)||!Array.isArray(raw.targets.out_of_scope))continue;
  let policy;try{policy=new URL(raw.url);if(policy.protocol!=='https:'||policy.hostname!==expected||policy.username||policy.password||policy.port||policy.search||policy.hash)continue;}catch{continue;}
  if(seen.has(policy.href)||source==='hackerone'&&raw.submission_state!=='open')continue;seen.add(policy.href);
  const suggestedHosts=[],suggestedExclusions=[],restrictedScope=[];
  for(const [key,dest,label] of [['in_scope',suggestedHosts,'Included'],['out_of_scope',suggestedExclusions,'Excluded']]){
   const targets=raw.targets[key];if(targets.length>100)restrictedScope.push(`${label}: directory has more than 100 entries; view the complete official policy.`);
   for(const t of targets.slice(0,100)){const value=source==='hackerone'?t?.asset_identifier:t?.target;const assetType=source==='hackerone'?t?.asset_type:t?.type;const supported=source==='hackerone'?['URL','WILDCARD','API','DOMAIN'].includes(assetType):['website','api'].includes(assetType);const host=supported?hostSuggestion(value):null;if(!supported)restrictedScope.push(`${label}: unsupported asset type ${String(assetType||'unspecified').slice(0,80)}; interpret the official policy manually.`);if(host)dest.push(host);else restrictedScope.push(`${label}: ${String(value||'Unsupported asset').slice(0,250)}`);if(t?.instruction)restrictedScope.push(`${label} asset has additional program instructions; consult official policy.`);if(source==='hackerone'&&key==='in_scope'&&t.eligible_for_submission===false)restrictedScope.push('Included asset is not eligible for submission; consult official policy.');}
  }
  result.push({id:`${source}:${policy.pathname}`,name:raw.name.trim().slice(0,120),policy:policy.href,source,sourceURL:FEEDS[source],retrievedAt,authorized:false,suggestedHosts:[...new Set(suggestedHosts)],suggestedExclusions:[...new Set(suggestedExclusions)],restrictedScope,offersBounties:source==='hackerone'?raw.offers_bounties===true:Number(raw.max_payout)>0,maxReward:Number.isFinite(raw.max_payout)&&raw.max_payout>0?raw.max_payout:null,scopeCount:raw.targets.in_scope.length,exclusionCount:raw.targets.out_of_scope.length});
 }
 return result.sort((a,b)=>Number(b.offersBounties)-Number(a.offersBounties)||a.name.localeCompare(b.name));
}
export function prepareCandidate(p){
 return {id:p.id,name:p.name,policy:p.policy,hosts:p.restrictedScope.length?[]:p.suggestedHosts,excluded:p.restrictedScope.length?[]:p.suggestedExclusions,expires:'',authorized:false,provenance:{source:p.source,sourceURL:p.sourceURL,retrievedAt:p.retrievedAt},reviewWarning:p.restrictedScope.length?'This listing includes path-specific, unsupported, or additional restrictions. Read the official policy and enter the permitted scope manually.':'Host suggestions are copied from an unofficial community snapshot. Review the current official policy and exclusions before confirming permission.'};
}
export async function fetchDiscovery(source,fetcher=fetch){
 const url=FEEDS[source];if(!url)throw new Error('Unknown directory source.');
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),45000);
 try{
  const response=await fetcher(url,{method:'GET',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',cache:'no-store',signal:controller.signal});
  if(!response.ok)throw new Error(`Directory download failed (${response.status}). Try again later.`);
  const limit=25000000;if(Number(response.headers.get('content-length')||0)>limit)throw new Error('Directory exceeds the 25 MB limit.');
  if(!response.body?.getReader)throw new Error('This browser cannot safely stream the directory. Update your browser or import a program file.');
  const reader=response.body.getReader(),decoder=new TextDecoder();let size=0,text='';
  try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){controller.abort();throw new Error('Directory exceeds the 25 MB limit.');}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}finally{reader.releaseLock();}
  return normalizeDiscovery(JSON.parse(text),source);
 }catch(error){if(error.name==='AbortError')throw new Error('Directory request timed out. No program scope was changed.');throw error;}finally{clearTimeout(timer);}
}
