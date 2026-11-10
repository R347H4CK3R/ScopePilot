'use strict';
(()=>{
const hostPattern=/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
function validateProgram(p, now=new Date()) {
 const errors=[];
 if(!p || typeof p!=='object') return ['Invalid program'];
 if(typeof p.name!=='string'||!p.name.trim()||p.name.length>120) errors.push('Enter a program name (1–120 characters).');
 try {const u=new URL(p.policy);if(u.protocol!=='https:'||u.username||u.password)throw 0;}catch{errors.push('Provide an HTTPS program policy URL.');}
 if(!Array.isArray(p.hosts)||!p.hosts.length||p.hosts.length>100||p.hosts.some(h=>typeof h!=='string'||!hostPattern.test(h)))errors.push('Enter valid exact hosts or *.domain.tld scope entries.');
 if(!Array.isArray(p.excluded)||p.excluded.some(h=>typeof h!=='string'||!hostPattern.test(h)))errors.push('Exclusions must be valid hosts.');
 if(!/^\d{4}-\d{2}-\d{2}$/.test(p.expires)||!Number.isFinite(Date.parse(p.expires))||new Date(p.expires).toISOString().slice(0,10)!==p.expires||new Date(p.expires)<=now)errors.push('Set a future authorization expiry date.');
 if(p.authorized!==true) errors.push('Review the current program policy and confirm your authorization.');
 return errors;
}
const matches=(host,rule)=>rule.startsWith('*.')?host.endsWith(rule.slice(1))&&host!==rule.slice(2):host===rule;
function inScope(target,p){
 if(validateProgram(p).length) return false;
 try{const u=new URL(target);return u.protocol==='https:'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&p.hosts.some(h=>matches(u.hostname,h))&&!p.excluded.some(h=>matches(u.hostname,h));}catch{return false;}
}
function redact(value){return String(value).replace(/^[ \t]*(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:.*$/gim,'$1: [REDACTED]');}
function analyze(url,headers,p){
 if(!inScope(url,p))throw new Error('Authorization missing, expired, or target outside approved scope. HTTPS on port 443 only; remove query strings and credentials.');
 if(typeof headers==='string'&&new TextEncoder().encode(headers).length>64000)throw new Error('Headers exceed 64 KB.');
 if(typeof headers!=='string'||headers.length>64000||!/^HTTP\/(?:1\.[01]|2|3)\s+[1-5]\d\d(?:\s|$)/.test(headers))throw new Error('Paste response headers beginning with a valid HTTP status line.');
 if(/\r?\n\r?\n\s*\S/.test(headers))throw new Error('Headers only. Remove the response body and any personal data.');
 const parsed=new Map();for(const line of headers.split(/\r?\n/).slice(1)){const i=line.indexOf(':');if(i>0)parsed.set(line.slice(0,i).trim().toLowerCase(),line.slice(i+1).trim());else if(line.trim())throw new Error('Malformed header line.');}
 const checks=[['content-security-policy','Content Security Policy not observed','Review whether this HTML response needs a CSP and demonstrate a relevant impact. Missing headers alone usually do not qualify for a bounty.'],['strict-transport-security','HSTS not observed','Verify transport policy in context. A missing header alone does not prove a vulnerability.'],['x-content-type-options','MIME protection not observed','Check whether a valid nosniff directive is present and whether content interpretation creates a demonstrable impact.']];
 return checks.filter(([key])=>!parsed.get(key)).map(([key,title,guidance])=>({id:key,title,guidance,severity:'Informational',status:'Needs verification'}));
}
function report({program,url,headers,findings,notes='',requestHeaders='',created=new Date().toISOString()}){
 return `# ScopePilot • Draft research report\n\nProgram: ${program.name}\nPolicy: ${program.policy}\nTarget: ${url}\nAuthorization expires: ${program.expires}${program.provenance?'\nDiscovery source: '+program.provenance.sourceURL+'\nSnapshot retrieved: '+program.provenance.retrievedAt:''}\nGenerated: ${created}\n\n## Status\nNo vulnerability is confirmed by this automated analysis. Human validation and program-rule review are required. No submission has been sent.\n\n## Observations\n${findings.length?findings.map(f=>`- ${f.title} (${f.severity}; ${f.status})\n  ${f.guidance}${f.evidence?'\n  Evidence: '+f.evidence:''}${f.confidence?'\n  Confidence: '+f.confidence:''}${f.validation?'\n  Validation: '+f.validation:''}${Array.isArray(f.references)?'\n  References: '+f.references.join(', '):''}`).join('\n'):'No missing-header observations. This is not a security clearance.'}\n\n## Researcher notes\n${redact(notes)||'Not yet provided. Add reproducible steps, actual impact, and remediation before submission.'}\n\n## Supplied request context\n${redact(requestHeaders)||'Not supplied.'}\n\n## Supplied response headers\n${redact(headers)}\n\nReview all content for secrets and personal data before sharing.\n`;
}
function reviseReportNotes(entry,notes){
 if(typeof notes!=='string')throw new Error('Researcher notes must be text.');
 if(notes.length>32000)throw new Error('Researcher notes exceed 32,000 characters.');
 const revised={...entry,notes:redact(notes)};
 if(revised.notes.length>32000)throw new Error('Redacted researcher notes exceed 32,000 characters. Shorten the notes.');
 if(new TextEncoder().encode(report(revised)).length>180000)throw new Error('Draft exceeds 180 KB. Shorten your notes before saving.');
 return revised;
}
function saveReportNotes(workspace,id,notes,persist){
 const entry=workspace.reports.find(r=>r.id===id);
 if(!entry)throw new Error('This report no longer exists.');
 const revised=reviseReportNotes(entry,notes);
 const next={...workspace,reports:workspace.reports.map(r=>r===entry?revised:r)};
 persist(next);
 return next;
}
function importPrograms(text){
 if(typeof text!=='string'||text.length>200000)throw new Error('Program file exceeds 200 KB.');
 const items=JSON.parse(text);if(!Array.isArray(items)||items.length>100)throw new Error('Expected an array of up to 100 programs.');
 const ids=new Set(); return items.map((p,i)=>{if(!p||typeof p!=='object')throw new Error('Invalid program entry.');const clean={id:String(p.id||`import-${i}`),name:p.name,policy:p.policy,hosts:p.hosts,excluded:p.excluded||[],expires:p.expires,authorized:true};if(ids.has(clean.id))throw new Error('Duplicate program IDs.');ids.add(clean.id);const errors=validateProgram(clean);if(errors.length)throw new Error(errors.join(' '));return {...clean,authorized:false};});
}
function restoreWorkspace(raw){
 if(raw===null)return {programs:[],reports:[]};
 const s=JSON.parse(raw),programValid=p=>p&&typeof p.id==='string'&&typeof p.authorized==='boolean'&&validateProgram({...p,authorized:true,expires:'2099-01-01'}).length===0&&typeof p.expires==='string';
 if(!s||!Array.isArray(s.programs)||!Array.isArray(s.reports)||s.programs.some(p=>!programValid(p))||s.reports.some(r=>!r||typeof r.id!=='string'||!programValid(r.program)||typeof r.url!=='string'||typeof r.headers!=='string'||typeof r.notes!=='string'||!Number.isFinite(Date.parse(r.created))||!Array.isArray(r.findings)||r.findings.some(f=>!f||['title','severity','status','guidance'].some(k=>typeof f[k]!=='string'))))throw new Error('Saved workspace has invalid entries.');
 return s;
}
// Public community-maintained directory snapshots, not official authorization feeds.
const FEEDS=Object.freeze({hackerone:'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json',bugcrowd:'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json'});
const discoveryHost=/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
function hostSuggestion(raw){
 if(typeof raw!=='string'||raw.length>2048)return null;
 const text=raw.trim().toLowerCase();if(discoveryHost.test(text))return text;
 try{const u=new URL(text);if(u.protocol!=='https:'||u.username||u.password||u.port||u.pathname!=='/'||u.search||u.hash||!discoveryHost.test(u.hostname))return null;return u.hostname;}catch{return null;}
}
function normalizeDiscovery(data,source,retrievedAt=new Date().toISOString()){
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
function prepareCandidate(p){
 return {id:p.id,name:p.name,policy:p.policy,hosts:p.restrictedScope.length?[]:p.suggestedHosts,excluded:p.restrictedScope.length?[]:p.suggestedExclusions,expires:'',authorized:false,provenance:{source:p.source,sourceURL:p.sourceURL,retrievedAt:p.retrievedAt},reviewWarning:p.restrictedScope.length?'This listing includes path-specific, unsupported, or additional restrictions. Read the official policy and enter the permitted scope manually.':'Host suggestions are copied from an unofficial community snapshot. Review the current official policy and exclusions before confirming permission.'};
}
async function fetchDiscovery(source,fetcher=fetch){
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
// Offline observations only. The caller must check scope and authorization first.
const TOKEN=/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const MDN='https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/';
function parseHeaders(input,request=false){
 if(typeof input!=='string') throw new Error('Headers must be text.');
 if(input.length>64000||new TextEncoder().encode(input).length>64000) throw new Error('Headers exceed 64 KB.');
 if(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(input)||/\r(?!\n)/.test(input)) throw new Error('Malformed header control characters.');
 const lines=input.replace(/\r\n/g,'\n').split('\n');
 if(!request){if(!/^HTTP\/(?:1\.[01]|2|3) [1-5]\d\d(?: [^\n]*)?$/.test(lines.shift()||''))throw new Error('Invalid response header status line.');}
 else if(/^[A-Z]+ \S+ HTTP\/(?:1\.[01]|2|3)$/.test(lines[0]))lines.shift();
 const map=new Map();let ended=false;
 for(const line of lines){
  if(line===''){ended=true;continue;}
  if(ended)throw new Error('Headers only; remove the body.');
  const colon=line.indexOf(':');const name=line.slice(0,colon);
  if(colon<1||!TOKEN.test(name))throw new Error('Malformed header line.');
  const key=name.toLowerCase();const values=map.get(key)||[];
  values.push(line.slice(colon+1).trim());map.set(key,values);
 }
 if(request&&(map.get('origin')||[]).length>1)throw new Error('Duplicate Origin request headers.');
 return map;
}
function one(headers,name){const values=headers.get(name)||[];return values.length===1?values[0]:undefined;}
function validOrigin(value){
 if(value==='null')return true;
 try{const u=new URL(value);return ['http:','https:'].includes(u.protocol)&&u.origin===value;}catch{return false;}
}
function observation(id,title,evidence,risk,validation,reference){return {id,title,evidence:`Observation: ${evidence}`,guidance:`Contextual risk: ${risk} No vulnerability is confirmed by these headers.`,validation:`Human exploitability validation: ${validation}`,severity:'Informational',status:'Needs verification',confidence:'High for supplied configuration; exploitability unverified',references:[MDN+reference]};}
function analyzeEvidence({url,headers,requestHeaders=''}={}){
 if(typeof url!=='string'||url.length>8192)throw new Error('Invalid target URL.');
 let target;try{target=new URL(url);}catch{throw new Error('Invalid target URL.');}
 if(!['http:','https:'].includes(target.protocol)||target.username||target.password)throw new Error('Invalid target URL.');
 const response=parseHeaders(headers),request=parseHeaders(requestHeaders,true),out=[];
 const add=(...args)=>out.push(observation(...args));
 (response.get('set-cookie')||[]).forEach((cookie,index)=>{
  const parts=cookie.split(';');const equal=parts[0].indexOf('=');const name=parts[0].slice(0,equal).trim();
  if(equal<1||!TOKEN.test(name))return;
  const attrs=new Map(parts.slice(1).map(p=>{const [k,...v]=p.trim().split('=');return [k.toLowerCase(),v.join('=').toLowerCase()];}));
  const missing=[];if(!attrs.has('secure'))missing.push('Secure');if(!attrs.has('httponly'))missing.push('HttpOnly');if(!/^(lax|strict|none)$/.test(attrs.get('samesite')||''))missing.push('SameSite');
  if(missing.length)add(`cookie-attributes-${index+1}`,'Cookie protection needs context',`Cookie ${name.slice(0,80)}: missing or invalid ${missing.join(', ')}. Cookie value omitted.`, 'Sensitive session cookies may need these attributes; a preference cookie may not. Browser SameSite defaults and application requirements affect impact.', 'In an authorized test account, identify whether this cookie controls authentication. Inspect its effective attributes in browser storage. Review cross-site and transport requirements without copying cookie values into a report.','Set-Cookie');
 });
 const allow=one(response,'access-control-allow-origin'),credentials=one(response,'access-control-allow-credentials'),origin=one(request,'origin');
 if(allow==='*'&&credentials==='true')add('cors-invalid-wildcard','Credentialed CORS has an invalid wildcard combination','Allow-Origin is wildcard and Allow-Credentials is true.','Browsers block credentialed reads for this combination. It does not establish cross-origin data exposure.','Review intended CORS policy and browser error logs. Do not report credentialed cross-origin exposure without a separate authorized demonstration of readable sensitive data.','Access-Control-Allow-Origin');
 else if(credentials==='true'&&origin&&validOrigin(origin)&&allow===origin)add('cors-credentialed','Credentialed CORS matches the supplied Origin','The supplied request Origin exactly matches the explicit response Allow-Origin; Allow-Credentials is true. Origin and credentials omitted.','An approved trusted origin is normal. Risk depends on whether an untrusted origin can read sensitive authenticated content; reflection is not established by one sample.','Verify who controls the matching origin, whether it is intended to be trusted, and whether the captured response contains sensitive account data. Only within program rules, have a human validate browser-readable impact using their own test account.','Access-Control-Allow-Credentials');
 const hsts=response.get('strict-transport-security');
 if(hsts&&target.protocol==='https:'){
  const ages=hsts.flatMap(v=>v.split(';').map(s=>s.trim()).filter(s=>/^max-age(?:\s*=|$)/i.test(s)));
  const match=ages.length===1&&/^max-age\s*=\s*(?:"(\d+)"|(\d+))$/i.exec(ages[0]);
  const age=match?Number(match[1]??match[2]):NaN;
  const kind=hsts.length!==1||!Number.isSafeInteger(age)?'invalid':age===0?'disabled':age<15552000?'short':null;
  if(kind)add(`hsts-${kind}`,`HSTS ${kind} policy observed`,kind==='invalid'?'HSTS has a missing, malformed, duplicate, or unsupported max-age. Raw values omitted.':`HSTS max-age is ${age} seconds.`, 'Transport protection depends on previous browser state, parent-domain policy, preload status, and first-visit conditions. A lifetime below 180 days is a review heuristic, not proof of a flaw.', 'Review the intended HSTS lifetime and parent-domain/preload coverage. Inspect effective browser policy using an authorized test environment; do not intercept another person’s traffic.','Strict-Transport-Security');
 }
 for(const [index,policy] of (response.get('content-security-policy')||[]).entries()){
  const directives=new Map();for(const part of policy.split(';')){const [name,...values]=part.trim().split(/\s+/);if(name&&!directives.has(name.toLowerCase()))directives.set(name.toLowerCase(),values);}
  const script=directives.get('script-src')??directives.get('default-src')??[];
  const elements=directives.get('script-src-elem')??script;
  const attributes=directives.get('script-src-attr')??script;
  const risky=new Set();
  for(const tokens of [elements,attributes]){
   if(tokens.includes("'unsafe-inline'")&&!tokens.some(v=>/^'(?:nonce-|sha(?:256|384|512)-)/.test(v)))risky.add("'unsafe-inline'");
  }
  if(script.includes("'unsafe-eval'"))risky.add("'unsafe-eval'");
  if(elements.includes('*'))risky.add('wildcard script source');
  if(risky.size)add(index?`csp-risky-${index+1}`:'csp-risky','CSP script allowances need review',`Enforced CSP contains ${[...risky].join(', ')} in effective script directives. Other source values omitted.`, 'These allowances can weaken defense in depth; they do not demonstrate injection. Multiple enforced policies intersect, and browser behavior and other protections can restrict execution.', 'Identify whether this response serves executable HTML, inspect all enforced policies in browser developer tools, and review whether these allowances are required. Human validation must establish an independently reproducible injection and impact within program rules.','Content-Security-Policy');
 }
 const caching=(response.get('cache-control')||[]).flatMap(s=>s.split(',').map(v=>v.trim().split('=')[0].toLowerCase()));
 const authenticated=['authorization','cookie'].some(key=>(request.get(key)||[]).some(Boolean));
 if(authenticated&&caching.includes('public')&&!caching.includes('no-store')&&!caching.includes('private'))add('cache-auth-public','Authenticated request has explicit public caching','Supplied request contains Authorization or Cookie; response explicitly includes Cache-Control: public without private/no-store. Credential values omitted.','Credentials do not prove this content is personalized or cached. Shared-cache exposure requires sensitive content and a reproducible cache-key or isolation failure.','Using only owned test accounts and approved environments, review whether content is personalized, cache keys vary correctly, and responses can cross account boundaries. Review Vary and CDN configuration. Never retrieve another person’s data.','Cache-Control');
 return out;
}
const HAR_RESPONSE_HEADERS=new Set(['content-type','content-security-policy','strict-transport-security','x-content-type-options','set-cookie','access-control-allow-origin','access-control-allow-credentials','cache-control','vary']);
const HAR_REQUEST_HEADERS=new Set(['origin','authorization','cookie']);
const HAR_HEADER_TOKEN=/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
function harHeaders(rows,request=false){
 if(!Array.isArray(rows)||rows.length>500)throw new Error('Invalid headers');
 return rows.map(h=>{
  if(!h||typeof h.name!=='string'||typeof h.value!=='string'||!HAR_HEADER_TOKEN.test(h.name)||/[\x00-\x08\x0a-\x1f\x7f]/.test(h.value))throw new Error('Invalid header');
  const name=h.name.toLowerCase();if(!(request?HAR_REQUEST_HEADERS:HAR_RESPONSE_HEADERS).has(name))return null;
  let value=h.value;
  if(name==='authorization'||name==='cookie'){
   // Redaction must not turn an empty field into evidence of authentication.
   if(!value.trim())return null;
   value='[REDACTED]';
  }
  if(name==='set-cookie'){
   const pair=value.split(';',1)[0],equal=pair.indexOf('=');
   // Preserve whether a cookie pair existed, without retaining its name or value.
   value=equal>0&&HAR_HEADER_TOKEN.test(pair.slice(0,equal).trim())?value.replace(/^[^;]*/, 'captured-cookie=[REDACTED]'):'[REDACTED]';
  }
  return `${name}: ${value}`;
 }).filter(Boolean).join('\n');
}
// No network access: only explicit, bounded local input is inspected.
function analyzeHar(text,program){
 if(validateProgram(program).length)throw new Error('Current program authorization and valid scope are required.');
 if(typeof text!=='string'||new TextEncoder().encode(text).length>5000000)throw new Error('HAR exceeds 5 MB. Export a smaller capture.');
 let data;try{data=JSON.parse(text);}catch{throw new Error('Invalid HAR JSON.');}
 if(!data?.log||!Array.isArray(data.log.entries))throw new Error('Expected a HAR log with entries.');
 if(data.log.entries.length>100)throw new Error('HAR exceeds 100 entries. Export a smaller capture.');
 const reports=[],skipped={scope:0,invalid:0,duplicate:0},seen=new Set();
 for(const e of data.log.entries){
  if(!e?.request||typeof e.request.url!=='string'||!inScope(e.request.url,program)){skipped.scope++;continue;}
  try{
   if(!e.response||!Number.isInteger(e.response.status)||e.response.status<100||e.response.status>599)throw new Error('Invalid response');
   const url=new URL(e.request.url).href,headers=`HTTP/2 ${e.response.status}\n${harHeaders(e.response.headers)}`,requestHeaders=harHeaders(e.request.headers,true);
   const findings=[...analyze(url,headers,program),...analyzeEvidence({url,headers,requestHeaders})];
   const method=typeof e.request.method==='string'&&/^[A-Z]{1,32}$/.test(e.request.method)?e.request.method:'not recorded';
   const key=JSON.stringify([url,method,headers,requestHeaders]);if(seen.has(key)){skipped.duplicate++;continue;}seen.add(key);
   const captured=typeof e.startedDateTime==='string'&&Number.isFinite(Date.parse(e.startedDateTime))?new Date(e.startedDateTime).toISOString():'not recorded';
   const draft={program:JSON.parse(JSON.stringify(program)),url,headers:redact(headers),requestHeaders:redact(requestHeaders),notes:`Imported from a user-selected HAR capture. Request method: ${method}. Capture timestamp (unverified): ${captured}. Status preserved; HTTP version normalized for offline parsing. Bodies, query-bearing URLs, custom headers, and credential values are not retained. Review retained URLs and policy headers for sensitive data. Add reproduction steps and demonstrated impact.`,findings,created:new Date().toISOString()};
   if(new TextEncoder().encode(report(draft)).length>180000)throw new Error('Report too large');
   reports.push(draft);
  }catch{skipped.invalid++;}
 }
 return {reports,skipped,total:data.log.entries.length};
}
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let candidates=[],discoveryLoading=false,discoveryError='',discoverySource='bugcrowd',discoveryQuery='',discoveryPage=0,programProvenance=null;
const reportEdits=new Map();
let page='overview', state={programs:[],reports:[]}, researchDraft={program:'',url:'',headers:'',requestHeaders:'',notes:''}, storageError='';
try{state=restoreWorkspace(localStorage.getItem('scopepilot-v1'));}catch{storageError='Saved workspace could not be read. Original data is preserved; saving is disabled for this session. Recover the app data before clearing storage.';}
const content=$('#content'), notify=text=>{$('#notice').textContent=text;clearTimeout(notify.timer);notify.timer=setTimeout(()=>$('#notice').textContent='',6000);};
function save(){if(storageError){notify(storageError);return false;}try{localStorage.setItem('scopepilot-v1',JSON.stringify(state));return true;}catch{notify('Storage unavailable or full. Your latest change is only in memory; export your reports now.');return false;}}
function go(next){captureDraft();page=next;document.querySelectorAll('nav button').forEach(b=>{b.classList.toggle('active',b.dataset.page===page);b.setAttribute('aria-current',b.dataset.page===page?'page':'false');});$('#breadcrumb').textContent=`WORKSPACE / ${page.toUpperCase()}`;render();window.scrollTo(0,0);}
function heading(kicker,title,copy){return `<div class="title-line"><span class="eyebrow">${kicker}</span><h1>${title}</h1><p class="muted">${copy}</p></div>`;}
function openProgram(candidate=null){ $('#program-form').reset();$('#form-error').textContent='';programProvenance=null;$('#scope-review').textContent='Copy scope from the current official policy. Importing a listing does not authorize testing.';if(candidate){const p=prepareCandidate(candidate),form=$('#program-form');for(const field of ['name','policy'])form.elements[field].value=p[field];form.elements.hosts.value=p.hosts.join('\n');form.elements.excluded.value=p.excluded.join('\n');$('#scope-review').textContent=p.reviewWarning;programProvenance=p.provenance;}$('#program-dialog').showModal(); }
function programCard(p){const errors=validateProgram(p);return `<article class="card"><span class="tag ${errors.length?'warn':''}">${errors.length?'REVIEW REQUIRED':'SCOPE RECORDED'}</span><h3>${esc(p.name)}</h3><p>${esc(p.hosts.join(' · '))}</p><p>Expires ${esc(p.expires)} · ${p.excluded.length} exclusions</p><div class="row"><button class="secondary" data-research="${esc(p.id)}">Research →</button><button class="secondary" data-policy="${esc(p.id)}">Policy ↗</button>${!p.authorized?`<button class="secondary" data-authorize="${esc(p.id)}">Confirm scope</button>`:''}<button class="delete" data-delete="${esc(p.id)}">Remove</button></div></article>`;}
function render(){
 if(page==='overview'){
 content.innerHTML=`<section class="hero"><div><span class="eyebrow">YOUR NEXT DISCOVERY STARTS HERE</span><h1>Less noise.<br>Better research.</h1><p>Bring program scope, evidence, and clear reporting into one focused workspace. You stay in control of every submission.</p><div class="row"><button class="primary" id="start">Start research ↗</button><button class="secondary" id="add">Add a program</button></div></div><div class="radar" aria-hidden="true"></div></section><section class="stats" aria-label="Workspace statistics"><div class="stat"><span>TRACKED PROGRAMS</span><strong>${state.programs.length.toString().padStart(2,'0')}</strong><span>Your research shortlist</span></div><div class="stat"><span>REPORT DRAFTS</span><strong>${state.reports.length.toString().padStart(2,'0')}</strong><span>Ready for your review</span></div><div class="stat"><span>CONFIRMED BUGS</span><strong>—</strong><span>Manual validation required</span></div></section><div class="section-head"><h2>A deliberate workflow</h2><span class="pill">3 SIMPLE STEPS</span></div><div class="grid"><article class="card"><div class="number">01 / GET YOUR BEARINGS</div><h3>Know the boundaries.</h3><p>Record the program’s official policy, allowed hosts, exclusions, and authorization expiry before analyzing evidence.</p><button class="secondary" id="browse">Explore programs →</button></article><article class="card"><div class="number">02 / TURN SIGNAL INTO EVIDENCE</div><h3>Inspect. Explain. Review.</h3><p>Analyze supplied response headers locally. Build a draft with observations and your impact notes, never invented vulnerabilities.</p><button class="secondary" id="inspect">Open research →</button></article></div><p class="footer-note">ScopePilot 0.3 · Public-directory discovery and offline evidence analysis. No autonomous probing, exploit execution, reward guarantees, or automatic submissions.</p>`;
 $('#start').onclick=()=>go('research');$('#inspect').onclick=()=>go('research');$('#browse').onclick=()=>go('programs');$('#add').onclick=()=>openProgram();
 }else if(page==='discover'){renderDiscovery();
 }else if(page==='programs'){
 content.innerHTML=heading('FIND YOUR FOCUS','Programs, with purpose.','Build your shortlist from official directories, then record the scope you are authorized to research.')+`<div class="row between"><div class="row"><button class="primary" id="add">Add program +</button><button class="secondary" id="import">Import JSON</button><input class="sr-only" id="file" type="file" accept="application/json,.json" aria-label="Program JSON file"></div><input id="search" class="search" placeholder="Search your programs" aria-label="Search programs"></div><div class="grid program-list" id="program-list"></div><div class="section-head"><h2>Start at the source</h2><span class="pill">EXTERNAL DIRECTORIES</span></div><div class="grid"><article class="card"><span class="tag">PUBLIC DIRECTORY</span><h3>HackerOne</h3><p>Browse opportunities and read each program’s current rules. Listings do not grant blanket authorization.</p><button class="secondary" data-open="https://hackerone.com/directory/programs">Open directory ↗</button></article><article class="card"><span class="tag">PUBLIC DIRECTORY</span><h3>Bugcrowd</h3><p>Discover public programs. Eligibility, scope, and reward terms must be checked with the program.</p><button class="secondary" data-open="https://bugcrowd.com/programs">Open directory ↗</button></article></div>`;
 const list=()=>{const needle=$('#search').value.toLowerCase();$('#program-list').innerHTML=state.programs.filter(p=>p.name.toLowerCase().includes(needle)).map(programCard).join('')||'<div class="empty"><h3>Your shortlist starts here.</h3><p>Add an authorized program or import a program file. No demo targets are pre-approved.</p></div>';wirePrograms();};list();$('#search').oninput=list;$('#add').onclick=()=>openProgram();$('#import').onclick=()=>$('#file').click();$('#file').onchange=async e=>{try{const file=e.target.files[0];if(!file)return;if(file.size>200000)throw new Error('Program file exceeds 200 KB.');const data=importPrograms(await file.text());if(data.some(p=>state.programs.some(x=>x.id===p.id)))throw new Error('An imported program already exists. Remove it first if you intend to replace it.');state.programs.push(...data);const saved=save();render();if(saved)notify(`${data.length} programs imported. Authorization must be reviewed individually.`);}catch(error){notify(error.message);}};
 }else if(page==='research'){
 content.innerHTML=heading('EVIDENCE BEFORE ASSUMPTIONS','Follow the signal.','Analyze response headers you already collected with permission. Nothing is sent to the target.')+(!state.programs.length?`<div class="empty"><h3>Begin with authorized scope.</h3><p>Add a program and review its policy before starting an evidence analysis.</p><button class="primary" id="add">Add your first program →</button></div>`:`<form id="research-form"><div class="grid"><section class="card"><span class="tag">01 · CONTEXT</span><label>Program<select id="research-program" required>${state.programs.map(p=>`<option value="${esc(p.id)}" ${researchDraft.program===p.id?'selected':''}>${esc(p.name)}</option>`).join('')}</select></label><label>Evidence URL<input id="research-url" type="url" required placeholder="https://authorized-host/path" value="${esc(researchDraft.url)}"></label><p class="muted" id="scope-status"></p><label>Optional request headers<textarea class="code" id="research-request" placeholder="Origin: https://your-controlled-origin.example&#10;Authorization: [REDACTED]">${esc(researchDraft.requestHeaders)}</textarea></label><p class="muted">Use already-collected request headers to contextualize CORS and cache observations. Do not paste credential values.</p><label>Impact and reproduction notes<textarea id="research-notes" maxlength="32000" placeholder="What did you observe? What is the impact? Avoid personal data and secrets.">${esc(researchDraft.notes)}</textarea></label></section><section class="card"><span class="tag">02 · RESPONSE EVIDENCE</span><label>HTTP response headers<textarea class="code" id="research-headers" required placeholder="HTTP/2 200&#10;Content-Type: text/html&#10;…">${esc(researchDraft.headers)}</textarea></label><p class="muted">Cookies and authorization headers are redacted before saving. Other secrets must be removed manually. Headers only, no response body.</p><button type="submit" class="primary">Analyze evidence →</button></section></div><p class="footer-note">This analyzer evaluates response policy, cookie attributes, and supplied request context. It cannot confirm exploitation, guarantee a bounty, or replace a security assessment.</p></form><div id="analysis-result"></div>`);
 if($('#add'))$('#add').onclick=()=>openProgram();
 if($('#research-form')){wireHarImport();const update=()=>{const p=state.programs.find(p=>p.id===$('#research-program').value);const errors=validateProgram(p);$('#scope-status').textContent=errors.length?errors.join(' '):`Scope: ${p.hosts.join(', ')}. Exclusions: ${p.excluded.join(', ')||'none recorded'}. Authorization expires ${p.expires}.`;};update();$('#research-program').onchange=update;$('#research-form').onsubmit=e=>{e.preventDefault();captureDraft();try{const program=state.programs.find(p=>p.id===researchDraft.program);const findings=[...analyze(researchDraft.url,researchDraft.headers,program),...analyzeEvidence({url:researchDraft.url,headers:researchDraft.headers,requestHeaders:researchDraft.requestHeaders})];const entry={id:crypto.randomUUID?crypto.randomUUID():String(Date.now()),created:new Date().toISOString(),program:{...program},url:researchDraft.url,headers:redact(researchDraft.headers),notes:redact(researchDraft.notes),requestHeaders:redact(researchDraft.requestHeaders),findings};if(new TextEncoder().encode(report(entry)).length>180000)throw new Error('Draft exceeds 180 KB. Shorten your notes or headers before saving.');state.reports.unshift(entry);const saved=save();researchDraft.headers=entry.headers;researchDraft.requestHeaders=entry.requestHeaders;$('#research-headers').value=entry.headers;$('#research-request').value=entry.requestHeaders;$('#analysis-result').innerHTML=`<article class="card"><span class="tag">${saved?'DRAFT SAVED':'SESSION ONLY · NOT SAVED'}</span><h2>${findings.length} evidence observations</h2><p>No vulnerability is confirmed. Review applicability and document actual impact before any submission.</p><button class="primary" id="view-report">Review report →</button></article>`;$('#view-report').onclick=()=>go('reports');if(saved)notify('Analysis complete. A redacted draft was saved locally.');}catch(error){notify(error.message);}};}
 }else{
 content.innerHTML=heading('MAKE YOUR WORK REPRODUCIBLE','Evidence, ready to explain.','Review every draft, remove sensitive data, and submit through the program’s approved channel yourself.')+(state.reports.length?state.reports.map(r=>`<article class="card"><div class="row between"><div><span class="tag warn">DRAFT · NOT SUBMITTED</span><h3>${esc(r.program.name)}</h3><p>${esc(r.url)} · ${new Date(r.created).toLocaleDateString()}</p></div><button class="secondary" data-export="${esc(r.id)}">Export draft ↗</button></div><details><summary>Read report · ${r.findings.length} observations</summary><pre class="report-preview">${esc(report(r))}</pre></details><button class="secondary" data-edit-report="${esc(r.id)}">Edit research notes</button>${reportEditor(r)}<button class="delete" data-remove-report="${esc(r.id)}">Delete local draft</button></article>`).join(''):`<div class="empty"><h3>Good reports begin with real evidence.</h3><p>Your analysis drafts will appear here. Nothing is automatically sent to a bounty program.</p><button class="primary" id="start">Start an analysis →</button></div>`);
 wireReportEditors();if($('#start'))$('#start').onclick=()=>go('research');document.querySelectorAll('[data-export]').forEach(b=>b.onclick=()=>exportReport(state.reports.find(r=>r.id===b.dataset.export)));document.querySelectorAll('[data-remove-report]').forEach(b=>b.onclick=()=>{if(confirm('Delete this local draft? Export it first if you need a copy.')){state.reports=state.reports.filter(r=>r.id!==b.dataset.removeReport);reportEdits.delete(b.dataset.removeReport);save();render();}});
 }
 document.querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>openExternal(b.dataset.open));
}
function reportEditor(entry){
 const draft=reportEdits.get(entry.id);if(!draft)return '';
 return `<form data-notes-form="${esc(entry.id)}"><label>Researcher notes<textarea name="notes" maxlength="32000" placeholder="Reproduction steps using owned accounts, demonstrated impact, and suggested remediation.">${esc(draft.notes)}</textarea></label><p class="muted">Keep capture provenance when useful. These are your notes, not verified findings. Known credential headers are redacted on save; remove secrets in prose, URLs and custom fields yourself.</p><p class="muted">Unsaved edits stay in this session while you navigate. Save before reloading or closing the app.</p><p class="error" data-notes-error role="alert">${esc(draft.error)}</p><div class="row"><button class="primary" type="submit">Save notes</button><button class="secondary" type="button" data-cancel-notes>Cancel edit</button></div></form>`;
}
function wireReportEditors(){
 document.querySelectorAll('[data-edit-report]').forEach(button=>button.onclick=()=>{
  const entry=state.reports.find(r=>r.id===button.dataset.editReport);if(!entry)return;
  if(!reportEdits.has(entry.id))reportEdits.set(entry.id,{notes:entry.notes,error:''});
  render();
 });
 document.querySelectorAll('[data-notes-form]').forEach(form=>{
  const id=form.dataset.notesForm,field=form.elements.notes;
  field.oninput=()=>{reportEdits.get(id).notes=field.value;};
  form.querySelector('[data-cancel-notes]').onclick=()=>{reportEdits.delete(id);render();};
  form.onsubmit=event=>{
   event.preventDefault();const draft=reportEdits.get(id);draft.notes=field.value;
   try{
    if(storageError)throw new Error(storageError);
    state=saveReportNotes(state,id,field.value,next=>localStorage.setItem('scopepilot-v1',JSON.stringify(next)));
    reportEdits.delete(id);render();notify('Research notes saved locally. Review the updated draft before exporting.');
   }catch(error){
    draft.error=`Notes not saved. ${error.message} Your edits remain here; copy them before reloading or closing the app.`;
    form.querySelector('[data-notes-error]').textContent=draft.error;
   }
  };
 });
}
function captureDraft(){if($('#research-form'))researchDraft={program:$('#research-program').value,url:$('#research-url').value,headers:$('#research-headers').value,requestHeaders:$('#research-request').value,notes:$('#research-notes').value};}
function wirePrograms(){document.querySelectorAll('[data-research]').forEach(b=>b.onclick=()=>{researchDraft.program=b.dataset.research;go('research');});document.querySelectorAll('[data-policy]').forEach(b=>b.onclick=()=>openExternal(state.programs.find(p=>p.id===b.dataset.policy).policy));document.querySelectorAll('[data-authorize]').forEach(b=>b.onclick=()=>{const p=state.programs.find(p=>p.id===b.dataset.authorize);if(confirm(`Have you reviewed ${p.policy} and confirmed your permission for ${p.hosts.join(', ')} with the recorded exclusions?`)){const errors=validateProgram({...p,authorized:true});if(errors.length)return notify(errors.join(' '));p.authorized=true;save();render();}});document.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>{if(confirm('Remove this program? Existing report drafts will be kept.')){state.programs=state.programs.filter(p=>p.id!==b.dataset.delete);save();render();}});}
function openExternal(url){try{const u=new URL(url);if(u.protocol!=='https:'||u.username||u.password)throw 0;if(window.NativeBridge)window.NativeBridge.openExternal(u.href);else if(window.webkit?.messageHandlers?.scopepilot)window.webkit.messageHandlers.scopepilot.postMessage({action:'open',url:u.href});else window.open(u.href,'_blank','noopener,noreferrer');}catch{notify('Only HTTPS links without embedded credentials are allowed.');}}
function exportReport(entry){const text=report(entry);if(new TextEncoder().encode(text).length>180000){notify('This draft is too large for native export. Shorten the evidence and create a new draft.');return;}if(window.NativeBridge){window.NativeBridge.exportReport(text);return;}if(window.webkit?.messageHandlers?.scopepilot){window.webkit.messageHandlers.scopepilot.postMessage({action:'export',text});return;}const blob=new Blob([text],{type:'text/markdown'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='scopepilot-draft.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('#close-dialog').onclick=()=>$('#program-dialog').close();$('#program-form').onsubmit=e=>{e.preventDefault();const f=new FormData(e.target),lines=n=>String(f.get(n)||'').split(/\n/).map(x=>x.trim().toLowerCase()).filter(Boolean);const p={id:crypto.randomUUID?crypto.randomUUID():String(Date.now()),name:String(f.get('name')).trim(),policy:String(f.get('policy')).trim(),hosts:lines('hosts'),excluded:lines('excluded'),expires:f.get('expires'),authorized:f.get('authorized')==='on',...(programProvenance?{provenance:programProvenance}:{})};const errors=validateProgram(p);if(errors.length){$('#form-error').textContent=errors.join(' ');return;}state.programs.push(p);const saved=save();$('#program-dialog').close();render();if(saved)notify('Program saved. Scope stays under your control.');};
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>go(b.dataset.page));render();if(storageError)notify(storageError);
function renderDiscovery(){
 content.innerHTML=heading('DISCOVER · REVIEW · AUTHORIZE','Find your next program.','Browse public community-maintained listings. A listing is not permission to test. No target is contacted.')+`<section class="card"><div class="row"><label>Directory source<select id="feed-source" ${discoveryLoading?'disabled':''}><option value="bugcrowd" ${discoverySource==='bugcrowd'?'selected':''}>Bugcrowd public listings</option><option value="hackerone" ${discoverySource==='hackerone'?'selected':''}>HackerOne public listings</option></select></label><button class="primary" id="refresh-discovery" ${discoveryLoading?'disabled':''}>${discoveryLoading?'Downloading directory…':'Refresh public listings ↗'}</button></div><p class="muted">Source: arkadiyt/bounty-targets-data on GitHub, an unofficial community snapshot. Refresh downloads only that directory, with no credentials or research content. HackerOne snapshots may use approximately 20 MB. Program rules must be checked on the official platform.</p><p class="error" role="alert">${esc(discoveryError)}</p><input id="discovery-search" class="search" aria-label="Search discovered programs" placeholder="Search program name or scope" value="${esc(discoveryQuery)}"></section><div id="discovery-results"></div><p class="footer-note">Snapshot attribution: Copyright © 2017 Arkadiy Tetelman, MIT license. Availability, scope and reward status may be stale. Refresh time describes this download, not independent verification of the program.</p>`;
 $('#feed-source').onchange=e=>{discoverySource=e.target.value;candidates=[];discoveryError='';discoveryPage=0;renderDiscovery();};
 $('#refresh-discovery').onclick=async()=>{if(discoveryLoading)return;discoveryLoading=true;discoveryError='';const source=discoverySource;renderDiscovery();try{const found=await fetchDiscovery(source);if(source===discoverySource){candidates=found;discoveryPage=0;}notify(`Loaded ${found.length} listings. Review the official scope before adding a program.`);}catch(error){discoveryError=error.message;notify('Directory unavailable. Your tracked programs and reports are unchanged.');}finally{discoveryLoading=false;if(page==='discover')renderDiscovery();}};
 $('#discovery-search').oninput=e=>{discoveryQuery=e.target.value;discoveryPage=0;renderDiscoveryResults();};renderDiscoveryResults();
}
function renderDiscoveryResults(){
 const matches=candidates.filter(p=>(p.name+' '+p.suggestedHosts.join(' ')).toLowerCase().includes(discoveryQuery.toLowerCase())),start=discoveryPage*20,rows=matches.slice(start,start+20);
 $('#discovery-results').innerHTML=rows.length?`<div class="section-head"><h2>${matches.length} matching listings</h2><span class="pill">PAGE ${discoveryPage+1} OF ${Math.ceil(matches.length/20)}</span></div><div class="grid">${rows.map(p=>`<article class="card"><span class="tag ${p.offersBounties?'':'warn'}">${p.offersBounties?'REWARDS LISTED · VERIFY TERMS':'DISCLOSURE PROGRAM · REWARDS UNCONFIRMED'}</span><h3>${esc(p.name)}</h3><p>${p.scopeCount} listed assets · ${p.exclusionCount} listed exclusions</p><p>${esc(p.suggestedHosts.slice(0,3).join(' · '))||'Scope needs manual interpretation'}</p>${p.restrictedScope.length?`<details><summary>${p.restrictedScope.length} restrictions need review</summary><p>${p.restrictedScope.slice(0,5).map(esc).join('<br>')}${p.restrictedScope.length>5?'<br>Additional restrictions omitted here. Read the complete official policy.':''}</p></details>`:''}<p class="muted">Downloaded ${esc(new Date(p.retrievedAt).toLocaleString())}. Not yet authorized.</p><div class="row"><button class="secondary" data-candidate-policy="${esc(p.id)}">Official policy ↗</button><button class="primary" data-adopt="${esc(p.id)}">Review and add →</button></div></article>`).join('')}</div><div class="row"><button class="secondary" id="discovery-prev" ${start===0?'disabled':''}>← Previous</button><button class="secondary" id="discovery-next" ${start+20>=matches.length?'disabled':''}>Next →</button></div>`:`<div class="empty"><h3>${candidates.length?'No matching programs.':'Fresh opportunities need fresh context.'}</h3><p>${candidates.length?'Try a different program name or hostname.':'Choose a directory and refresh its public listings. Your shortlist remains local and separate from discovered candidates.'}</p></div>`;
 document.querySelectorAll('[data-adopt]').forEach(b=>b.onclick=()=>openProgram(candidates.find(p=>p.id===b.dataset.adopt)));document.querySelectorAll('[data-candidate-policy]').forEach(b=>b.onclick=()=>openExternal(candidates.find(p=>p.id===b.dataset.candidatePolicy).policy));
 if($('#discovery-prev'))$('#discovery-prev').onclick=()=>{discoveryPage--;renderDiscoveryResults();};if($('#discovery-next'))$('#discovery-next').onclick=()=>{discoveryPage++;renderDiscoveryResults();};
}


function wireHarImport(){
 const section=document.createElement('section');section.className='card';section.id='har-import';
 section.innerHTML=`<span class="tag">BATCH · LOCAL CAPTURE</span><h2>Turn a capture into research.</h2><p>Import a HAR file from traffic you collected with permission. Uses the selected program above. Up to 5 MB and 100 entries. No requests are replayed. Query-bearing and out-of-scope URLs are skipped; bodies and custom headers are discarded.</p><p class="muted">HAR files can contain account data. Select only your authorized capture. Retained URLs and policy headers still need a privacy review before sharing.</p><label>HAR capture<input id="har-file" type="file" accept=".har,.json,application/json"></label><div id="har-result" aria-live="polite"></div>`;
 $('#research-form').after(section);
 let generation=0;
 $('#har-file').onchange=async e=>{
  const token=++generation,result=section.querySelector('#har-result'),file=e.target.files[0];result.replaceChildren();if(!file)return;
  const selected=$('#research-program').value,program=state.programs.find(p=>p.id===selected);
  try{
   if(file.size>5000000)throw new Error('HAR exceeds 5 MB. Export a smaller capture.');
   const batch=analyzeHar(await file.text(),program);
   if(token!==generation||!section.isConnected)return;
   result.innerHTML=`<h3>${batch.reports.length} drafts prepared</h3><p>${batch.total} entries inspected. Skipped: ${batch.skipped.scope} outside scope or unsupported URLs, ${batch.skipped.invalid} invalid, ${batch.skipped.duplicate} duplicate.</p><p>Preview only. Nothing has been saved or submitted.</p>${batch.reports.map(r=>`<details><summary>${esc(r.url)} · ${r.findings.length} observations</summary><pre class="report-preview">${esc(report(r))}</pre></details>`).join('')}${batch.reports.length?'<div class="row"><button class="primary" id="har-save">Save reviewed drafts</button><button class="secondary" id="har-discard">Discard preview</button></div>':''}`;
   const discard=()=>{generation++;result.replaceChildren();section.querySelector('#har-file').value='';};
   if(result.querySelector('#har-discard'))result.querySelector('#har-discard').onclick=discard;
   if(result.querySelector('#har-save'))result.querySelector('#har-save').onclick=()=>{
    const current=state.programs.find(p=>p.id===selected);
    if($('#research-program').value!==selected||!current||batch.reports.some(r=>!inScope(r.url,current))){notify('Program or authorization changed. Reimport under the current scope.');return;}
    state.reports.unshift(...batch.reports.map(r=>({...r,id:crypto.randomUUID?crypto.randomUUID():String(Date.now())+Math.random(),program:JSON.parse(JSON.stringify(current))})));
    const saved=save();discard();result.textContent=saved?'Reviewed drafts saved locally. Open Reports to export.':'Drafts kept in this session only. Export them from Reports before leaving.';
   };
  }catch(error){if(token===generation&&section.isConnected)result.textContent=error.message;}
 };
}
})();
