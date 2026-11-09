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
export function analyzeEvidence({url,headers,requestHeaders=''}={}){
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
