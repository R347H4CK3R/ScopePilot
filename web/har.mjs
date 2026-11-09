import {validateProgram,inScope,analyze,redact,report} from './core.mjs';
import {analyzeEvidence} from './evidence.mjs';
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
export function analyzeHar(text,program){
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
