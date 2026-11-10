const hostPattern=/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
export function validateProgram(p, now=new Date()) {
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
export function inScope(target,p){
 if(validateProgram(p).length) return false;
 try{const u=new URL(target);return u.protocol==='https:'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&p.hosts.some(h=>matches(u.hostname,h))&&!p.excluded.some(h=>matches(u.hostname,h));}catch{return false;}
}
export function redact(value){return String(value).replace(/^[ \t]*(authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:.*$/gim,'$1: [REDACTED]');}
export function analyze(url,headers,p){
 if(!inScope(url,p))throw new Error('Authorization missing, expired, or target outside approved scope. HTTPS on port 443 only; remove query strings and credentials.');
 if(typeof headers==='string'&&new TextEncoder().encode(headers).length>64000)throw new Error('Headers exceed 64 KB.');
 if(typeof headers!=='string'||headers.length>64000||!/^HTTP\/(?:1\.[01]|2|3)\s+[1-5]\d\d(?:\s|$)/.test(headers))throw new Error('Paste response headers beginning with a valid HTTP status line.');
 if(/\r?\n\r?\n\s*\S/.test(headers))throw new Error('Headers only. Remove the response body and any personal data.');
 const parsed=new Map();for(const line of headers.split(/\r?\n/).slice(1)){const i=line.indexOf(':');if(i>0)parsed.set(line.slice(0,i).trim().toLowerCase(),line.slice(i+1).trim());else if(line.trim())throw new Error('Malformed header line.');}
 const checks=[['content-security-policy','Content Security Policy not observed','Review whether this HTML response needs a CSP and demonstrate a relevant impact. Missing headers alone usually do not qualify for a bounty.'],['strict-transport-security','HSTS not observed','Verify transport policy in context. A missing header alone does not prove a vulnerability.'],['x-content-type-options','MIME protection not observed','Check whether a valid nosniff directive is present and whether content interpretation creates a demonstrable impact.']];
 return checks.filter(([key])=>!parsed.get(key)).map(([key,title,guidance])=>({id:key,title,guidance,severity:'Informational',status:'Needs verification'}));
}
export function report({program,url,headers,findings,notes='',requestHeaders='',created=new Date().toISOString()}){
 return `# ScopePilot • Draft research report\n\nProgram: ${program.name}\nPolicy: ${program.policy}\nTarget: ${url}\nAuthorization expires: ${program.expires}${program.provenance?'\nDiscovery source: '+program.provenance.sourceURL+'\nSnapshot retrieved: '+program.provenance.retrievedAt:''}\nGenerated: ${created}\n\n## Status\nNo vulnerability is confirmed by this automated analysis. Human validation and program-rule review are required. No submission has been sent.\n\n## Observations\n${findings.length?findings.map(f=>`- ${f.title} (${f.severity}; ${f.status})\n  ${f.guidance}${f.evidence?'\n  Evidence: '+f.evidence:''}${f.confidence?'\n  Confidence: '+f.confidence:''}${f.validation?'\n  Validation: '+f.validation:''}${Array.isArray(f.references)?'\n  References: '+f.references.join(', '):''}`).join('\n'):'No missing-header observations. This is not a security clearance.'}\n\n## Researcher notes\n${redact(notes)||'Not yet provided. Add reproducible steps, actual impact, and remediation before submission.'}\n\n## Supplied request context\n${redact(requestHeaders)||'Not supplied.'}\n\n## Supplied response headers\n${redact(headers)}\n\nReview all content for secrets and personal data before sharing.\n`;
}
export function reviseReportNotes(entry,notes){
 if(typeof notes!=='string')throw new Error('Researcher notes must be text.');
 if(notes.length>32000)throw new Error('Researcher notes exceed 32,000 characters.');
 const revised={...entry,notes:redact(notes)};
 if(revised.notes.length>32000)throw new Error('Redacted researcher notes exceed 32,000 characters. Shorten the notes.');
 if(new TextEncoder().encode(report(revised)).length>180000)throw new Error('Draft exceeds 180 KB. Shorten your notes before saving.');
 return revised;
}
export function saveReportNotes(workspace,id,notes,persist){
 const entry=workspace.reports.find(r=>r.id===id);
 if(!entry)throw new Error('This report no longer exists.');
 const revised=reviseReportNotes(entry,notes);
 const next={...workspace,reports:workspace.reports.map(r=>r===entry?revised:r)};
 persist(next);
 return next;
}
export function importPrograms(text){
 if(typeof text!=='string'||text.length>200000)throw new Error('Program file exceeds 200 KB.');
 const items=JSON.parse(text);if(!Array.isArray(items)||items.length>100)throw new Error('Expected an array of up to 100 programs.');
 const ids=new Set(); return items.map((p,i)=>{if(!p||typeof p!=='object')throw new Error('Invalid program entry.');const clean={id:String(p.id||`import-${i}`),name:p.name,policy:p.policy,hosts:p.hosts,excluded:p.excluded||[],expires:p.expires,authorized:true};if(ids.has(clean.id))throw new Error('Duplicate program IDs.');ids.add(clean.id);const errors=validateProgram(clean);if(errors.length)throw new Error(errors.join(' '));return {...clean,authorized:false};});
}
export function restoreWorkspace(raw){
 if(raw===null)return {programs:[],reports:[]};
 const s=JSON.parse(raw),programValid=p=>p&&typeof p.id==='string'&&typeof p.authorized==='boolean'&&validateProgram({...p,authorized:true,expires:'2099-01-01'}).length===0&&typeof p.expires==='string';
 if(!s||!Array.isArray(s.programs)||!Array.isArray(s.reports)||s.programs.some(p=>!programValid(p))||s.reports.some(r=>!r||typeof r.id!=='string'||!programValid(r.program)||typeof r.url!=='string'||typeof r.headers!=='string'||typeof r.notes!=='string'||!Number.isFinite(Date.parse(r.created))||!Array.isArray(r.findings)||r.findings.some(f=>!f||['title','severity','status','guidance'].some(k=>typeof f[k]!=='string'))))throw new Error('Saved workspace has invalid entries.');
 return s;
}
