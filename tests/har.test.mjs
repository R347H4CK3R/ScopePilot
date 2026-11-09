import test from 'node:test';
import assert from 'node:assert/strict';
import {analyzeHar} from '../web/har.mjs';
const p={id:'p',name:'Test',policy:'https://example.com/policy',hosts:['example.com'],excluded:['excluded.example.com'],expires:'2099-01-01',authorized:true};
const entry=(url='https://example.com/test')=>({startedDateTime:'2026-11-01T12:00:00Z',request:{url,method:'GET',headers:[{name:'Authorization',value:'Bearer SECRET'},{name:'X-Custom-Secret',value:'SECRET'}],postData:{text:'SECRET'}},response:{status:200,httpVersion:'HTTP/2',headers:[{name:'Content-Type',value:'text/html'},{name:'Set-Cookie',value:'session=SECRET; Path=/'},{name:'X-Secret',value:'SECRET'}],content:{text:'SECRET'}}});
const har=entries=>JSON.stringify({log:{version:'1.2',entries}});
test('imports scoped evidence without retaining bodies or credential values',()=>{const r=analyzeHar(har([entry()]),p);assert.equal(r.reports.length,1);assert.equal(r.reports[0].url,'https://example.com/test');assert.ok(r.reports[0].findings.length);assert.ok(!JSON.stringify(r).includes('SECRET'));assert.match(r.reports[0].headers,/set-cookie: \[REDACTED\]/i);assert.match(r.reports[0].notes,/2026-11-01/);});
test('rejects authorization gaps and mixed scopes without exposing skipped URLs',()=>{assert.throws(()=>analyzeHar(har([entry()]),{...p,authorized:false}),/authorization/i);const r=analyzeHar(har([entry(),entry('https://other.example/private?token=SECRET'),entry('http://example.com/'),entry('https://example.com/?secret=SECRET')]),p);assert.equal(r.reports.length,1);assert.equal(r.skipped.scope,3);assert.ok(!JSON.stringify(r).includes('SECRET'));});
test('bounds malformed and oversized input and entries',()=>{assert.throws(()=>analyzeHar('x',p),/JSON/);assert.throws(()=>analyzeHar(har(Array(101).fill(entry())),p),/100/);assert.throws(()=>analyzeHar(' '.repeat(5000001),p),/5 MB/);assert.throws(()=>analyzeHar('{}',p),/HAR/);});
test('skips malformed HTTP headers and non-HTTP responses',()=>{const a=entry();a.response.headers[0].value='html\nInjected: yes';const b=entry();b.response.status=0;const r=analyzeHar(har([a,b]),p);assert.equal(r.reports.length,0);assert.equal(r.skipped.invalid,2);});
test('deduplicates identical evidence but keeps changed responses',()=>{const changed=entry();changed.response.headers.push({name:'Strict-Transport-Security',value:'max-age=31536000'});const r=analyzeHar(har([entry(),entry(),changed]),p);assert.equal(r.reports.length,2);assert.equal(r.skipped.duplicate,1);});
test('does not invent authentication from empty request credentials',()=>{
 for(const name of ['Authorization','Cookie'])for(const value of ['','   ']){
  const e=entry();e.request.headers=[{name,value}];e.response.headers.push({name:'Cache-Control',value:'public'});
  const r=analyzeHar(har([e]),p);assert.equal(r.reports.length,1);
  assert.ok(!r.reports[0].findings.some(f=>f.id==='cache-auth-public'));
  assert.equal(r.reports[0].requestHeaders,'');
 }
});
test('does not invent a valid cookie when redacting malformed cookie syntax',()=>{
 for(const value of ['','SECRET','bad name=SECRET','; path=SECRET']){
  const e=entry();e.response.headers=[{name:'Set-Cookie',value}];
  const r=analyzeHar(har([e]),p);assert.equal(r.reports.length,1);
  assert.ok(!r.reports[0].findings.some(f=>f.id.startsWith('cookie-attributes-')));
  assert.ok(!JSON.stringify(r).includes('SECRET'));
 }
});
test('accepts HTTP horizontal whitespace while preserving evidence and redaction',()=>{
 const e=entry();e.request.headers=[{name:'Authorization',value:'\t'}];e.response.headers=[{name:'Cache-Control',value:'\tpublic\t'},{name:'Set-Cookie',value:'\tsession=SECRET;\tPath=/'}];
 const r=analyzeHar(har([e]),p);assert.equal(r.reports.length,1);
 assert.ok(!r.reports[0].findings.some(f=>f.id==='cache-auth-public'));
 assert.ok(r.reports[0].findings.some(f=>f.id==='cookie-attributes-1'));
 assert.ok(!JSON.stringify(r).includes('SECRET'));
});
test('keeps different HTTP methods as distinct evidence',()=>{const post=entry();post.request.method='POST';const r=analyzeHar(har([entry(),post]),p);assert.equal(r.reports.length,2);assert.match(r.reports[1].notes,/POST/);});
