import test from 'node:test';
import assert from 'node:assert/strict';
import {analyzeEvidence} from '../web/evidence.mjs';
const run=(headers,requestHeaders='')=>{assert.equal(typeof analyzeEvidence,'function','Evidence analyzer is implemented');return analyzeEvidence({url:'https://example.com/account',headers:`HTTP/2 200\n${headers}`,requestHeaders});};
const ids=x=>x.map(f=>f.id);
test('reports cookie attributes separately with names only, preserving repeated cookies',()=>{
 const f=run('Set-Cookie: session=SECRET_ONE; Path=/\nSet-Cookie: theme=SECRET_TWO; Secure; HttpOnly; SameSite=Lax\nSet-Cookie: pref=SECRET_THREE; Secure; SameSite=None');
 assert.equal(f.length,2); assert.match(f[0].evidence,/session/); assert.match(f[0].evidence,/Secure.*HttpOnly.*SameSite/); assert.match(f[1].evidence,/pref/); assert.doesNotMatch(JSON.stringify(f),/SECRET_|Path=/);
});
test('requires exact supplied request origin and credentials for contextual CORS',()=>{
 const h='Access-Control-Allow-Origin: https://client.example\nAccess-Control-Allow-Credentials: true';
 assert.deepEqual(run(h),[]); assert.deepEqual(run(h,'Origin: https://other.example'),[]);
 assert.deepEqual(ids(run(h,'Origin: https://client.example')),['cors-credentialed']);
 assert.deepEqual(ids(run('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true','Origin: https://client.example')),['cors-invalid-wildcard']);
 assert.match(run('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true')[0].guidance,/block/i);
 assert.deepEqual(run(h.replace('true','TRUE'),'Origin: https://client.example'),[]);
 assert.deepEqual(run(h+'\nAccess-Control-Allow-Origin: https://client.example','Origin: https://client.example'),[]);
});
test('distinguishes HSTS disabled invalid short and adequate lifetimes',()=>{
 for(const [value,id] of [['max-age=0','hsts-disabled'],['max-age=bad','hsts-invalid'],['max-age=100','hsts-short'],['max-age=1; max-age=31536000','hsts-invalid']]) assert.deepEqual(ids(run('Strict-Transport-Security: '+value)),[id]);
 assert.deepEqual(run('Strict-Transport-Security: max-age=31536000; includeSubDomains'),[]);
});
test('CSP evaluates script fallback and avoids claiming nonce unsafe-inline bypass',()=>{
 assert.deepEqual(ids(run("Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'")),['csp-risky']);
 assert.deepEqual(run("Content-Security-Policy: default-src *; script-src 'self'"),[]);
 assert.deepEqual(run("Content-Security-Policy: script-src 'unsafe-inline' 'nonce-SECRET_NONCE'"),[]);
 assert.deepEqual(run("Content-Security-Policy-Report-Only: script-src 'unsafe-inline'"),[]);
});
test('public caching needs supplied authentication and no overriding no-store/private',()=>{
 assert.deepEqual(run('Cache-Control: public, max-age=60'),[]);
 assert.deepEqual(ids(run('Cache-Control: public, max-age=60','Authorization: Bearer SECRET_AUTH')),['cache-auth-public']);
 assert.deepEqual(ids(run('Cache-Control: public','Cookie: session=SECRET_COOKIE')),['cache-auth-public']);
 assert.deepEqual(run('Cache-Control: public, private','Authorization: Bearer SECRET_AUTH'),[]);
 assert.deepEqual(run('Cache-Control: public\nCache-Control: no-store','Cookie: session=SECRET_COOKIE'),[]);
});
test('rejects malformed request headers bodies controls oversized data and ambiguous origins',()=>{
 for(const h of ['Origin https://client.example',' Origin: https://client.example','Origin: x\n\nsecret','Authorization: abc\rInjected: x','Origin: x\u0000','Origin: a\nOrigin: b','POST / HTTP/1.1\n\n{}','X-Test: '+'🙂'.repeat(20000)]) assert.throws(()=>run('',h),/header|body|64 KB/i,h.slice(0,50));
 assert.throws(()=>run('X-Test: a\n\nSecret body'));
 assert.throws(()=>run('X-Test: '+'a'.repeat(65000)));
});
test('all results separate observations contextual risk and manual validation without leaking values',()=>{
 const f=run("Set-Cookie: session=SECRET_COOKIE\nStrict-Transport-Security: max-age=SECRET_HSTS\nContent-Security-Policy: script-src 'unsafe-eval' https://SECRET_CSP\nCache-Control: public\nX-Secret: SECRET_CUSTOM",'Authorization: Bearer SECRET_AUTH');
 assert.ok(f.length>=4); assert.doesNotMatch(JSON.stringify(f),/SECRET_/);
 for(const x of f){assert.equal(x.status,'Needs verification');assert.equal(x.severity,'Informational');assert.match(x.guidance,/Contextual risk:/);assert.match(x.evidence,/Observation:/);assert.ok(x.validation.length>20);assert.ok(x.confidence);assert.ok(Array.isArray(x.references));}
});

test('rejects invalid targets and non-text evidence without echoing supplied secrets',()=>{
 for(const input of [{url:'not a URL',headers:'HTTP/2 200'},{url:'https://user:SECRET@example.com',headers:'HTTP/2 200'},{url:'https://example.com',headers:{}},{url:'https://example.com',headers:'HTTP/2 200',requestHeaders:{}}]){
  assert.throws(()=>analyzeEvidence(input),error=>!error.message.includes('SECRET'));
 }
});
test('accepts normal CRLF request lines and never turns lookalike authentication into a cache finding',()=>{
 assert.deepEqual(ids(run('Cache-Control: public','GET /account HTTP/1.1\r\nAuthorization: Bearer credential\r\n')),['cache-auth-public']);
 assert.deepEqual(run('Cache-Control: public','X-Authorization: Bearer credential'),[]);
});
