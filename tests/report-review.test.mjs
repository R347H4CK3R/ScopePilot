import test from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../web/core.mjs';
const entry=()=>({id:'draft-1',program:{id:'program-1',name:'Example',policy:'https://example.com/security',hosts:['example.com'],excluded:[],expires:'2020-01-01',authorized:false},url:'https://example.com/owned-account',created:'2026-11-01T12:00:00.000Z',headers:'HTTP/2 200\nContent-Type: text/html',requestHeaders:'Authorization: [REDACTED]',findings:[{title:'Observation',severity:'Informational',status:'Needs verification',guidance:'Validate under current program rules.'}],notes:'Original capture provenance.'});
const revise=(e,notes)=>{assert.equal(typeof core.reviseReportNotes,'function','Saved reports support local note revision');return core.reviseReportNotes(e,notes);};
test('revises only notes without mutating captured evidence or granting authorization',()=>{
 const original=entry(),before=structuredClone(original);
 const updated=revise(original,'Reproduction: use my own test account.\nImpact: not demonstrated.');
 assert.notStrictEqual(updated,original);assert.deepEqual(original,before);
 assert.deepEqual({...updated,notes:before.notes},before);
 assert.match(core.report(updated),/Reproduction: use my own test account/);
 assert.match(core.report(updated),/No vulnerability is confirmed/);
});
test('redacts known credential headers before notes can be persisted or exported',()=>{
 const revised=revise(entry(),'Steps:\nAuthorization: Bearer SECRET_ONE\n  Cookie: session=SECRET_TWO\nX-Api-Key: SECRET_THREE\nSet-Cookie: sid=SECRET_FOUR\nActual impact remains unverified.');
 assert.doesNotMatch(JSON.stringify(revised),/SECRET_/);
 assert.match(revised.notes,/Authorization: \[REDACTED\]/);
 assert.match(core.report(revised),/Actual impact remains unverified/);
});
test('allows clearing notes and the exact 32000 character boundary',()=>{
 assert.equal(revise(entry(),'').notes,'');
 assert.equal(revise(entry(),'x'.repeat(32000)).notes.length,32000);
});
test('rejects non-text and excessive notes without changing the prior report',()=>{
 const original=entry(),before=structuredClone(original);
 for(const notes of [null,undefined,{},42])assert.throws(()=>revise(original,notes),/text/i);
 assert.throws(()=>revise(original,'x'.repeat(32001)),/32,000/);
 assert.deepEqual(original,before);
});
test('enforces the final UTF-8 report limit rather than just character count',()=>{
 const original=entry();original.headers='HTTP/2 200\nX-Existing: '+'x'.repeat(120000);
 assert.doesNotThrow(()=>revise(original,'a'.repeat(32000)));
 assert.throws(()=>revise(original,'界'.repeat(32000)),/180 KB/);
 assert.equal(original.notes,'Original capture provenance.');
});

test('commits a redacted candidate only after persistence succeeds',()=>{
 assert.equal(typeof core.saveReportNotes,'function');
 const original=entry(),workspace={programs:[],reports:[original]},before=structuredClone(workspace);
 let persisted;
 const next=core.saveReportNotes(workspace,original.id,'Cookie: SECRET_SAVE\nImpact still unverified.',candidate=>{persisted=structuredClone(candidate);});
 assert.deepEqual(workspace,before);assert.notStrictEqual(next,workspace);
 assert.deepEqual(next,persisted);assert.doesNotMatch(JSON.stringify(next),/SECRET_SAVE/);
 assert.equal(next.reports.length,1);
});
test('failed persistence and missing reports never change the saved workspace',()=>{
 assert.equal(typeof core.saveReportNotes,'function');
 const workspace={programs:[],reports:[entry()]},before=structuredClone(workspace);
 assert.throws(()=>core.saveReportNotes(workspace,'draft-1','New review',()=>{throw new Error('Storage full');}),/Storage full/);
 assert.deepEqual(workspace,before);
 assert.throws(()=>core.saveReportNotes(workspace,'removed','New review',()=>{throw new Error('Must not persist');}),/no longer exists/i);
 assert.deepEqual(workspace,before);
});

test('rejects redaction-expanded notes before persistence',()=>{
 const workspace={programs:[],reports:[entry()]},before=structuredClone(workspace);
 const notes='Cookie:\n'.repeat(4000);assert.equal(notes.length,32000);
 assert.throws(()=>core.saveReportNotes(workspace,'draft-1',notes,()=>{throw new Error('Must not persist expanded notes');}),/32,000/);
 assert.deepEqual(workspace,before);
});
