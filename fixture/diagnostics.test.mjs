import test from 'node:test';
import assert from 'node:assert/strict';
import {diagnostic} from './diagnostics.mjs';
for (const stage of ['first-run-gate','scope','key','jwt','app','installation','rules','pre-observe']) test(stage,()=>{const x=diagnostic(stage,new Error('test-only-secret'));assert.equal(x.stage,stage);assert.equal(x.issuanceUnresolved,false);assert.equal(x.hold,true);assert.equal(x.mutationAuthority,false);assert.equal(JSON.stringify(x).includes('test-only-secret'),false);});
for (const stage of ['issuance','permission','repository-scope','post-issue-observe','revocation','revocation-readback','final-observe','proof']) test(stage,()=>{const x=diagnostic(stage,new Error('test-only-secret'));assert.equal(x.issuanceUnresolved,true);assert.equal(x.hold,true);assert.equal(x.mutationAuthority,false);assert.equal(x.code,'UNCLASSIFIED');});
test('unknown stage fails closed without echo',()=>{const x=diagnostic('secret-stage',new Error('secret-message'));assert.deepEqual(x,{stage:'unknown',code:'UNCLASSIFIED',issuanceUnresolved:true,hold:true,mutationAuthority:false});});
test('known error uses only allowlisted code',()=>assert.equal(diagnostic('issuance',new Error('UNKNOWN_TOKEN_ISSUANCE')).code,'UNKNOWN_TOKEN_ISSUANCE'));
test('HTTP errors and response contents not emitted',()=>assert.equal(diagnostic('app',new Error('HTTP_401: secret payload')).code,'UNCLASSIFIED'));
test('non-error remains bounded',()=>assert.equal(diagnostic('key',null).code,'UNCLASSIFIED'));
