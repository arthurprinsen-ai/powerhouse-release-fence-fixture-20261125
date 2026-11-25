import test from 'node:test';import assert from 'node:assert/strict';import {generateKeyPairSync} from 'node:crypto';import {guard,run} from './preflight.mjs';
const repo='arthurprinsen-ai/powerhouse-release-fence-fixture-20261125',sha='a'.repeat(40);
const e={GITHUB_REPOSITORY:repo,GITHUB_REPOSITORY_ID:'1472298284',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:sha,FIXTURE_APP_PRIVATE_KEY:generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs8',format:'pem'})};
function mock(o={}){let revoked=false;const calls=[];return {calls,fetch:async(u,r)=>{const p=u.pathname;calls.push([p,r.method]);let d,status=200;
if(p==='/app')d={id:5927059,slug:'powerhouse-fixture-controller',owner:{login:'arthurprinsen-ai'},permissions:{contents:'write'},...o.app};
else if(p.endsWith('/installation'))d={app_id:5927059,id:1,account:{login:'arthurprinsen-ai'},repository_selection:'selected',suspended_at:null,...o.inst};
else if(p.endsWith('/rules/branches/main'))d=o.rules??[{ruleset_id:28107028,type:'update'}];
else if(p.endsWith('/git/ref/heads/main'))d={object:{sha:o.base??sha}};
else if(p.endsWith('/access_tokens')){assert.deepEqual(JSON.parse(r.body),{repository_ids:[1472298284],permissions:{contents:'write',pull_requests:'read'}});d={token:'synthetic-token-12345678901234567890',permissions:{contents:'write',pull_requests:'read',metadata:'read',...o.perms}}}
else if(p==='/installation/token'){revoked=true;status=o.revoke??204}
else if(p==='/installation/repositories'){if(revoked)status=o.after??401;else d={total_count:1,repositories:[{id:1472298284,full_name:repo}],...o.scope}}
else throw Error('unexpected');return {ok:status>=200&&status<300,status,json:async()=>d}}}}
test('exact workflow scope',()=>{guard(e);for(const x of [{GITHUB_REPOSITORY:'other/repo'},{GITHUB_REF:'refs/heads/evil'},{GITHUB_EVENT_NAME:'pull_request'},{GITHUB_REPOSITORY_ID:'1'}])assert.throws(()=>guard({...e,...x}))});
test('scoped token and revocation only',async()=>{const f=mock(),p=await run(e,f.fetch);assert.equal(p.revocationVerified,true);assert.equal(p.mutationAuthority,false);assert.equal(p.positiveMergeVerified,false);assert.equal(f.calls.filter(x=>x[1]==='DELETE').length,1)});
for(const [name,o] of [['wrong app',{app:{id:1}}],['all repositories',{inst:{repository_selection:'all'}}],['missing rule',{rules:[]}],['base drift',{base:'b'.repeat(40)}],['extra permission',{perms:{administration:'write'}}],['extra repository',{scope:{total_count:2}}],['revocation failure',{revoke:500}],['revocation readback',{after:200}]])test(name,async()=>{const f=mock(o);await assert.rejects(run(e,f.fetch));if(f.calls.some(x=>x[0].endsWith('/access_tokens')))assert.equal(f.calls.filter(x=>x[0]==='/installation/token').length,1)});
