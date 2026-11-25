import {createPrivateKey,sign} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const repo='arthurprinsen-ai/powerhouse-release-fence-fixture-20261125', appId=5927059, repoId=1472298284, ruleId=28107028;
const check=(v,c)=>{if(!v)throw Error(c)};
const enc=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
export function guard(e){check(e.GITHUB_REPOSITORY===repo&&e.GITHUB_REPOSITORY_ID===String(repoId)&&e.GITHUB_REF==='refs/heads/main'&&e.GITHUB_EVENT_NAME==='workflow_dispatch'&&/^[a-f0-9]{40}$/.test(e.GITHUB_SHA||''),'SCOPE_DENIED')}
export async function run(e,fetcher=fetch){
 guard(e);const key=createPrivateKey(e.FIXTURE_APP_PRIVATE_KEY||'');check(key.asymmetricKeyType==='rsa'&&key.asymmetricKeyDetails.modulusLength>=2048,'KEY_DENIED');
 const n=Math.floor(Date.now()/1000),b=enc({alg:'RS256',typ:'JWT'})+'.'+enc({iat:n-60,exp:n+480,iss:String(appId)}),jwt=b+'.'+sign('RSA-SHA256',Buffer.from(b),key).toString('base64url');
 const api=(p,m='GET',t,body)=>fetcher(new URL(p,'https://api.github.com'),{method:m,redirect:'error',signal:AbortSignal.timeout(15000),headers:{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(t?{Authorization:'Bearer '+t}:{}),...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const json=async(...a)=>{const r=await api(...a);check(r.ok,'HTTP_'+r.status);return r.json()};
 const app=await json('/app','GET',jwt);check(app.id===appId&&app.slug==='powerhouse-fixture-controller'&&app.owner?.login==='arthurprinsen-ai'&&app.permissions?.contents==='write','APP_DENIED');
 const i=await json('/repos/'+repo+'/installation','GET',jwt);check(i.app_id===appId&&Number.isSafeInteger(i.id)&&i.id>0&&i.account?.login==='arthurprinsen-ai'&&i.repository_selection==='selected'&&i.suspended_at===null,'INSTALLATION_DENIED');
 const rules=await json('/repos/'+repo+'/rules/branches/main');check(Array.isArray(rules)&&rules.some(r=>r.ruleset_id===ruleId&&r.type==='update'),'RULE_DENIED');
 const observe=async()=>{
  const base=await json('/repos/'+repo+'/git/ref/heads/main');check(base.object?.sha===e.GITHUB_SHA,'BASE_DRIFT');
  const pr=await json('/repos/'+repo+'/pulls/1');check(pr.number===1&&pr.state==='open'&&pr.merged===false&&pr.head?.repo?.id===repoId&&pr.base?.repo?.id===repoId&&pr.head?.ref==='fixture-negative-control'&&pr.head?.sha==='de7342f64838c5003de791aadbbb6c0c7cdda731'&&pr.base?.ref==='main'&&pr.base?.sha===e.GITHUB_SHA,'PR_IDENTITY_DENIED');
 };
 await observe();
 let t,proof;
 try{
  let g;
  try{g=await json('/app/installations/'+i.id+'/access_tokens','POST',jwt,{repository_ids:[repoId],permissions:{contents:'write',pull_requests:'read'}})}catch{throw Error('UNKNOWN_TOKEN_ISSUANCE')}
  if(typeof g?.token!=='string'||g.token.length<=20)throw Error('UNKNOWN_TOKEN_ISSUANCE');
  t=g.token;
  check(typeof t==='string'&&t.length>20,'TOKEN_DENIED');check(g.permissions?.contents==='write'&&g.permissions?.pull_requests==='read'&&g.permissions?.metadata==='read'&&Object.entries(g.permissions).every(([k,v])=>({contents:'write',pull_requests:'read',metadata:'read'})[k]===v),'PERMISSION_DENIED');
  const s=await json('/installation/repositories?per_page=100','GET',t);check(s.total_count===1&&s.repositories?.length===1&&s.repositories[0].id===repoId&&s.repositories[0].full_name===repo,'TOKEN_SCOPE_DENIED');
  await observe();
  proof={appId,repoId,ruleId,installationId:i.id,base:e.GITHUB_SHA,scopeVerified:true,positiveMergeVerified:false,mutationAuthority:false};
 }finally{if(t){const r=await api('/installation/token','DELETE',t);check(r.status===204,'REVOCATION_FAILED');const v=await api('/installation/repositories','GET',t);check(v.status===401,'REVOCATION_READBACK_FAILED')}}
 await observe();
 check(proof,'PROOF_MISSING');return {...proof,revocationVerified:true};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{console.log('FIXTURE_PREFLIGHT_PROOF '+JSON.stringify(await run(process.env)))}catch(err){console.error(err?.message==='UNKNOWN_TOKEN_ISSUANCE'?'FIXTURE_UNKNOWN_TOKEN_ISSUANCE_HOLD':'FIXTURE_PREFLIGHT_FAILED');process.exitCode=1}}
