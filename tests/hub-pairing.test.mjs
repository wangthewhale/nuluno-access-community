import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdtemp,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createServer} from 'node:net';
import {randomUUID} from 'node:crypto';
import {stableKeySource} from './helpers/hub-fixtures.mjs';

// Real SQLite/HTTP pairing with synthetic in-memory installation keys. No
// Keychain, private state, real platform account or provider call is used.
const root=resolve(import.meta.dirname,'..'),temporary=await mkdtemp(join(tmpdir(),'nuluno-hub-pairing-'));
await symlink(join(root,'node_modules'),join(temporary,'node_modules'),'dir');
const bundle=join(temporary,'hub.mjs');await build({entryPoints:[join(root,'src/account-hub/server.ts')],outfile:bundle,bundle:true,platform:'node',format:'esm',packages:'external',logLevel:'silent'});
const {startAccountHub}=await import(pathToFileURL(bundle).href),nativeFetch=globalThis.fetch;
let externalCalls=0;globalThis.fetch=async(input,init)=>{if(!['127.0.0.1','localhost'].includes(new URL(String(input)).hostname)){externalCalls++;throw Error('External I/O forbidden');}return nativeFetch(input,init);};
after(async()=>{globalThis.fetch=nativeFetch;await rm(temporary,{recursive:true,force:true});});
async function fixture(){
 const allocator=createServer();await new Promise(r=>allocator.listen(0,'127.0.0.1',r));const port=allocator.address().port;await new Promise(r=>allocator.close(r));
 const origin='http://127.0.0.1:'+port,stateDirectory=join(temporary,randomUUID()),keySource=stableKeySource();let clock=Date.now(),hub;
 const options={rootDirectory:root,stateDirectory,origin,keySource,clock:()=>clock};hub=await startAccountHub(options);
 async function call(path,{body,cookie,csrf,proof,headers={}}={}){const r=await nativeFetch(origin+path,{method:body===undefined?'GET':'POST',headers:{connection:'close',...(cookie?{cookie}:{}),...(proof?{'x-hub-owner-proof':proof}:{}),...(body===undefined?{}:{origin,'content-type':'application/json','x-hub-csrf':csrf??''}),...headers},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'manual'});return {r,status:r.status,value:r.headers.get('content-type')?.includes('json')?await r.json():await r.text()};}
 const challenge=async()=>{const result=await call('/hub-api/pairing/challenge');return {cookie:result.r.headers.getSetCookie().find(v=>v.startsWith('nuluno_hub_pairing_'))?.split(';')[0],csrf:result.value.csrf};};
 const issue=async()=>{const result=await hub.issuePairing();return {...result,token:new URLSearchParams(new URL(result.activationUrl).hash.slice(1)).get('pair')};};
 const pair=async(input,pre)=>{const current=pre??await challenge();return call('/hub-api/pairing/complete',{...current,body:{token:input.token}});};
 const owner=result=>result.r.headers.getSetCookie().find(v=>v.startsWith('nuluno_hub_owner_'))?.split(';')[0];
 const close=async()=>{hub.server.closeAllConnections?.();await new Promise(r=>hub.server.close(r));hub.close();};
 return {origin,call,challenge,issue,pair,owner,keySource,options,get hub(){return hub;},advance(ms){clock+=ms;},async restart(){await close();hub=await startAccountHub(options);},close};
}

test('ordinary GET never bootstraps an owner or echoes an activation fragment; stranger owner and MCP routes remain denied',async()=>{
 const f=await fixture();try{const issued=await f.issue(),page=await f.call('/account-hub/activate#pair='+issued.token);assert.equal(page.status,200);assert.match(page.value,/本人啟用/);assert.equal(page.r.headers.get('set-cookie'),null);assert.equal(page.r.headers.get('referrer-policy'),'no-referrer');assert.ok(!page.value.includes(issued.token));assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_owner_sessions').get().n,0);
  assert.equal((await f.call('/hub-api/state')).status,401);for(const [path,body]of [['/hub-api/connect',{provider:'mastodon'}],['/hub-api/preferences',{rememberDevice:true}],['/hub-api/disconnect',{provider:'gmail'}],['/hub-api/logout',{}]])assert.equal((await f.call(path,{body})).status,401);
  assert.equal((await f.call('/admin/tenants')).status,403);const mcp=await f.call('/mcp',{body:{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'unauthorized-controlled',version:'1'}}}});assert.equal(mcp.status,401);
  const pre=await f.challenge();assert.equal((await f.call('/hub-api/state',{cookie:pre.cookie})).status,401);const dump=JSON.stringify(f.hub.repo.db.prepare('SELECT * FROM hub_pairing_tokens').all());assert.ok(!dump.includes(issued.token));assert.equal(externalCalls,0);
 }finally{await f.close();}
});

test('pairing requires exact Origin, same-site metadata and pre-session CSRF before issuing any owner cookie',async()=>{
 const f=await fixture();try{const issued=await f.issue(),pre=await f.challenge();for(const patch of [{headers:{origin:'https://evil.test'}},{headers:{origin:'null'}},{headers:{'sec-fetch-site':'cross-site'}},{csrf:'wrong'},{cookie:''}]){const result=await f.call('/hub-api/pairing/complete',{...pre,body:{token:issued.token},...patch});assert.ok([403,400].includes(result.status));assert.equal(f.owner(result),undefined);}
  assert.equal((await f.call('/hub-api/pairing/challenge',{headers:{origin:'https://evil.test'}})).status,403);assert.equal((await f.call('/hub-api/pairing/challenge',{headers:{'sec-fetch-site':'cross-site'}})).status,403);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_owner_sessions').get().n,0);assert.equal(f.hub.repo.db.prepare('SELECT used_at FROM hub_pairing_tokens').get().used_at,null);assert.equal((await f.pair(issued,pre)).status,200);
 }finally{await f.close();}
});

test('parallel redemption creates exactly one owner session, and retry cannot reuse or extend the original capability',async()=>{
 const f=await fixture();try{const issued=await f.issue(),a=await f.challenge(),b=await f.challenge(),results=await Promise.all([f.pair(issued,a),f.pair(issued,b)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,403]);const succeeded=results.find(r=>r.status===200),cookie=f.owner(succeeded),proof=succeeded.value.ownerProof;assert.ok(cookie);assert.match(succeeded.r.headers.get('set-cookie'),/HttpOnly; SameSite=Strict/);assert.ok(!JSON.stringify(succeeded.value).includes(issued.token));
  assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_owner_sessions').get().n,1);assert.equal((await f.pair(issued)).status,403);const record=f.hub.repo.db.prepare('SELECT expires_at,used_at FROM hub_pairing_tokens').get();assert.equal(record.expires_at,issued.expiresAt);assert.ok(record.used_at);assert.equal((await f.call('/hub-api/state',{cookie,proof})).status,200);assert.equal((await f.call('/mcp',{cookie,proof,body:{jsonrpc:'2.0',id:1,method:'tools/list',params:{}}})).status,401,'Owner cookie never becomes an agent bearer');
 }finally{await f.close();}
});

test('expired and superseded links fail closed, while failed session insertion rolls the whole consumption back',async()=>{
 const f=await fixture();try{const old=await f.issue();f.advance(300000);assert.equal((await f.pair(old)).status,403);const fresh=await f.issue(),next=await f.issue();assert.equal((await f.pair(fresh)).status,403);
  const pre=await f.challenge();f.hub.repo.db.exec("CREATE TRIGGER controlled_owner_insert_failure BEFORE INSERT ON hub_owner_sessions BEGIN SELECT RAISE(ABORT,'controlled'); END");assert.equal((await f.pair(next,pre)).status,400);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_owner_sessions').get().n,0);const pending=f.hub.repo.db.prepare('SELECT used_at FROM hub_pairing_tokens WHERE revoked_at IS NULL').get();assert.equal(pending.used_at,null);f.hub.repo.db.exec('DROP TRIGGER controlled_owner_insert_failure');assert.equal((await f.pair(next,pre)).status,200);
 }finally{await f.close();}
});

test('remembered owner session survives true restart, used pairing stays used, and logout persists denial across restart',async()=>{
 const f=await fixture();try{const issued=await f.issue(),paired=await f.pair(issued),cookie=f.owner(paired),proof=paired.value.ownerProof,state=await f.call('/hub-api/state',{cookie,proof});assert.equal(state.status,200);const gmail=state.value.providers.find(provider=>provider.id==='gmail');assert.equal(gmail.phase,'configuration_required');assert.equal(gmail.canConnect,false);assert.equal((await f.call('/hub-api/connect',{cookie,proof,csrf:state.value.csrf,body:{provider:'gmail'}})).value.status,'configuration_required');assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,0);
  const remembered=await f.call('/hub-api/preferences',{cookie,proof,csrf:state.value.csrf,body:{rememberDevice:true}});assert.match(remembered.r.headers.get('set-cookie'),/Max-Age=604800/);const expires=f.hub.repo.db.prepare('SELECT expires_at FROM hub_owner_sessions').get().expires_at;await f.restart();const after=await f.call('/hub-api/state',{cookie,proof});assert.equal(after.status,200);assert.equal(after.value.rememberDevice,true);assert.equal(f.hub.repo.db.prepare('SELECT expires_at FROM hub_owner_sessions').get().expires_at,expires);assert.equal((await f.pair(issued)).status,403);
  assert.equal((await f.call('/hub-api/logout',{cookie,proof,csrf:after.value.csrf,body:{}})).status,200);await f.restart();assert.equal((await f.call('/hub-api/state',{cookie,proof})).status,401);assert.equal(externalCalls,0);
 }finally{await f.close();}
});

test('pre-session guessing and challenge creation are bounded without any owner or installation metadata exposure',async()=>{
 const f=await fixture();try{const pre=await f.challenge();for(let i=0;i<5;i++)assert.equal((await f.call('/hub-api/pairing/complete',{...pre,body:{token:'x'.repeat(43)}})).status,403);assert.equal((await f.call('/hub-api/pairing/complete',{...pre,body:{token:'x'.repeat(43)}})).status,429);
  for(let i=1;i<64;i++)assert.equal((await f.call('/hub-api/pairing/challenge')).status,200);const limited=await f.call('/hub-api/pairing/challenge');assert.equal(limited.status,429);assert.ok(!JSON.stringify(limited.value).includes('installation'));assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_owner_sessions').get().n,0);
 }finally{await f.close();}
});

test('two installations do not overwrite each other’s owner cookies in the same browser cookie jar',async()=>{
 const a=await fixture(),b=await fixture();try{const pairedA=await a.pair(await a.issue()),pairedB=await b.pair(await b.issue()),ownerA=a.owner(pairedA),ownerB=b.owner(pairedB);assert.ok(ownerA.split('=')[0]!==ownerB.split('=')[0]);const cookie=ownerA+'; '+ownerB;assert.equal((await a.call('/hub-api/state',{cookie,proof:pairedA.value.ownerProof})).status,200);assert.equal((await b.call('/hub-api/state',{cookie,proof:pairedB.value.ownerProof})).status,200);assert.equal(externalCalls,0);
 }finally{await a.close();await b.close();}
});
