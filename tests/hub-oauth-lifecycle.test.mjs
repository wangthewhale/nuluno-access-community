import {stableKeySource,pairBrowser,controlledGmailExtension} from './helpers/hub-fixtures.mjs';
import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {mkdtemp,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {createServer} from 'node:net';

// Real loopback HTTP + SQLite + production Google handler, with fake official
// token/identity responses only when explicitly installed below. No real
// account, real provider grant, platform request or production state is used.
const root=resolve(import.meta.dirname,'..'),temp=await mkdtemp(join(tmpdir(),'nuluno-hub-oauth-lifecycle-'));
await symlink(join(root,'node_modules'),join(temp,'node_modules'),'dir');
const bundle=join(temp,'server.mjs');
await build({entryPoints:[join(root,'src/account-hub/server.ts')],outfile:bundle,bundle:true,platform:'node',format:'esm',packages:'external',logLevel:'silent'});
const {startAccountHub}=await import(pathToFileURL(bundle).href);
const nativeFetch=globalThis.fetch;let actualExternalCalls=0,controlledProviderCalls=0,providerFixture=null;
globalThis.fetch=async(input,init)=>{
 const u=new URL(String(input));
 if(!['127.0.0.1','localhost'].includes(u.hostname)){
  if(providerFixture&&['https://oauth2.googleapis.com/token','https://openidconnect.googleapis.com/v1/userinfo'].includes(u.href)){controlledProviderCalls++;return providerFixture(u,init);}
  actualExternalCalls++;throw Error('External network is forbidden in this controlled test');
 }
 const headers=new Headers(init?.headers);headers.set('connection','close');return nativeFetch(input,{...init,headers});
};
after(async()=>{globalThis.fetch=nativeFetch;await rm(temp,{recursive:true,force:true});});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
const readScope='https://www.googleapis.com/auth/gmail.readonly';

async function fixture({controlledStart=false,beforeSave,failStart=false}={}){
 const allocator=createServer();await new Promise(r=>allocator.listen(0,'127.0.0.1',r));const port=allocator.address().port;await new Promise(r=>allocator.close(r));
 const origin='http://127.0.0.1:'+port,stateDirectory=join(temp,randomUUID());let clock=Date.now(),starts=0,hub;
 const options={rootDirectory:root,stateDirectory,origin,clock:()=>clock,keySource:stableKeySource(),extensions:[controlledGmailExtension()],googleClientConfigured:true,...(controlledStart?{startOAuthForTest:async(provider,tenantId)=>{starts++;if(failStart)throw Error('Controlled start failure');await beforeSave?.();const state='CONTROLLED_OPAQUE_STATE_'+starts;await hub.repo.saveOAuth(state,await hub.repo.tenant(tenantId),provider,{controlled:true});return {authorizationUrl:(provider==='gmail'?'https://accounts.google.com/o/oauth2/v2/auth':'https://mastodon.social/oauth/authorize')+'?state='+state,expiresAt:clock+600000};}}:{})};
 hub=await startAccountHub(options);
 const call=async(browser,path,body,{csrf=browser?.csrf,originValue=origin,headers={}}={})=>{
  const result=await nativeFetch(origin+path,{method:body===undefined?'GET':'POST',headers:{accept:'application/json',connection:'close',...(browser?.cookie?{cookie:browser.cookie}:{}),...(browser?.proof?{'x-hub-owner-proof':browser.proof}:{}),...(body===undefined?{}:{origin:originValue,'x-hub-csrf':csrf??'','content-type':'application/json'}),...headers},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'manual'});
  return {status:result.status,headers:result.headers,value:result.headers.get('content-type')?.includes('json')?await result.json():await result.text()};
 };
 const browser=()=>pairBrowser(hub,origin,nativeFetch);
 const close=async()=>{hub.server.closeAllConnections?.();await new Promise(r=>hub.server.close(r));hub.close();};
 return {origin,call,browser,get hub(){return hub;},get starts(){return starts;},setFail(value){failStart=value;},advance(ms){clock+=ms;},async restart(){await close();hub=await startAccountHub(options);},close};
}
function assertNoAgentArtifacts(f){const state=JSON.parse(f.hub.repo.db.prepare('SELECT state FROM tenants').get().state);assert.equal(Object.keys(state.grants).length,0);assert.equal(Object.keys(state.tasks).length,0);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM schedule').get().n,0);assert.equal(actualExternalCalls,0);}

test('parallel browser sessions share one tenant/provider admission, preserved across actual server restart',async()=>{
 const f=await fixture();try{
  const a=await f.browser(),b=await f.browser();await f.call(a,'/hub-api/preferences',{rememberDevice:true});
  const results=await Promise.all([f.call(a,'/hub-api/connect',{provider:'gmail'}),f.call(b,'/hub-api/connect',{provider:'gmail'})]);
  assert.deepEqual(results.map(r=>r.value.status).sort(),['pending','requires_owner']);assert.equal(results[0].value.attemptId,results[1].value.attemptId);
  assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,1);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_connection_attempts').get().n,1);
  const row={...f.hub.repo.db.prepare('SELECT * FROM hub_connection_attempts').get()},oauthCipher=f.hub.repo.db.prepare('SELECT encrypted FROM oauth').get().encrypted;
  await f.restart();for(const browser of [a,b]){const repeat=await f.call(browser,'/hub-api/connect',{provider:'gmail'});assert.equal(repeat.value.status,'pending');assert.equal(repeat.value.attemptId,row.id);assert.equal(repeat.value.authorizationUrl,undefined);assert.equal((await f.call(browser,'/hub-api/attempt/'+row.id)).value.status,'requires_owner');}
  assert.deepEqual({...f.hub.repo.db.prepare('SELECT * FROM hub_connection_attempts').get()},row);assert.equal(f.hub.repo.db.prepare('SELECT encrypted FROM oauth').get().encrypted,oauthCipher);assert.equal((await f.call(a,'/hub-api/state')).value.rememberDevice,true);assertNoAgentArtifacts(f);
 }finally{await f.close();}
});

test('disconnect retires pending nonce for every session; old callback stays denied after restart and cannot create a connection',async()=>{
 const f=await fixture();try{
  const a=await f.browser(),b=await f.browser(),started=await f.call(a,'/hub-api/connect',{provider:'gmail'}),oldState=new URL(started.value.authorizationUrl).searchParams.get('state');
  assert.equal((await f.call(b,'/hub-api/disconnect',{provider:'gmail'},{csrf:'wrong'})).status,403);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,1);
  assert.equal((await f.call(b,'/hub-api/disconnect',{provider:'gmail'})).status,200);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,0);assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'cancelled');
  const calls=controlledProviderCalls;await f.restart();const callback=await f.call(null,'/oauth/google/callback?state='+encodeURIComponent(oldState)+'&code=CONTROLLED_CODE');assert.equal(callback.status,400);assert.equal(controlledProviderCalls,calls);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM connections').get().n,0);assert.equal((await f.call(a,'/hub-api/attempt/'+started.value.attemptId)).value.status,'expired');
  const fresh=await f.call(a,'/hub-api/connect',{provider:'gmail'});assert.equal(fresh.value.status,'requires_owner');assert.notEqual(fresh.value.attemptId,started.value.attemptId);assertNoAgentArtifacts(f);
 }finally{await f.close();}
});

test('a normal controlled official callback still saves the connection once and remains remembered through restart',async()=>{
 const f=await fixture();try{
  const a=await f.browser(),started=await f.call(a,'/hub-api/connect',{provider:'gmail'}),state=new URL(started.value.authorizationUrl).searchParams.get('state'),before=controlledProviderCalls;
  providerFixture=async url=>url.href==='https://oauth2.googleapis.com/token'?json({access_token:'CONTROLLED_ACCESS_NOT_REAL',refresh_token:'CONTROLLED_REFRESH_NOT_REAL',expires_in:3600,scope:'openid email '+readScope}):json({sub:'CONTROLLED_SUBJECT',email:'controlled@example.test',email_verified:true});
  const callbackPath='/oauth/google/callback?state='+encodeURIComponent(state)+'&code=CONTROLLED_CODE';assert.equal((await f.call(null,callbackPath)).status,200);assert.equal(controlledProviderCalls-before,2);assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'connected');assert.equal(f.hub.repo.db.prepare('SELECT phase,encrypted FROM oauth').get().encrypted,'');assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM connections').get().n,1);
  const status=await f.call(a,'/hub-api/state');assert.equal(status.value.providers.find(p=>p.id==='gmail').phase,'remembered');for(const privateValue of ['CONTROLLED_ACCESS_NOT_REAL','CONTROLLED_REFRESH_NOT_REAL','CONTROLLED_SUBJECT'])assert.ok(!JSON.stringify(status.value).includes(privateValue));assert.ok(!f.hub.repo.db.prepare('SELECT encrypted FROM connections').get().encrypted.includes('CONTROLLED_ACCESS_NOT_REAL'));
  await f.restart();assert.equal((await f.call(a,'/hub-api/connect',{provider:'gmail'})).value.status,'remembered');assert.equal((await f.call(null,callbackPath)).status,400);assert.equal(controlledProviderCalls-before,2);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM hub_connection_attempts').get().n,1);assertNoAgentArtifacts(f);
 }finally{providerFixture=null;await f.close();}
});

test('an already claimed callback cannot save credentials after cancellation, including while a polling read is in flight',async()=>{
 const f=await fixture(),entered=deferred(),release=deferred();let callback;
 try{
  const a=await f.browser(),started=await f.call(a,'/hub-api/connect',{provider:'gmail'}),state=new URL(started.value.authorizationUrl).searchParams.get('state');
  providerFixture=async url=>{if(url.href==='https://oauth2.googleapis.com/token')return json({access_token:'CONTROLLED_ACCESS_NOT_REAL',refresh_token:'CONTROLLED_REFRESH_NOT_REAL',expires_in:3600,scope:'openid email '+readScope});entered.resolve();await release.promise;return json({sub:'CONTROLLED_SUBJECT',email:'controlled@example.test',email_verified:true});};
  callback=f.call(null,'/oauth/google/callback?state='+encodeURIComponent(state)+'&code=CONTROLLED_CODE');await entered.promise;
  assert.equal(f.hub.repo.db.prepare('SELECT phase FROM oauth').get().phase,'exchanging');assert.equal((await f.call(a,'/hub-api/attempt/'+started.value.attemptId)).value.status,'requires_owner');assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'exchanging');
  await f.call(a,'/hub-api/disconnect',{provider:'gmail'});release.resolve();const result=await callback;assert.equal(result.status,400);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM connections').get().n,0);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,0);assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'cancelled');assert.ok(!String(result.value).includes('CONTROLLED_'));assertNoAgentArtifacts(f);
 }finally{release.resolve();await callback?.catch(()=>{});providerFixture=null;await f.close();}
});

test('late saveOAuth after explicit cancellation cannot recreate a pending nonce or overwrite cancelled phase',async()=>{
 const entered=deferred(),release=deferred(),f=await fixture({controlledStart:true,beforeSave:async()=>{entered.resolve();await release.promise;}});let start;
 try{const a=await f.browser(),b=await f.browser();start=f.call(a,'/hub-api/connect',{provider:'gmail'});await entered.promise;
  assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'starting');assert.equal((await f.call(b,'/hub-api/disconnect',{provider:'gmail'})).status,200);release.resolve();assert.equal((await start).status,502);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,0);assert.equal(f.hub.repo.db.prepare('SELECT phase FROM hub_connection_attempts').get().phase,'cancelled');assert.equal(f.starts,1);assertNoAgentArtifacts(f);
 }finally{release.resolve();await start?.catch(()=>{});await f.close();}
});

test('unknown starts have an explicit owner cancellation path and never automatically retry through time or restart',async()=>{
 const f=await fixture({controlledStart:true,failStart:true});try{
  const a=await f.browser();assert.equal((await f.call(a,'/hub-api/connect',{provider:'gmail'})).status,502);assert.equal(f.starts,1);f.advance(3600000);await f.restart();
  let card=(await f.call(a,'/hub-api/state')).value.providers.find(p=>p.id==='gmail');assert.equal(card.phase,'needs_owner');assert.equal(card.canConnect,false);assert.equal(card.canDisconnect,true);assert.match(card.note,/取消這次連接/);
  assert.equal((await f.call(a,'/hub-api/connect',{provider:'gmail'})).value.status,'pending');assert.equal(f.starts,1);await f.call(a,'/hub-api/disconnect',{provider:'gmail'});card=(await f.call(a,'/hub-api/state')).value.providers.find(p=>p.id==='gmail');assert.equal(card.canConnect,true);assert.equal(card.canDisconnect,false);assert.equal(f.starts,1);
  f.setFail(false);assert.equal((await f.call(a,'/hub-api/connect',{provider:'gmail'})).value.status,'requires_owner');assert.equal(f.starts,2);assertNoAgentArtifacts(f);
 }finally{await f.close();}
});

test('browser-supplied start headers and secret-bearing return contexts are rejected without exposing stored data',async()=>{
 const f=await fixture();try{
  const a=await f.browser(),started=await f.call(a,'/hub-api/connect',{provider:'gmail'}),tenant=(await f.hub.repo.listTenants())[0].tenantId;
  const forged=await f.call(a,'/admin/tenants/'+tenant+'/google/start',{}, {headers:{'x-hub-attempt':started.value.attemptId,authorization:'Bearer CONTROLLED_WRONG_OWNER'}});assert.equal(forged.status,403);assert.equal(f.hub.repo.db.prepare('SELECT count(*) AS n FROM oauth').get().n,1);
  for(const returnPath of ['/account-hub#','/account-hub#access_token=CONTROLLED_PRIVATE','/account-hub?csrf=CONTROLLED_PRIVATE','/account-hub?nonce=CONTROLLED_PRIVATE','/account-hub?my_access_token=CONTROLLED_PRIVATE','/account-hub?sessionId=CONTROLLED_PRIVATE','/account-hub?%61ccess_token=CONTROLLED_PRIVATE']){const result=await f.call(a,'/hub-api/context',{returnPath});assert.equal(result.status,400);assert.ok(!JSON.stringify(result.value).includes('CONTROLLED_PRIVATE'));}
  assert.equal((await f.call(a,'/hub-api/context',{returnPath:'/account-hub?product_id=demo'})).status,200);const state=await f.call(a,'/hub-api/state');assert.equal(state.value.context.returnPath,'/account-hub?product_id=demo');assert.ok(!JSON.stringify(state.value).includes('CONTROLLED_PRIVATE'));
  const legacy=JSON.stringify({hasTask:true,returnPath:'/account-hub#access_token=CONTROLLED_PRIVATE',label:'CONTROLLED_PRIVATE'});f.hub.repo.db.prepare('UPDATE hub_owner_sessions SET context=?').run(legacy);f.hub.repo.db.prepare('UPDATE hub_connection_attempts SET context=?').run(legacy);const safeState=await f.call(a,'/hub-api/state'),safeAttempt=await f.call(a,'/hub-api/attempt/'+started.value.attemptId);assert.equal(safeState.value.context.returnPath,'/account-hub');assert.equal(safeState.value.context.hasTask,true);assert.equal(safeAttempt.value.returnPath,'/account-hub');assert.ok(!JSON.stringify([safeState.value,safeAttempt.value]).includes('CONTROLLED_PRIVATE'));assertNoAgentArtifacts(f);
 }finally{await f.close();}
});
