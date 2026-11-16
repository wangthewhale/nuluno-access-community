// SPDX-License-Identifier: Apache-2.0
// Controlled HTTP/SQLite security checks. No browser, Keychain, provider OAuth,
// private account or external network is used by this fixture.
import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, symlink, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes, randomUUID, createHash} from 'node:crypto';
import {createServer} from 'node:net';
import {build} from 'esbuild';
import {stableKeySource, pairBrowser} from './helpers/hub-fixtures.mjs';

const root=resolve(import.meta.dirname,'..'), temp=await mkdtemp(join(tmpdir(),'nuluno-owner-proof-'));
await symlink(join(root,'node_modules'),join(temp,'node_modules'),'dir');
const bundle=join(temp,'hub-server.mjs');
await build({entryPoints:[join(root,'src/account-hub/server.ts')],outfile:bundle,bundle:true,platform:'node',format:'esm',packages:'external',logLevel:'silent'});
const {startAccountHub}=await import(pathToFileURL(bundle).href), realFetch=globalThis.fetch;
let externalCalls=0;
globalThis.fetch=async(input,init)=>{const url=new URL(String(input)); if(!['127.0.0.1','localhost'].includes(url.hostname)){externalCalls++; throw Error('external_network_forbidden_in_owner_proof_fixture');} return realFetch(input,init);};
after(async()=>{globalThis.fetch=realFetch;assert.equal(externalCalls,0);await rm(temp,{recursive:true,force:true});});

async function fixture(){
  const portServer=createServer();await new Promise(resolve=>portServer.listen(0,'127.0.0.1',resolve));const port=portServer.address().port;await new Promise(resolve=>portServer.close(resolve));
  const origin='http://127.0.0.1:'+port,stateDirectory=join(temp,randomUUID()),options={rootDirectory:root,stateDirectory,origin,keySource:stableKeySource()};
  let hub=await startAccountHub(options),owner=null,completion=null;
  const pair=async()=>{
    owner=await pairBrowser(hub,origin,async(input,init)=>{
      const response=await realFetch(input,init);
      if(new URL(String(input)).pathname==='/hub-api/pairing/complete') completion={input:String(input),init,value:await response.clone().json()};
      return response;
    });
    assert.match(owner.proof,/^[A-Za-z0-9_-]{43}$/);return owner;
  };
  const call=async(path,body,{cookie=owner?.cookie??'',proof=owner?.proof??'',csrf=owner?.csrf??'',requestOrigin=origin,method=body===undefined?'GET':'POST'}={})=>{
    const response=await realFetch(origin+path,{method,headers:{connection:'close',origin:requestOrigin,...(cookie?{cookie}:{}),...(proof?{'x-hub-owner-proof':proof}:{}),...(method==='POST'?{'content-type':'application/json','x-hub-csrf':csrf}:{})},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'error'});
    return {status:response.status,headers:response.headers,value:response.headers.get('content-type')?.includes('application/json')?await response.json():await response.text()};
  };
  const stop=async()=>{hub.server.closeAllConnections?.();await new Promise(resolve=>hub.server.close(resolve));hub.close();};
  return {pair,call,origin,stateDirectory,get hub(){return hub;},get owner(){return owner;},get completion(){return completion;},restart:async()=>{await stop();hub=await startAccountHub(options);},close:stop};
}
function denied(reply){assert.equal(reply.status,401);assert.equal(reply.value.error,'local_owner_session_required');assert.equal(reply.value.csrf,undefined);assert.equal(reply.value.ownerProof,undefined);assert.equal(reply.value.agents,undefined);}
const count=(f,table)=>f.hub.repo.db.prepare('SELECT count(*) AS n FROM '+table).get().n;
function notEchoed(value,secrets){const text=typeof value==='string'?value:JSON.stringify(value);for(const secret of secrets)assert.ok(!text.includes(secret),'a private fixture capability must not be reflected');}

test('a copied cookie and forged matching Origin cannot read CSRF/agents or create/connect without the owner proof',async()=>{
  const f=await fixture();
  try{
    const owner=await f.pair(),wrongProof=randomBytes(32).toString('base64url');
    for(const proof of ['',wrongProof]){
      denied(await f.call('/hub-api/state',undefined,{proof,requestOrigin:f.origin}));
      denied(await f.call('/hub-api/agents',undefined,{proof,requestOrigin:f.origin}));
      denied(await f.call('/hub-api/agents',{requestKey:randomUUID(),preset:'public-read'},{proof,requestOrigin:f.origin}));
      denied(await f.call('/hub-api/connect',{provider:'mastodon'},{proof,requestOrigin:f.origin}));
    }
    assert.equal(count(f,'hub_agent_tokens'),0);assert.equal(count(f,'hub_connection_attempts'),0);assert.equal(count(f,'oauth'),0);
    const state=await f.call('/hub-api/state');assert.equal(state.status,200);assert.equal(state.value.csrf,owner.csrf);
    const list=await f.call('/hub-api/agents');assert.equal(list.status,200);assert.deepEqual(list.value.agents,[]);
    const created=await f.call('/hub-api/agents',{requestKey:randomUUID(),preset:'public-read'});assert.equal(created.status,200);assert.equal(created.value.preset,'public-read');
    notEchoed([state.value,list.value,created.value],[owner.proof]);assert.equal(externalCalls,0);
  }finally{await f.close();}
});

test('the pairing proof is returned only by the successful POST, remains hashed in SQLite and never appears in GETs or HTML shells',async()=>{
  const f=await fixture();
  try{
    const owner=await f.pair(),completion=f.completion;
    assert.deepEqual(Object.keys(completion.value).sort(),['ownerProof','paired','returnPath']);assert.equal(completion.value.ownerProof,owner.proof);assert.equal(completion.value.paired,true);
    const session=f.hub.repo.db.prepare('SELECT * FROM hub_owner_sessions').get();
    assert.equal(session.proof_hash,createHash('sha256').update(owner.proof).digest('hex'));
    const rawCookie=owner.cookie.slice(owner.cookie.indexOf('=')+1),pairToken=JSON.parse(completion.init.body).token;
    notEchoed(session,[owner.proof,rawCookie,pairToken]);
    for(const path of ['/hub-api/state','/hub-api/agents']){
      const reply=await f.call(path);assert.equal(reply.status,200);notEchoed(reply.value,[owner.proof,rawCookie,pairToken]);assert.equal(reply.value.ownerProof,undefined);assert.equal(reply.headers.get('cache-control'),'no-store');
    }
    for(const path of ['/','/account-hub','/account-hub/activate']){
      const anonymous=await f.call(path,undefined,{cookie:'',proof:''}),authenticated=await f.call(path);
      assert.equal(anonymous.status,200);assert.equal(authenticated.status,200);assert.equal(anonymous.value,authenticated.value);
      notEchoed(authenticated.value,[owner.proof,rawCookie,pairToken,owner.csrf]);
      if(path.endsWith('/activate')) assert.match(authenticated.value,/src="\/pairing\.mjs"/);
    }
    const replayResponse=await realFetch(completion.input,completion.init),replay=await replayResponse.json();assert.equal(replayResponse.status,403);assert.equal(replay.ownerProof,undefined);notEchoed(replay,[owner.proof,rawCookie,pairToken]);
    const wrongMethod=await f.call('/hub-api/pairing/complete');assert.equal(wrongMethod.status,404);notEchoed(wrongMethod.value,[owner.proof,rawCookie,pairToken]);
    for(const suffix of ['','-wal']){
      const bytes=await readFile(join(f.stateDirectory,'access.sqlite')+suffix).catch(error=>{if(error.code==='ENOENT')return Buffer.alloc(0);throw error;});
      for(const secret of [owner.proof,rawCookie,pairToken])assert.equal(bytes.includes(Buffer.from(secret)),false,'raw pairing capabilities must not be stored in SQLite');
    }
  }finally{await f.close();}
});

test('logout removes the cookie-plus-proof authority and a repository/server restart does not resurrect the session',async()=>{
  const f=await fixture();
  try{
    const owner=await f.pair();assert.equal(count(f,'hub_owner_sessions'),1);
    denied(await f.call('/hub-api/logout',{}, {proof:randomBytes(32).toString('base64url')}));assert.equal(count(f,'hub_owner_sessions'),1);
    const signedOut=await f.call('/hub-api/logout',{});assert.equal(signedOut.status,200);assert.equal(signedOut.value.signedOut,true);assert.match(signedOut.headers.get('set-cookie'),/Max-Age=0/);notEchoed(signedOut.value,[owner.proof]);assert.equal(count(f,'hub_owner_sessions'),0);
    denied(await f.call('/hub-api/state'));denied(await f.call('/hub-api/agents'));
    await f.restart();denied(await f.call('/hub-api/state'));denied(await f.call('/hub-api/agents'));denied(await f.call('/hub-api/agents',{requestKey:randomUUID(),preset:'public-read'}));
    assert.equal(count(f,'hub_owner_sessions'),0);assert.equal(count(f,'hub_agent_tokens'),0);
  }finally{await f.close();}
});

test('a sibling localhost port may receive cookies but gains no owner authority without the target origin proof',async()=>{
  const first=await fixture(),second=await fixture();
  try{
    const a=await first.pair(),b=await second.pair();assert.notEqual(first.origin,second.origin);assert.notEqual(a.cookie.split('=')[0],b.cookie.split('=')[0]);
    let observedHeaders=null;
    const observe=req=>{observedHeaders={...req.headers};};second.hub.server.prependListener('request',observe);
    const shell=await second.call('/account-hub',undefined,{cookie:a.cookie,proof:''});assert.equal(shell.status,200);assert.equal(observedHeaders.cookie,a.cookie);assert.equal(observedHeaders['x-hub-owner-proof'],undefined);notEchoed(shell.value,[a.proof,b.proof]);
    // Native HTTP can forge Origin. The stolen cookie still cannot obtain the
    // target's CSRF value or perform a privileged action without its proof.
    denied(await first.call('/hub-api/state',undefined,{cookie:observedHeaders.cookie,proof:'',requestOrigin:first.origin}));
    denied(await first.call('/hub-api/agents',{requestKey:randomUUID(),preset:'public-read'},{cookie:a.cookie,proof:'',requestOrigin:first.origin}));
    denied(await first.call('/hub-api/state',undefined,{cookie:a.cookie,proof:b.proof,requestOrigin:first.origin}));
    denied(await second.call('/hub-api/state',undefined,{cookie:b.cookie,proof:a.proof,requestOrigin:second.origin}));
    const browserCookies=a.cookie+'; '+b.cookie;
    assert.equal((await first.call('/hub-api/state',undefined,{cookie:browserCookies,proof:a.proof})).status,200);
    assert.equal((await second.call('/hub-api/state',undefined,{cookie:browserCookies,proof:b.proof})).status,200);
    denied(await first.call('/hub-api/state',undefined,{cookie:browserCookies,proof:''}));denied(await second.call('/hub-api/state',undefined,{cookie:browserCookies,proof:''}));
    assert.equal(count(first,'hub_agent_tokens'),0);assert.equal(count(second,'hub_agent_tokens'),0);assert.equal(externalCalls,0);
  }finally{await first.close();await second.close();}
});
