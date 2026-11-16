import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createStandaloneService} from '../src/service';

// Native adapter + persisted core ledger; all provider responses are controlled.
// No listener, real token, private environment, DNS lookup, or external request.
const gate=()=>{let resolve!:(v?:unknown)=>void;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function bounded<T>(promise:Promise<T>):Promise<T>{let timer:NodeJS.Timeout;try{return await Promise.race([promise,new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(Error('revoke_waited_for_provider')),1000);})]);}finally{clearTimeout(timer!);}}
const status={id:'456',account:{id:'123'},url:'https://mastodon.social/@controlled/456'};
const source={id:'456',text:'controlled'};
async function fixture(){
 const directory=mkdtempSync(join(tmpdir(),'mastodon-readback-revoke-'));
 const service=createStandaloneService({path:join(directory,'state.sqlite'),vaultKey:'CONTROLLED_REVIEW_VAULT_'+'v'.repeat(40),origin:'http://127.0.0.1:8889'});
 const owner=await service.repository.createTenant('Controlled readback');
 await service.repository.setConnection(owner.scope,{provider:'mastodon',accountId:'123',label:'Controlled',scopes:['read:statuses','write:statuses'],secret:{accessToken:'CONTROLLED_ORIGINAL_TOKEN'},expiresAt:null});
 const issued=await service.broker.issue(owner.scope,{label:'Controlled readback',expiresAt:Date.now()+600000,rules:[{provider:'mastodon',actions:['publish_text'],accountIds:['123'],writeLimit:1}]});
 const task=await service.broker.submit(issued.key,{idempotencyKey:'controlled-readback-original',provider:'mastodon',action:'publish_text',accountId:'123',payload:{text:'controlled'}});
 return {service,owner,issued,task,async published(){await service.repository.transact(owner.scope,s=>{s.tasks[task.id].cursor={phase:'published',postId:'456'};});},async saved(){return (await service.repository.read(owner.scope)).tasks[task.id];},advance(){return service.broker.advance(issued.key,task.id,service.adapterFor('mastodon')!);},reconcile(){return service.broker.reconcile(issued.key,task.id,service.adapterFor('mastodon')!);},async revoke(){await bounded(service.broker.revoke(owner.scope,issued.grant.id));await bounded(service.repository.disconnect(owner.scope,'mastodon','123'));},close(){service.close();rmSync(directory,{recursive:true,force:true});}};
}
function controlledFetch(steps:Array<{path:string;body:unknown;pause?:ReturnType<typeof gate>;started?:ReturnType<typeof gate>}>) {
 const original=globalThis.fetch,calls:string[]=[];
 globalThis.fetch=async(input,init)=>{
  const value=String(input),next=steps.shift();calls.push(value);
  assert.ok(next,'every outbound request must have a controlled response');
  assert.equal(value,'https://mastodon.social'+next.path);assert.equal(init?.method??'GET','GET');
  assert.equal(new Headers(init?.headers).get('authorization'),'Bearer CONTROLLED_ORIGINAL_TOKEN');
  next.started?.resolve();if(next.pause)await next.pause.promise;return Response.json(next.body);
 };
 return {calls,restore(){globalThis.fetch=original;},consumed(){assert.equal(steps.length,0);}};
}

test('native readback admits and accounts status/source as distinct calls on the original dispatch',async()=>{
 const f=await fixture(),network=controlledFetch([{path:'/api/v1/statuses/456',body:status},{path:'/api/v1/statuses/456/source',body:source}]);
 try{
  await f.published();assert.equal((await f.advance()).status,'succeeded');network.consumed();
  const saved=await f.saved(),dispatch=saved.dispatches[0],calls=Object.entries(dispatch.calls);
  assert.equal(saved.id,f.task.id);assert.equal(saved.keyId,f.issued.grant.id);assert.equal(saved.dispatches.length,1);assert.equal(calls.length,2);
  assert.deepEqual(calls.map(([id])=>id),[dispatch.id+':1',dispatch.id+':2']);
  assert.ok(calls.every(([,call])=>!call.step.write&&call.state==='completed'&&call.observedAt));
  assert.equal(saved.evidence?.resourceId,'456');assert.equal(saved.cursor.postId,'456');
 }finally{network.restore();f.close();}
});

test('revoke/disconnect during status read blocks a fresh source request and retains the known native post ID',async()=>{
 const f=await fixture(),started=gate(),release=gate(),network=controlledFetch([{path:'/api/v1/statuses/456',body:status,pause:release,started}]);
 try{
  await f.published();const pending=f.advance();await started.promise;const original=(await f.saved()).dispatches[0];
  await f.revoke();assert.equal(network.calls.length,1);release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const saved=await f.saved(),dispatch=saved.dispatches[0];
  assert.equal(network.calls.length,1);assert.equal(saved.id,f.task.id);assert.equal(saved.keyId,f.issued.grant.id);assert.equal(saved.dispatches.length,1);assert.equal(dispatch.id,original.id);
  assert.deepEqual(Object.keys(dispatch.calls),[original.id+':1']);assert.equal(dispatch.calls[original.id+':1'].state,'completed');assert.ok(dispatch.calls[original.id+':1'].observedAt);
  assert.equal(dispatch.outcome?.kind,'unknown');assert.equal(dispatch.outcome?.cursor?.postId,'456');assert.equal(saved.cursor.postId,'456');assert.equal(saved.evidence,undefined);
  assert.equal((await f.service.repository.connections(f.owner.scope)).length,0);await assert.rejects(f.advance(),/access_revoked/);
 }finally{release.resolve();network.restore();f.close();}
});

test('a source read admitted before revoke may save its late receipt without fresh calls or credential recovery',async()=>{
 const f=await fixture(),started=gate(),release=gate(),network=controlledFetch([{path:'/api/v1/statuses/456',body:status},{path:'/api/v1/statuses/456/source',body:source,pause:release,started}]);
 try{
  await f.published();const pending=f.advance();await started.promise;const original=(await f.saved()).dispatches[0];
  assert.equal(Object.keys(original.calls).length,2);await f.revoke();release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const saved=await f.saved(),dispatch=saved.dispatches[0];assert.equal(network.calls.length,2);assert.equal(dispatch.id,original.id);
  assert.equal(dispatch.outcome?.evidence?.resourceId,'456');assert.equal(dispatch.outcome?.cursor?.postId,'456');assert.equal(saved.evidence?.resourceId,'456');assert.equal(saved.cursor.postId,'456');
  assert.ok(Object.values(dispatch.calls).every(call=>call.state==='completed'&&call.observedAt));assert.equal((await f.service.repository.connections(f.owner.scope)).length,0);
 }finally{release.resolve();network.restore();f.close();}
});

test('reconciliation keeps a newly identified post ID when revocation stops its follow-up read',async()=>{
 const f=await fixture(),started=gate(),release=gate(),network=controlledFetch([
  {path:'/api/v1/accounts/123/statuses?limit=5&exclude_replies=true',body:[{id:'456',account:{id:'123'},created_at:new Date(Date.now()+1000).toISOString()}]},
  {path:'/api/v1/statuses/456/source',body:source},
  {path:'/api/v1/statuses/456',body:status,pause:release,started},
 ]);
 try{
  const pending=f.reconcile();await started.promise;await f.revoke();release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const saved=await f.saved(),dispatch=saved.dispatches[0];assert.equal(network.calls.length,3);assert.equal(dispatch.kind,'reconcile');assert.equal(Object.keys(dispatch.calls).length,3);
  assert.equal(saved.cursor.postId,'456');assert.equal(dispatch.outcome?.cursor?.postId,'456');assert.equal(saved.evidence,undefined);assert.equal(saved.status,'revoked');
 }finally{release.resolve();network.restore();f.close();}
});
