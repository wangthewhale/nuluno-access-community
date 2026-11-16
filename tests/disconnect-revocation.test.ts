import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer,request} from 'node:http';
import {createStandaloneService} from '../src/service';
import {createAccessApp} from '../src/server';
import type {AccessRule} from '../src/core/types';

const vault='CONTROLLED_DISCONNECT_VAULT_'+'v'.repeat(40),admin='CONTROLLED_DISCONNECT_ADMIN_'+'a'.repeat(40);
const privateRule=(account='123'):AccessRule=>({provider:'mastodon',actions:['publish_text','verify_identity'],accountIds:[account],writeLimit:1});
const publicRule:AccessRule={provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0};
const gate=()=>{let resolve!:(v?:unknown)=>void;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function bounded<T>(promise:Promise<T>):Promise<T>{let timer:NodeJS.Timeout;try{return await Promise.race([promise,new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(Error('disconnect_waited_for_provider')),1000);})]);}finally{clearTimeout(timer!);}}
async function fixture(http=false){
 const directory=mkdtempSync(join(tmpdir(),'access-disconnect-')),path=join(directory,'state.sqlite');
 let app:any;const server=http?createServer((req,res)=>app(req,res)):null;
 if(server)await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 const origin=server?'http://127.0.0.1:'+(server.address() as any).port:'http://127.0.0.1:8889';
 const created=http?createAccessApp({path,vaultKey:vault,adminKey:admin,origin}):null;if(created)app=created.app;
 const service=created?.service??createStandaloneService({path,vaultKey:vault,origin}),owner=await service.repository.createTenant('Controlled disconnect');let closed=false;
 const connect=(account='123')=>service.repository.setConnection(owner.scope,{provider:'mastodon',accountId:account,label:'Controlled',scopes:['read:statuses','write:statuses'],secret:{accessToken:'CONTROLLED_DISCONNECT_TOKEN'},expiresAt:null});
 const issue=(rules:AccessRule[],managed=false)=>service.broker.issue(owner.scope,{label:'Controlled original grant',expiresAt:Date.now()+600000,rules,managed});
 const send=(route:string,key=admin,method='POST')=>new Promise<{status:number;body:any}>((resolve,reject)=>{const r=request(origin+route,{method,headers:{authorization:'Bearer '+key,'content-type':'application/json',connection:'close'}},response=>{let body='';response.setEncoding('utf8');response.on('data',chunk=>body+=chunk);response.on('end',()=>resolve({status:response.statusCode!,body:JSON.parse(body)}));});r.on('error',reject);r.end(method==='POST'?'{}':undefined);});
 return {service,owner,path,origin,connect,issue,send,async closeService(){if(!closed){service.close();closed=true;}},async close(){if(server){server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}if(!closed)service.close();rmSync(directory,{recursive:true,force:true});}};
}
function mockProvider(steps:Array<{path:string;body?:unknown;pause?:ReturnType<typeof gate>;started?:ReturnType<typeof gate>;fail?:boolean}>){
 const original=globalThis.fetch,calls:string[]=[];
 globalThis.fetch=async(input,init)=>{const url=String(input),step=steps.shift();calls.push(url);assert.ok(step,'no unplanned provider request');assert.equal(url,'https://mastodon.social'+step.path);assert.equal(new Headers(init?.headers).get('authorization'),'Bearer CONTROLLED_DISCONNECT_TOKEN');step.started?.resolve();if(step.pause)await step.pause.promise;if(step.fail)throw Error('Controlled lost response');return Response.json(step.body);};
 return {calls,restore(){globalThis.fetch=original;},consumed(){assert.equal(steps.length,0);}};
}

test('disconnect atomically revokes exact-account grants, retires managed work, and preserves public/unrelated capabilities and original quota',async()=>{
 const f=await fixture();try{
  await f.connect();await f.connect('789');const original=await f.issue([privateRule(),publicRule],true),multi=await f.issue([{...privateRule(),accountIds:['123','789']}]),other=await f.issue([privateRule('789')]),publicOnly=await f.issue([publicRule]),privateRead=await f.issue([{...privateRule(),actions:['verify_identity'],writeLimit:0}]);
  const task=await f.service.broker.submit(original.key,{idempotencyKey:'controlled-disconnect-original',provider:'mastodon',action:'publish_text',accountId:'123',payload:{text:'controlled'}});
  await f.service.repository.retain(f.owner.scope,original.key,original.grant.id);await f.service.repository.scheduleTask(f.owner.scope,task.id);
  await f.service.repository.transact(f.owner.scope,s=>{s.grants[original.grant.id].writesUsed['0']=1;});
  await f.service.repository.disconnect(f.owner.scope,'mastodon','123');const state=await f.service.repository.read(f.owner.scope),saved=state.grants[original.grant.id];
  for(const item of [original,multi,privateRead])await assert.rejects(f.service.broker.authenticate(item.key),/access_revoked/);
  for(const item of [other,publicOnly])assert.equal((await f.service.broker.authenticate(item.key)).keyId,item.grant.id);
  assert.equal(saved.revision,2);assert.equal(saved.writesUsed['0'],1);assert.equal(saved.expiresAt,original.grant.expiresAt);assert.deepEqual(saved.rules,original.grant.rules);assert.equal(state.tasks[task.id].status,'revoked');
  assert.equal((await f.service.repository.managedKeys()).length,0);assert.equal((await f.service.repository.continuation(f.owner.scope)).length,0);assert.equal((await f.service.repository.connections(f.owner.scope)).length,1);
  await f.service.repository.disconnect(f.owner.scope,'mastodon','123');assert.equal((await f.service.repository.read(f.owner.scope)).grants[original.grant.id].revision,2);
  await f.service.repository.disconnect(f.owner.scope,'mastodon','public:mastodon.social');assert.equal((await f.service.broker.authenticate(publicOnly.key)).keyId,publicOnly.grant.id);
  await f.connect();await assert.rejects(f.service.broker.authenticate(original.key),/access_revoked/);
 }finally{await f.close();}
});

test('disconnect rolls back the deletion and grant retirement together if managed retirement fails',async()=>{
 const f=await fixture();try{await f.connect();const issued=await f.issue([privateRule()]),before=await f.service.repository.read(f.owner.scope),original=f.service.repository.retireManaged.bind(f.service.repository);
  f.service.repository.retireManaged=async()=>{throw Error('Controlled retirement failure');};
  await assert.rejects(f.service.repository.disconnect(f.owner.scope,'mastodon','123'),/Controlled retirement failure/);f.service.repository.retireManaged=original;
  assert.deepEqual(await f.service.repository.read(f.owner.scope),before);assert.equal((await f.service.repository.connections(f.owner.scope)).length,1);assert.equal((await f.service.broker.authenticate(issued.key)).keyId,issued.grant.id);
 }finally{await f.close();}
});

for(const viaRest of [false,true])test('actual builtin paused readback stops after '+(viaRest?'admin REST':'repository')+' disconnect alone and stays revoked across restart',async()=>{
 const f=await fixture(viaRest),started=gate(),release=gate(),network=mockProvider([{path:'/api/v1/statuses/456',body:{id:'456',account:{id:'123'},url:'https://mastodon.social/@controlled/456'},pause:release,started}]);
 try{
  await f.connect();const issued=await f.issue([privateRule()],true),task=await f.service.broker.submit(issued.key,{idempotencyKey:'controlled-readback-disconnect',provider:'mastodon',accountId:'123',action:'publish_text',payload:{text:'controlled'}});
  await f.service.repository.retain(f.owner.scope,issued.key,issued.grant.id);await f.service.repository.scheduleTask(f.owner.scope,task.id);await f.service.repository.transact(f.owner.scope,s=>{s.tasks[task.id].cursor={phase:'published',postId:'456'};});
  const pending=f.service.broker.advance(issued.key,task.id,f.service.adapterFor('mastodon')!);await started.promise;const original=(await f.service.repository.read(f.owner.scope)).tasks[task.id].dispatches[0];
  if(viaRest){const disconnected=await bounded(f.send('/admin/tenants/'+f.owner.tenantId+'/connections/mastodon/123/disconnect'));assert.equal(disconnected.status,200);assert.equal(disconnected.body.disconnected,true);assert.equal((await f.send('/api/access/v1/status',issued.key,'GET')).body.error,'access_revoked');}
  else await bounded(f.service.repository.disconnect(f.owner.scope,'mastodon','123'));
  assert.equal(network.calls.length,1);release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const state=await f.service.repository.read(f.owner.scope),saved=state.tasks[task.id],dispatch=saved.dispatches[0];assert.equal(network.calls.length,1);assert.equal(saved.id,task.id);assert.equal(saved.keyId,issued.grant.id);assert.equal(dispatch.id,original.id);assert.deepEqual(Object.keys(dispatch.calls),[original.id+':1']);assert.equal(dispatch.calls[original.id+':1'].state,'completed');assert.ok(dispatch.calls[original.id+':1'].observedAt);
  assert.equal(saved.cursor.postId,'456');assert.equal(dispatch.outcome?.cursor?.postId,'456');assert.equal(saved.evidence,undefined);assert.equal((await f.service.repository.managedKeys()).length,0);assert.equal((await f.service.repository.continuation(f.owner.scope)).length,0);await assert.rejects(f.service.broker.authenticate(issued.key),/access_revoked/);
  await f.closeService();const restart=createStandaloneService({path:f.path,vaultKey:vault,origin:f.origin});try{await restart.pump();assert.deepEqual(await restart.repository.read(f.owner.scope),state);assert.equal((await restart.repository.connections(f.owner.scope)).length,0);assert.equal((await restart.repository.managedKeys()).length,0);await assert.rejects(restart.broker.authenticate(issued.key),/access_revoked/);assert.equal(network.calls.length,1);}finally{restart.close();}
 }finally{release.resolve();network.restore();await f.close();}
});

test('actual builtin late POST keeps its native post ID on the original revoked dispatch after disconnect alone',async()=>{
 const f=await fixture(),started=gate(),release=gate(),network=mockProvider([{path:'/api/v1/statuses',body:{id:'456'},pause:release,started}]);
 try{
  await f.connect();const issued=await f.issue([privateRule()]),task=await f.service.broker.submit(issued.key,{idempotencyKey:'controlled-publication-disconnect',provider:'mastodon',action:'publish_text',accountId:'123',payload:{text:'controlled'}});
  const pending=f.service.broker.advance(issued.key,task.id,f.service.adapterFor('mastodon')!);await started.promise;const original=(await f.service.repository.read(f.owner.scope)).tasks[task.id].dispatches[0];await bounded(f.service.repository.disconnect(f.owner.scope,'mastodon','123'));release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const state=await f.service.repository.read(f.owner.scope),saved=state.tasks[task.id];assert.equal(saved.id,task.id);assert.equal(saved.dispatches[0].id,original.id);assert.equal(saved.cursor.postId,'456');assert.equal(saved.dispatches[0].outcome?.cursor?.postId,'456');assert.equal(state.grants[issued.grant.id].writesUsed['0'],1);assert.equal(network.calls.length,1);await assert.rejects(f.service.broker.authenticate(issued.key),/access_revoked/);
 }finally{release.resolve();network.restore();await f.close();}
});

test('a lost original POST after disconnect still blocks a new grant and logical write identity',async()=>{
 const f=await fixture(),started=gate(),release=gate(),network=mockProvider([{path:'/api/v1/statuses',pause:release,started,fail:true}]);
 try{
  await f.connect();const issued=await f.issue([privateRule()]),task=await f.service.broker.submit(issued.key,{idempotencyKey:'controlled-lost-disconnected',provider:'mastodon',action:'publish_text',accountId:'123',payload:{text:'controlled'}});
  const pending=f.service.broker.advance(issued.key,task.id,f.service.adapterFor('mastodon')!);await started.promise;await f.service.repository.disconnect(f.owner.scope,'mastodon','123');release.resolve();assert.equal((await pending).status,'revoked');network.consumed();
  const state=await f.service.repository.read(f.owner.scope),dispatch=state.tasks[task.id].dispatches[0];assert.equal(dispatch.state,'uncertain');assert.equal(Object.values(dispatch.calls)[0].state,'uncertain');assert.equal(state.grants[issued.grant.id].writesUsed['0'],1);
  await f.connect();const fresh=await f.issue([privateRule()]);await assert.rejects(f.service.broker.submit(fresh.key,{idempotencyKey:'controlled-new-identity-must-stop',provider:'mastodon',action:'publish_text',accountId:'123',payload:{text:'controlled'}}),/access_reconciliation_required/);assert.equal(network.calls.length,1);
 }finally{release.resolve();network.restore();await f.close();}
});
