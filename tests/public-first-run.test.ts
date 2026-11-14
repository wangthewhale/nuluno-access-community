import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
import {createAccessApp} from '../src/server';
import {NulunoAccessClient} from '../src/core/client';

test('fixed public REST/SDK route reuses the MCP task and rejects arbitrary targets and wrong grants',async()=>{
 const reserve=createServer();await new Promise<void>(r=>reserve.listen(0,'127.0.0.1',r));const port=(reserve.address() as any).port;await new Promise<void>(r=>reserve.close(()=>r()));
 const dir=mkdtempSync(join(tmpdir(),'access-first-run-')),origin='http://127.0.0.1:'+port;
 const {app,service}=createAccessApp({path:join(dir,'state.sqlite'),vaultKey:'v'.repeat(40),adminKey:'a'.repeat(40),origin});
 const server=app.listen(port,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
 try{
  const owner=await service.repository.createTenant('public first run');
  const issued=await service.broker.issue(owner.scope,{label:'public only',expiresAt:Date.now()+60000,rules:[{provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0}]});
  const original=await service.broker.submit(issued.key,{idempotencyKey:'first-run-original',provider:'mastodon',action:'read_public_status',accountId:'public:mastodon.social',payload:{statusId:'123'}});
  let controlledCalls=0;
  await service.broker.advance(issued.key,original.id,{provider:'mastodon',execute:async ctx=>{
   await ctx.external({provider:'mastodon',action:'read_public_status',accountId:'public:mastodon.social',write:false},async()=>{controlledCalls++;return {};});
   return {kind:'completed',evidence:{resourceId:'123',verifiedAt:Date.now(),receiptHash:'c'.repeat(64)}};
  },reconcile:async()=>({kind:'unknown'})});
  const client=new NulunoAccessClient({baseUrl:origin+'/api/access/v1',accessKey:issued.key});
  const same=await client.readPublicStatus({statusId:'123',idempotencyKey:'first-run-original'});
  assert.equal(same.id,original.id);assert.equal(same.status,'succeeded');assert.equal(controlledCalls,1);
  const post=async(body:unknown,key=issued.key)=>fetch(origin+'/api/access/v1/read-public-status',{method:'POST',headers:{authorization:'Bearer '+key,'content-type':'application/json'},body:JSON.stringify(body)});
  for(const extra of [{url:'https://attacker.invalid/'},{provider:'threads'},{action:'publish_text'},{accountId:'other'}]){
   assert.equal((await post({statusId:'123',idempotencyKey:'first-run-original',...extra})).status,400);
  }
  const wrong=await service.broker.issue(owner.scope,{label:'wrong account',expiresAt:Date.now()+60000,rules:[{provider:'mastodon',actions:['read_public_status'],accountIds:['other'],writeLimit:0}]});
  assert.equal((await post({statusId:'123',idempotencyKey:'first-run-denied'},wrong.key)).status,403);
  await service.broker.revoke(owner.scope,issued.grant.id);
  await assert.rejects(client.readPublicStatus({statusId:'123',idempotencyKey:'first-run-original'}),/access_revoked/);
  assert.equal((await service.usage(owner.scope)).providerCallsReserved,1);
 }finally{await new Promise<void>(r=>server.close(()=>r()));service.close();rmSync(dir,{recursive:true,force:true});}
});
