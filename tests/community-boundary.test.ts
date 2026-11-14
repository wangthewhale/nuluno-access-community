// SPDX-License-Identifier: Apache-2.0
// Actual loopback HTTP, SQLite and official MCP transports. Private providers
// below are explicitly trusted-host controlled fixtures, never live accounts.
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createServer} from 'node:net';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {createAccessApp} from '../src/server';
import type {InstalledExtension} from '../src/service';
import type {AccessProviderAdapter} from '../src/core/types';

const admin='a'.repeat(40),vault='v'.repeat(40);
const publicRule={provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0};
async function fixture(path:string,extensions:readonly InstalledExtension[]=[],fetchImpl:typeof fetch=globalThis.fetch){
 const held=createServer();await new Promise<void>(r=>held.listen(0,'127.0.0.1',r));const port=(held.address() as any).port;await new Promise<void>(r=>held.close(()=>r()));
 const origin='http://127.0.0.1:'+port,{app,service}=createAccessApp({path,vaultKey:vault,adminKey:admin,origin,extensions});
 const server=app.listen(port,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
 const request=(url:string,body?:unknown,key=admin)=>fetchImpl(origin+url,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+key,...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
 async function owner(url:string,body?:unknown){const r=await request(url,body);assert.ok(r.ok,'controlled owner request failed');return r.json() as Promise<any>;}
 async function connect(key:string){const c=new Client({name:'community-boundary-controlled-client',version:'1.0.0'});await c.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+key}}}));return c;}
 return {origin,service,request,owner,connect,close:async()=>{await new Promise<void>(r=>server.close(()=>r()));service.close();}};
}
function mcpResult(value:any){assert.notEqual(value.isError,true);return value.structuredContent??JSON.parse(value.content.find((c:any)=>c.type==='text').text);}

test('community HTTP/MCP discovery excludes uninstalled paid providers; owner grant attempts make zero provider calls',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'access-community-boundary-')),original=globalThis.fetch;let blockedExternal=0,client:Client|undefined;
 let f:Awaited<ReturnType<typeof fixture>>|undefined;
 globalThis.fetch=(async(input:any,init?:any)=>{const u=new URL(input instanceof Request?input.url:String(input));if(u.hostname==='127.0.0.1')return original(input,init);blockedExternal++;throw Error('external network forbidden in community boundary test');}) as typeof fetch;
 try{
  f=await fixture(join(dir,'state.sqlite'),[],original);
  const metadata=await (await original(f.origin+'/.well-known/nuluno-access.json')).json() as any;
  assert.equal(metadata.license,'Apache-2.0');assert.deepEqual(metadata.extensions,[]);
  assert.deepEqual(metadata.providers,[{id:'mastodon',actions:['read_public_status','verify_identity','publish_text']}]);
  const tenant=await f.owner('/admin/tenants',{label:'Community no private provider'}),base='/admin/tenants/'+tenant.tenantId;
  const expiresAt=Date.now()+120000,issued=await f.owner(base+'/keys',{label:'Public only',expiresAt,rules:[publicRule],managed:false});
  client=await f.connect(issued.key);
  assert.ok((await client.listTools()).tools.some(t=>t.name==='read_public_status'));
  const caps=mcpResult(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(caps.grant.rules,[publicRule]);assert.equal(caps.grant.expiresAt,expiresAt);
  for(const rule of [
   {provider:'gmail',actions:['verify_email'],accountIds:['controlled-mailbox'],writeLimit:0},
   {provider:'threads',actions:['publish_text'],accountIds:['controlled-brand'],writeLimit:1},
   {provider:'mastodon',actions:['create_account'],accountIds:['controlled-prepared'],writeLimit:1},
  ]){
   const denied=await f.request(base+'/keys',{label:'Unavailable private action',expiresAt,rules:[rule],managed:false});assert.equal(denied.status,403);assert.equal((await denied.json() as any).error,'access_rule_denied');
  }
  const bad=mcpResult(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(bad.grant.rules,[publicRule]);
  const status=await f.owner(base+'/status');assert.equal(status.keys.length,1);assert.equal(status.usage.tasks,0);assert.equal(status.usage.providerCallsReserved,0);assert.equal(status.usage.providerWriteReservations,0);assert.equal(blockedExternal,0);
 }finally{await client?.close();await f?.close();globalThis.fetch=original;rmSync(dir,{recursive:true,force:true});}
});

test('free Mastodon OAuth preparation has PKCE and exact callback; unknown callbacks fail without token exchange',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'access-community-oauth-')),original=globalThis.fetch;let controlledAppResponses=0,unexpectedExternal=0;
 let f:Awaited<ReturnType<typeof fixture>>|undefined;
 // Only the public app-registration response is controlled; no outside request
 // is sent and no real application or social account is created.
 globalThis.fetch=(async(input:any,init?:any)=>{
  const u=new URL(input instanceof Request?input.url:String(input));if(u.hostname==='127.0.0.1')return original(input,init);
  if(u.href==='https://mastodon.social/api/v1/apps'&&init?.method==='POST'){controlledAppResponses++;return Response.json({client_id:'CONTROLLED_CLIENT_ID',client_secret:'CONTROLLED_CLIENT_SECRET'});}
  unexpectedExternal++;throw Error('outside request forbidden');
 }) as typeof fetch;
 try{
  f=await fixture(join(dir,'state.sqlite'),[],original);const tenant=await f.owner('/admin/tenants',{label:'Controlled OAuth preparation'}),base='/admin/tenants/'+tenant.tenantId;
  const unauth=await original(f.origin+base+'/mastodon/start',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});assert.equal(unauth.status,403);assert.equal(controlledAppResponses,0);
  const start=await f.owner(base+'/mastodon/start',{}),url=new URL(start.authorizationUrl);
  assert.equal(url.origin,'https://mastodon.social');assert.equal(url.pathname,'/oauth/authorize');assert.equal(url.searchParams.get('response_type'),'code');assert.equal(url.searchParams.get('code_challenge_method'),'S256');assert.match(url.searchParams.get('code_challenge')??'',/^[A-Za-z0-9_-]{43}$/);assert.match(url.searchParams.get('state')??'',/^[A-Za-z0-9_-]{43}$/);
  assert.equal(url.searchParams.get('redirect_uri'),f.origin+'/oauth/mastodon/callback');assert.equal(start.authorizationUrl.includes('CONTROLLED_CLIENT_SECRET'),false);
  const empty=await original(f.origin+'/oauth/mastodon/callback');assert.equal(empty.status,400);assert.equal((await empty.json() as any).error,'access_invalid_input');
  const unknown=await original(f.origin+'/oauth/mastodon/callback?state=unknown-controlled-state&code=controlled-not-real-code');assert.equal(unknown.status,403);assert.equal((await unknown.json() as any).error,'access_verification_rejected');
  assert.equal(controlledAppResponses,1);assert.equal(unexpectedExternal,0);assert.equal((await f.owner(base+'/usage')).providerCallsReserved,0);
  const rows=f.service.repository.db.prepare('SELECT encrypted,phase FROM oauth').all() as any[];assert.equal(rows.length,1);assert.equal(rows[0].phase,'pending');assert.equal(rows[0].encrypted.includes('CONTROLLED_CLIENT_SECRET'),false);
 }finally{await f?.close();globalThis.fetch=original;rmSync(dir,{recursive:true,force:true});}
});

test('uninstalling a trusted extension filters capabilities and blocks original pending work without resetting its grant',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'access-community-uninstall-')),path=join(dir,'state.sqlite'),original=globalThis.fetch;
 let f:Awaited<ReturnType<typeof fixture>>|undefined,client:Client|undefined,controlledCallbacks=0,unexpectedExternal=0;
 const adapters:Record<string,AccessProviderAdapter>={};
 for(const provider of ['gmail','threads','mastodon'])adapters[provider]={provider,execute:async ctx=>{
  controlledCallbacks++;
  await ctx.external({provider,action:ctx.task.action,accountId:ctx.task.accountId,write:false},async()=>({controlled:true}));
  return {kind:'completed',evidence:{resourceId:'controlled-fixture-only',receiptHash:'1'.repeat(64),verifiedAt:Date.now()}};
 },reconcile:async()=>({kind:'unknown'})};
 const extension:InstalledExtension={id:'controlled-extension',module:'@controlled/fixture',version:'1.0.0',entryPath:'/CONTROLLED/FIXTURE_ONLY.mjs',entrySha256:'0'.repeat(64),providers:[
  {provider:'gmail',actions:['verify_email'],readOnlyActions:[]},
  {provider:'threads',actions:['publish_text'],readOnlyActions:[]},
  {provider:'mastodon',actions:['connect','create_account'],readOnlyActions:[],augment:true},
 ],install:()=>({adapters})};
 globalThis.fetch=(async(input:any,init?:any)=>{const u=new URL(input instanceof Request?input.url:String(input));if(u.hostname==='127.0.0.1')return original(input,init);unexpectedExternal++;throw Error('no private provider network');}) as typeof fetch;
 try{
  // This bypasses the loader deliberately: it is a trusted-host integration
  // fixture, not proof that the fake module passed entry-hash validation.
  f=await fixture(path,[extension],original);
  const meta=await (await original(f.origin+'/.well-known/nuluno-access.json')).json() as any;
  assert.deepEqual(meta.providers.find((p:any)=>p.id==='gmail').actions,['verify_email']);assert.deepEqual(meta.providers.find((p:any)=>p.id==='threads').actions,['publish_text']);assert.deepEqual(meta.providers.find((p:any)=>p.id==='mastodon').actions,['read_public_status','verify_identity','publish_text','connect','create_account']);
  const tenant=await f.owner('/admin/tenants',{label:'Trusted extension lifecycle'}),base='/admin/tenants/'+tenant.tenantId,expiresAt=Date.now()+120000;
  const rules=[publicRule,{provider:'gmail',actions:['verify_email'],accountIds:['controlled-mailbox'],writeLimit:0},{provider:'threads',actions:['publish_text'],accountIds:['controlled-brand'],writeLimit:1},{provider:'mastodon',actions:['create_account'],accountIds:['controlled-prepared'],writeLimit:1}];
  const issued=await f.owner(base+'/keys',{label:'Unchanged original authority',expiresAt,rules,managed:false,maxTasks:5});
  client=await f.connect(issued.key);const beforeCaps=mcpResult(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(beforeCaps.grant.rules,rules);
  const gmail=await (await f.request('/api/access/v1/tasks',{idempotencyKey:'original-pending-verification',provider:'gmail',action:'verify_email',accountId:'controlled-mailbox',payload:{targetId:'controlled-only'}},issued.key)).json() as any;
  const signup=await (await f.request('/api/access/v1/tasks',{idempotencyKey:'original-pending-signup',provider:'mastodon',action:'create_account',accountId:'controlled-prepared',payload:{connectionId:'controlled-prepared'}},issued.key)).json() as any;
  assert.equal(gmail.status,'pending');assert.equal(signup.status,'pending');
  const active=await (await f.request('/api/access/v1/tasks',{idempotencyKey:'controlled-installed-adapter',provider:'threads',action:'publish_text',accountId:'controlled-brand',payload:{text:'CONTROLLED FIXTURE, NO PLATFORM'}},issued.key)).json() as any;
  const advanced=await f.request('/api/access/v1/tasks/'+active.id+'/advance',{},issued.key);assert.equal(advanced.status,200);assert.equal((await advanced.json() as any).status,'succeeded');assert.equal(controlledCallbacks,1);
  const beforeState=await f.service.repository.read(tenant.scope),beforeGrant=structuredClone(beforeState.grants[issued.grant.id]),pending=structuredClone(beforeState.tasks[gmail.id]),signupPending=structuredClone(beforeState.tasks[signup.id]);
  await client.close();client=undefined;await f.close();f=await fixture(path,[],original);
  const afterMeta=await (await original(f.origin+'/.well-known/nuluno-access.json')).json() as any;assert.deepEqual(afterMeta.providers,[{id:'mastodon',actions:['read_public_status','verify_identity','publish_text']}]);assert.deepEqual(afterMeta.extensions,[]);
  client=await f.connect(issued.key);const afterCaps=mcpResult(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(afterCaps.grant.rules,[publicRule]);assert.equal(afterCaps.grant.expiresAt,expiresAt);assert.equal(afterCaps.grant.revision,beforeGrant.revision);
  const deniedGmail=await f.request('/api/access/v1/tasks/'+gmail.id+'/advance',{},issued.key);assert.equal(deniedGmail.status,503);assert.equal((await deniedGmail.json() as any).error,'access_provider_unavailable');
  const deniedSignup=await f.request('/api/access/v1/tasks/'+signup.id+'/advance',{},issued.key);assert.equal(deniedSignup.status,403);assert.equal((await deniedSignup.json() as any).error,'access_rule_denied');
  await assert.rejects(f.service.broker.advance(issued.key,gmail.id,adapters.gmail),/access_rule_denied/);
  const afterState=await f.service.repository.read(tenant.scope);assert.deepEqual(afterState.grants[issued.grant.id],beforeGrant);assert.deepEqual(afterState.tasks[gmail.id],pending);assert.deepEqual(afterState.tasks[signup.id],signupPending);assert.equal(controlledCallbacks,1);assert.equal(unexpectedExternal,0);
 }finally{await client?.close();await f?.close();globalThis.fetch=original;rmSync(dir,{recursive:true,force:true});}
});

test('managed removed signup actions stay quiescent across pump ticks and resume under the original grant when reinstalled',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'access-community-managed-uninstall-')),path=join(dir,'state.sqlite'),original=globalThis.fetch;
 let f:Awaited<ReturnType<typeof fixture>>|undefined,controlledCallbacks=0,unexpectedExternal=0;
 // Trusted-host runtime fixture only. It performs no actual account creation,
 // provider network or loader-integrity acceptance.
 const adapter:AccessProviderAdapter={provider:'mastodon',execute:async ctx=>{
  controlledCallbacks++;
  await ctx.external({provider:'mastodon',action:'create_account',accountId:'controlled-prepared',write:true},async()=>({id:'controlled-created-account'}));
  return {kind:'completed',evidence:{resourceId:'controlled-created-account',receiptHash:'4'.repeat(64),verifiedAt:Date.now()}};
 },reconcile:async()=>({kind:'unknown'})};
 const extension:InstalledExtension={id:'controlled-managed-signup',module:'@controlled/managed-signup',version:'1.0.0',entryPath:'/CONTROLLED/SERVICE_COMPONENT_ONLY.mjs',entrySha256:'0'.repeat(64),providers:[{provider:'mastodon',actions:['create_account'],readOnlyActions:[],augment:true}],install:()=>({adapters:{mastodon:adapter}})};
 globalThis.fetch=(async(input:any,init?:any)=>{const u=new URL(input instanceof Request?input.url:String(input));if(u.hostname==='127.0.0.1')return original(input,init);unexpectedExternal++;throw Error('no private signup network in controlled test');}) as typeof fetch;
 try{
  f=await fixture(path,[extension],original);
  const tenant=await f.owner('/admin/tenants',{label:'Managed installed-action lifecycle'}),base='/admin/tenants/'+tenant.tenantId,expiresAt=Date.now()+120000;
  const issued=await f.owner(base+'/keys',{label:'Original managed signup',expiresAt,rules:[{provider:'mastodon',actions:['create_account'],accountIds:['controlled-prepared'],writeLimit:1}],managed:true,maxTasks:1});
  const response=await f.request('/api/access/v1/tasks',{idempotencyKey:'managed-original-signup-task',provider:'mastodon',action:'create_account',accountId:'controlled-prepared',payload:{connectionId:'controlled-prepared'}},issued.key);assert.equal(response.status,201);const task=await response.json() as any;assert.equal(task.status,'pending');
  const before=await f.service.repository.read(tenant.scope),originalTask=structuredClone(before.tasks[task.id]),originalGrant=structuredClone(before.grants[issued.grant.id]);
  const originalSchedule=f.service.repository.db.prepare('SELECT task_id,next_at,attempts,held FROM schedule WHERE task_id=?').get(task.id) as any;
  const originalAudit=(f.service.repository.db.prepare('SELECT COUNT(*) AS n FROM audit').get() as any).n;
  const originalUsage=await f.owner(base+'/usage');assert.equal(originalSchedule.attempts,0);assert.equal(originalUsage.providerCallsReserved,0);assert.equal(controlledCallbacks,0);
  await f.close();f=await fixture(path,[],original);
  for(let i=0;i<6;i++)await f.service.pump();
  const blockedUsage=await f.owner(base+'/usage'),blockedState=await f.service.repository.read(tenant.scope);
  assert.deepEqual(blockedUsage.capabilityBlocks,[{taskId:task.id,provider:'mastodon',action:'create_account',reason:'extension_not_installed'}]);
  assert.deepEqual(blockedState.tasks[task.id],originalTask);assert.deepEqual(blockedState.grants[issued.grant.id],originalGrant);
  assert.deepEqual(f.service.repository.db.prepare('SELECT task_id,next_at,attempts,held FROM schedule WHERE task_id=?').get(task.id),originalSchedule);
  assert.equal((f.service.repository.db.prepare('SELECT COUNT(*) AS n FROM audit').get() as any).n,originalAudit);
  assert.equal(blockedUsage.providerCallsReserved,originalUsage.providerCallsReserved);assert.equal(blockedUsage.providerWriteReservations,0);assert.equal(blockedState.tasks[task.id].dispatches.length,0);assert.equal(controlledCallbacks,0);assert.equal(unexpectedExternal,0);
  await f.close();f=await fixture(path,[extension],original);
  const eligible=(await f.service.repository.continuation(tenant.scope)).find((entry:any)=>entry.taskId===task.id)!;assert.equal(eligible.automaticEligible,true);assert.equal(eligible.attempts,0);assert.equal(eligible.dispatches,0);assert.equal(eligible.expiresAt,expiresAt);assert.equal(f.service.repository.due(task.id),true);assert.deepEqual((await f.owner(base+'/usage')).capabilityBlocks,[]);
  await f.service.pump();
  const finalState=await f.service.repository.read(tenant.scope),completed=finalState.tasks[task.id],grant=finalState.grants[issued.grant.id];assert.equal(completed.id,task.id);assert.equal(completed.keyId,originalTask.keyId);assert.equal(completed.createdAt,originalTask.createdAt);assert.equal(completed.status,'succeeded');assert.equal(completed.dispatches.length,1);assert.equal(controlledCallbacks,1);
  assert.equal(grant.expiresAt,expiresAt);assert.equal(grant.createdAt,originalGrant.createdAt);assert.equal(grant.revision,originalGrant.revision);assert.equal(grant.maxTasks,originalGrant.maxTasks);assert.equal((await f.owner(base+'/usage')).providerWriteReservations,1);assert.equal(unexpectedExternal,0);
 }finally{await f?.close();globalThis.fetch=original;rmSync(dir,{recursive:true,force:true});}
});
