// SPDX-License-Identifier: Apache-2.0
// Clean-consumer component acceptance, not private provider acceptance.
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,realpathSync,statSync} from 'node:fs';
import {createRequire} from 'node:module';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname,isAbsolute,join,relative,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';

const {values}=parseArgs({options:{installation:{type:'string'}}});
if(!values.installation||!isAbsolute(values.installation))throw Error('absolute_installation_required');
// This child process needs no inherited private configuration. Do not read,
// print or copy another host application's credential environment into Access.
for(const name of Object.keys(process.env))if(!['PATH','TMPDIR','TEMP','TMP','SystemRoot','WINDIR'].includes(name))delete process.env[name];
const originalFetch=globalThis.fetch;let blockedExternalFetches=0,stage='resolve_packages';
globalThis.fetch=(async(input,init)=>{
 const u=new URL(input instanceof Request?input.url:String(input));
 if(u.protocol==='http:'&&['127.0.0.1','localhost','[::1]'].includes(u.hostname))return originalFetch(input,init);
 blockedExternalFetches++;throw Error('commercial_acceptance_external_fetch_forbidden');
});
let stateDir,server,service,client;
const sha=path=>createHash('sha256').update(readFileSync(path)).digest('hex');
function packageMetadata(entry,expectedName){
 let directory=dirname(entry);
 for(let i=0;i<24;i++){
  try{const path=join(directory,'package.json');if(statSync(path).size>65536)throw Error('invalid_package_metadata');const p=JSON.parse(readFileSync(path,'utf8'));assert.equal(p.name,expectedName);return p;}
  catch(error){if(error.code!=='ENOENT')throw error;}
  const parent=dirname(directory);if(parent===directory)break;directory=parent;
 }
 throw Error('package_metadata_missing');
}
function assertConsumerEntry(installation,entry){const r=relative(join(installation,'node_modules'),entry);assert.ok(r&&!r.startsWith('..')&&!isAbsolute(r),'package resolved outside clean consumer');}
async function close(){
 if(client){await client.close();client=undefined;}
 if(server){const active=server;server=undefined;await new Promise(r=>active.close(r));}
 if(service){service.close();service=undefined;}
}
try{
 const installation=realpathSync(resolve(values.installation));
 const require=createRequire(join(installation,'package.json'));
 const serviceEntry=realpathSync(require.resolve('@nuluno/access-community/service'));
 const registryEntry=realpathSync(require.resolve('@nuluno/access-community/extensions'));
 const commercialEntry=realpathSync(require.resolve('@nuluno/access-commercial-extension'));
 const clientEntry=realpathSync(require.resolve('@modelcontextprotocol/client'));
 const serverEntry=realpathSync(join(dirname(serviceEntry),'server.mjs'));
 for(const entry of [serviceEntry,registryEntry,commercialEntry,clientEntry,serverEntry])assertConsumerEntry(installation,entry);
 const community=packageMetadata(serviceEntry,'@nuluno/access-community'),commercial=packageMetadata(commercialEntry,'@nuluno/access-commercial-extension');
 assert.equal(community.version,'0.1.0-alpha.1');assert.equal(commercial.version,'0.1.0-alpha.1');assert.equal(community.license,'Apache-2.0');assert.notEqual(commercial.license,'Apache-2.0');
 const entrySha256=sha(commercialEntry);
 const {loadAccessExtensions}=await import(pathToFileURL(registryEntry).href);
 const {createAccessApp}=await import(pathToFileURL(serverEntry).href);
 const {Client,StreamableHTTPClientTransport}=await import(pathToFileURL(clientEntry).href);
 stage='pinned_registry_load';
 const extensions=await loadAccessExtensions([{id:'commercial',module:'@nuluno/access-commercial-extension',version:'0.1.0-alpha.1',entrySha256}],{resolveFrom:join(installation,'package.json')});
 assert.equal(extensions.length,1);assert.equal(extensions[0].entrySha256,entrySha256);
 stateDir=mkdtempSync(join(tmpdir(),'access-commercial-installed-'));
 const held=createServer();await new Promise(r=>held.listen(0,'127.0.0.1',r));const port=held.address().port;await new Promise(r=>held.close(r));
 const origin='http://127.0.0.1:'+port,adminKey=randomBytes(32).toString('hex'),vaultKey=randomBytes(32).toString('hex'),path=join(stateDir,'state.sqlite');
 async function boot(installed){const app=createAccessApp({path,vaultKey,adminKey,origin,extensions:installed});service=app.service;server=app.app.listen(port,'127.0.0.1');await new Promise((r,j)=>{server.once('listening',r);server.once('error',j);});}
 // This fixture deliberately closes/reopens the same listener. Do not reuse a
 // pooled socket from the previous process generation or retry a failed POST.
 async function request(path,body,key=adminKey){return fetch(origin+path,{method:body===undefined?'GET':'POST',headers:{connection:'close',authorization:'Bearer '+key,...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});}
 async function owner(path,body){const r=await request(path,body);assert.ok(r.ok,'owner fixture request failed');return r.json();}
 async function connect(key){client=new Client({name:'clean-installed-commercial-boundary-client',version:'1.0.0'});await client.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{connection:'close',authorization:'Bearer '+key}}}));}
 function value(result){assert.notEqual(result.isError,true);return result.structuredContent??JSON.parse(result.content.find(c=>c.type==='text').text);}
 stage='installed_http_and_mcp';await boot(extensions);
 const metadata=await (await request('/.well-known/nuluno-access.json')).json(),providers=new Map(metadata.providers.map(p=>[p.id,p.actions]));
 assert.deepEqual(providers.get('gmail'),['verify_email']);assert.deepEqual(providers.get('threads'),['publish_text']);
 for(const action of ['read_public_status','verify_identity','publish_text','connect','create_account'])assert.ok(providers.get('mastodon').includes(action));
 const tenant=await owner('/admin/tenants',{label:'Clean installed extension boundary'}),base='/admin/tenants/'+tenant.tenantId,expiresAt=Date.now()+120000;
 const rules=[{provider:'gmail',actions:['verify_email'],accountIds:['unconfigured-controlled-mailbox'],writeLimit:0}];
 const issued=await owner(base+'/keys',{label:'Unconfigured verification only',expiresAt,rules,managed:false,maxTasks:1});
 await connect(issued.key);assert.ok((await client.listTools()).tools.some(t=>t.name==='discover_access_capabilities'));
 const caps=value(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(caps.grant.rules,rules);assert.equal(caps.grant.expiresAt,expiresAt);
 stage='unconfigured_private_actions_fail_closed';
 const google=await request(base+'/google/start',{});assert.equal(google.status,503);assert.equal((await google.json()).error,'access_provider_unavailable');
 const taskResponse=await request('/api/access/v1/tasks',{idempotencyKey:'commercial-unconfigured-original-task',provider:'gmail',action:'verify_email',accountId:'unconfigured-controlled-mailbox',payload:{targetId:'not-an-installed-verification-target',connectionId:'unprepared-controlled-connection'}},issued.key);
 assert.equal(taskResponse.status,201);const task=await taskResponse.json();assert.equal(task.status,'pending');
 const advance=await request('/api/access/v1/tasks/'+task.id+'/advance',{},issued.key);assert.equal(advance.status,200);const unresolved=await advance.json();assert.notEqual(unresolved.status,'succeeded');assert.equal(unresolved.evidence,undefined);
 const usage=await owner(base+'/usage');assert.equal(usage.providerCallsReserved,0);assert.equal(usage.providerWriteReservations,0);assert.equal(usage.verifiedReceipts,0);assert.equal(blockedExternalFetches,0);
 const original=await service.repository.read(tenant.scope),originalGrant=structuredClone(original.grants[issued.grant.id]),originalTask=structuredClone(original.tasks[task.id]);
 stage='uninstall_boot_without_extension';await close();await boot([]);
 stage='uninstalled_metadata';
 const unloaded=await (await request('/.well-known/nuluno-access.json')).json();assert.deepEqual(unloaded.extensions,[]);assert.deepEqual(unloaded.providers,[{id:'mastodon',actions:['read_public_status','verify_identity','publish_text']}]);
 stage='uninstalled_scoped_capabilities';await connect(issued.key);const afterCaps=value(await client.callTool({name:'discover_access_capabilities',arguments:{}}));assert.deepEqual(afterCaps.grant.rules,[]);assert.equal(afterCaps.grant.expiresAt,expiresAt);assert.equal(afterCaps.grant.revision,originalGrant.revision);
 stage='uninstalled_advance_denied';
 const denied=await request('/api/access/v1/tasks/'+task.id+'/advance',{},issued.key);assert.equal(denied.status,503);assert.equal((await denied.json()).error,'access_provider_unavailable');
 stage='uninstalled_original_task_readback';const saved=value(await client.callTool({name:'get_access_task',arguments:{taskId:task.id}}));assert.equal(saved.id,task.id);assert.equal(saved.status,unresolved.status);assert.deepEqual(saved.evidence,unresolved.evidence);
 const after=await service.repository.read(tenant.scope);stage='uninstalled_original_grant';assert.deepEqual(after.grants[issued.grant.id],originalGrant);stage='uninstalled_original_task';assert.deepEqual(after.tasks[task.id],originalTask);assert.equal(blockedExternalFetches,0);
 await close();assert.equal(blockedExternalFetches,0);
 const receipt={schema:'nuluno-access-commercial-clean-consumer-v1',passed:true,observedAt:new Date().toISOString(),communityVersion:community.version,communityLicense:community.license,commercialVersion:commercial.version,commercialLicense:commercial.license,communityServerBundleSha256:sha(serverEntry),commercialEntrySha256:entrySha256,installedOutsideSource:true,loadedByPinnedRegistry:true,officialMcpClient:true,loopbackHttpAndPersistentSqlite:true,installedGmailThreadsAndSignupActionsAdvertised:true,originalMastodonReadIdentityPostActionsRetained:true,exactScopedGmailGrantDiscovered:true,unconfiguredGoogleStartDenied:true,unpreparedInvalidVerificationTargetDidNotSucceed:true,uninstallRemovedPrivateCapabilities:true,uninstallDeniedFurtherAdvancement:true,originalGrantAndDeadlinePreserved:true,originalTaskAndEvidencePreserved:true,originalTaskId:task.id,providerCalls:0,providerWrites:0,verifiedNativeReceipts:0,blockedExternalFetches,modelCalls:0,privateInboxSignupPublicationAccepted:false,commercialSuccessVerified:false,limits:['Real clean-installed package/loader/HTTP/MCP integration, without private platform credentials.','No Google OAuth client or account consent was configured; rejection is the expected result.','An installed provider is not evidence of successful private inbox, verification, signup or publication.']};
 process.stdout.write(JSON.stringify(receipt,null,2)+'\n');
}catch(error){
 const code=typeof error?.code==='string'&&/^(?:ERR_[A-Z_]+|access_[a-z_]+)$/.test(error.code)?error.code:'acceptance_failed';
 const causeCode=typeof error?.cause?.code==='string'&&/^(?:ERR_[A-Z_]+|UND_ERR_[A-Z_]+)$/.test(error.cause.code)?error.cause.code:undefined;
 const failureName=['TypeError','ReferenceError','SyntaxError','RangeError','AssertionError'].includes(error?.name)?error.name:'Error';
 process.stderr.write(JSON.stringify({passed:false,error:code,failureName,...(causeCode?{causeCode}:{}),stage,privateDataUsed:false})+'\n');process.exitCode=1;
}finally{
 await close().catch(()=>{});globalThis.fetch=originalFetch;if(stateDir)rmSync(stateDir,{recursive:true,force:true});
}
