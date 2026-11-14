// Real public-provider demo. Fresh loopback service/state/key; no private accounts.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {createServer} from 'node:net';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {StdioClientTransport} from '@modelcontextprotocol/client/stdio';
import {NulunoAccessClient} from '@nuluno/access-community';

const {values}=parseArgs({options:{output:{type:'string'},'status-id':{type:'string',default:'117466985005297414'}}});
if(!/^\d{1,40}$/.test(values['status-id']))throw Error('invalid_public_status_id');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const pkg=JSON.parse(readFileSync(join(root,'package.json'),'utf8'));
const version=pkg.version;
const state=mkdtempSync(join(tmpdir(),'nuluno-public-demo-'));
const ownerKey=randomBytes(32).toString('hex'),vaultKey=randomBytes(32).toString('hex');
let child,mcp,stdio;
const reserve=createServer();await new Promise(r=>reserve.listen(0,'127.0.0.1',r));
const port=reserve.address().port;await new Promise(r=>reserve.close(r));
const origin='http://127.0.0.1:'+port;
const safeEnv={PATH:process.env.PATH??'',PORT:String(port),HOST:'127.0.0.1',NULUNO_ACCESS_ORIGIN:origin,NULUNO_ACCESS_STATE:join(state,'access.sqlite'),NULUNO_ACCESS_ADMIN_KEY:ownerKey,NULUNO_ACCESS_VAULT_KEY:vaultKey};
async function boot(){
 child=spawn(process.execPath,[join(root,'dist/server.mjs')],{env:safeEnv,stdio:['ignore','ignore','ignore']});
 for(let i=0;i<80;i++){
  if(child.exitCode!==null)throw Error('demo_service_start_failed');
  try{const r=await fetch(origin+'/healthz',{signal:AbortSignal.timeout(500)});if(r.ok){assert.equal((await r.json()).version,version);return;}}catch{}
  await new Promise(r=>setTimeout(r,100));
 }
 throw Error('demo_service_not_ready');
}
async function stop(signal='SIGKILL'){
 if(!child||child.exitCode!==null||child.signalCode!==null)return;
 const ended=new Promise(r=>child.once('exit',r));child.kill(signal);await ended;child=undefined;
}
async function owner(path,body){
 const r=await fetch(origin+path,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+ownerKey,...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});
 assert.ok(r.ok,'demo_owner_request_failed');return r.json();
}
async function connect(key){
 const c=new Client({name:'external-public-first-run-agent',version:'1.0.0'});
 await c.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+key}}}));return c;
}
function result(value){
 assert.notEqual(value.isError,true,'demo_mcp_tool_failed');
 const v=value.structuredContent??JSON.parse(value.content.find(x=>x.type==='text').text);
 return v;
}
try{
 await boot();
 const tenant=await owner('/admin/tenants',{label:'Disposable public first-run demo'}),base='/admin/tenants/'+tenant.tenantId;
 const issued=await owner(base+'/keys',{label:'Exact public GET only',expiresAt:Date.now()+600000,rules:[{provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0}],managed:false,maxTasks:1});
 const input={statusId:values['status-id'],idempotencyKey:'public-demo-'+randomBytes(10).toString('hex')};
 mcp=await connect(issued.key);
 const tools=(await mcp.listTools()).tools,readTool=tools.find(t=>t.name==='read_public_status');
 assert.equal(readTool?.annotations?.readOnlyHint,true);assert.equal(readTool.annotations.destructiveHint,false);
 const first=result(await mcp.callTool({name:'read_public_status',arguments:input}));
 assert.equal(first.status,'succeeded','real_public_provider_not_succeeded');
 assert.equal(first.evidence.sourceKind,'native_provider');assert.equal(first.evidence.resourceId,input.statusId);
 assert.match(first.evidence.receiptHash,/^[a-f0-9]{64}$/);
 assert.equal(typeof first.evidence.fields?.postText,'string');assert.equal(first.evidence.fields.untrustedData,true);assert.ok(Buffer.byteLength(first.evidence.fields.postText)<=4096);
 const sdk=new NulunoAccessClient({baseUrl:origin+'/api/access/v1',accessKey:issued.key});
 const sdkReuse=await sdk.readPublicStatus(input);assert.equal(sdkReuse.id,first.id);assert.deepEqual(sdkReuse.evidence,first.evidence);
 stdio=new Client({name:'external-stdio-first-run-agent',version:'1.0.0'});
 await stdio.connect(new StdioClientTransport({command:process.execPath,args:[join(root,'scripts/mcp-stdio-bridge.mjs')],env:{PATH:process.env.PATH??'',NULUNO_ACCESS_MCP_URL:origin+'/mcp',NULUNO_ACCESS_KEY:issued.key},stderr:'pipe'}));
 const stdioTools=(await stdio.listTools()).tools;assert.ok(stdioTools.some(t=>t.name==='read_public_status'));assert.ok(!stdioTools.some(t=>t.name==='submit_access_task'));
 const bridged=result(await stdio.callTool({name:'read_public_status',arguments:input}));assert.equal(bridged.id,first.id);assert.deepEqual(bridged.evidence,first.evidence);await stdio.close();stdio=undefined;
 const before=await owner(base+'/usage');assert.equal(before.tasks,1);assert.equal(before.providerCallsReserved,1);assert.equal(before.providerWriteReservations,0);
 await mcp.close();mcp=undefined;await stop();await boot();
 mcp=await connect(issued.key);
 const resumed=result(await mcp.callTool({name:'read_public_status',arguments:input}));assert.equal(resumed.id,first.id);assert.deepEqual(resumed.evidence,first.evidence);
 assert.equal((await sdk.getTask(first.id)).id,first.id);
 const flow=await sdk.flow(first.id);
 await owner(base+'/keys/'+issued.grant.id+'/revoke',{});
 let mcpDenied=false;try{const denied=await mcp.callTool({name:'get_access_task',arguments:{taskId:first.id}});mcpDenied=denied.isError===true;}catch{mcpDenied=true;}assert.equal(mcpDenied,true);
 await assert.rejects(sdk.readPublicStatus(input),e=>e.code==='access_revoked');
 await mcp.close();mcp=undefined;await stop();await boot();
 await assert.rejects(sdk.capabilities(),e=>e.code==='access_revoked');
 const after=await owner(base+'/status');assert.equal(after.usage.tasks,1);assert.equal(after.usage.providerCallsReserved,1);assert.equal(after.usage.providerWriteReservations,0);assert.equal(after.usage.revokedKeys,1);
 const original=after.tasks.find(t=>t.id===first.id);assert.deepEqual(original.evidence,first.evidence);
 const receipt={schema:'nuluno-access-public-demo-v1',passed:true,observedAt:new Date().toISOString(),version,platform:process.platform,architecture:process.arch,node:process.version,serverBundleSha256:createHash('sha256').update(readFileSync(join(root,'dist/server.mjs'))).digest('hex'),officialMcpClient:true,officialStdioBridgeClient:true,stdioDefaultExposesReadOnlyToolsOnly:true,externalServiceProcess:true,exactReadOnlyTool:true,restSdkReadPublicStatus:true,boundedPublicPostTextReturned:true,publicTextMarkedUntrusted:true,publicTextBytes:Buffer.byteLength(first.evidence.fields.postText),publicTextSha256:createHash('sha256').update(first.evidence.fields.postText).digest('hex'),provider:'mastodon.social',providerCalls:1,providerWrites:0,modelCalls:0,statusId:input.statusId,taskId:first.id,receiptHash:first.evidence.receiptHash,publicUrl:first.evidence.publicUrl,sourceKind:first.evidence.sourceKind,sameTaskAcrossMcpAndSdk:true,sameTaskAndReceiptAfterSigkill:true,revocationDeniedByMcpAndSdk:true,revocationSurvivedSecondSigkill:true,taskAndReceiptRetainedAfterRevocation:true,fullCostMicros:after.usage.cost?.fullCostMicros??null,privateInboxSignupOrPublicationAccepted:false,commercialSuccessVerified:false,limits:['One real public status GET; no private account connection, inbox, signup or publication.','Process crash occurs after the successful read; uncertain-write recovery is a separate controlled demo.','A real provider outage, deleted status or rate limit makes this demo fail; it is never replaced by a mock.']};
 // Deliberately omit grants, bearer keys, full capability/flow objects and state paths.
 assert.ok(flow&&typeof flow==='object');
 if(values.output)writeFileSync(resolve(values.output),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
 process.stdout.write(JSON.stringify(receipt,null,2)+'\n');
}catch(error){
 process.stderr.write(JSON.stringify({passed:false,error:'public_demo_failed',version,privateDataUsed:false,providerWrites:0,detail:error?.code==='ERR_ASSERTION'?String(error.message).slice(0,100):'Inspect connectivity, Node version, build and the selected public status. No mock fallback is used.'})+'\n');process.exitCode=1;
}finally{
 if(stdio)await stdio.close().catch(()=>{});if(mcp)await mcp.close().catch(()=>{});await stop().catch(()=>{});rmSync(state,{recursive:true,force:true});
}
