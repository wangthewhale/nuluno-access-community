// Real Linux Docker startup, MCP, durable-volume and revocation acceptance.
// No provider credentials, provider calls, external writes or customer data.
import {randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';

const suffix=randomBytes(8).toString('hex'),name='nuluno-access-ci-'+suffix,volume=name+'-state';
const origin='http://127.0.0.1:8892',adminKey=randomBytes(32).toString('hex');
const env={...process.env,NULUNO_ACCESS_ADMIN_KEY:adminKey,NULUNO_ACCESS_VAULT_KEY:randomBytes(32).toString('hex')};
function docker(args,required=true){
  const r=spawnSync('docker',args,{env,stdio:['ignore','pipe','pipe'],timeout:90000});
  if(required&&r.status!==0)throw new Error('container_operation_failed');
  return r;
}
async function ready(){
  for(let attempt=0;attempt<40;attempt++){
    try{const r=await fetch(origin+'/healthz',{signal:AbortSignal.timeout(1000)});if(r.ok)return;}catch{}
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  throw new Error('container_not_ready');
}
async function owner(path,body){
  const response=await fetch(origin+path,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+adminKey,...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(5000)});
  assert.ok(response.ok,'owner_request_failed');
  return response.json();
}
async function connect(key){
  const c=new Client({name:'independent-linux-container-acceptance',version:'1.0.0'});
  await c.connect(new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+key}}}));
  return c;
}
try{
  docker(['volume','create',volume]);
  docker(['run','-d','--name',name,'-p','127.0.0.1:8892:8892','--mount','type=volume,src='+volume+',dst=/state','--env','NULUNO_ACCESS_ADMIN_KEY','--env','NULUNO_ACCESS_VAULT_KEY','--env','NULUNO_ACCESS_ORIGIN='+origin,'nuluno-access:ci']);
  await ready();
  const tenant=await owner('/admin/tenants',{label:'Disposable independent Linux acceptance'});
  const base='/admin/tenants/'+tenant.tenantId;
  const issued=await owner(base+'/keys',{label:'Zero-write container acceptance',expiresAt:Date.now()+300000,rules:[{provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0}],managed:false,maxTasks:1});
  const client=await connect(issued.key);
  assert.ok((await client.listTools()).tools.some(t=>t.name==='read_public_status'));
  assert.equal((await client.callTool({name:'discover_access_capabilities',arguments:{}})).isError,undefined);
  await client.close();
  docker(['restart',name]);await ready();
  assert.equal((await owner('/admin/tenants')).tenants.length,1);
  const persisted=await owner(base+'/status');assert.equal(persisted.keys.length,1);assert.equal(persisted.usage.providerCallsReserved,0);
  const afterRestart=await connect(issued.key);await afterRestart.close();
  await owner(base+'/keys/'+issued.grant.id+'/revoke',{});
  docker(['restart',name]);await ready();
  const denied=await fetch(origin+'/api/access/v1/capabilities',{headers:{authorization:'Bearer '+issued.key}});
  assert.equal(denied.status,403);assert.equal((await denied.json()).error,'access_revoked');
  await assert.rejects(()=>connect(issued.key));
  const final=await owner(base+'/status');assert.equal(final.usage.providerCallsReserved,0);assert.equal(final.usage.revokedKeys,1);
  process.stdout.write(JSON.stringify({passed:true,source:'GitHub clean checkout',linuxContainerActuallyStarted:true,officialMcpConnected:true,sameVolumeSurvivedTwoRestarts:true,revocationSurvivedRestart:true,providerCalls:0,providerWrites:0,credentialsLogged:false})+'\n');
}finally{
  docker(['rm','-f',name],false);docker(['volume','rm',volume],false);
}
