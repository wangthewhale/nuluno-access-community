// Disposable host for an actual external agent. No inherited provider grants.
import {randomBytes} from 'node:crypto';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {createServer} from 'node:net';
const {values}=parseArgs({options:{directory:{type:'string'},status:{type:'boolean'},revoke:{type:'boolean'},'status-id':{type:'string',default:'117466985005297414'}}});
if(values.status&&values.revoke)throw Error('choose_one_control_operation');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
if(values.status||values.revoke){
 if(!values.directory)throw Error('private_directory_required');
 const path=join(resolve(values.directory),'owner-control.json'),s=statSync(path);if(process.platform!=='win32'&&(s.mode&0o077)!==0)throw Error('private_control_file_required');
 const c=JSON.parse(readFileSync(path,'utf8')),url=new URL(c.origin);if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('invalid_fixture_origin');
 const base=c.origin+'/admin/tenants/'+c.tenantId;
 if(values.revoke){const r=await fetch(base+'/keys/'+c.keyId+'/revoke',{method:'POST',headers:{authorization:'Bearer '+c.adminKey,'content-type':'application/json'},body:'{}'});if(!r.ok)throw Error('fixture_revoke_failed');process.stdout.write(JSON.stringify({revoked:true,version:c.version})+'\n');}
 else{const r=await fetch(base+'/status',{headers:{authorization:'Bearer '+c.adminKey}});if(!r.ok)throw Error('fixture_status_failed');const v=await r.json();process.stdout.write(JSON.stringify({version:c.version,origin:c.origin,tasks:v.tasks.map(t=>({id:t.id,status:t.status,idempotencyKey:t.idempotencyKey,evidence:t.evidence})),providerCallsReserved:v.usage.providerCallsReserved,providerWritesReserved:v.usage.providerWriteReservations,revokedKeys:v.usage.revokedKeys,verifiedReceipts:v.usage.verifiedReceipts,fullCostMicros:v.usage.cost?.fullCostMicros??null},null,2)+'\n');}
}else{
 if(!/^\d{1,40}$/.test(values['status-id']))throw Error('invalid_status_id');
 let directory;if(values.directory){directory=resolve(values.directory);mkdirSync(directory,{mode:0o700});}else directory=mkdtempSync(join(tmpdir(),'nuluno-external-agent-'));
 const hold=createServer();await new Promise(r=>hold.listen(0,'127.0.0.1',r));const port=hold.address().port;await new Promise(r=>hold.close(r));
 const origin='http://127.0.0.1:'+port,adminKey=randomBytes(32).toString('hex'),vaultKey=randomBytes(32).toString('hex');
 const {createAccessApp}=await import('../dist/server.mjs');
 const {app,service}=createAccessApp({path:join(directory,'state.sqlite'),adminKey,vaultKey,origin});
 const tenant=await service.repository.createTenant('External candidate agent public acceptance');
 const issued=await service.repository.atomic(async()=>{const value=await service.broker.issue(tenant.scope,{label:'Candidate external agent public only',expiresAt:Date.now()+1800000,rules:[{provider:'mastodon',actions:['read_public_status'],accountIds:['public:mastodon.social'],writeLimit:0}],managed:true,maxTasks:1});await service.repository.retain(tenant.scope,value.key,value.grant.id);return value;});
 const version=service.version,keyFile=join(directory,'agent.key'),input={statusId:values['status-id'],idempotencyKey:'candidate-external-'+randomBytes(10).toString('hex')};
 for(const [name,value]of Object.entries({'agent.key':issued.key+'\n','bridge.env':'NULUNO_ACCESS_MCP_URL='+origin+'/mcp\nNULUNO_ACCESS_KEY_FILE='+keyFile+'\n','owner-control.json':JSON.stringify({origin,adminKey,vaultKey,tenantId:tenant.tenantId,keyId:issued.grant.id,version})+'\n','public-input.json':JSON.stringify(input)+'\n'}))writeFileSync(join(directory,name),value,{mode:0o600,flag:'wx'});
 const server=app.listen(port,'127.0.0.1',()=>process.stdout.write(JSON.stringify({ready:true,version,origin,directory,bridgeEnvFile:join(directory,'bridge.env'),agentKeyFile:keyFile,publicInputFile:join(directory,'public-input.json'),ownerControlCommand:process.execPath+' '+fileURLToPath(import.meta.url)+' --directory '+directory+' --status',expiresAt:issued.grant.expiresAt,providerWritesAllowed:0})+'\n'));
 const stop=()=>server.close(()=>{service.close();process.exit(0);});for(const signal of ['SIGTERM','SIGINT'])process.on(signal,stop);
}
