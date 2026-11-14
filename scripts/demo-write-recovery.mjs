// CONTROLLED localhost provider, not a live social-platform publication.
// The HTTP fixture commits one write then drops its response; Access is killed
// and reopened with the original state/key before read-only reconciliation.
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {createServer} from 'node:http';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
const file=fileURLToPath(import.meta.url),root=resolve(dirname(file),'..');
const version=JSON.parse(readFileSync(join(root,'package.json'),'utf8')).version;
if(process.argv[2]==='--worker'){
 process.once('message',async cfg=>{
  let service;
  try{
   const {createStandaloneService}=await import('../dist/service.mjs');
   service=createStandaloneService({path:cfg.path,vaultKey:cfg.vaultKey,origin:'http://127.0.0.1:8892'});
   const adapter={provider:'mastodon',execute:async ctx=>{
    await ctx.external({provider:'mastodon',action:'publish_text',accountId:'controlled-fixture',write:true},async()=>{
     await fetch(cfg.fixture+'/write',{method:'POST',body:'controlled payload',signal:AbortSignal.timeout(3000)});return {};
    });return {kind:'unknown'};
   },reconcile:async ctx=>{
    const native=await ctx.external({provider:'mastodon',action:'publish_text',accountId:'controlled-fixture',write:false},async()=>{const r=await fetch(cfg.fixture+'/read',{signal:AbortSignal.timeout(3000)});return r.json();});
    if(native.writes!==1)return {kind:'unknown'};
    return {kind:'completed',evidence:{resourceId:'controlled-only-1',receiptHash:createHash('sha256').update(JSON.stringify(native)).digest('hex'),verifiedAt:Date.now()}};
   }};
   if(cfg.phase==='execute'){
    const tenant=await service.repository.createTenant('Controlled lost response demo');
    const issued=await service.broker.issue(tenant.scope,{label:'Controlled one write',expiresAt:Date.now()+600000,rules:[{provider:'mastodon',actions:['publish_text'],accountIds:['controlled-fixture'],writeLimit:1}]});
    const task=await service.broker.submit(issued.key,{idempotencyKey:'controlled-original-write',provider:'mastodon',action:'publish_text',accountId:'controlled-fixture',payload:{text:'CONTROLLED FIXTURE ONLY'}});
    const result=await service.broker.advance(issued.key,task.id,adapter);assert.equal(result.status,'uncertain');
    process.send({ok:true,phase:'uncertain',taskId:task.id,key:issued.key,keyId:issued.grant.id,scope:tenant.scope});
   }else{
    assert.equal((await service.broker.getTask(cfg.key,cfg.taskId)).status,'uncertain');
    await assert.rejects(service.broker.submit(cfg.key,{idempotencyKey:'controlled-new-id-cannot-resend',provider:'mastodon',action:'publish_text',accountId:'controlled-fixture',payload:{text:'CONTROLLED FIXTURE ONLY'}}),/access_reconciliation_required/);
    const result=await service.broker.reconcile(cfg.key,cfg.taskId,adapter);assert.equal(result.id,cfg.taskId);assert.equal(result.status,'succeeded');
    await service.broker.revoke(cfg.scope,cfg.keyId);
    await assert.rejects(service.broker.advance(cfg.key,cfg.taskId,adapter),/access_revoked/);
    const usage=await service.usage(cfg.scope);assert.equal(usage.providerWriteReservations,1);
    process.send({ok:true,phase:'reconciled',taskId:result.id,receiptHash:result.evidence.receiptHash,writeReservations:usage.providerWriteReservations});
   }
  }catch{process.send?.({ok:false,error:'controlled_recovery_failed'});process.exitCode=1;}
 });
}else{
 const {values}=parseArgs({options:{output:{type:'string'}}});
 const dir=mkdtempSync(join(tmpdir(),'nuluno-recovery-demo-'));let child,writes=0,reads=0;
 const fixture=createServer((req,res)=>{
  if(req.method==='POST'&&req.url==='/write'){req.resume();req.once('end',()=>{writes++;res.destroy();});return;}
  if(req.method==='GET'&&req.url==='/read'){reads++;res.setHeader('content-type','application/json');res.end(JSON.stringify({writes,resourceId:'controlled-only-1'}));return;}
  res.statusCode=404;res.end();
 });
 await new Promise(r=>fixture.listen(0,'127.0.0.1',r));
 const config={path:join(dir,'access.sqlite'),vaultKey:randomBytes(32).toString('hex'),fixture:'http://127.0.0.1:'+fixture.address().port};
 async function run(cfg){
  child=fork(file,['--worker'],{env:{PATH:process.env.PATH??''},stdio:['ignore','ignore','ignore','ipc']});
  return new Promise((resolve,reject)=>{
   const timeout=setTimeout(()=>reject(Error('controlled_demo_timeout')),15000);
   child.once('message',m=>{clearTimeout(timeout);m.ok?resolve(m):reject(Error('controlled_demo_failed'));});
   child.once('exit',code=>{if(code){clearTimeout(timeout);reject(Error('controlled_demo_worker_exit'));}});child.send(cfg);
  });
 }
 async function kill(){if(!child||child.exitCode!==null||child.signalCode!==null)return;const done=new Promise(r=>child.once('exit',r));child.kill('SIGKILL');await done;child=undefined;}
 try{
  const first=await run({...config,phase:'execute'});assert.equal(writes,1);await kill();
  const after=await run({...config,...first,phase:'reconcile'});assert.equal(after.taskId,first.taskId);assert.equal(writes,1);assert.equal(reads,1);
  const receipt={schema:'nuluno-access-controlled-recovery-demo-v1',passed:true,observedAt:new Date().toISOString(),version,platform:process.platform,node:process.version,acceptanceKind:'controlled localhost HTTP provider with committed write and deliberately lost response; real SIGKILL and persistent SQLite reopen',externalSocialProviderCalls:0,externalSocialProviderWrites:0,controlledHttpWrites:writes,controlledHttpReadbacks:reads,writeReservations:after.writeReservations,originalTaskId:first.taskId,receiptHash:after.receiptHash,unknownOutcomeBeforeCrash:true,replacementTaskDenied:true,sameTaskReconciledAfterSigkill:true,revokedKeyDenied:true,platformCredentialsUsed:false,modelCalls:0,privatePlatformPublicationAccepted:false,commercialSuccessVerified:false};
  if(values.output)writeFileSync(resolve(values.output),JSON.stringify(receipt,null,2)+'\n',{mode:0o600,flag:'wx'});
  process.stdout.write(JSON.stringify(receipt,null,2)+'\n');
 }catch{process.stderr.write(JSON.stringify({passed:false,error:'controlled_recovery_demo_failed',version,externalSocialProviderWrites:0})+'\n');process.exitCode=1;}
 finally{await kill();await new Promise(r=>fixture.close(r));rmSync(dir,{recursive:true,force:true});}
}
