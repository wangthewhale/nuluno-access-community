import {NulunoAccessBroker} from './core/broker';
import {StandaloneRepository} from './core/repository';
import {CredentialVault} from './core/vault';
import {VaultAccessTokenCodec} from './core/token-codec';
import {AccessError,type AccessProviderAdapter,type AccessScope,type AccessSafeTask} from './core/types';
import {MastodonProvider} from './providers/mastodon';
import {AccessObservability} from './observability';
import {ACCESS_VERSION} from './version';
import type {LoadedAccessExtension} from './extensions/registry';
export type ExtensionContext={repository:StandaloneRepository;vault:CredentialVault;flow:AccessObservability;origin:string;vaultKey:string;error:(code:any)=>AccessError};
export type ExtensionRuntime={adapters:Record<string,AccessProviderAdapter>;mountOwnerRoutes?:(host:any)=>void;connections?:(scope:AccessScope)=>Promise<any[]>;close?:()=>void};
export type InstalledExtension=LoadedAccessExtension<ExtensionContext,ExtensionRuntime>;
export function createStandaloneService(options:{path:string;vaultKey:string;origin:string;extensions?:readonly InstalledExtension[]}){
 const vault=new CredentialVault(options.vaultKey),repository=new StandaloneRepository(options.path,vault),flow=new AccessObservability(repository);
 const installed=options.extensions??[],runtimes=installed.map(extension=>({extension,runtime:extension.install({repository,vault,flow,origin:options.origin,vaultKey:options.vaultKey,error:code=>new AccessError(code)})}));
 const builtinActions=['read_public_status','verify_identity','publish_text'];
 const installedActions:Record<string,string[]>={mastodon:[...builtinActions]};
 const readOnly=(provider:string,action:string)=>provider==='mastodon'&&['read_public_status','verify_identity'].includes(action)||installed.some(e=>e.providers.some(p=>p.provider===provider&&p.readOnlyActions.includes(action)));
 for(const {extension,runtime} of runtimes){
  if(!runtime||typeof runtime!=='object'||!runtime.adapters||typeof runtime.adapters!=='object'||Object.keys(runtime.adapters).length!==extension.providers.length)throw new Error('invalid_extension_runtime');
  for(const p of extension.providers){if(!runtime.adapters[p.provider]||runtime.adapters[p.provider].provider!==p.provider)throw new Error('invalid_extension_adapter');installedActions[p.provider]=[...(installedActions[p.provider]??[]),...p.actions];}
 }
 const coreBroker=new NulunoAccessBroker({repository,tokenCodec:new VaultAccessTokenCodec(vault,options.vaultKey),policy:{isReadOnly:readOnly,check:async({phase,task,grant})=>{
  if(process.env.NULUNO_ACCESS_EGRESS_PAUSED==='true'&&['execute','reconcile','external','verification'].includes(phase))throw new AccessError('access_host_hold');
  if(phase==='issue'&&grant&&grant.rules.some(r=>!installedActions[r.provider]||r.actions.some(a=>!installedActions[r.provider].includes(a))))throw new AccessError('access_rule_denied');
  if(task){if(!installedActions[task.provider]?.includes(task.action))throw new AccessError('access_rule_denied');
}
 }}});
 repository.db.exec('CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at INTEGER NOT NULL,tenant_id TEXT,operation TEXT NOT NULL,outcome TEXT NOT NULL)');
 const codec=new VaultAccessTokenCodec(vault,options.vaultKey);
 const broker=new Proxy(coreBroker,{get(target,property){const value=Reflect.get(target,property);if(typeof value!=='function')return value;return async(...args:any[])=>{let tenant:string|null=null;try{const first=args[0];tenant=typeof first==='string'?codec.decode(first).scope.workspaceId:first?.workspaceId??null;}catch{}try{const result=String(property)==='revoke'?await repository.atomic(async()=>{const revoked=await value.apply(target,args);await repository.retireManaged(args[0],args[1]);return revoked;}):await value.apply(target,args);if(String(property)==='getCapabilities'&&result?.grant)result.grant.rules=result.grant.rules.map((r:any)=>({...r,actions:r.actions.filter((a:string)=>installedActions[r.provider]?.includes(a))})).filter((r:any)=>r.actions.length);if(['submit','advance','reconcile','revoke'].includes(String(property)))await repository.atomic(()=>repository.db.prepare('INSERT INTO audit(at,tenant_id,operation,outcome) VALUES(?,?,?,?)').run(Date.now(),tenant,String(property),'accepted'));return result;}catch(error){const outcome=error instanceof AccessError?error.code:'access_internal';await repository.atomic(()=>repository.db.prepare('INSERT INTO audit(at,tenant_id,operation,outcome) VALUES(?,?,?,?)').run(Date.now(),tenant,String(property),outcome));throw error;}};}});
 const simpleMastodon=new MastodonProvider(repository);
 const adapterFor=(provider:string):AccessProviderAdapter|undefined=>{
  if(!installedActions[provider])return undefined;
  return {provider,execute:ctx=>runAdapter('execute',provider,ctx),reconcile:ctx=>runAdapter('reconcile',provider,ctx)};
 };
 async function runAdapter(kind:'execute'|'reconcile',provider:string,ctx:any){
  if(provider==='mastodon'&&builtinActions.includes(ctx.task.action))return simpleMastodon[kind](ctx);
  const owner=runtimes.find(({extension})=>extension.providers.some(p=>p.provider===provider&&p.actions.includes(ctx.task.action)));
  if(!owner)throw new AccessError('access_rule_denied');
  try{return await owner.runtime.adapters[provider][kind](ctx);}catch(e){if(e&&typeof e==='object'&&'code'in e&&typeof e.code==='string'&&/^access_[a-z_]+$/.test(e.code))throw new AccessError(e.code as any);throw e;}
 }
 let busy=false,closed=false,lastCleanup=0;
 async function pump(){if(busy||closed)return;busy=true;try{if(Date.now()-lastCleanup>=60000){await repository.cleanupExpired();lastCleanup=Date.now();}for(const item of await repository.managedKeys()){
   let principal;try{principal=await broker.authenticate(item.key);}catch{continue;}
   for(const task of await broker.listOwnerActiveTasks(principal)){if(!installedActions[task.provider]?.includes(task.action)||!repository.due(task.id))continue;if(await broker.hasPendingWriteBlock(item.key,task.id))continue;const adapter=adapterFor(task.provider);if(!adapter)continue;
    try{const result=await(task.status==='uncertain'||task.status==='dispatching'?broker.reconcile(item.key,task.id,adapter):broker.advance(item.key,task.id,adapter));await repository.reschedule(task.id,result.status==='waiting'&&['owner','authentication'].includes(result.waitReason??''),['succeeded','failed','revoked'].includes(result.status));}catch(error){if(error instanceof AccessError&&['access_busy','access_reconciliation_required'].includes(error.code))await repository.deferAdmission(task.id);else await repository.reschedule(task.id,error instanceof AccessError&&['access_revoked','access_expired','access_scope_denied','access_limit_reached'].includes(error.code),false);}
   }
  }}finally{busy=false;}}
 const timer=setInterval(()=>void pump().catch(()=>{}),1000);timer.unref();
 async function onTaskSubmitted(key:string,task:AccessSafeTask){const principal=await broker.authenticate(key),{grant}=await broker.getCapabilities(key);if(grant.managed)await repository.scheduleTask(principal,task.id);}
 async function onTaskAdvanced(key:string,task:AccessSafeTask){const {grant}=await broker.getCapabilities(key);if(grant.managed)await repository.reschedule(task.id,task.status==='waiting'&&['owner','authentication'].includes(task.waitReason??''),['succeeded','failed','revoked'].includes(task.status));}
 const transport={broker,adapterFor,readOnlyAction:readOnly,taskObservability:async(key:string,taskId:string)=>{const principal=await broker.authenticate(key);await broker.getTask(key,taskId);return flow.taskFlow(principal,taskId);},submitTransaction:async<T>(_key:string,fn:()=>Promise<T>)=>repository.atomic(fn),onTaskSubmitted,onTaskAdvanced};
 async function connections(scope:AccessScope){return [...await repository.connections(scope),...(await Promise.all(runtimes.map(r=>r.runtime.connections?.(scope)??Promise.resolve([])))).flat()];}
 async function usage(scope:AccessScope){const s=await repository.read(scope),tasks=Object.values(s.tasks),calls=tasks.flatMap(t=>t.dispatches.flatMap(d=>Object.values(d.calls)));const continuation=await repository.continuation(scope);const denials=repository.db.prepare("SELECT outcome,COUNT(*) AS count FROM audit WHERE tenant_id=? AND outcome<>'accepted' GROUP BY outcome").all(scope.workspaceId);return {capabilityBlocks:tasks.filter(t=>!installedActions[t.provider]?.includes(t.action)&&!['succeeded','failed','revoked'].includes(t.status)).map(t=>({taskId:t.id,provider:t.provider,action:t.action,reason:'extension_not_installed'})),flowMetrics:await flow.metrics(scope),cost:await flow.costSummary(scope),denials,exhausted:continuation.filter(c=>c.reason==='dispatch_limit_exhausted').length,held:continuation.filter(c=>c.reason.startsWith('waiting_')).length,basis:'persisted native execution ledger; not financial savings or sales attribution',tasks:tasks.length,succeeded:tasks.filter(t=>t.status==='succeeded').length,uncertain:tasks.filter(t=>t.status==='uncertain').length,waitingForOwner:tasks.filter(t=>t.status==='waiting'&&t.waitReason==='owner').length,waitingForAuthentication:tasks.filter(t=>t.status==='waiting'&&t.waitReason==='authentication').length,providerCallsReserved:calls.length,providerCallsCompleted:calls.filter(c=>c.state==='completed').length,providerWriteReservations:calls.filter(c=>c.step.write).length,verifiedReceipts:tasks.filter(t=>t.evidence?.receiptHash&&t.status==='succeeded').length,revokedKeys:Object.values(s.grants).filter(g=>g.revokedAt!==null).length,reconciliationDispatches:tasks.flatMap(t=>t.dispatches).filter(d=>d.kind==='reconcile').length};}
 return {version:ACCESS_VERSION,installedActions,installedExtensions:installed.map(e=>({id:e.id,version:e.version,providers:e.providers})),runtimes,repository,flow,broker,vault,adapterFor,connections,usage,transport,pump,close:()=>{closed=true;clearInterval(timer);for(const r of runtimes)r.runtime.close?.();flow.stop();repository.close();}};
}
export type StandaloneService=ReturnType<typeof createStandaloneService>;
