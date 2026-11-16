// SPDX-License-Identifier: Apache-2.0
import {AsyncLocalStorage} from 'node:async_hooks';
import {createHash,timingSafeEqual} from 'node:crypto';
import {accessDigest,type StandaloneRepository} from '../core/repository';
import {AccessError} from '../core/types';
import type {ProviderId} from './hub-domain';

type ProviderHooks={schema:'nuluno-provider-lifecycle-hooks-v1';providers:readonly string[];install():void;withOwnerConnection<T>(scope:any,provider:ProviderId,fn:()=>Promise<T>):Promise<T>;withOAuthCallback<T>(provider:ProviderId,state:string,fn:()=>Promise<T>):Promise<T>;retire(scope:any,provider:ProviderId):Promise<unknown>};

type StartFlow={kind:'start';attemptId:string;tenantId:string;provider:ProviderId};
type CallbackFlow={kind:'callback';oauthHash:string;provider:ProviderId;tenantId?:string;attemptId?:string};
const fail=()=>{throw new AccessError('access_scope_denied');};

/** Instance-local host boundary. Shared Access core and provider code remain
 * unchanged. No HTTP caller can supply callback context or bypass the owner
 * session by supplying an attempt header. Provider I/O stays outside atomic. */
export function installHubOAuthBoundary(repo:StandaloneRepository,adminKey:string,now:()=>number,providerHooks:readonly ProviderHooks[]=[]){
 for(const hook of providerHooks){if(hook.schema!=='nuluno-provider-lifecycle-hooks-v1'||!Array.isArray(hook.providers))throw Error('invalid_provider_lifecycle_hooks');hook.install();}
 const withOwnerHooks=async<T>(flow:StartFlow,fn:()=>Promise<T>)=>{const scope=await repo.tenant(flow.tenantId),hooks=providerHooks.filter(h=>h.providers.includes(flow.provider));const run=(i:number):Promise<T>=>i===hooks.length?fn():hooks[i].withOwnerConnection(scope,flow.provider,()=>run(i+1));return run(0);};
 const withCallbackHooks=async<T>(provider:ProviderId,state:string,fn:()=>Promise<T>)=>{const hooks=providerHooks.filter(h=>h.providers.includes(provider));const run=(i:number):Promise<T>=>i===hooks.length?fn():hooks[i].withOAuthCallback(provider,state,()=>run(i+1));return run(0);};
 const context=new AsyncLocalStorage<StartFlow|CallbackFlow>();
 const original={save:repo.saveOAuth.bind(repo),claim:repo.claimOAuth.bind(repo),set:repo.setConnection.bind(repo),complete:repo.completeOAuth.bind(repo)};
 const attempt=(id:string)=>repo.db.prepare('SELECT * FROM hub_connection_attempts WHERE id=?').get(id) as any;
 const matchingStart=(flow:StartFlow)=>{const row=attempt(flow.attemptId);if(!row||row.tenant_id!==flow.tenantId||row.provider!==flow.provider||row.phase!=='starting'||row.expires_at<=now())fail();return row;};
 const matchingCallback=(flow:CallbackFlow)=>{const row=repo.db.prepare('SELECT * FROM hub_connection_attempts WHERE oauth_state_hash=? AND provider=?').get(flow.oauthHash,flow.provider) as any;const oauth=repo.db.prepare('SELECT tenant_id,provider,phase FROM oauth WHERE state_hash=?').get(flow.oauthHash) as any;if(!row||row.phase!=='exchanging'||row.expires_at<=now()||row.tenant_id!==flow.tenantId||row.id!==flow.attemptId||!oauth||oauth.phase!=='exchanging'||oauth.tenant_id!==row.tenant_id||oauth.provider!==flow.provider)fail();return row;};
 repo.saveOAuth=async(state,scope,provider,value)=>{
  const flow=context.getStore();if(flow?.kind!=='start'||flow.provider!==provider||flow.tenantId!==scope.workspaceId)fail();
  await repo.atomic(async()=>{const row=matchingStart(flow as StartFlow);if(row.oauth_state_hash)fail();await original.save(state,scope,provider,value);repo.db.prepare('UPDATE hub_connection_attempts SET oauth_state_hash=? WHERE id=?').run(accessDigest(state),row.id);});
 };
 repo.claimOAuth=async(state,provider)=>{
  const flow=context.getStore();if(flow?.kind!=='callback'||flow.provider!==provider||flow.oauthHash!==accessDigest(state))fail();
  return repo.atomic(async()=>{const callback=flow as CallbackFlow,row=repo.db.prepare('SELECT * FROM hub_connection_attempts WHERE oauth_state_hash=? AND provider=?').get(callback.oauthHash,provider) as any;if(!row||row.phase!=='pending'||row.expires_at<=now())fail();const result=await original.claim(state,provider);if(result.scope!==row.tenant_id)fail();callback.tenantId=row.tenant_id;callback.attemptId=row.id;repo.db.prepare("UPDATE hub_connection_attempts SET phase='exchanging' WHERE id=?").run(row.id);return result;});
 };
 repo.setConnection=async(scope,value)=>{
  const flow=context.getStore();if(flow?.kind==='start')fail();
  await repo.atomic(async()=>{if(flow?.kind==='callback'){matchingCallback(flow);if(flow.tenantId!==scope.workspaceId||flow.provider!==value.provider)fail();}await original.set(scope,value);});
 };
 repo.completeOAuth=async state=>{
  const flow=context.getStore();if(flow?.kind!=='callback'||flow.oauthHash!==accessDigest(state))fail();
  await repo.atomic(async()=>{const row=matchingCallback(flow as CallbackFlow);await original.complete(state);repo.db.prepare("UPDATE hub_connection_attempts SET phase='connected' WHERE id=?").run(row.id);});
 };
 return {
  async runStart<T>(flow:Omit<StartFlow,'kind'>,fn:()=>Promise<T>){await repo.atomic(()=>matchingStart({...flow,kind:'start'}));return context.run({...flow,kind:'start'},()=>withOwnerHooks({...flow,kind:'start'},fn));},
  middleware(req:any,res:any,next:()=>void){
   const start=/^\/admin\/tenants\/([^/]+)\/(google|mastodon)\/start$/.exec(req.path);
   if(req.method==='POST'&&start){
    const supplied=req.header('authorization')??'',actual=createHash('sha256').update(supplied).digest(),expected=createHash('sha256').update('Bearer '+adminKey).digest();
    if(supplied.length>4096||!timingSafeEqual(actual,expected))return res.status(403).json({error:'page_source_rejected'});
    const attemptId=req.header('x-hub-attempt'),flow:StartFlow={kind:'start',attemptId,tenantId:start[1],provider:start[2]==='google'?'gmail':'mastodon'};
    if(typeof attemptId!=='string'||!/^[A-Za-z0-9_-]{24,80}$/.test(attemptId))return res.status(403).json({error:'page_source_rejected'});
    return repo.atomic(()=>matchingStart(flow)).then(()=>context.run(flow,()=>withOwnerHooks(flow,async()=>next()))).catch(()=>res.status(403).json({error:'page_source_rejected'}));
   }
   const callback=/^\/oauth\/(google|mastodon)\/callback$/.exec(req.path);
   if(req.method==='GET'&&callback){const state=typeof req.query.state==='string'?req.query.state:'';if(!state||state.length>200)return res.status(400).json({error:'connection_not_completed'});const provider=callback[1]==='google'?'gmail':'mastodon';return context.run({kind:'callback',oauthHash:accessDigest(state),provider},()=>withCallbackHooks(provider,state,async()=>next())).catch(()=>res.status(403).json({error:'connection_not_completed'}));}
   next();
  },
  async finishStart(id:string,url:string,expiresAt:number){return repo.atomic(()=>{const row=attempt(id),state=new URL(url).searchParams.get('state');if(!row||row.phase!=='starting'||row.expires_at<=now()||!state||row.oauth_state_hash!==accessDigest(state))fail();const oauth=repo.db.prepare("SELECT phase FROM oauth WHERE state_hash=? AND tenant_id=? AND provider=?").get(row.oauth_state_hash,row.tenant_id,row.provider) as any;if(!oauth||oauth.phase!=='pending')fail();const expiry=Math.min(row.expires_at,expiresAt);if(!Number.isSafeInteger(expiry)||expiry<=now())fail();repo.db.prepare("UPDATE hub_connection_attempts SET phase='pending',expires_at=? WHERE id=?").run(expiry,id);return expiry;});},
  async markUnknown(id:string){await repo.atomic(()=>repo.db.prepare("UPDATE hub_connection_attempts SET phase='unknown' WHERE id=? AND phase='starting'").run(id));},
  async retire(tenantId:string,provider:ProviderId){return repo.atomic(async()=>{const scope=await repo.tenant(tenantId);for(const hook of providerHooks)if(hook.providers.includes(provider))await hook.retire(scope,provider);for(const connection of await repo.connections(scope))if(connection.provider===provider)await repo.disconnect(scope,provider,connection.accountId);repo.db.prepare("DELETE FROM oauth WHERE tenant_id=? AND provider=? AND phase IN ('pending','exchanging')").run(tenantId,provider);const retired=repo.db.prepare("UPDATE hub_connection_attempts SET phase='cancelled' WHERE tenant_id=? AND provider=? AND phase IN ('starting','pending','exchanging','unknown','connected')").run(tenantId,provider).changes;return {retired:Number(retired)};});},
 };
}
