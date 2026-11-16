// SPDX-License-Identifier: Apache-2.0
import express from 'express';
import {createServer} from 'node:http';
import {randomBytes} from 'node:crypto';
import {type InstalledExtension} from '../service';
import {createOwnerAuth,type KeySource} from './owner-auth';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {accessDigest} from '../core/repository';
import {createAccessApp} from '../server';
import {providerId,connectionCards,checkedAuthorizationUrl,safeReturnPath,type ProviderId} from './hub-domain';
import {unsupportedPaymentPort} from './payment-authorization';
import {installHubOAuthBoundary} from './hub-oauth';
import {AccessError} from '../core/types';
import {mountHubAgentAccess} from './agent-access';

const jsid=(v:unknown)=>typeof v==='string'&&/^[A-Za-z0-9_-]{24,80}$/.test(v);
function publicContext(raw:string){let value:any;try{value=JSON.parse(raw);}catch{value={};}let returnPath='/account-hub';try{returnPath=safeReturnPath(value.returnPath);}catch{}return {hasTask:value.hasTask===true,returnPath,label:value.hasTask===true?'原本的工作':'目前專案'};}
export async function createAccountHub(options:{rootDirectory:string;stateDirectory:string;origin:string;extensions?:readonly InstalledExtension[];googleClientConfigured?:boolean;keySource:KeySource;clock?:()=>number;startOAuthForTest?:(provider:ProviderId,tenantId:string)=>Promise<{authorizationUrl:string;expiresAt:number}>}){
 const origin=new URL(options.origin);if(origin.protocol!=='http:'||!['127.0.0.1','localhost'].includes(origin.hostname)||origin.pathname!=='/'||origin.search||origin.hash)throw Error('loopback_preview_only');
 const now=()=>options.clock?.()??Date.now(),secrets=await options.keySource(options.stateDirectory),googleInstalled=Boolean(options.extensions?.some(e=>e.module==='@nuluno/access-commercial-extension'&&e.providers.some(p=>p.provider==='gmail'))),googleConfigured=options.googleClientConfigured===true&&googleInstalled;
 const core=createAccessApp({path:join(options.stateDirectory,'access.sqlite'),adminKey:secrets.adminKey,vaultKey:secrets.vaultKey,origin:origin.origin,extensions:options.extensions??[]});
 const repo=core.service.repository;let projects=await repo.listTenants();if(!projects.length){await repo.createTenant('我的專案');projects=await repo.listTenants();}const defaultTenant=String(projects[0].tenantId);
 repo.db.exec('CREATE TABLE IF NOT EXISTS hub_connection_attempts(id TEXT PRIMARY KEY,session_hash TEXT NOT NULL,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,phase TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,context TEXT NOT NULL,oauth_state_hash TEXT)');
 if(!(repo.db.prepare('PRAGMA table_info(hub_connection_attempts)').all() as any[]).some(c=>c.name==='oauth_state_hash'))repo.db.exec('ALTER TABLE hub_connection_attempts ADD COLUMN oauth_state_hash TEXT');
 let auth:ReturnType<typeof createOwnerAuth>;try{auth=createOwnerAuth({repo,keys:secrets,tenantId:defaultTenant,origin:origin.origin,clock:now});}catch(error){core.service.close();throw error;}const providerHooks=core.service.runtimes.flatMap(item=>{const hooks=(item.runtime as any).hostProviderLifecycle;return hooks?[hooks]:[];});const oauth=installHubOAuthBoundary(repo,secrets.adminKey,now,providerHooks);
 const app=express();app.disable('x-powered-by');
 app.use((req,res,next)=>{res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');if(req.header('host')!==origin.host||req.header('origin')&&req.header('origin')!==origin.origin)return res.status(403).json({error:'page_source_rejected',message:'請從原帳號中心頁面操作。'});next();});app.use(express.json({limit:8192,strict:true}));
 const requireOwner=auth.requireOwner;
 const handle=(fn:any)=>async(req:any,res:any)=>{try{await fn(req,res);}catch(error){if(error instanceof AccessError)return res.status(error.status).json({error:error.code,message:'這次操作未完成，請核對目前連接範圍與狀態。'});const code=error instanceof Error&&['local_owner_session_required','page_source_rejected','unsupported_provider','invalid_return_context','invalid_input','payment_provider_not_installed','pairing_rejected','pairing_limit_reached'].includes(error.message)?error.message:'connection_not_completed';res.status(code==='local_owner_session_required'?401:code==='page_source_rejected'||code==='pairing_rejected'?403:code==='pairing_limit_reached'?429:400).json({error:code,message:code==='local_owner_session_required'?'請從本機帳號中心重新開啟。':code==='page_source_rejected'?'這次頁面來源無法核對，沒有送出連線。':'連接尚未完成，原設定會保留。請核對狀態後再選擇需要的步驟。'});}};
 const ownerApi=async(path:string,body?:unknown,attemptId?:string)=>{const response=await fetch(origin.origin+path,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+secrets.adminKey,accept:'application/json',...(attemptId?{'x-hub-attempt':attemptId}:{}),...(body===undefined?{}:{'content-type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'error',signal:AbortSignal.timeout(15000)});if(!response.headers.get('content-type')?.includes('json'))throw Error('owner_backend_unavailable');const value=await response.json();if(!response.ok)throw Error('owner_backend_unavailable');return value as any;};
 // Local backend metadata only: this helper is safe inside a repository
 // transaction and never runs a provider request or a loopback HTTP request.
 const providerViews=async(s:any)=>{const scope=await repo.tenant(s.tenant_id),connections=await core.service.connections(scope),views=connections.map((c:any)=>{if(c.provider!=='gmail'||typeof c.accountId!=='string')return c;let refreshAvailable=false;try{const saved=repo.connection(scope,'gmail',c.accountId);refreshAvailable=typeof saved.secret.refreshToken==='string'&&saved.secret.refreshToken.length>0;}catch{}return {...c,ownerRefreshAvailable:refreshAvailable};}),cards=connectionCards(views,googleConfigured,now());if(!googleInstalled){const gmail=cards.find(c=>c.id==='gmail')!;gmail.phase='configuration_required';gmail.canConnect=false;gmail.accountLabel=null;gmail.note='免費社群版未安裝相容的商用 Gmail 擴充，這裡不會讀取驗證信。';}return {cards};};
 const pendingAttempt=(tenantId:string,provider:ProviderId)=>repo.db.prepare("SELECT * FROM hub_connection_attempts WHERE tenant_id=? AND provider=? AND (phase IN ('starting','exchanging','unknown') OR phase='pending' AND expires_at>?) ORDER BY created_at DESC LIMIT 1").get(tenantId,provider,now()) as any;
 const state=async(s:any)=>repo.atomic(async()=>{const {cards}=await providerViews(s);for(const card of cards){const pending=pendingAttempt(s.tenant_id,card.id);if(card.phase!=='remembered'&&pending){card.phase='needs_owner';card.canDisconnect=true;card.canConnect=pending.phase==='pending';card.note=pending.phase==='pending'?'原連接仍在等待官方確認，不會另開授權。原視窗若已關閉，可先取消這次連接，再由你重新連接。':'這次連接的結果尚未確認，不會自行重試。你可以先取消這次連接，再重新連接；原專案會保留。';}}const tenant=(await repo.listTenants()).find((p:any)=>p.tenantId===s.tenant_id),context=publicContext(s.context);return {csrf:auth.csrfForOwner(s),mode:'isolated-local',project:{label:String(tenant?.label??'目前專案')},rememberDevice:s.remember===1,context,providers:cards,payment:unsupportedPaymentPort.capability(),advanced:{localOwnerMode:true,persistentVault:true,googleConfigured,googleCallback:origin.origin+'/oauth/google/callback',ownerLoginProductionReady:false,note:'本機使用獨立加密資料庫。正式多人產品仍需登入與身分隔離；這個預覽沒有載入原正式帳號。'}};});
 const page=(file:string)=>(_req:any,res:any)=>{res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");res.type('html').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/'+file));};
 app.get(['/','/account-hub'],page('index.html'));app.get('/account-hub/activate',page('pairing.html'));
 app.get('/styles.css',(_req,res)=>res.type('text/css').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/styles.css')));app.get('/app.mjs',(_req,res)=>res.type('application/javascript').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/app.mjs')));
 app.get('/pairing.mjs',(_req,res)=>res.type('application/javascript').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/pairing.mjs')));
 app.get('/agent-access.mjs',(_req,res)=>res.type('application/javascript').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/agent-access.mjs')));
 app.get('/owner-proof.mjs',(_req,res)=>res.type('application/javascript').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/owner-proof.mjs')));app.get('/owner-start.mjs',(_req,res)=>res.type('application/javascript').sendFile(resolve(options.rootDirectory,'src/account-hub/ui/owner-start.mjs')));
 auth.mount(app,handle);
 mountHubAgentAccess({app,repo,broker:core.service.broker,requireOwner,handle,origin:origin.origin,clock:now});
 app.get('/hub-api/state',handle(async(req:any,res:any)=>res.json(await state(requireOwner(req)))));
 app.post('/hub-api/preferences',handle(async(req:any,res:any)=>{const s=requireOwner(req,true);if(!req.body||Object.keys(req.body).join(',')!=='rememberDevice'||typeof req.body.rememberDevice!=='boolean')throw Error('invalid_input');const remember=req.body.rememberDevice;repo.db.prepare('UPDATE hub_owner_sessions SET remember=?,expires_at=? WHERE id_hash=?').run(remember?1:0,now()+(remember?7*86400000:86400000),s.id_hash);auth.setCookie(res,s.token,remember);res.json({rememberDevice:remember});}));
 app.post('/hub-api/connect',handle(async(req:any,res:any)=>{
  const s=requireOwner(req,true);if(!req.body||Object.keys(req.body).join(',')!=='provider')throw Error('invalid_input');const id=providerId(req.body.provider);
  const admitted=await repo.atomic(async()=>{const {cards}=await providerViews(s),card=cards.find(c=>c.id===id)!;
   if(card.phase==='remembered')return {reply:{status:'remembered',note:'已沿用保存的授權，不需要重新連接。'}};
   const pending=pendingAttempt(s.tenant_id,id);if(pending)return {reply:{status:'pending',attemptId:pending.id,expiresAt:pending.expires_at,note:'原連接仍在等待確認，沒有另開授權。若原視窗已關閉，可先取消這次連接再重新連接。'}};
   if(!card.canConnect)return {reply:{status:'configuration_required',note:card.note}};
   const attemptId=randomBytes(24).toString('base64url'),expiresAt=now()+600000;
   repo.db.prepare('INSERT INTO hub_connection_attempts(id,session_hash,tenant_id,provider,phase,created_at,expires_at,context) VALUES(?,?,?,?,?,?,?,?)').run(attemptId,s.id_hash,s.tenant_id,id,'starting',now(),expiresAt,JSON.stringify(publicContext(s.context)));
   return {attemptId,expiresAt};
  });
  if(admitted.reply)return res.json(admitted.reply);const attemptId=admitted.attemptId!,expiresAt=admitted.expiresAt!;
  try{const started=options.startOAuthForTest?await oauth.runStart({attemptId,tenantId:s.tenant_id,provider:id},()=>options.startOAuthForTest!(id,s.tenant_id)):await ownerApi('/admin/tenants/'+s.tenant_id+'/'+(id==='gmail'?'google':'mastodon')+'/start',{},attemptId),url=checkedAuthorizationUrl(id,started.authorizationUrl),expiry=await oauth.finishStart(attemptId,url,Number.isSafeInteger(started.expiresAt)?started.expiresAt:expiresAt);return res.json({status:'requires_owner',attemptId,expiresAt:expiry,authorizationUrl:url,note:'請在平台官方視窗完成登入或同意；原專案與任務會保留。'});}catch{await oauth.markUnknown(attemptId);return res.status(502).json({error:'connection_not_completed',note:'目前未確認新的授權，沒有更動原有帳號。可先取消這次連接，再由你重新連接；不會自行重試。'});}
 }));
 app.get('/hub-api/attempt/:id',handle(async(req:any,res:any)=>{const s=requireOwner(req);if(!jsid(req.params.id))throw Error('invalid_input');const row=repo.db.prepare('SELECT * FROM hub_connection_attempts WHERE id=? AND tenant_id=?').get(req.params.id,s.tenant_id) as any;if(!row)throw Error('invalid_input');const context=publicContext(row.context);
  if(['cancelled','consumed','expired'].includes(row.phase))return res.json({status:'expired',note:'這次連接已取消或到期，舊授權入口不會接回。需要時請由你重新連接。',returnPath:context.returnPath});
  const {cards}=await providerViews(s),card=cards.find(c=>c.id===row.provider)!;if(card.phase==='remembered')return res.json({status:'remembered',note:'帳號已保存，可以返回原本的工作內容。',returnPath:context.returnPath});
  if(['unknown','starting','exchanging'].includes(row.phase))return res.json({status:'requires_owner',note:'這次連接結果尚未確認，不會另開授權。需要時可先取消這次連接，再重新連接。',returnPath:context.returnPath});
  return res.json({status:row.expires_at<=now()?'expired':'requires_owner',note:row.expires_at<=now()?'這次官方頁面已到期；原專案仍在，請明確重新連接缺少的帳號。':'官方連接尚未完成，請在原視窗完成本人確認。',returnPath:context.returnPath});
 }));
 app.post('/hub-api/disconnect',handle(async(req:any,res:any)=>{const s=requireOwner(req,true);if(!req.body||Object.keys(req.body).join(',')!=='provider')throw Error('invalid_input');await oauth.retire(s.tenant_id,providerId(req.body.provider));res.json({disconnected:true,cancelled:true,note:'已取消這個專案的未完成連接並解除已保存的連線，舊授權入口不能接回。平台上的應用程式同意仍可另由你在官方設定撤回。'});}));
 app.post('/hub-api/payment',handle(async(req:any,res:any)=>{requireOwner(req,true);throw Error('payment_provider_not_installed');}));
 app.post('/hub-api/context',handle(async(req:any,res:any)=>{const s=requireOwner(req,true),v=req.body;if(!v||Object.keys(v).some(k=>!['returnPath','taskRef'].includes(k)))throw Error('invalid_return_context');const returnPath=safeReturnPath(v.returnPath),scope=await repo.tenant(s.tenant_id),project=await repo.read(scope);if(v.taskRef!==undefined&&(typeof v.taskRef!=='string'||!project.tasks[v.taskRef]))throw Error('invalid_return_context');const context={hasTask:typeof v.taskRef==='string',returnPath,label:typeof v.taskRef==='string'?'原本的工作':'目前專案'};repo.db.prepare('UPDATE hub_owner_sessions SET context=? WHERE id_hash=?').run(JSON.stringify(context),s.id_hash);res.json({saved:true,context});}));
 app.use(oauth.middleware);app.use(core.app);
 return {app,core,repo,issuePairing:auth.issuePairing,origin:origin.origin,close:()=>core.service.close()};
}
export async function startAccountHub(options:Parameters<typeof createAccountHub>[0]){const hub=await createAccountHub(options),server=createServer(hub.app);await new Promise<void>(resolve=>server.listen(Number(new URL(hub.origin).port),'127.0.0.1',resolve));return {...hub,server};}
