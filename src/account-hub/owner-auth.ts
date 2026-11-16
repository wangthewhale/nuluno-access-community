// SPDX-License-Identifier: Apache-2.0
import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import type {StandaloneRepository} from '../core/repository';

export type InstallationKeys=Readonly<{installationId:string;adminKey:string;vaultKey:string;sessionKey:string;keySource:string}>;
export type KeySource=(stateDirectory:string)=>Promise<InstallationKeys>;
const digest=(value:string)=>createHash('sha256').update(value).digest('hex');
const opaque=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value);
const same=(a:string,b:string)=>{const left=Buffer.from(a),right=Buffer.from(b);return left.length===right.length&&timingSafeEqual(left,right);};
const cookie=(req:any,name:string)=>{const value=(req.header('cookie')??'').split(/;\s*/).find((part:string)=>part.startsWith(name+'='))?.slice(name.length+1);return opaque(value)?value:null;};
const fail=(code='local_owner_session_required'):never=>{throw Error(code);};

/** Local single-owner pairing. This is not cloud membership or a replacement
 * for KMS, OS login, HTTPS deployment or independent credential revocation. */
export function createOwnerAuth(options:{repo:StandaloneRepository;keys:InstallationKeys;tenantId:string;origin:string;clock:()=>number}){
 const {repo,keys,tenantId,origin,clock:now}=options;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(keys.installationId)||[keys.adminKey,keys.vaultKey,keys.sessionKey].some(value=>typeof value!=='string'||value.length<32)||new Set([keys.adminKey,keys.vaultKey,keys.sessionKey]).size!==3)fail('installation_identity_invalid');
 const suffix=keys.installationId.replace(/-/g,''),OWNER_COOKIE='nuluno_hub_owner_'+suffix,PRE_COOKIE='nuluno_hub_pairing_'+suffix;
 repo.db.exec(`CREATE TABLE IF NOT EXISTS hub_auth_meta(id INTEGER PRIMARY KEY CHECK(id=1),installation_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,pair_epoch INTEGER NOT NULL,key_fingerprint TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS hub_owner_sessions(id_hash TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,installation_id TEXT NOT NULL,owner_epoch INTEGER NOT NULL,remember INTEGER NOT NULL,expires_at INTEGER NOT NULL,context TEXT NOT NULL,proof_hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS hub_pairing_tokens(token_hash TEXT PRIMARY KEY,installation_id TEXT NOT NULL,pair_epoch INTEGER NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,used_at INTEGER,revoked_at INTEGER);
 CREATE TABLE IF NOT EXISTS hub_pairing_browsers(id_hash TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0);`);
 if(!(repo.db.prepare('PRAGMA table_info(hub_owner_sessions)').all() as any[]).some(column=>column.name==='proof_hash')){repo.db.exec("ALTER TABLE hub_owner_sessions ADD COLUMN proof_hash TEXT NOT NULL DEFAULT '';DELETE FROM hub_owner_sessions");}
 const fingerprint=digest('hub-session-key\0'+keys.sessionKey),existing=repo.db.prepare('SELECT * FROM hub_auth_meta WHERE id=1').get() as any;
 if(existing&&(existing.installation_id!==keys.installationId||existing.key_fingerprint!==fingerprint))fail('installation_identity_changed');
 if(!existing)repo.db.prepare('INSERT INTO hub_auth_meta VALUES(1,?,1,0,?)').run(keys.installationId,fingerprint);
 const meta=()=>repo.db.prepare('SELECT * FROM hub_auth_meta WHERE id=1').get() as any;
 const csrf=(purpose:string,idHash:string)=>createHmac('sha256',keys.sessionKey).update(purpose+'\0'+keys.installationId+'\0'+idHash).digest('base64url');
 const setOwnerCookie=(res:any,token:string,remember:boolean)=>res.append('Set-Cookie',OWNER_COOKIE+'='+token+'; Path=/; HttpOnly; SameSite=Strict'+(origin.startsWith('https:')?'; Secure':'')+(remember?'; Max-Age=604800':''));
 const clearPreCookie=(res:any)=>res.append('Set-Cookie',PRE_COOKIE+'=; Path=/hub-api/pairing; HttpOnly; SameSite=Strict; Max-Age=0');
 const source=(req:any)=>{if(req.header('host')!==new URL(origin).host||req.header('origin')!==origin||req.header('sec-fetch-site')&&!['same-origin','none'].includes(req.header('sec-fetch-site')))fail('page_source_rejected');};
 function session(req:any){const token=cookie(req,OWNER_COOKIE),proof=req.header('x-hub-owner-proof');if(!token||!opaque(proof))return null;const row=repo.db.prepare('SELECT * FROM hub_owner_sessions WHERE id_hash=? AND expires_at>?').get(digest(token),now()) as any,m=meta();return row&&row.installation_id===keys.installationId&&row.owner_epoch===m.owner_epoch&&same(row.proof_hash,digest(proof))?{...row,token}:null;}
 function requireOwner(req:any,write=false){const current=session(req);if(!current)fail();if(write){source(req);if(!same(req.header('x-hub-csrf')??'',csrf('owner-csrf',current.id_hash)))fail('page_source_rejected');}return current;}
 async function issuePairing(){return repo.atomic(()=>{
  const token=randomBytes(32).toString('base64url'),createdAt=now(),expiresAt=createdAt+300000,m=meta(),epoch=m.pair_epoch+1;
  repo.db.prepare('UPDATE hub_auth_meta SET pair_epoch=? WHERE id=1').run(epoch);
  repo.db.prepare('UPDATE hub_pairing_tokens SET revoked_at=? WHERE used_at IS NULL AND revoked_at IS NULL').run(createdAt);
  repo.db.prepare('INSERT INTO hub_pairing_tokens VALUES(?,?,?,?,?,NULL,NULL)').run(digest('pairing\0'+keys.installationId+'\0'+token),keys.installationId,epoch,expiresAt,createdAt);
  // Raw material is returned only to the trusted local installer, never a
  // request handler, GET, log, state API or persisted database column.
  return {activationUrl:origin+'/account-hub/activate#pair='+token,expiresAt};
 });}
 function mount(app:any,handle:any){
  app.get('/hub-api/pairing/challenge',handle(async(req:any,res:any)=>{
   if(req.header('origin')&&req.header('origin')!==origin||req.header('sec-fetch-site')&&!['same-origin','none'].includes(req.header('sec-fetch-site')))fail('page_source_rejected');
   const result=await repo.atomic(()=>{
    repo.db.prepare('DELETE FROM hub_pairing_browsers WHERE id_hash IN (SELECT id_hash FROM hub_pairing_browsers WHERE expires_at<=? LIMIT 100)').run(now());
    const token=cookie(req,PRE_COOKIE),row=token?repo.db.prepare('SELECT * FROM hub_pairing_browsers WHERE id_hash=? AND expires_at>?').get(digest(token),now()) as any:null;
    if(row)return {token:token!,row};
    if((repo.db.prepare('SELECT count(*) AS n FROM hub_pairing_browsers WHERE expires_at>?').get(now()) as any).n>=64)fail('pairing_limit_reached');
    const next=randomBytes(32).toString('base64url'),expiresAt=now()+300000;repo.db.prepare('INSERT INTO hub_pairing_browsers VALUES(?,?,0)').run(digest(next),expiresAt);return {token:next,row:{id_hash:digest(next),expires_at:expiresAt}};
   });
   res.append('Set-Cookie',PRE_COOKIE+'='+result.token+'; Path=/hub-api/pairing; HttpOnly; SameSite=Strict'+(origin.startsWith('https:')?'; Secure':'')+'; Max-Age=300');res.json({csrf:csrf('pairing-csrf',result.row.id_hash),expiresAt:result.row.expires_at});
  }));
  app.post('/hub-api/pairing/complete',handle(async(req:any,res:any)=>{
   source(req);const pre=cookie(req,PRE_COOKIE),body=req.body;if(!pre||!body||Object.keys(body).join(',')!=='token'||!opaque(body.token))fail('pairing_rejected');
   const preHash=digest(pre as string);if(!same(req.header('x-hub-csrf')??'',csrf('pairing-csrf',preHash)))fail('page_source_rejected');
   const outcome=await repo.atomic(()=>{
    const browser=repo.db.prepare('SELECT * FROM hub_pairing_browsers WHERE id_hash=?').get(preHash) as any;if(!browser||browser.expires_at<=now())return {error:'pairing_rejected'};
    if(browser.attempts>=5)return {error:'pairing_limit_reached'};repo.db.prepare('UPDATE hub_pairing_browsers SET attempts=attempts+1 WHERE id_hash=?').run(preHash);
    const hash=digest('pairing\0'+keys.installationId+'\0'+body.token),pair=repo.db.prepare('SELECT * FROM hub_pairing_tokens WHERE token_hash=?').get(hash) as any,m=meta();
    if(!pair||pair.installation_id!==keys.installationId||pair.pair_epoch!==m.pair_epoch||pair.expires_at<=now()||pair.used_at!==null||pair.revoked_at!==null)return {error:'pairing_rejected'};
    const token=randomBytes(32).toString('base64url'),ownerProof=randomBytes(32).toString('base64url'),context=JSON.stringify({hasTask:false,returnPath:'/account-hub',label:'目前專案'});
    repo.db.prepare('INSERT INTO hub_owner_sessions VALUES(?,?,?,?,0,?,?,?)').run(digest(token),tenantId,keys.installationId,m.owner_epoch,now()+86400000,context,digest(ownerProof));
    repo.db.prepare('UPDATE hub_pairing_tokens SET used_at=? WHERE token_hash=?').run(now(),hash);repo.db.prepare('DELETE FROM hub_pairing_browsers WHERE id_hash=?').run(preHash);return {token,ownerProof};
   });
   if(outcome.error)fail(outcome.error);setOwnerCookie(res,outcome.token!,false);clearPreCookie(res);res.json({paired:true,ownerProof:outcome.ownerProof,returnPath:'/account-hub'});
  }));
  app.post('/hub-api/logout',handle(async(req:any,res:any)=>{const current=requireOwner(req,true);await repo.atomic(()=>repo.db.prepare('DELETE FROM hub_owner_sessions WHERE id_hash=?').run(current.id_hash));res.append('Set-Cookie',OWNER_COOKIE+'=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');res.json({signedOut:true});}));
 }
 return {session,requireOwner,issuePairing,mount,csrfForOwner:(s:any)=>csrf('owner-csrf',s.id_hash),setCookie:setOwnerCookie};
}
