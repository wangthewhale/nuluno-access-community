import {createHash} from 'node:crypto';
import {AccessError,type AccessAdapterContext,type AccessProviderAdapter,type AccessStepResult} from '../core/types';
import {StandaloneRepository,accessDigest} from '../core/repository';
export const MASTODON_ORIGIN='https://mastodon.social';
export const PUBLIC_MASTODON_ACCOUNT='public:mastodon.social';
const id=(v:unknown):v is string=>typeof v==='string'&&/^\d{1,40}$/.test(v);
/** Public post projection only. Never forward account objects or raw responses. */
export function publicStatusFields(native:{content:string;account:{id:string;acct:string}}){
 const entities:Record<string,string>={amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '};
 const plain=native.content.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,'').replace(/<br\s*\/?\s*>/gi,'\n').replace(/<\/(?:p|div|li)>/gi,'\n').replace(/<[^>]*>/g,'').replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi,(_all,entity:string)=>{if(entity[0]!=='#')return entities[entity.toLowerCase()]??'';const n=entity[1].toLowerCase()==='x'?parseInt(entity.slice(2),16):parseInt(entity.slice(1),10);return n>0&&n<=0x10ffff&&!(n>=0xd800&&n<=0xdfff)?String.fromCodePoint(n):'';}).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,'').trim();
 const redact=(value:string)=>value.replace(/\bBearer\s+[^\s<>"']+/gi,'[REDACTED]').replace(/\b(?:sk_(?:live|test)_[A-Za-z0-9]{8,}|sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|ya29\.[A-Za-z0-9_-]{12,})/g,'[REDACTED]').replace(/([?&])(?:access_token|refresh_token|token|secret|password|otp|code)=[^\s&#<>"']*/gi,'$1redacted=[REDACTED]');
 const fieldsTruncated:string[]=[];
 const bounded=(name:string,value:string,max:number)=>{let out='',used=0;for(const c of value){const n=Buffer.byteLength(JSON.stringify(c))-2;if(used+n>max){fieldsTruncated.push(name);break;}out+=c;used+=n;}return out;};
 const text=redact(plain),handle=redact(native.account.acct.replace(/[\u0000-\u001f\u007f]/g,''));
 return {fields:{postText:bounded('postText',text,4096),authorId:native.account.id,authorHandle:bounded('authorHandle',handle,256),contentFormat:'plain_text_derived_from_public_html',untrustedData:true,...(text!==plain?{postTextRedacted:true}:{})},fieldsTruncated};
}
export async function nativeJson(path:string,options:RequestInit={},token?:string){
 const r=await fetch(MASTODON_ORIGIN+path,{...options,redirect:'error',signal:AbortSignal.timeout(12000),headers:{accept:'application/json',...(token?{authorization:'Bearer '+token}:{}),...options.headers}});
 if(!r.ok){await r.body?.cancel();throw new AccessError('access_provider_unavailable');}
 const reader=r.body?.getReader();if(!reader)throw new AccessError('access_provider_unavailable');let size=0;const chunks:Uint8Array[]=[];for(;;){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>262144){await reader.cancel();throw new AccessError('access_provider_unavailable');}chunks.push(p.value);}return JSON.parse(Buffer.concat(chunks).toString()) as any;
}
export class MastodonProvider implements AccessProviderAdapter{
 readonly provider='mastodon';constructor(private repository:StandaloneRepository){}
 private async readback(ctx:AccessAdapterContext,statusId:string,text:string,token:string):Promise<AccessStepResult>{
  const original=await ctx.external({provider:'mastodon',action:'publish_text',accountId:ctx.task.accountId,write:false},async()=>({status:await nativeJson('/api/v1/statuses/'+statusId,{},token),source:await nativeJson('/api/v1/statuses/'+statusId+'/source',{},token)}));
  if(original.status.id!==statusId||original.status.account?.id!==ctx.task.accountId||original.source.id!==statusId||original.source.text!==text)return {kind:'unknown'};
  const u=new URL(original.status.url);if(u.protocol!=='https:'||u.hostname!=='mastodon.social'||u.username||u.password)throw new AccessError('access_verification_rejected');
  return {kind:'completed',cursor:{phase:'verified',postId:statusId},evidence:{sourceKind:'native_provider',resourceId:statusId,publicUrl:u.href,receiptHash:accessDigest({provider:'mastodon',accountId:ctx.task.accountId,statusId,textHash:createHash('sha256').update(text).digest('hex')}),verifiedAt:Date.now()}};
 }
 async execute(ctx:AccessAdapterContext):Promise<AccessStepResult>{
  const p=ctx.task.payload;
  if(ctx.task.action==='read_public_status'){
   if(ctx.task.accountId!==PUBLIC_MASTODON_ACCOUNT||Object.keys(p).join(',')!=='statusId'||!id(p.statusId))throw new AccessError('access_invalid_input');
   const native=await ctx.external({provider:'mastodon',action:'read_public_status',accountId:PUBLIC_MASTODON_ACCOUNT,write:false},()=>nativeJson('/api/v1/statuses/'+p.statusId));
   if(native.id!==p.statusId||native.visibility!=='public'||typeof native.url!=='string'||typeof native.content!=='string'||!id(native.account?.id)||typeof native.account?.acct!=='string')throw new AccessError('access_verification_rejected');
   return {kind:'completed',evidence:{sourceKind:'native_provider',...publicStatusFields(native),resourceId:native.id,publicUrl:native.url,receiptHash:accessDigest({id:native.id,account:native.account.id,content:native.content,createdAt:native.created_at}),verifiedAt:Date.now()}};
  }
  const c=this.repository.connection(ctx.principal,'mastodon',ctx.task.accountId),token=c.secret.accessToken;
  if(typeof token!=='string')throw new AccessError('access_provider_unavailable');
  if(ctx.task.action==='verify_identity'){
   if(Object.keys(p).length)throw new AccessError('access_invalid_input');const native=await ctx.external({provider:'mastodon',action:'verify_identity',accountId:ctx.task.accountId,write:false},()=>nativeJson('/api/v1/accounts/verify_credentials',{},token));
   if(native.id!==ctx.task.accountId)throw new AccessError('access_verification_rejected');return {kind:'completed',evidence:{sourceKind:'native_provider',resourceId:native.id,receiptHash:accessDigest({id:native.id,username:native.username}),verifiedAt:Date.now()}};
  }
  if(ctx.task.action!=='publish_text'||Object.keys(p).some(k=>!['text','visibility'].includes(k))||typeof p.text!=='string'||!p.text.trim()||Array.from(p.text).length>500||p.visibility!==undefined&&!['public','unlisted','private'].includes(String(p.visibility)))throw new AccessError('access_invalid_input');
  const text=p.text.trim();if(ctx.task.cursor.phase==='published'&&id(ctx.task.cursor.postId))return this.readback(ctx,ctx.task.cursor.postId,text,token);
  const native=await ctx.external({provider:'mastodon',action:'publish_text',accountId:ctx.task.accountId,write:true},()=>nativeJson('/api/v1/statuses',{method:'POST',headers:{'content-type':'application/json','idempotency-key':ctx.task.id},body:JSON.stringify({status:text,visibility:p.visibility??'unlisted'})},token));
  if(!id(native.id))return {kind:'unknown'};
  return {kind:'continue',cursor:{phase:'published',postId:native.id}};
 }
 async reconcile(ctx:AccessAdapterContext):Promise<AccessStepResult>{
  if(ctx.task.action!=='publish_text')return this.execute(ctx);
  const c=this.repository.connection(ctx.principal,'mastodon',ctx.task.accountId),token=c.secret.accessToken,text=ctx.task.payload.text;
  if(typeof token!=='string'||typeof text!=='string')throw new AccessError('access_provider_unavailable');
  if(id(ctx.task.cursor.postId))return this.readback(ctx,ctx.task.cursor.postId,text.trim(),token);
  const values=await ctx.external({provider:'mastodon',action:'publish_text',accountId:ctx.task.accountId,write:false},()=>nativeJson('/api/v1/accounts/'+ctx.task.accountId+'/statuses?limit=5&exclude_replies=true',{},token));
  if(!Array.isArray(values))return {kind:'unknown'};const matches=[];
  for(const status of values){if(!id(status.id)||Date.parse(status.created_at)<ctx.task.createdAt||status.account?.id!==ctx.task.accountId)continue;const source=await ctx.external({provider:'mastodon',action:'publish_text',accountId:ctx.task.accountId,write:false},()=>nativeJson('/api/v1/statuses/'+status.id+'/source',{},token));if(source.text===text.trim())matches.push(status.id);}
  return matches.length===1?this.readback(ctx,matches[0],text.trim(),token):{kind:'unknown'};
 }
}
