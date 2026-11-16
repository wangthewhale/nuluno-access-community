// Trusted host fixtures, not a licensed Gmail implementation or real provider
// acceptance. The production addon does not contain a Google OAuth connector.
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
export function stableKeySource(){const keys=Object.freeze({installationId:randomUUID(),adminKey:randomBytes(32).toString('hex'),vaultKey:randomBytes(32).toString('hex'),sessionKey:randomBytes(32).toString('hex'),keySource:'controlled-test'});return async()=>keys;}
export async function pairBrowser(hub,origin,fetchImpl){
 const activation=await hub.issuePairing(),token=new URLSearchParams(new URL(activation.activationUrl).hash.slice(1)).get('pair');
 const challenge=await fetchImpl(origin+'/hub-api/pairing/challenge',{headers:{connection:'close'},redirect:'error'}),pre=challenge.headers.getSetCookie().find(value=>value.startsWith('nuluno_hub_pairing_'))?.split(';')[0],value=await challenge.json();
 const result=await fetchImpl(origin+'/hub-api/pairing/complete',{method:'POST',headers:{connection:'close',origin,cookie:pre,'x-hub-csrf':value.csrf,'content-type':'application/json'},body:JSON.stringify({token}),redirect:'error'});assert.equal(result.status,200);
 const cookie=result.headers.getSetCookie().find(value=>value.startsWith('nuluno_hub_owner_'))?.split(';')[0],completed=await result.json(),proof=completed.ownerProof;assert.ok(cookie);assert.ok(typeof proof==='string');const state=await fetchImpl(origin+'/hub-api/state',{headers:{connection:'close',cookie,'x-hub-owner-proof':proof},redirect:'error'});assert.equal(state.status,200);return {cookie,proof,csrf:(await state.json()).csrf};
}
export function controlledGmailExtension(){
 return {id:'commercial',module:'@nuluno/access-commercial-extension',version:'0.0.0-controlled',entryPath:'controlled-test-only',entrySha256:'0'.repeat(64),providers:[{provider:'gmail',actions:['verify_email'],readOnlyActions:['verify_email']}],install({repository,origin}){
  const adapter={provider:'gmail',execute:async()=>({kind:'waiting',waitReason:'owner'}),reconcile:async()=>({kind:'unknown'})};
  return {adapters:{gmail:adapter},mountOwnerRoutes({app,scope,handle}){
   app.post('/admin/tenants/:tenantId/google/start',handle(async(req,res)=>{const s=await scope(req),state=randomBytes(32).toString('base64url');await repository.saveOAuth(state,s,'gmail',{controlled:true});res.json({authorizationUrl:'https://accounts.google.com/o/oauth2/v2/auth?client_id=CONTROLLED_CLIENT&state='+state,expiresAt:Date.now()+600000});}));
   app.get('/oauth/google/callback',async(req,res)=>{try{const state=typeof req.query.state==='string'?req.query.state:'',saved=await repository.claimOAuth(state,'gmail'),s=await repository.tenant(saved.scope),token=await (await fetch('https://oauth2.googleapis.com/token',{method:'POST',redirect:'error',body:'controlled-fixture-only'})).json(),identity=await (await fetch('https://openidconnect.googleapis.com/v1/userinfo',{redirect:'error'})).json();if(identity.email_verified!==true||typeof identity.sub!=='string')throw Error('controlled_verification_rejected');await repository.setConnection(s,{provider:'gmail',accountId:identity.sub,label:'Connected Gmail',scopes:String(token.scope).split(' '),secret:{accessToken:token.access_token,refreshToken:token.refresh_token},expiresAt:Date.now()+3600000});await repository.completeOAuth(state);res.json({connected:true});}catch{res.status(400).json({error:'controlled_callback_rejected'});}});
  }};
 }};
}
