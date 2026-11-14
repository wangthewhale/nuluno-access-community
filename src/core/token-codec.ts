import {createHmac} from 'node:crypto';
import {CredentialVault,type EncryptedCredential} from './vault';
import {AccessError,type AccessToken,type AccessTokenCodec} from './types';
const PURPOSE='nuluno-access-agent-key-v2';
export class VaultAccessTokenCodec implements AccessTokenCodec {
 constructor(private vault:CredentialVault,private fingerprintKey?:string){}
 encode(value:AccessToken):string {return 'nla2.'+Buffer.from(JSON.stringify(this.vault.encrypt(JSON.stringify(value),PURPOSE))).toString('base64url');}
 decode(key:string):AccessToken {
  try {
   if(typeof key!=='string'||key.length>4096||!/^nla2\.[A-Za-z0-9_-]+$/.test(key))throw new Error();
   const e=JSON.parse(Buffer.from(key.slice(5),'base64url').toString()) as EncryptedCredential;
   if(!e||Object.keys(e).sort().join(',')!=='ciphertext,iv,tag'||[e.ciphertext,e.iv,e.tag].some(v=>typeof v!=='string'))throw new Error();
   const v=JSON.parse(this.vault.decrypt(e,PURPOSE)) as AccessToken;
   if(v.v!==2||typeof v.keyId!=='string'||!/^[0-9a-f]{64}$/.test(v.secret)||!v.scope||['workspaceId','ownerId','missionId'].some(k=>typeof (v.scope as Record<string,unknown>)[k]!=='string'))throw new Error();
   return v;
  } catch {throw new AccessError('access_invalid_key');}
 }
 fingerprint(purpose:string,value:string):string {
  if(!this.fingerprintKey||this.fingerprintKey.length<32)throw new AccessError('access_provider_unavailable');
  return createHmac('sha256',this.fingerprintKey).update('nuluno-access-fingerprint-v1:'+purpose+'\0'+value).digest('hex');
 }
}
