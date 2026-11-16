import {createHash,createHmac,hkdfSync,randomUUID,timingSafeEqual} from 'node:crypto';
import {spawn} from 'node:child_process';
import {constants as fsConstants} from 'node:fs';
import {open,lstat,mkdir,readdir,readFile,rename,unlink,chmod,link} from 'node:fs/promises';
import {dirname,join,resolve,parse} from 'node:path';
import {fileURLToPath} from 'node:url';
import {inspect} from 'node:util';

export const MASTER_KEY_ENV='NULUNO_ACCESS_MASTER_KEY';
export const INSTALLATION_FILE='installation-key.json';
export const INSTALLATION_BINDING_FILE='installation-key-binding.json';
const SCHEMA='nuluno-access-installation-key-v1';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SOURCES=new Set(['macos-file-keychain','operator-env']);
const OPTION_KEYS=new Set(['source','allowCreate','environment','expectedInstallationId','keychainHelper']);
const HEX=/^[a-f0-9]{64}$/;
export class KeySourceError extends Error{constructor(code){super(code);this.name='KeySourceError';this.code=code;}}
const fail=code=>{throw new KeySourceError(code);};
const digest=value=>createHash('sha256').update(value).digest('hex');
const safeEqual=(a,b)=>typeof a==='string'&&typeof b==='string'&&HEX.test(a)&&HEX.test(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));

async function noSymlinkAncestors(path){
 const absolute=resolve(path),root=parse(absolute).root;let cursor=root;
 for(const segment of absolute.slice(root.length).split('/').filter(Boolean)){
  cursor=join(cursor,segment);try{const s=await lstat(cursor);if(s.isSymbolicLink())fail('key_source_symlink_rejected');}catch(e){if(e.code!=='ENOENT')throw e;}
 }
 return absolute;
}
async function privateDirectory(path){
 await noSymlinkAncestors(path);await mkdir(path,{recursive:true,mode:0o700});await noSymlinkAncestors(path);
 const s=await lstat(path);if(!s.isDirectory()||process.getuid&&s.uid!==process.getuid())fail('key_source_state_owner_required');await chmod(path,0o700);
}
async function regular(path,{missing=false,allowRootOwner=false}={}){
 try{const s=await lstat(path);if(s.isSymbolicLink())fail('key_source_symlink_rejected');if(!s.isFile()||process.getuid&&s.uid!==process.getuid()&&!(allowRootOwner&&s.uid===0))fail('key_source_regular_owner_file_required');return s;}
 catch(e){if(missing&&e.code==='ENOENT')return null;throw e;}
}
async function syncDirectory(path){const fd=await open(path,fsConstants.O_RDONLY|(fsConstants.O_DIRECTORY??0)|(fsConstants.O_NOFOLLOW??0));try{await fd.sync();}finally{await fd.close();}}
function checkedMetadata(value){
 const keys=['schema','installationId','keySource','phase','createdAt','keyCheck'].sort().join(',');
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==keys||value.schema!==SCHEMA||!UUID.test(value.installationId)||!SOURCES.has(value.keySource)||!['pending','ready'].includes(value.phase)||!Number.isSafeInteger(value.createdAt)||value.createdAt<=0||!(value.keyCheck===null&&value.phase==='pending'||HEX.test(value.keyCheck)&&value.phase==='ready'))fail('key_source_installation_metadata_invalid');
 return value;
}
async function metadata(path){
 const s=await regular(path,{missing:true});if(!s)return null;if(s.size>2048)fail('key_source_installation_metadata_invalid');
 const fd=await open(path,fsConstants.O_RDONLY|(fsConstants.O_NOFOLLOW??0));try{return checkedMetadata(JSON.parse(await fd.readFile('utf8')));}catch(e){if(e instanceof KeySourceError)throw e;fail('key_source_installation_metadata_invalid');}finally{await fd.close();}
}
async function writeReady(path,value){
 const name=join(dirname(path),'.installation-write-'+randomUUID());const fd=await open(name,'wx',0o600);
 try{await fd.writeFile(JSON.stringify(value)+'\n');await fd.sync();}finally{await fd.close();}
 try{await regular(path);await rename(name,path);await syncDirectory(dirname(path));}finally{await unlink(name).catch(e=>{if(e.code!=='ENOENT')throw e;});}
}
async function createIntent(path,keySource){
 const value={schema:SCHEMA,installationId:randomUUID(),keySource,phase:'pending',createdAt:Date.now(),keyCheck:null};
 let fd;try{fd=await open(path,fsConstants.O_WRONLY|fsConstants.O_CREAT|fsConstants.O_EXCL|(fsConstants.O_NOFOLLOW??0),0o600);}catch(e){if(e.code==='EEXIST')return metadata(path);throw e;}
 try{await fd.writeFile(JSON.stringify(value)+'\n');await fd.sync();}finally{await fd.close();}
 await syncDirectory(dirname(path));return value;
}
function sameInstallation(a,b){return a.installationId===b.installationId&&a.keySource===b.keySource&&a.createdAt===b.createdAt;}
async function winBinding(path,info,check){
 const staged=join(dirname(path),'.installation-binding-write-'+randomUUID()),value={...info,phase:'ready',keyCheck:check};
 const fd=await open(staged,'wx',0o600);
 try{await fd.writeFile(JSON.stringify(value)+'\n');await fd.sync();}finally{await fd.close();}
 try{
  // link() is an atomic no-overwrite CAS across processes. The fully written
  // immutable binding, not a later metadata rename, chooses the sole master.
  try{await link(staged,path);await syncDirectory(dirname(path));}catch(error){if(error.code!=='EEXIST')throw error;}
  const winner=await metadata(path);
  if(!winner||winner.phase!=='ready'||!sameInstallation(info,winner)||!safeEqual(winner.keyCheck,check))fail('key_source_original_master_changed');
  return winner;
 }finally{await unlink(staged).catch(error=>{if(error.code!=='ENOENT')throw error;});}
}
function masterCheck(master,value){return createHmac('sha256',master).update('nuluno-access-installation-check-v1\0'+value.installationId+'\0'+value.keySource).digest('hex');}
function environmentMaster(environment){
 const encoded=environment?.[MASTER_KEY_ENV];if(typeof encoded!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(encoded))fail('key_source_operator_master_required');
 const master=Buffer.from(encoded,'base64url');if(master.length!==32||master.toString('base64url')!==encoded||new Set(master).size<8){master.fill(0);fail('key_source_operator_master_invalid');}return master;
}

export class InstallationKeys{
 #keys;#destroyed=false;
 constructor(master,info){
  const salt=createHash('sha256').update('nuluno-access-installation-salt-v1\0'+info.installationId).digest();
  this.#keys=Object.fromEntries(['admin','vault','session'].map(name=>[name,Buffer.from(hkdfSync('sha256',master,salt,'nuluno-access-'+name+'-key-v1',32))]));
  Object.defineProperties(this,{installationId:{value:info.installationId,enumerable:true},keySource:{value:info.keySource,enumerable:true}});Object.freeze(this);
 }
 #key(name){if(this.#destroyed)fail('key_source_keys_destroyed');return this.#keys[name].toString('hex');}
 get adminKey(){return this.#key('admin');}get vaultKey(){return this.#key('vault');}get sessionKey(){return this.#key('session');}
 toJSON(){return publicInstallationMetadata(this);}[inspect.custom](){return publicInstallationMetadata(this);}
 destroy(){for(const key of Object.values(this.#keys))key.fill(0);this.#destroyed=true;}
}
export function publicInstallationMetadata(keys){
 if(!(keys instanceof InstallationKeys))fail('key_source_keys_required');
 return Object.freeze({schema:SCHEMA,installationId:keys.installationId,keySource:keys.keySource,secretMaterialReturned:false});
}

/** Trusted startup configuration only. Never accept this options object from an
 * HTTP/MCP caller. A helper path/hash is installer configuration, not authority
 * granted to an agent. Its only stdin fields are protocol, operation and UUID. */
async function keychainMaster(request,helper){
 if(process.platform!=='darwin')fail('key_source_macos_required');
 let configured=helper;
 if(configured===undefined){
  const manifestPath=fileURLToPath(new URL('../native/helper-manifest.json',import.meta.url));
  try{await noSymlinkAncestors(manifestPath);const stat=await regular(manifestPath,{allowRootOwner:true});if(stat.size>2048)fail('key_source_pinned_helper_required');const saved=JSON.parse(await readFile(manifestPath,'utf8'));if(saved.schema!=='nuluno-macos-file-keychain-helper-v1'||Object.keys(saved).sort().join(',')!=='schema,sha256,sourceSha256'||!HEX.test(saved.sourceSha256??''))fail('key_source_pinned_helper_required');configured={executable:fileURLToPath(new URL('../native/bin/nuluno-keychain-helper',import.meta.url)),sha256:saved.sha256};}
  catch{fail('key_source_pinned_helper_required');}
 }
 if(!configured||Object.keys(configured).some(k=>!['executable','sha256'].includes(k))||typeof configured.executable!=='string'||!HEX.test(configured.sha256??''))fail('key_source_pinned_helper_required');
 const path=await noSymlinkAncestors(configured.executable),s=await regular(path,{allowRootOwner:true});
 if(!(s.mode&0o111)||s.mode&0o022||s.size>16*1024*1024||digest(await readFile(path))!==configured.sha256)fail('key_source_helper_integrity_failed');
 return new Promise((resolveKey,reject)=>{
  const child=spawn(path,[],{stdio:['pipe','pipe','pipe'],shell:false,env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin'},windowsHide:true});
  const chunks=[];let bytes=0,settled=false;
  const rejectSafe=code=>{if(settled)return;settled=true;clearTimeout(timer);for(const c of chunks)c.fill(0);reject(new KeySourceError(code));};
  const timer=setTimeout(()=>{child.kill('SIGTERM');rejectSafe('key_source_helper_timeout');},30000);
  child.on('error',()=>rejectSafe('key_source_helper_unavailable'));
  child.stdout.on('data',chunk=>{bytes+=chunk.length;if(bytes>32){chunk.fill(0);child.kill('SIGTERM');rejectSafe('key_source_helper_protocol_rejected');}else chunks.push(chunk);});
  child.stderr.on('data',chunk=>{chunk.fill(0);}); // Never surface native/private errors.
  child.stdin.on('error',()=>{});
  child.on('close',code=>{
   if(settled)return;
   if(code!==0)return rejectSafe(code===21?'key_source_key_missing':code===22?'key_source_owner_unlock_required':'key_source_helper_rejected');
   if(bytes!==32)return rejectSafe('key_source_helper_protocol_rejected');
   settled=true;clearTimeout(timer);const result=Buffer.concat(chunks);for(const chunk of chunks)chunk.fill(0);resolveKey(result);
  });
  child.stdin.end(JSON.stringify({version:1,operation:request.operation,installationId:request.installationId})+'\n');
 });
}

function checkedOptions(options){if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>!OPTION_KEYS.has(k))||options.source!==undefined&&!SOURCES.has(options.source)||options.allowCreate!==undefined&&typeof options.allowCreate!=='boolean'||options.expectedInstallationId!==undefined&&!UUID.test(options.expectedInstallationId))fail('key_source_invalid_startup_options');return options;}

// Dependency injection is limited to an internal factory used by the test
// module. The production package export exposes only the fixed native runner.
function createInstallationKeyLoader(nativeRunner=keychainMaster,platform=process.platform){
 return async function load(stateDir,options={}){
  try{
  checkedOptions(options);if(typeof stateDir!=='string'||!stateDir||stateDir.includes('\0'))fail('key_source_state_directory_required');
  const state=await noSymlinkAncestors(stateDir);await privateDirectory(state);const path=join(state,INSTALLATION_FILE);let info=await metadata(path);
  const source=options.source??info?.keySource??(platform==='darwin'?'macos-file-keychain':'operator-env');
  if(source==='macos-file-keychain'&&platform!=='darwin')fail('key_source_macos_required');
  if(info&&info.keySource!==source)fail('key_source_original_source_changed');
  if(options.expectedInstallationId&&(!info||info.installationId!==options.expectedInstallationId))fail('key_source_original_installation_required');
  if(!info){
   if((await readdir(state)).length)fail('key_source_existing_state_without_installation');
   if(options.allowCreate!==true)fail('key_source_explicit_initialization_required');
   info=await createIntent(path,source);if(!info||info.keySource!==source)fail('key_source_original_source_changed');
  }
  const bindingPath=join(state,INSTALLATION_BINDING_FILE),binding=await metadata(bindingPath);
  if(binding&&(!sameInstallation(info,binding)||binding.phase!=='ready'||info.phase==='ready'&&!safeEqual(binding.keyCheck,info.keyCheck)))fail('key_source_original_installation_changed');
  if(info.phase==='ready'&&!binding)fail('key_source_original_binding_missing');
  const hasOtherState=(await readdir(state)).some(name=>name!==INSTALLATION_FILE&&name!==INSTALLATION_BINDING_FILE);
  let master;
  try{
   if(source==='operator-env')master=environmentMaster(options.environment??process.env);
   else{
    try{master=await nativeRunner({operation:'read',installationId:info.installationId},options.keychainHelper);}
    catch(error){
     if(error?.code!=='key_source_key_missing'||info.phase!=='pending'||binding||options.allowCreate!==true||hasOtherState)throw error;
     master=await nativeRunner({operation:'create',installationId:info.installationId},options.keychainHelper);
    }
   }
   if(!Buffer.isBuffer(master)||master.length!==32)fail('key_source_master_protocol_rejected');
   const check=masterCheck(master,info);
   if(info.phase==='ready'&&!safeEqual(info.keyCheck,check))fail('key_source_original_master_changed');
   if(binding&&!safeEqual(binding.keyCheck,check))fail('key_source_original_master_changed');
   const latest=await metadata(path);
   if(!latest||latest.installationId!==info.installationId||latest.keySource!==info.keySource||latest.createdAt!==info.createdAt||latest.phase==='ready'&&!safeEqual(latest.keyCheck,check))fail('key_source_original_installation_changed');
   const winner=binding??await winBinding(bindingPath,info,check);
   if(latest.phase==='pending')await writeReady(path,winner);
   return new InstallationKeys(master,info);
  }catch(error){if(error instanceof KeySourceError)throw error;fail('key_source_load_rejected');}
  finally{if(Buffer.isBuffer(master))master.fill(0);}
  }catch(error){if(error instanceof KeySourceError)throw error;fail('key_source_state_rejected');}
 };
}
export const loadInstallationKeys=createInstallationKeyLoader();
