// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {readFileSync,realpathSync,statSync} from 'node:fs';
import {createRequire} from 'node:module';
import {dirname,isAbsolute,join,parse} from 'node:path';
import {pathToFileURL} from 'node:url';

export type AccessExtensionConfig=Readonly<{id:string;module:string;version:string;entrySha256:string}>;
export type AccessExtensionProvider=Readonly<{provider:string;actions:readonly string[];readOnlyActions:readonly string[];augment?:true}>;
export type AccessExtensionManifest<Context=unknown,Installed=unknown>={
 id:string;version:string;providers:readonly AccessExtensionProvider[];
 install(context:Context):Installed;
};
export type LoadedAccessExtension<Context=unknown,Installed=unknown>=Readonly<{
 id:string;module:string;version:string;entryPath:string;entrySha256:string;
 providers:readonly AccessExtensionProvider[];install(context:Context):Installed;
}>;
export class AccessExtensionError extends Error{
 constructor(readonly code:string){super(code);this.name='AccessExtensionError';}
}
const ID=/^[a-z][a-z0-9_-]{0,63}$/;
const MODULE=/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const VERSION=/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$/;
const ACTION=/^[A-Za-z0-9_.:-]{1,120}$/;
const RESERVED=new Set(['__proto__','constructor','prototype']);
function fail(code:string):never{throw new AccessExtensionError(code);}
function record(v:unknown):Record<string,unknown>{
 if(!v||typeof v!=='object'||Array.isArray(v)||![Object.prototype,null].includes(Object.getPrototypeOf(v)))return fail('access_extension_invalid_config');
 return v as Record<string,unknown>;
}
function keys(v:Record<string,unknown>,allowed:readonly string[]){if(Object.keys(v).length!==allowed.length||Object.keys(v).some(k=>!allowed.includes(k)))fail('access_extension_invalid_config');}
function validId(v:unknown):v is string{return typeof v==='string'&&ID.test(v)&&!RESERVED.has(v);}

/** Host bootstrap only. Never derive this configuration from an agent payload. */
export function parseAccessExtensionConfigs(raw:unknown):readonly AccessExtensionConfig[]{
 if(raw===undefined)return Object.freeze([]);
 if(!Array.isArray(raw)||raw.length>16)fail('access_extension_invalid_config');
 const ids=new Set<string>(),modules=new Set<string>();
 return Object.freeze(raw.map(value=>{
  const v=record(value);keys(v,['id','module','version','entrySha256']);
  if(!validId(v.id)||typeof v.module!=='string'||v.module.length>214||!MODULE.test(v.module)||typeof v.version!=='string'||v.version.length>100||!VERSION.test(v.version)||typeof v.entrySha256!=='string'||!(/^[a-f0-9]{64}$/).test(v.entrySha256))fail('access_extension_invalid_config');
  const config=v as unknown as AccessExtensionConfig;
  if(ids.has(config.id)||modules.has(config.module))fail('access_extension_duplicate');ids.add(config.id);modules.add(config.module);
  return Object.freeze({id:config.id,module:config.module,version:config.version,entrySha256:config.entrySha256});
 }));
}

function providers(raw:unknown,occupied:Set<string>,extensionOwned:Set<string>,builtinActions:ReadonlyMap<string,ReadonlySet<string>>):readonly AccessExtensionProvider[]{
 if(!Array.isArray(raw)||raw.length<1||raw.length>16)fail('access_extension_invalid_manifest');
 return Object.freeze(raw.map(value=>{
  let v:Record<string,unknown>;try{v=record(value);keys(v,Object.hasOwn(v,'augment')?['provider','actions','readOnlyActions','augment']:['provider','actions','readOnlyActions']);}catch{ return fail('access_extension_invalid_manifest'); }
  if(!validId(v.provider)||!Array.isArray(v.actions)||v.actions.length<1||v.actions.length>64||!Array.isArray(v.readOnlyActions)||v.readOnlyActions.length>64)fail('access_extension_invalid_manifest');
  const name=v.provider as string,actions=v.actions as unknown[],reads=v.readOnlyActions as unknown[];
  if(actions.some(a=>typeof a!=='string'||!ACTION.test(a)||RESERVED.has(a))||new Set(actions).size!==actions.length||reads.some(a=>typeof a!=='string'||!actions.includes(a))||new Set(reads).size!==reads.length)fail('access_extension_invalid_manifest');
  const augment=Object.hasOwn(v,'augment');
  if(augment){
   if(v.augment!==true||name!=='mastodon'||!builtinActions.has(name))fail('access_extension_invalid_manifest');
   if(reads.length>0||actions.some(a=>!['connect','create_account'].includes(a as string)))fail('access_extension_invalid_manifest');
   if(extensionOwned.has(name)||actions.some(a=>builtinActions.get(name)!.has(a as string)))fail('access_extension_provider_conflict');
  }else if(occupied.has(name))fail('access_extension_provider_conflict');
  occupied.add(name);extensionOwned.add(name);
  return Object.freeze({provider:name,actions:Object.freeze([...actions] as string[]),readOnlyActions:Object.freeze([...reads] as string[]),...(augment?{augment:true as const}:{})});
 }));
}
function entryDigest(path:string){const s=statSync(path);if(!s.isFile()||s.size>4*1024*1024)fail('access_extension_invalid_package');return createHash('sha256').update(readFileSync(path)).digest('hex');}
function packageIdentity(entry:string,moduleName:string,version:string){
 let current=dirname(entry);const boundary=parse(current).root;
 for(let depth=0;depth<24;depth++){
  const path=join(current,'package.json');
  try{
   const s=statSync(path);if(!s.isFile()||s.size>65536)fail('access_extension_invalid_package');
   const pkg=JSON.parse(readFileSync(path,'utf8'));
   // The nearest package.json owns the entry. Do not walk past a mismatched package.
   if(pkg.name!==moduleName||pkg.version!==version)fail('access_extension_package_identity_mismatch');return;
  }catch(error){if(error instanceof AccessExtensionError)throw error;if((error as NodeJS.ErrnoException).code!=='ENOENT')fail('access_extension_invalid_package');}
  if(current===boundary)break;current=dirname(current);
 }
 fail('access_extension_invalid_package');
}

/** Resolve exact operator-installed packages, check identity/hash, then import.
 * Extensions are trusted host code, not a sandbox or delegated agent authority.
 * A pinned entry hash does not authenticate its transitive imports; lock them.
 */
export async function loadAccessExtensions<Context=unknown,Installed=unknown>(raw:unknown,options:{resolveFrom:string;builtinProviders?:readonly string[];builtinActions?:Readonly<Record<string,readonly string[]>>}):Promise<readonly LoadedAccessExtension<Context,Installed>[]>{
 const configs=parseAccessExtensionConfigs(raw);if(configs.length===0)return Object.freeze([]);
 if(typeof options.resolveFrom!=='string'||!isAbsolute(options.resolveFrom))fail('access_extension_invalid_resolution_root');
 const occupied=new Set(['mastodon',...(options.builtinProviders??[])]),extensionOwned=new Set<string>();
 for(const name of occupied)if(!validId(name))fail('access_extension_invalid_config');
 const builtinActions=new Map<string,ReadonlySet<string>>([['mastodon',new Set(['read_public_status','verify_identity','publish_text'])]]);
 for(const [name,actions]of Object.entries(options.builtinActions??{})){
  if(!validId(name)||!Array.isArray(actions)||actions.length>64||actions.some(a=>typeof a!=='string'||!ACTION.test(a)||RESERVED.has(a))||new Set(actions).size!==actions.length)fail('access_extension_invalid_config');
  occupied.add(name);builtinActions.set(name,new Set([...(builtinActions.get(name)??[]),...actions]));
 }
 const require=createRequire(options.resolveFrom);
 // Validate all package identities and bytes before executing any extension entry.
 const resolved=configs.map(config=>{
  let entryPath:string;
  try{entryPath=realpathSync(require.resolve(config.module));if(!/\.(?:mjs|cjs|js)$/.test(entryPath))fail('access_extension_invalid_package');packageIdentity(entryPath,config.module,config.version);if(entryDigest(entryPath)!==config.entrySha256)fail('access_extension_integrity_mismatch');}
  catch(error){if(error instanceof AccessExtensionError)throw error;return fail('access_extension_package_unavailable');}
  return {config,entryPath};
 });
 const loaded:LoadedAccessExtension<Context,Installed>[]=[];
 for(const {config,entryPath}of resolved){
  if(entryDigest(entryPath)!==config.entrySha256)fail('access_extension_integrity_mismatch');
  let value:unknown;try{const url=pathToFileURL(entryPath);url.searchParams.set('nulunoAccessIntegrity',config.entrySha256);value=(await import(url.href)).accessExtension;}catch{return fail('access_extension_import_failed');}
  let manifest:Record<string,unknown>;try{manifest=record(value);keys(manifest,['id','version','providers','install']);}catch{return fail('access_extension_invalid_manifest');}
  if(manifest.id!==config.id||manifest.version!==config.version||typeof manifest.install!=='function')fail('access_extension_manifest_mismatch');
  const descriptors=providers(manifest.providers,occupied,extensionOwned,builtinActions),install=manifest.install as(context:Context)=>Installed;
  loaded.push(Object.freeze({id:config.id,module:config.module,version:config.version,entryPath,entrySha256:config.entrySha256,providers:descriptors,install:(context:Context)=>Reflect.apply(install,undefined,[context]) as Installed}));
 }
 return Object.freeze(loaded);
}
