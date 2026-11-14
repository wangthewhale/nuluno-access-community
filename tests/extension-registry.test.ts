// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,rmSync,symlinkSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {loadAccessExtensions,parseAccessExtensionConfigs,AccessExtensionError} from '../src/extensions/registry';

function fixture(){
 const root=mkdtempSync(join(tmpdir(),'access-extension-registry-')),configPath=join(root,'extensions.json');writeFileSync(configPath,'[]');
 function packageFile(name:string,source:string,version='1.2.3'){
  const packageRoot=join(root,'node_modules',name),entry=join(packageRoot,'entry.mjs');mkdirSync(dirname(entry),{recursive:true});
  writeFileSync(join(packageRoot,'package.json'),JSON.stringify({name,version,type:'module',exports:'./entry.mjs'}));writeFileSync(entry,source);
  return {entry,packageRoot,config:{id:'commercial',module:name,version,entrySha256:createHash('sha256').update(source).digest('hex')}};
 }
 return {root,configPath,packageFile,cleanup:()=>rmSync(root,{recursive:true,force:true})};
}
const provider=(name='gmail',actions=['verify_email'],reads:string[]=[])=>({provider:name,actions,readOnlyActions:reads});
const source=(providers:unknown[],extra='')=>`export const accessExtension={id:'commercial',version:'1.2.3',providers:${JSON.stringify(providers)},install(context){return {marker:context.marker};}};${extra}`;

test('absent extensions are empty and immutable; no provider is invented',async()=>{
 assert.deepEqual(parseAccessExtensionConfigs(undefined),[]);assert.ok(Object.isFrozen(parseAccessExtensionConfigs([])));
 assert.deepEqual(await loadAccessExtensions(undefined,{resolveFrom:'/not-needed.json'}),[]);
});

test('operator-pinned real ESM package loads frozen descriptors and does not install automatically',async()=>{
 const f=fixture();try{
  const p=f.packageFile('@demo/access-commercial',source([provider('gmail',['verify_email','read_profile'],['read_profile'])]));
  const loaded=await loadAccessExtensions<{marker:string},{marker:string}>([p.config],{resolveFrom:f.configPath});
  assert.equal(loaded.length,1);const extension=loaded[0];assert.equal(extension.entryPath,realpathSync(p.entry));assert.equal(extension.module,p.config.module);assert.equal(extension.entrySha256,p.config.entrySha256);
  assert.ok(Object.isFrozen(loaded));assert.ok(Object.isFrozen(extension));assert.ok(Object.isFrozen(extension.providers));assert.ok(Object.isFrozen(extension.providers[0]));assert.ok(Object.isFrozen(extension.providers[0].actions));assert.ok(Object.isFrozen(extension.providers[0].readOnlyActions));
  assert.throws(()=>{(extension.providers[0].actions as string[]).push('create_anything');},TypeError);
  assert.deepEqual(extension.install({marker:'host-value'}),{marker:'host-value'});
  assert.deepEqual(extension.providers[0].actions,['verify_email','read_profile']);
 }finally{f.cleanup();}
});

test('configuration rejects arbitrary paths, URLs, ranges, unknown fields and duplicates before package import',()=>{
 const valid={id:'commercial',module:'@demo/access-commercial',version:'1.2.3',entrySha256:'a'.repeat(64)};
 for(const module of ['./local.mjs','../local.mjs','/tmp/entry.mjs','file:///tmp/entry.mjs','https://example.invalid/a.mjs','node:fs','@demo/access-commercial/extra','@demo/access-*','eval(code)'])assert.throws(()=>parseAccessExtensionConfigs([{...valid,module}]),/access_extension_invalid_config/);
 for(const raw of [null,{},[{...valid,version:'^1.2.3'}],[{...valid,version:'latest'}],[{...valid,entrySha256:'bad'}],[{...valid,path:'/tmp/entry.mjs'}],[{...valid,id:'__proto__'}]])assert.throws(()=>parseAccessExtensionConfigs(raw),AccessExtensionError);
 assert.throws(()=>parseAccessExtensionConfigs([valid,{...valid,module:'@demo/another'}]),/access_extension_duplicate/);
 assert.throws(()=>parseAccessExtensionConfigs([valid,{...valid,id:'another'}]),/access_extension_duplicate/);
});

test('hash and package-version mismatches reject before executing the module',async()=>{
 const f=fixture();try{
  const marker=join(f.root,'module-executed');
  const p=f.packageFile('@demo/access-commercial',source([provider()],`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},'executed');`));
  await assert.rejects(loadAccessExtensions([{...p.config,entrySha256:'0'.repeat(64)}],{resolveFrom:f.configPath}),/access_extension_integrity_mismatch/);assert.equal(existsSync(marker),false);
  await assert.rejects(loadAccessExtensions([{...p.config,version:'1.2.4'}],{resolveFrom:f.configPath}),/access_extension_package_identity_mismatch/);assert.equal(existsSync(marker),false);
  await assert.rejects(loadAccessExtensions([p.config],{resolveFrom:'relative.json'}),/access_extension_invalid_resolution_root/);assert.equal(existsSync(marker),false);
 }finally{f.cleanup();}
});

test('the entire operator package set is verified before any entry is executed',async()=>{
 const f=fixture();try{
  const marker=join(f.root,'first-executed'),first=f.packageFile('@demo/first',source([provider()],`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},'executed');`));
  const second=f.packageFile('@demo/second',source([provider('threads',['publish_text'])]));
  await assert.rejects(loadAccessExtensions([first.config,{...second.config,id:'second',entrySha256:'0'.repeat(64)}],{resolveFrom:f.configPath}),/access_extension_integrity_mismatch/);
  assert.equal(existsSync(marker),false);
 }finally{f.cleanup();}
});

test('manifest identity, actions and immutable read-only classifications are exact',async()=>{
 const invalid=[
  source([provider()]).replace("version:'1.2.3'","version:'2.0.0'"),
  source([provider()]).replace("id:'commercial'","id:'different'"),
  source([provider()]).replace('install(context){return {marker:context.marker};}','install:42'),
  source([provider('gmail',['verify_email','verify_email'])]),
  source([provider('gmail',['verify_email'],['not_installed'])]),
  source([provider('gmail',['verify_email'],['verify_email','verify_email'])]),
  source([{...provider(),endpoint:'https://attacker.invalid/'}]),
  source([{...provider(),actions:['*']}]),
  source([{...provider(),provider:'__proto__'}]),
 ];
 for(const code of invalid){const f=fixture();try{const p=f.packageFile('@demo/access-commercial',code);await assert.rejects(loadAccessExtensions([p.config],{resolveFrom:f.configPath}),AccessExtensionError);}finally{f.cleanup();}}
});

test('built-in Mastodon and duplicate provider ownership cannot be overwritten or merged',async()=>{
 for(const descriptors of [[provider('mastodon',['publish_text'])],[provider(),provider()]]){
  const f=fixture();try{const p=f.packageFile('@demo/access-commercial',source(descriptors));await assert.rejects(loadAccessExtensions([p.config],{resolveFrom:f.configPath}),/access_extension_provider_conflict/);}finally{f.cleanup();}
 }
 const f=fixture();try{
  const a=f.packageFile('@demo/first',source([provider('gmail',['verify_email'])]));
  const b=f.packageFile('@demo/second',source([provider('gmail',['read_other'])]).replace("id:'commercial'","id:'second'"));
  await assert.rejects(loadAccessExtensions([a.config,{...b.config,id:'second'}],{resolveFrom:f.configPath}),/access_extension_provider_conflict/);
 }finally{f.cleanup();}
});

test('resolved real entry must belong to the named package; a symlink cannot borrow another package identity',async()=>{
 const f=fixture();try{
  const a=f.packageFile('@demo/access-commercial',source([provider()])),other=f.packageFile('@demo/different',source([provider()]));
  rmSync(a.entry);symlinkSync(other.entry,a.entry);
  await assert.rejects(loadAccessExtensions([a.config],{resolveFrom:f.configPath}),/access_extension_package_identity_mismatch/);
  assert.equal(readFileSync(other.entry,'utf8').includes('accessExtension'),true);
 }finally{f.cleanup();}
});

test('explicit Mastodon augmentation adds only disjoint signup actions and keeps immutable ownership',async()=>{
 const f=fixture();try{
  const descriptor={...provider('mastodon',['connect','create_account']),augment:true};
  const p=f.packageFile('@demo/access-commercial',source([descriptor]));
  const loaded=await loadAccessExtensions([p.config],{resolveFrom:f.configPath});
  assert.deepEqual(loaded[0].providers,[descriptor]);assert.equal(loaded[0].providers[0].augment,true);assert.ok(Object.isFrozen(loaded[0].providers[0]));
  await assert.rejects(loadAccessExtensions([p.config],{resolveFrom:f.configPath,builtinActions:{mastodon:['connect']}}),/access_extension_provider_conflict/);
 }finally{f.cleanup();}
});

test('augmentation cannot replace native actions, claim reads, target another provider or share ownership',async()=>{
 const bad=[
  {...provider('mastodon',['publish_text']),augment:true},
  {...provider('mastodon',['connect','read_public_status']),augment:true},
  {...provider('mastodon',['connect'],['connect']),augment:true},
  {...provider('gmail',['verify_email']),augment:true},
  {...provider('mastodon',['connect']),augment:false},
 ];
 for(const descriptor of bad){const f=fixture();try{const p=f.packageFile('@demo/access-commercial',source([descriptor]));await assert.rejects(loadAccessExtensions([p.config],{resolveFrom:f.configPath}),AccessExtensionError);}finally{f.cleanup();}}
 const f=fixture();try{
  const first=f.packageFile('@demo/first',source([{...provider('mastodon',['connect']),augment:true}]));
  const second=f.packageFile('@demo/second',source([{...provider('mastodon',['create_account']),augment:true}]).replace("id:'commercial'","id:'second'"));
  await assert.rejects(loadAccessExtensions([first.config,{...second.config,id:'second'}],{resolveFrom:f.configPath}),/access_extension_provider_conflict/);
 }finally{f.cleanup();}
});
