import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,readdir,rm,symlink,mkdir,realpath,stat,chmod} from 'node:fs/promises';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {inspect} from 'node:util';
import {spawn} from 'node:child_process';
import * as production from '../src/account-hub/keys/src/key-source.mjs';

const root=resolve(import.meta.dirname,'..'),temp=await realpath(await mkdtemp(join(tmpdir(),'nuluno-key-source-instrumented-')));
// Instrumented test-only export, never part of the public production module.
const subject=join(temp,'instrumented-subject.mjs');await writeFile(subject,(await readFile(join(root,'src/account-hub/keys/src/key-source.mjs'),'utf8'))+'\nexport {createInstallationKeyLoader,keychainMaster};\n');
const {createInstallationKeyLoader,keychainMaster,KeySourceError:InstrumentedError}=await import(pathToFileURL(subject));
const state=()=>join(temp,'state-'+randomUUID());
const env=()=>({[production.MASTER_KEY_ENV]:randomBytes(32).toString('base64url')});
const fails=code=>error=>error?.code===code;
const metadata=async path=>JSON.parse(await readFile(join(path,production.INSTALLATION_FILE),'utf8'));
after(()=>rm(temp,{recursive:true,force:true}));
function nativeFixture(){
 const items=new Map(),calls=[];
 const run=async(request)=>{calls.push({...request});if(request.operation==='read'){if(!items.has(request.installationId))throw new InstrumentedError('key_source_key_missing');return Buffer.from(items.get(request.installationId));}assert.equal(request.operation,'create');if(!items.has(request.installationId))items.set(request.installationId,randomBytes(32));return Buffer.from(items.get(request.installationId));};
 return {items,calls,run,load:createInstallationKeyLoader(run,'darwin')};
}

test('operator source is deterministic across restart, HKDF domains differ, and no plaintext key file or public secret is produced',async()=>{
 const path=state(),environment=env(),first=await production.loadInstallationKeys(path,{source:'operator-env',allowCreate:true,environment});
 const second=await production.loadInstallationKeys(path,{source:'operator-env',environment});
 assert.equal(first.installationId,second.installationId);assert.equal(first.adminKey,second.adminKey);assert.equal(first.vaultKey,second.vaultKey);assert.equal(first.sessionKey,second.sessionKey);assert.equal(new Set([first.adminKey,first.vaultKey,first.sessionKey]).size,3);
 const safe=JSON.stringify(first)+inspect(first)+JSON.stringify(production.publicInstallationMetadata(first));
 for(const secret of [environment[production.MASTER_KEY_ENV],first.adminKey,first.vaultKey,first.sessionKey])assert.ok(!safe.includes(secret));
 assert.deepEqual((await readdir(path)).sort(),[production.INSTALLATION_FILE,production.INSTALLATION_BINDING_FILE].sort());const raw=(await Promise.all([production.INSTALLATION_FILE,production.INSTALLATION_BINDING_FILE].map(name=>readFile(join(path,name),'utf8')))).join('');for(const secret of [environment[production.MASTER_KEY_ENV],first.adminKey,first.vaultKey,first.sessionKey])assert.ok(!raw.includes(secret));
 assert.equal((await stat(path)).mode&0o777,0o700);assert.equal((await stat(join(path,production.INSTALLATION_FILE))).mode&0o777,0o600);
 first.destroy();second.destroy();
});

test('wrong or missing operator master, source changes and wrong expected UUID never replace an existing identity',async()=>{
 const path=state(),environment=env(),keys=await production.loadInstallationKeys(path,{source:'operator-env',allowCreate:true,environment}),before=await readFile(join(path,production.INSTALLATION_FILE),'utf8');
 await assert.rejects(production.loadInstallationKeys(path,{source:'operator-env',environment:env()}),fails('key_source_original_master_changed'));
 await assert.rejects(production.loadInstallationKeys(path,{source:'operator-env',environment:{}}),fails('key_source_operator_master_required'));
 await assert.rejects(production.loadInstallationKeys(path,{source:'operator-env',environment,expectedInstallationId:randomUUID()}),fails('key_source_original_installation_required'));
 await assert.rejects(production.loadInstallationKeys(path,{source:'macos-file-keychain'}),fails('key_source_original_source_changed'));
 assert.equal(await readFile(join(path,production.INSTALLATION_FILE),'utf8'),before);keys.destroy();
});

test('existing SQLite or a legacy plaintext-owner file without installation metadata is not automatically migrated or re-keyed',async()=>{
 for(const name of ['access.sqlite','local-owner.json']){
  const path=state();await mkdir(path);await writeFile(join(path,name),'CONTROLLED_EXISTING_STATE');const native=nativeFixture();
  await assert.rejects(native.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_existing_state_without_installation'));
  assert.equal(native.calls.length,0);assert.equal(await readFile(join(path,name),'utf8'),'CONTROLLED_EXISTING_STATE');assert.deepEqual(await readdir(path),[name]);
 }
});

test('new native install creates only one UUID-scoped item, restarts read it, and missing ready item never silently creates another',async()=>{
 const f=nativeFixture(),path=state(),first=await f.load(path,{source:'macos-file-keychain',allowCreate:true}),value=first.vaultKey;
 assert.deepEqual(f.calls.map(c=>c.operation),['read','create']);assert.ok(f.calls.every(c=>c.installationId===first.installationId));
 const second=await f.load(path,{source:'macos-file-keychain'});assert.equal(second.vaultKey,value);assert.equal(f.calls.at(-1).operation,'read');
 f.items.delete(first.installationId);const count=f.calls.length;
 await assert.rejects(f.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_key_missing'));
 assert.deepEqual(f.calls.slice(count).map(c=>c.operation),['read']);assert.equal((await metadata(path)).installationId,first.installationId);first.destroy();second.destroy();
});

test('interruption after keychain create resumes by reading the same pending UUID, not by rotating keys',async()=>{
 const f=nativeFixture(),path=state();let interrupted=false;
 const load=createInstallationKeyLoader(async request=>{const key=await f.run(request);if(request.operation==='create'&&!interrupted){interrupted=true;key.fill(0);throw new InstrumentedError('key_source_helper_timeout');}return key;},'darwin');
 await assert.rejects(load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_helper_timeout'));
 const original=await metadata(path);assert.equal(original.phase,'pending');
 const resumed=await load(path,{source:'macos-file-keychain',allowCreate:true});assert.equal(resumed.installationId,original.installationId);assert.equal((await metadata(path)).phase,'ready');
 assert.equal(f.calls.filter(c=>c.operation==='create').length,1);assert.ok(f.calls.every(c=>c.installationId===original.installationId));resumed.destroy();
});

test('pending identity with preexisting database cannot create a missing keystore item',async()=>{
 const f=nativeFixture(),path=state(),load=createInstallationKeyLoader(async()=>{throw new InstrumentedError('key_source_owner_unlock_required');},'darwin');
 await assert.rejects(load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_owner_unlock_required'));
 await writeFile(join(path,'access.sqlite'),'CONTROLLED_OLD_DB');
 await assert.rejects(f.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_key_missing'));assert.deepEqual(f.calls.map(c=>c.operation),['read']);
});

test('committed binding with pending metadata resumes the same original key, but a missing native key is not recreated',async()=>{
 const f=nativeFixture(),path=state(),first=await f.load(path,{source:'macos-file-keychain',allowCreate:true}),original=await metadata(path),key=first.vaultKey;
 await writeFile(join(path,production.INSTALLATION_FILE),JSON.stringify({...original,phase:'pending',keyCheck:null}));
 const resumed=await f.load(path,{source:'macos-file-keychain',allowCreate:true});assert.equal(resumed.installationId,first.installationId);assert.equal(resumed.vaultKey,key);assert.equal((await metadata(path)).phase,'ready');
 await writeFile(join(path,production.INSTALLATION_FILE),JSON.stringify({...original,phase:'pending',keyCheck:null}));f.items.delete(first.installationId);const before=f.calls.length;
 await assert.rejects(f.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_key_missing'));assert.deepEqual(f.calls.slice(before).map(c=>c.operation),['read']);first.destroy();resumed.destroy();
});

test('missing ready binding fails closed before loading a key or creating replacement authority',async()=>{
 const f=nativeFixture(),path=state(),first=await f.load(path,{source:'macos-file-keychain',allowCreate:true});await rm(join(path,production.INSTALLATION_BINDING_FILE));const before=f.calls.length;
 await assert.rejects(f.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_original_binding_missing'));assert.equal(f.calls.length,before);first.destroy();
});

test('changed UUID does not regenerate missing authority and a concurrent metadata change is rejected',async()=>{
 const f=nativeFixture(),path=state(),key=await f.load(path,{source:'macos-file-keychain',allowCreate:true}),original=await metadata(path),changed={...original,installationId:randomUUID()};
 await writeFile(join(path,production.INSTALLATION_FILE),JSON.stringify(changed));const before=f.calls.length;
 await assert.rejects(f.load(path,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_original_installation_changed'));assert.equal(f.calls.length,before);key.destroy();
 const other=state();const late=createInstallationKeyLoader(async request=>{const master=await f.run(request);if(request.operation==='create'){const m=await metadata(other);await writeFile(join(other,production.INSTALLATION_FILE),JSON.stringify({...m,installationId:randomUUID()}));}return master;},'darwin');
 await assert.rejects(late(other,{source:'macos-file-keychain',allowCreate:true}),fails('key_source_original_installation_changed'));
});

test('state, parent and metadata symlinks fail closed without altering the target',async()=>{
 const target=state();await mkdir(target);await writeFile(join(target,'untouched'),'CONTROLLED_TARGET');
 const linked=state();await symlink(target,linked,'dir');await assert.rejects(production.loadInstallationKeys(linked,{source:'operator-env',allowCreate:true,environment:env()}),fails('key_source_symlink_rejected'));
 await assert.rejects(production.loadInstallationKeys(join(linked,'child'),{source:'operator-env',allowCreate:true,environment:env()}),fails('key_source_symlink_rejected'));
 const path=state();await mkdir(path);await symlink(join(target,'untouched'),join(path,production.INSTALLATION_FILE));await assert.rejects(production.loadInstallationKeys(path,{source:'operator-env',allowCreate:true,environment:env()}),fails('key_source_symlink_rejected'));
 assert.equal(await readFile(join(target,'untouched'),'utf8'),'CONTROLLED_TARGET');assert.deepEqual(await readdir(target),['untouched']);
});

test('new installations require explicit creation and unsupported DPK/agent-supplied extras are rejected',async()=>{
 const f=nativeFixture();await assert.rejects(f.load(state(),{source:'macos-file-keychain'}),fails('key_source_explicit_initialization_required'));
 for(const options of [{source:'macos-data-protection-keychain',allowCreate:true},{source:'operator-env',allowCreate:true,environment:env(),agentPayload:{override:true}},{source:'operator-env',allowCreate:true,environment:env(),expectedInstallationId:'not-uuid'}])await assert.rejects(production.loadInstallationKeys(state(),options),fails('key_source_invalid_startup_options'));
 const linux=createInstallationKeyLoader(f.run,'linux');await assert.rejects(linux(state(),{source:'macos-file-keychain',allowCreate:true}),fails('key_source_macos_required'));assert.equal(f.calls.length,0);
});

test('destroyed key material cannot be retrieved and module production exports no injected runner factory',async()=>{
 const keys=await production.loadInstallationKeys(state(),{source:'operator-env',allowCreate:true,environment:env()});keys.destroy();assert.throws(()=>keys.vaultKey,fails('key_source_keys_destroyed'));assert.equal(JSON.parse(JSON.stringify(keys)).secretMaterialReturned,false);assert.equal(production.createInstallationKeyLoader,undefined);assert.equal(production.keychainMaster,undefined);
});

test('instrumented executable receives UUID commands only over stdin, returns 32 binary bytes, and inherits no master environment',async()=>{
 if(process.platform!=='darwin')return; // Native runner is macOS-only by design.
 const executable=join(temp,'instrumented-helper'),capture=join(temp,'instrumented-helper-request.json'),id=randomUUID();
 const code='#!'+process.execPath+'\n'+`import {readFileSync,writeFileSync} from 'node:fs';import {createHash} from 'node:crypto';const req=JSON.parse(readFileSync(0,'utf8'));writeFileSync(${JSON.stringify(capture)},JSON.stringify({request:req,args:process.argv.slice(2),envKeys:Object.keys(process.env)}));process.stdout.write(createHash('sha256').update('INSTRUMENTED-SYNTHETIC-HELPER-'+req.installationId).digest());`;
 await writeFile(executable,code,{mode:0o700});const config={executable,sha256:createHash('sha256').update(code).digest('hex')},result=await keychainMaster({operation:'read',installationId:id},config);assert.equal(result.length,32);result.fill(0);
 const actual=JSON.parse(await readFile(capture,'utf8'));assert.deepEqual(actual.request,{version:1,operation:'read',installationId:id});assert.deepEqual(actual.args,[]);assert.ok(!actual.envKeys.includes(production.MASTER_KEY_ENV));assert.ok(actual.envKeys.every(k=>['PATH','__CF_USER_TEXT_ENCODING'].includes(k)),'macOS may add its non-secret text-encoding marker');
 await assert.rejects(keychainMaster({operation:'read',installationId:id},{...config,sha256:'0'.repeat(64)}),fails('key_source_helper_integrity_failed'));
 const linked=join(temp,'linked-helper');await symlink(executable,linked);await assert.rejects(keychainMaster({operation:'read',installationId:id},{...config,executable:linked}),fails('key_source_symlink_rejected'));
});

test('two real child processes with different operator masters cannot both win one installation; only the original winner restarts',async()=>{
 const childFile=join(temp,'operator-race-child.mjs');await writeFile(childFile,`import {loadInstallationKeys} from ${JSON.stringify(pathToFileURL(join(root,'src/account-hub/keys/src/key-source.mjs')).href)};import {createHash} from 'node:crypto';let input='';for await(const c of process.stdin)input+=c;const v=JSON.parse(input);await new Promise(r=>setTimeout(r,Math.max(0,v.startAt-Date.now())));try{const keys=await loadInstallationKeys(v.path,{source:'operator-env',allowCreate:v.create,environment:{NULUNO_ACCESS_MASTER_KEY:v.master}});process.stdout.write(JSON.stringify({ok:true,installationId:keys.installationId,vaultDigest:createHash('sha256').update(keys.vaultKey).digest('hex')}));keys.destroy();}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code}));}`);
 const run=input=>new Promise((resolve,reject)=>{const child=spawn(process.execPath,[childFile],{stdio:['pipe','pipe','pipe']}),chunks=[];let bytes=0;child.stdout.on('data',c=>{bytes+=c.length;if(bytes>4096){child.kill();reject(Error('race response overflow'));}else chunks.push(c);});child.on('error',reject);child.on('close',code=>{if(code!==0)return reject(Error('race child failed'));try{resolve(JSON.parse(Buffer.concat(chunks).toString()));}catch(e){reject(e);}});child.stdin.end(JSON.stringify(input));});
 for(let count=0;count<12;count++){
  const path=state(),masters=[env()[production.MASTER_KEY_ENV],env()[production.MASTER_KEY_ENV]],startAt=Date.now()+150;
  const results=await Promise.all(masters.map(master=>run({path,master,create:true,startAt}))),winners=results.flatMap((r,i)=>r.ok?[i]:[]);
  assert.equal(winners.length,1,'exactly one distinct master may commit and receive keys');const winner=winners[0],m=await metadata(path);
  const restart=await run({path,master:masters[winner],create:false,startAt:0});assert.equal(restart.ok,true);assert.equal(restart.installationId,m.installationId);assert.equal(restart.vaultDigest,results[winner].vaultDigest);
  const denied=await run({path,master:masters[1-winner],create:false,startAt:0});assert.equal(denied.ok,false);assert.equal(denied.code,'key_source_original_master_changed');
 }
});

test('instrumented executable overlong stdout and missing-item exit fail closed without returning partial material',async()=>{
 if(process.platform!=='darwin')return;
 for(const [suffix,body,code] of [['long',"process.stdout.write(Buffer.alloc(33,120));",'key_source_helper_protocol_rejected'],['missing',"process.exit(21);",'key_source_key_missing']]){
  const executable=join(temp,'instrumented-'+suffix),source='#!'+process.execPath+'\n'+body;await writeFile(executable,source,{mode:0o700});await assert.rejects(keychainMaster({operation:'read',installationId:randomUUID()},{executable,sha256:createHash('sha256').update(source).digest('hex')}),fails(code));
 }
});
