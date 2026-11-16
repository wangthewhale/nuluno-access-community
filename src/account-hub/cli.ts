// SPDX-License-Identifier: Apache-2.0
import {mkdir,open,readFile} from 'node:fs/promises';
import {realpathSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {homedir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createAccountHub,startAccountHub} from './server';
import {loadHubExtensions} from './extension-config';
// External at bundle time: source-relative native paths remain intact.
import {loadInstallationKeys,type InstallationKeys} from './keys/src/key-source.mjs';

export async function main(argv=process.argv.slice(2)){
 const args=[...argv],command=args[0]&&!args[0].startsWith('--')?args.shift()!:'serve';
 if(!['serve','pair'].includes(command))throw Error('hub_invalid_command');
 const flags:Record<string,string>={};while(args.length){const name=args.shift()!,value=args.shift();if(!['--state','--port','--origin','--pairing-file','--extensions','--key-source'].includes(name)||!value||value.startsWith('--')||flags[name]!==undefined)throw Error('hub_invalid_arguments');flags[name]=value;}
 if(!flags['--pairing-file']&&!process.stderr.isTTY)throw Error('hub_private_activation_output_required');
 const stateDirectory=resolve(flags['--state']??join(homedir(),'.local/share/nuluno/access-hub')),port=Number(flags['--port']??18995);
 if(!Number.isInteger(port)||port<1024||port>65535)throw Error('hub_invalid_port');
 const origin=flags['--origin']??'http://127.0.0.1:'+port,source=flags['--key-source']??process.env.NULUNO_ACCESS_KEY_SOURCE;
 if(source!==undefined&&!['operator-env','macos-file-keychain'].includes(source))throw Error('hub_invalid_key_source');
 const extensionSetup=await loadHubExtensions(flags['--extensions']??process.env.NULUNO_ACCESS_EXTENSIONS_CONFIG),rootDirectory=resolve(import.meta.dirname,'../..');let loaded:InstallationKeys|undefined;
 const keySource=async()=>{
  if(loaded)return loaded;
  const options={...(source?{source:source as 'operator-env'|'macos-file-keychain'}:{}),allowCreate:command==='serve'};
  try{loaded=await loadInstallationKeys(stateDirectory,options);}catch(error){if((error as {code?:string}).code!=='key_source_pinned_helper_required'||process.platform!=='darwin'||source==='operator-env')throw error;
   const builder=fileURLToPath(new URL('./keys/native/build-helper.mjs',import.meta.url)),result=spawnSync(process.execPath,[builder],{stdio:['ignore','pipe','pipe'],timeout:120000});if(result.status!==0)throw Error('hub_apple_command_line_tools_required');loaded=await loadInstallationKeys(stateDirectory,options);
  }return loaded!;
 };
 const options={rootDirectory,stateDirectory,origin,keySource,...extensionSetup};
 const hub=command==='serve'?await startAccountHub(options):await createAccountHub(options);
 try{
  const activation=await hub.issuePairing();
  if(flags['--pairing-file']){const path=resolve(flags['--pairing-file']);await mkdir(dirname(path),{recursive:true,mode:0o700});const file=await open(path,'wx',0o600);try{await file.writeFile(JSON.stringify({schema:'nuluno-hub-private-activation-v1',url:activation.activationUrl,expiresAt:activation.expiresAt})+'\n');await file.sync();}finally{await file.close();}process.stderr.write('Private activation link saved to the owner-selected file. It expires in five minutes.\n');}
  else process.stderr.write('Open privately; do not share this one-use link:\n'+activation.activationUrl+'\n');
  if(command==='pair'){hub.close();loaded?.destroy();return;}
  process.stderr.write('Nuluno Access Hub: '+origin+'/account-hub\n');
  const stop=()=>{(hub as Awaited<ReturnType<typeof startAccountHub>>).server.close(()=>{hub.close();loaded?.destroy();process.exit(0);});};process.on('SIGTERM',stop);process.on('SIGINT',stop);
 }catch(error){if('server'in hub)await new Promise<void>(resolve=>(hub as Awaited<ReturnType<typeof startAccountHub>>).server.close(()=>resolve()));hub.close();loaded?.destroy();throw error;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(realpathSync(process.argv[1])).href)main().catch(error=>{const code=typeof error?.code==='string'?error.code:typeof error?.message==='string'&&/^(?:hub_|key_source_)[a-z_]+$/.test(error.message)?error.message:'hub_startup_rejected';process.stderr.write('Nuluno Access Hub could not start: '+code+'\n');if(code==='hub_apple_command_line_tools_required')process.stderr.write('Install Apple Command Line Tools to build the dedicated local helper, or explicitly configure operator-env. No plaintext fallback is used.\n');process.exitCode=1;});
