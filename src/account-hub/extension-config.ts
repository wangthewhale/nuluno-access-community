// SPDX-License-Identifier: Apache-2.0
import {readFileSync,realpathSync,statSync} from 'node:fs';
import {createRequire} from 'node:module';
import {resolve,dirname,join,parse} from 'node:path';
import {loadAccessExtensions,parseAccessExtensionConfigs} from '../extensions/registry';
import type {ExtensionContext,ExtensionRuntime,InstalledExtension} from '../service';
import {ACCESS_VERSION} from '../version';

/** Trusted installer configuration only; never derive an extension path,
 * module, version, digest or client configuration from an agent request. */
export async function loadHubExtensions(configPath?:string,environment:Record<string,string|undefined>=process.env){
 if(!configPath)return {extensions:[] as readonly InstalledExtension[],googleClientConfigured:false};
 const path=resolve(configPath);if(!statSync(path).isFile()||statSync(path).size>65536)throw Error('hub_extension_configuration_invalid');
 const raw=JSON.parse(readFileSync(path,'utf8')),configs=parseAccessExtensionConfigs(raw),require=createRequire(path);
 for(const config of configs){
  if(config.module!=='@nuluno/access-commercial-extension')continue;
  let current=dirname(realpathSync(require.resolve(config.module))),found=false;
  for(let depth=0;depth<24;depth++){
   try{const p=join(current,'package.json'),s=statSync(p);if(!s.isFile()||s.size>65536)throw Error('hub_extension_configuration_invalid');const pkg=JSON.parse(readFileSync(p,'utf8'));if(pkg.name!==config.module||pkg.version!==config.version||pkg.peerDependencies?.['@nuluno/access-community']!==ACCESS_VERSION)throw Error('hub_extension_core_version_incompatible');found=true;break;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
   if(current===parse(current).root)break;current=dirname(current);
  }
  if(!found)throw Error('hub_extension_package_unavailable');
 }
 const extensions=await loadAccessExtensions<ExtensionContext,ExtensionRuntime>(raw,{resolveFrom:path});
 const googleClientConfigured=Boolean(extensions.some(extension=>extension.module==='@nuluno/access-commercial-extension'&&extension.providers.some(provider=>provider.provider==='gmail'))&&environment.NULUNO_ACCESS_COMMERCIAL_GOOGLE_CLIENT_ID&&environment.NULUNO_ACCESS_COMMERCIAL_GOOGLE_CLIENT_SECRET);
 return {extensions,googleClientConfigured};
}
