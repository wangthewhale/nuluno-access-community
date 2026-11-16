/** Compile only; never invoke SecItem or open/read/create a keychain item. */
import {execFileSync} from 'node:child_process';
import {readFile,mkdir,writeFile,chmod} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const hash=b=>createHash('sha256').update(b).digest('hex');
if(process.platform!=='darwin')throw Error('macos_build_required');
const source=fileURLToPath(new URL('./NulunoKeychain.swift',import.meta.url)),binary=fileURLToPath(new URL('./bin/nuluno-keychain-helper',import.meta.url));
await mkdir(fileURLToPath(new URL('./bin/',import.meta.url)),{recursive:true});
execFileSync('/usr/bin/swiftc',['-O',source,'-o',binary],{stdio:['ignore','pipe','pipe'],timeout:120000});
await chmod(binary,0o755);
const manifest={schema:'nuluno-macos-file-keychain-helper-v1',sha256:hash(await readFile(binary)),sourceSha256:hash(await readFile(source))};
const manifestPath=fileURLToPath(new URL('./helper-manifest.json',import.meta.url));
await writeFile(manifestPath,JSON.stringify(manifest,null,2)+'\n',{mode:0o644});await chmod(manifestPath,0o644);
console.log(JSON.stringify({...manifest,compiled:true,executed:false,keychainOperations:0}));
