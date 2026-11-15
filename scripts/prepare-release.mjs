/** Build exact-HEAD community artifacts. No registry/GitHub release or deployment. */
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync,readdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve,posix} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const top=new Set(['README.md','LICENSE','NOTICE','THIRD_PARTY.md','SECURITY.md','CONTRIBUTING.md','package.json','package-lock.json','Dockerfile','compose.yaml','tsconfig.json','tsconfig.build.json','.gitignore','.dockerignore','.env.example']);
const dirs=new Set(['.github','src','tests','scripts','docs','evidence','examples']);
const forbidden=new Set(['.git','.private','private','node_modules','state','credentials','commercial-extension']);
const hash=data=>createHash('sha256').update(data).digest('hex');
const git=(...args)=>execFileSync('git',args,{cwd:root});
export function safePath(name){
 const parts=name.split('/');
 if(!name||name.startsWith('/')||name.includes('\\')||parts.some(p=>!p||p==='.'||p==='..'||forbidden.has(p)))throw Error('unsafe_release_path');
 const base=posix.basename(name);
 if((base.startsWith('.env')&&base!=='.env.example')||['credentials.json','authorization.json','service.json','.npmrc'].includes(base)||/\.(?:sqlite.*|db(?:-.*)?|log|tgz|zip)$/.test(base))throw Error('private_or_generated_release_file');
 if(!dirs.has(parts[0])&&!top.has(name))throw Error('unreviewed_release_root');
 if(parts[0]==='examples'&&!['examples/public-status/README.md','examples/public-status/read-once.mjs'].includes(name))throw Error('unreviewed_example_path');
 if(name.startsWith('src/providers/')&&name!=='src/providers/mastodon.ts')throw Error('noncommunity_provider_forbidden');
 if(name.startsWith('src/extensions/')&&name!=='src/extensions/registry.ts')throw Error('noncommunity_extension_forbidden');
 return name;
}
export function validatePackage(pkg,expected='',tag=''){
 if(pkg.name!=='@nuluno/access-community'||pkg.license!=='Apache-2.0'||typeof pkg.version!=='string'||!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(pkg.version))throw Error('invalid_community_package_identity');
 if(JSON.stringify(pkg.bin)!==JSON.stringify({'nuluno-access-community':'dist/server.mjs'}))throw Error('legacy_binary_overwrite');
 if([...Object.keys({...pkg.dependencies,...pkg.optionalDependencies,...pkg.devDependencies,...pkg.peerDependencies}),...(pkg.bundledDependencies??[])].some(name=>name.includes('access-commercial-extension')))throw Error('commercial_dependency_forbidden');
 if(expected&&expected!==pkg.version)throw Error('requested_version_mismatch');
 if(tag&&tag!=='access-community-v'+pkg.version)throw Error('tag_version_mismatch');
 return pkg.version;
}
export function collectSource(){
 const commit=git('rev-parse','HEAD').toString().trim(),files=new Map();let total=0;
 for(const entry of git('ls-tree','-r','-z','HEAD').toString().split('\0').filter(Boolean)){
  const split=entry.indexOf('\t'),[mode,type,sha]=entry.slice(0,split).split(' '),name=safePath(entry.slice(split+1));
  if(type!=='blob'||!['100644','100755'].includes(mode))throw Error('source_links_or_submodules_forbidden');
  const data=git('cat-file','blob',sha);total+=data.length;
  if(data.length>8*1024*1024||total>64*1024*1024)throw Error('source_size_limit');
  if(/sk_(?:live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{32,}|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\s+[A-Za-z0-9+/=\r\n]{32,}-----END (?:RSA |EC )?PRIVATE KEY-----/.test(data.toString()))throw Error('possible_credential_in_source');
  files.set(name,data);
 }
 if(!files.size||files.size>5000)throw Error('source_inventory_limit');
 return {commit,files};
}
export async function prepare(output,expected=''){
 const {commit,files}=collectSource(),pkg=JSON.parse(files.get('package.json').toString());
 const version=validatePackage(pkg,expected,process.env.GITHUB_REF_TYPE==='tag'?process.env.GITHUB_REF_NAME:'');
 if(!files.get('src/version.ts').toString().includes("ACCESS_VERSION='"+version+"'"))throw Error('runtime_package_version_mismatch');
 output=resolve(output);mkdirSync(output,{recursive:true});if(readdirSync(output).length)throw Error('output_must_be_empty');
 const temporary=mkdtempSync(join(tmpdir(),'nuluno-access-release-'));const source=join(temporary,'source');mkdirSync(source);
 try{
  for(const [name,data]of files){const destination=join(source,name);mkdirSync(dirname(destination),{recursive:true});writeFileSync(destination,data);}
  const userConfig=join(temporary,'user.npmrc'),globalConfig=join(temporary,'global.npmrc');writeFileSync(userConfig,'');writeFileSync(globalConfig,'');
  const env=Object.fromEntries(['PATH','SYSTEMROOT','LANG','LC_ALL','TMPDIR','SSL_CERT_FILE','SSL_CERT_DIR'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]));
  Object.assign(env,{NPM_CONFIG_USERCONFIG:userConfig,NPM_CONFIG_GLOBALCONFIG:globalConfig,NPM_CONFIG_CACHE:join(temporary,'npm-cache')});
  const npm=(...args)=>execFileSync(process.platform==='win32'?'npm.cmd':'npm',args,{cwd:source,env,stdio:['ignore','pipe','pipe'],timeout:180000});
  npm('ci','--ignore-scripts','--no-audit','--no-fund');npm('run','build');
  const packed=JSON.parse(npm('pack','--ignore-scripts','--json','--pack-destination',temporary).toString())[0];
  if(packed.name!==pkg.name||packed.version!==version||packed.filename!=='nuluno-access-community-'+version+'.tgz')throw Error('packed_identity_mismatch');
  const names=packed.files.map(file=>file.path);
  for(const name of names){
   const base=posix.basename(name);
   if(base.startsWith('.env')||['credentials.json','authorization.json','service.json','.npmrc'].includes(base)||/\.(?:sqlite.*|db(?:-.*)?|log)$/.test(base))throw Error('private_file_in_packed_payload');
   if(name.startsWith('dist/')){
    if(name.includes('..')||name.includes('\\')||name.split('/').some(p=>forbidden.has(p))||name.includes('/providers/')&&!/\/mastodon\./.test(name)||name.includes('/extensions/')&&!/\/registry\./.test(name))throw Error('restricted_compiled_payload');
   }else safePath(name);
  }
  for(const required of ['LICENSE','NOTICE','dist/server.mjs','dist/core/client.mjs','scripts/demo-public-read.mjs','scripts/mcp-stdio-bridge.mjs'])if(!names.includes(required))throw Error('incomplete_community_package');
  const archive=join(temporary,packed.filename);
  const actualNames=execFileSync('tar',['-tzf',archive],{encoding:'utf8'}).trim().split('\n').filter(n=>!n.endsWith('/')).map(n=>{if(!n.startsWith('package/'))throw Error('invalid_tar_root');return n.slice(8);});
  if(JSON.stringify(actualNames.slice().sort())!==JSON.stringify(names.slice().sort()))throw Error('pack_inventory_mismatch');
  const native=JSON.parse(execFileSync('tar',['-xOf',archive,'package/package.json'],{encoding:'utf8'}));validatePackage(native,version);
  writeFileSync(join(output,packed.filename),readFileSync(archive),{flag:'wx'});
  const sourceName='nuluno-access-community-'+version+'-source.zip';
  git('archive','--format=zip','--prefix=nuluno-access-community-'+version+'/','--output='+join(output,sourceName),'HEAD');
  const artifacts=Object.fromEntries([packed.filename,sourceName].map(name=>{const data=readFileSync(join(output,name));return [name,{sha256:hash(data),bytes:data.length}];}));
  const manifest={schema:'nuluno-access-release-readiness-v1',name:pkg.name,version,sourceCommit:commit,sourceFiles:files.size,packageFiles:names.length,artifacts,commercialExtensionIncluded:false,publishedToNpm:false,publishedRelease:false,signedAttestation:false,modelCalls:0,providerCalls:0};
  const body=JSON.stringify(manifest,null,2)+'\n';writeFileSync(join(output,'release-manifest.json'),body,{flag:'wx'});
  const sums={...artifacts,'release-manifest.json':{sha256:hash(body)}};writeFileSync(join(output,'SHA256SUMS'),Object.entries(sums).sort().map(([name,value])=>value.sha256+'  '+name+'\n').join(''),{flag:'wx'});
  return manifest;
 }finally{rmSync(temporary,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const {values}=parseArgs({options:{output:{type:'string'},version:{type:'string',default:''}}});
 if(!values.output)throw Error('output_required');
 prepare(values.output,values.version).then(result=>process.stdout.write(JSON.stringify(result,null,2)+'\n')).catch(error=>{process.stderr.write(JSON.stringify({prepared:false,error:error?.status?'release_build_failed':String(error.message).slice(0,100)})+'\n');process.exitCode=1;});
}
