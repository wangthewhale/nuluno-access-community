import {writeFileSync,existsSync,realpathSync,readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes} from 'node:crypto';
import {createAccessApp} from './server';
import type {InstalledExtension} from './service';
import {loadAccessExtensions} from './extensions/registry';
export {createAccessApp} from './server';
async function main(){
 if(process.argv[2]==='init'){const dest=resolve(process.argv[3]??'.env');if(existsSync(dest))throw new Error('configuration_already_exists');const values='PORT=8892\nHOST=127.0.0.1\nNULUNO_ACCESS_ORIGIN=http://localhost:8892\nNULUNO_ACCESS_STATE=./state/access.sqlite\nNULUNO_ACCESS_ADMIN_KEY='+randomBytes(32).toString('hex')+'\nNULUNO_ACCESS_VAULT_KEY='+randomBytes(32).toString('hex')+'\n';writeFileSync(dest,values,{mode:0o600,flag:'wx'});process.stderr.write('Private configuration created. Load it only in this service process; keep it out of Git.\n');return;}
 const port=Number(process.env.PORT??8892),origin=process.env.NULUNO_ACCESS_ORIGIN??'http://localhost:'+port;
 const extensionPath=process.env.NULUNO_ACCESS_EXTENSIONS_CONFIG;
 const extensions=extensionPath?await loadAccessExtensions(JSON.parse(readFileSync(extensionPath,'utf8')),{resolveFrom:resolve(extensionPath)}):[];
 const {app,service}=createAccessApp({path:process.env.NULUNO_ACCESS_STATE??'./state/access.sqlite',vaultKey:process.env.NULUNO_ACCESS_VAULT_KEY??'',adminKey:process.env.NULUNO_ACCESS_ADMIN_KEY??'',origin,extensions:extensions as readonly InstalledExtension[]});const server=app.listen(port,process.env.HOST??'127.0.0.1',()=>process.stderr.write('Nuluno Access Community listening at '+origin+'\n'));
 const stop=()=>server.close(()=>{service.close();process.exit(0);});process.on('SIGTERM',stop);process.on('SIGINT',stop);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(realpathSync(process.argv[1])).href)main().catch(()=>{process.stderr.write('Nuluno Access startup failed; check private configuration and state.\n');process.exitCode=1;});
