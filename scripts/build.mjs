// SPDX-License-Identifier: Apache-2.0
import {build} from 'esbuild';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {cp,mkdir} from 'node:fs/promises';
process.chdir(resolve(import.meta.dirname,'..'));
await build({entryPoints:{server:'src/cli.ts',app:'src/server.ts',service:'src/service.ts','core/client':'src/core/client.ts','core/types':'src/core/types.ts','extensions/registry':'src/extensions/registry.ts','host-ports':'src/host-ports.ts','account-hub/server':'src/account-hub/server.ts','account-hub/cli':'src/account-hub/cli.ts'},bundle:true,platform:'node',target:'node24',format:'esm',packages:'external',external:['./keys/src/key-source.mjs'],outdir:'dist',outExtension:{'.js':'.mjs'},banner:{js:'#!/usr/bin/env node'}});
await mkdir('dist/account-hub/keys',{recursive:true});await cp('src/account-hub/keys','dist/account-hub/keys',{recursive:true});
const result=spawnSync(process.execPath,['node_modules/typescript/bin/tsc','-p','tsconfig.build.json'],{stdio:'inherit'});if(result.status!==0)process.exit(result.status??1);
