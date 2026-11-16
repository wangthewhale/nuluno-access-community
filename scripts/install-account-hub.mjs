#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import {existsSync} from 'node:fs';
import {resolve} from 'node:path';
import {spawn} from 'node:child_process';
if(Number(process.versions.node.split('.')[0])<24){process.stderr.write('Nuluno Access Hub requires Node 24 or newer.\n');process.exit(1);}
const entry=resolve(import.meta.dirname,'../dist/account-hub/cli.mjs');if(!existsSync(entry)){process.stderr.write('First run npm ci (or npm run build), then run this installer again.\n');process.exit(1);}
const child=spawn(process.execPath,[entry,...process.argv.slice(2)],{stdio:'inherit',env:process.env});child.on('exit',code=>{process.exitCode=code??1;});child.on('error',()=>{process.stderr.write('Hub installer could not start the local service.\n');process.exitCode=1;});
