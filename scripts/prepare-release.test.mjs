import {test} from 'node:test';
import assert from 'node:assert/strict';
import {safePath,validatePackage} from './prepare-release.mjs';
const pkg={name:'@nuluno/access-community',version:'0.1.0-alpha.1',license:'Apache-2.0',bin:{'nuluno-access-community':'dist/server.mjs'},dependencies:{express:'^5'}};
test('private files, traversal and commercial provider implementation cannot enter release',()=>{
 for(const path of ['../outside','/absolute','src\\private.ts','state/access.sqlite','docs/.env','src/providers/gmail.ts','src/extensions/gmail.ts','private/key.json'])assert.throws(()=>safePath(path));
 assert.equal(safePath('src/providers/mastodon.ts'),'src/providers/mastodon.ts');assert.equal(safePath('src/extensions/registry.ts'),'src/extensions/registry.ts');
});
test('package and binary identity cannot overwrite commercial Access',()=>{
 assert.equal(validatePackage(pkg),'0.1.0-alpha.1');
 assert.throws(()=>validatePackage({...pkg,name:'@nuluno/access'}));assert.throws(()=>validatePackage({...pkg,bin:{'nuluno-access':'dist/server.mjs'}}));
 assert.throws(()=>validatePackage({...pkg,dependencies:{'@nuluno/access-commercial-extension':'1.0.0'}}));
 assert.throws(()=>validatePackage({...pkg,devDependencies:{'@nuluno/access-commercial-extension':'1.0.0'}}));
});
test('manual version and existing tag must match source, without bumping it',()=>{
 assert.equal(validatePackage(pkg,pkg.version,'access-community-v'+pkg.version),pkg.version);
 assert.throws(()=>validatePackage(pkg,'1.0.0'));assert.throws(()=>validatePackage(pkg,pkg.version,'access-community-v1.0.0'));
});
