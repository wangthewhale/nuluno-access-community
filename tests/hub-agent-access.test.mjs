// SPDX-License-Identifier: Apache-2.0
// Controlled component fixtures: real Express, SQLite, vault and broker; no
// provider OAuth, real-account use or external provider reads/writes.
import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, rm, symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes, randomUUID} from 'node:crypto';
import {createServer} from 'node:http';
import express from 'express';
import {build} from 'esbuild';

const root = resolve(import.meta.dirname, '..'), temp = await mkdtemp(join(tmpdir(), 'nuluno-hub-agent-'));
await symlink(join(root, 'node_modules'), join(temp, 'node_modules'), 'dir');
const bundle = join(temp, 'component.mjs');
await build({stdin:{contents: `export {mountHubAgentAccess} from './src/account-hub/agent-access'; export {StandaloneRepository} from './src/core/repository'; export {CredentialVault} from './src/core/vault'; export {VaultAccessTokenCodec} from './src/core/token-codec'; export {NulunoAccessBroker} from './src/core/broker'; export {AccessError} from './src/core/types';`, resolveDir:root, loader:'ts'}, outfile:bundle, bundle:true, platform:'node', format:'esm', packages:'external', logLevel:'silent'});
const {mountHubAgentAccess, StandaloneRepository, CredentialVault, VaultAccessTokenCodec, NulunoAccessBroker, AccessError} = await import(pathToFileURL(bundle).href);
const realFetch = globalThis.fetch;
let externalCalls = 0;
globalThis.fetch = async (input, init) => {
  const url = new URL(String(input));
  if (!['localhost', '127.0.0.1'].includes(url.hostname)) {externalCalls++; throw Error('external_network_forbidden_in_component_fixture');}
  return realFetch(input, init);
};
after(async () => {globalThis.fetch = realFetch; assert.equal(externalCalls, 0); await rm(temp, {recursive:true, force:true});});

async function fixture() {
  const path = join(temp, randomUUID(), 'access.sqlite'), vaultKey = randomBytes(32).toString('hex'), csrf = randomBytes(32).toString('hex');
  let time = Date.now(), repo, broker, server, origin, tenants;
  const clock = () => time;
  const sessions = new Map();
  async function start() {
    const vault = new CredentialVault(vaultKey);
    repo = new StandaloneRepository(path, vault);
    broker = new NulunoAccessBroker({repository:repo, tokenCodec:new VaultAccessTokenCodec(vault, vaultKey), clock, policy:{isReadOnly:(provider, action) => provider === 'mastodon' && action === 'read_public_status', check:async () => {}}});
    if (!tenants) {
      tenants = [await repo.createTenant('Fixture A'), await repo.createTenant('Fixture B')];
      sessions.set('owner=a', {tenant_id:tenants[0].tenantId}); sessions.set('owner=b', {tenant_id:tenants[1].tenantId});
    }
    const app = express(); app.disable('x-powered-by'); app.use(express.json({limit:8192}));
    server = createServer(app);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    origin = 'http://127.0.0.1:' + server.address().port;
    // The host injects its owner/CSRF boundary. These controlled sessions cover
    // two tenants without introducing a provider or a production login bypass.
    const requireOwner = (req, mutation = false) => {
      const owner = sessions.get(req.header('cookie'));
      if (!owner) throw new AccessError('access_invalid_key');
      if (mutation && (req.header('origin') !== origin || req.header('x-hub-csrf') !== csrf)) throw new AccessError('access_scope_denied');
      return owner;
    };
    const handle = fn => async (req, res) => {try {await fn(req, res);} catch (error) {res.status(error instanceof AccessError ? error.status : 500).json({error:error instanceof AccessError ? error.code : 'fixture_internal'});}};
    mountHubAgentAccess({app, repo, broker, requireOwner, handle, origin, clock});
  }
  async function stop() {server.closeAllConnections?.(); await new Promise(resolve => server.close(resolve)); repo.close();}
  await start();
  const call = async (route, body, {owner='a', csrfValue=csrf, requestOrigin=origin, method=body === undefined ? 'GET' : 'POST'} = {}) => {
    const response = await realFetch(origin + route, {method, headers:{connection:'close', ...(owner ? {cookie:'owner=' + owner} : {}), ...(method === 'POST' ? {'content-type':'application/json', origin:requestOrigin, 'x-hub-csrf':csrfValue} : {})}, ...(body === undefined ? {} : {body:JSON.stringify(body)}), redirect:'error'});
    return {status:response.status, headers:response.headers, value:response.headers.get('content-type')?.includes('application/json') ? await response.json() : await response.text()};
  };
  const create = async (requestKey = randomUUID(), options) => {const result = await call('/hub-api/agents', {requestKey, preset:'public-read'}, options); assert.equal(result.status, 200); return {...result.value, requestKey};};
  const download = (id, options) => call('/hub-api/agents/' + id + '/connection', {client:'mcp-http'}, options);
  return {call, create, download, csrf, tenants, get repo(){return repo;}, get broker(){return broker;}, get origin(){return origin;}, get time(){return time;}, advance:ms => {time += ms;}, restart:async () => {await stop(); await start();}, close:stop};
}
const count = (f, table) => f.repo.db.prepare('SELECT count(*) AS n FROM ' + table).get().n;
const keyFrom = reply => reply.value.configuration.headers.Authorization.slice('Bearer '.length);
const noSecretMetadata = value => assert.doesNotMatch(JSON.stringify(value), /tokenHash|encrypted|Authorization|Bearer |accessToken|refreshToken|CONTROLLED_PROVIDER_CREDENTIAL/);

test('owner creation is CSRF protected, fixed to a bounded public read, concurrent idempotent, and exposes only metadata', async () => {
  const f = await fixture();
  try {
    assert.equal((await f.call('/hub-api/agents', undefined, {owner:''})).status, 401);
    const requestKey = randomUUID();
    for (const options of [{owner:''}, {csrfValue:'wrong'}, {requestOrigin:'https://evil.example'}]) assert.ok([401,403].includes((await f.call('/hub-api/agents', {requestKey, preset:'public-read'}, options)).status));
    assert.equal(count(f, 'hub_agent_tokens'), 0);
    const results = await Promise.all(Array.from({length:8}, () => f.create(requestKey)));
    assert.equal(new Set(results.map(result => result.grant.id)).size, 1);
    assert.equal(count(f, 'hub_agent_tokens'), 1);
    const {grant} = results[0];
    assert.deepEqual(grant.rules, [{provider:'mastodon', actions:['read_public_status'], accountIds:['public:mastodon.social'], writeLimit:0}]);
    assert.equal(grant.managed, false); assert.equal(grant.maxTasks, 25); assert.equal(grant.expiresAt, f.time + 3600000);
    assert.equal(count(f, 'managed'), 0); noSecretMetadata(results);
    assert.equal((await f.call('/hub-api/agents', {requestKey, preset:'write'})).status, 409);
    for (const body of [{requestKey:randomUUID(), preset:'write'}, {requestKey:'invalid', preset:'public-read'}, {requestKey:randomUUID(), preset:'public-read', expiresAt:f.time + 86400000}, {requestKey:randomUUID(), preset:'public-read', id:grant.id}]) assert.equal((await f.call('/hub-api/agents', body)).status, 400);
    await f.repo.setConnection(f.tenants[0].scope, {provider:'mastodon', accountId:'fixture-account', label:'Fixture', scopes:['read'], secret:{accessToken:'CONTROLLED_PROVIDER_CREDENTIAL'}, expiresAt:null});
    const decrypt = f.repo.vault.decrypt.bind(f.repo.vault); let decrypts = 0;
    f.repo.vault.decrypt = (...args) => {decrypts++; return decrypt(...args);};
    const list = await f.call('/hub-api/agents');
    assert.equal(list.value.agents.length, 1); assert.equal(list.value.agents[0].connectionAvailable, true);
    noSecretMetadata(list.value); assert.equal(decrypts, 0); assert.equal(list.headers.get('cache-control'), 'no-store');
    assert.equal((await f.call('/hub-api/agents/' + grant.id + '/connection')).status, 404);
    assert.equal(decrypts, 0);
  } finally {await f.close();}
});

test('explicit download survives SQLite restart with the same deadline/key and denies non-public actions and accounts', async () => {
  const f = await fixture();
  try {
    const created = await f.create(), id = created.grant.id;
    assert.equal((await f.download(id, {csrfValue:'wrong'})).status, 403);
    assert.equal((await f.call('/hub-api/agents/' + id + '/connection', {client:'claude'})).status, 400);
    const first = await f.download(id); assert.equal(first.status, 200);
    assert.deepEqual(Object.keys(first.value).sort(), ['configuration','contentType','fileName']);
    assert.equal(first.value.configuration.transport, 'streamable-http'); assert.equal(first.value.configuration.url, f.origin + '/mcp');
    assert.match(first.value.configuration.headers.Authorization, /^Bearer .+/); assert.equal(first.headers.get('cache-control'), 'no-store');
    const key = keyFrom(first), sealed = f.repo.db.prepare('SELECT encrypted FROM hub_agent_tokens').get().encrypted;
    assert.ok(!sealed.includes(key)); assert.equal((await f.broker.authenticate(key)).keyId, id);
    for (const input of [{provider:'gmail', action:'verify_email', accountId:'fixture-account'}, {provider:'mastodon', action:'publish_text', accountId:'public:mastodon.social'}, {provider:'mastodon', action:'read_public_status', accountId:'private-account'}]) await assert.rejects(f.broker.submit(key, {...input, idempotencyKey:randomUUID(), payload:{}}), {code:'access_rule_denied'});
    for (let i = 0; i < 25; i++) await f.broker.submit(key, {idempotencyKey:'fixture-read-' + i, provider:'mastodon', action:'read_public_status', payload:{statusId:String(i)}});
    await assert.rejects(f.broker.submit(key, {idempotencyKey:'over-limit', provider:'mastodon', action:'read_public_status', payload:{}}), {code:'access_limit_reached'});
    f.advance(120000); await f.restart();
    const repeat = await f.create(created.requestKey); assert.equal(repeat.grant.id, id); assert.equal(repeat.grant.expiresAt, created.grant.expiresAt);
    const second = await f.download(id); assert.equal(second.status, 200); assert.equal(keyFrom(second), key);
    assert.equal(count(f, 'hub_agent_tokens'), 1); assert.equal(count(f, 'managed'), 0);
    noSecretMetadata((await f.call('/hub-api/agents')).value);
  } finally {await f.close();}
});

test('expiry denies downloads and idempotent create never renews the grant', async () => {
  const f = await fixture();
  try {
    const created = await f.create(), id = created.grant.id, key = keyFrom(await f.download(id));
    f.advance(3600000);
    assert.equal((await f.download(id)).value.error, 'access_expired');
    await assert.rejects(f.broker.authenticate(key), {code:'access_expired'});
    const repeated = await f.create(created.requestKey); assert.equal(repeated.grant.id, id); assert.equal(repeated.grant.expiresAt, created.grant.expiresAt);
    assert.equal((await f.call('/hub-api/agents')).value.agents[0].connectionAvailable, false);
    assert.equal(count(f, 'hub_agent_tokens'), 1);
  } finally {await f.close();}
});

test('tenant scope and the stored hub grant are required for download and revocation', async () => {
  const f = await fixture();
  try {
    const created = await f.create(), id = created.grant.id;
    assert.equal((await f.call('/hub-api/agents', undefined, {owner:'b'})).value.agents.length, 0);
    assert.equal((await f.download(id, {owner:'b'})).status, 403);
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {}, {owner:'b'})).status, 403);
    const ownB = await f.create(created.requestKey, {owner:'b'}); assert.notEqual(ownB.grant.id, id);
    const orphanId = randomUUID();
    await f.repo.transact(f.tenants[0].scope, state => {state.grants[orphanId] = {...state.grants[id], id:orphanId};});
    assert.equal((await f.download(orphanId)).status, 403);
    assert.equal((await f.call('/hub-api/agents/' + orphanId + '/revoke', {})).status, 403);
    await f.repo.transact(f.tenants[0].scope, state => {state.grants[id].ownerId = f.tenants[1].scope.ownerId;});
    assert.equal((await f.download(id)).status, 403);
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {})).status, 403);
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {id:ownB.grant.id})).status, 400);
  } finally {await f.close();}
});

test('revocation retires only the sealed secret and preserves tasks and their receipt history across restart', async () => {
  const f = await fixture();
  try {
    const created = await f.create(), id = created.grant.id, key = keyFrom(await f.download(id));
    const done = await f.broker.submit(key, {idempotencyKey:'finished', provider:'mastodon', action:'read_public_status', payload:{}});
    const receipt = 'a'.repeat(64);
    await f.broker.advance(key, done.id, {provider:'mastodon', execute:async () => ({kind:'completed', evidence:{resourceId:'controlled-component-receipt', receiptHash:receipt}}), reconcile:async () => ({kind:'unknown'})});
    const pending = await f.broker.submit(key, {idempotencyKey:'pending', provider:'mastodon', action:'read_public_status', payload:{}});
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {}, {csrfValue:'wrong'})).status, 403);
    const revoked = await f.call('/hub-api/agents/' + id + '/revoke', {}); assert.equal(revoked.status, 200); assert.equal(revoked.value.revoked, true); noSecretMetadata(revoked.value);
    assert.equal(f.repo.db.prepare('SELECT encrypted FROM hub_agent_tokens WHERE grant_id=?').get(id).encrypted, '');
    assert.equal(count(f, 'managed'), 0); assert.equal((await f.download(id)).value.error, 'access_revoked');
    await assert.rejects(f.broker.authenticate(key), {code:'access_revoked'});
    const twice = await f.call('/hub-api/agents/' + id + '/revoke', {}); assert.equal(twice.value.grant.revision, revoked.value.grant.revision);
    await f.restart();
    const state = await f.repo.read(f.tenants[0].scope);
    assert.equal(state.tasks[done.id].evidence.receiptHash, receipt); assert.equal(state.tasks[done.id].status, 'succeeded'); assert.equal(state.tasks[pending.id].status, 'revoked');
    assert.equal(Object.keys(state.tasks).length, 2);
    const same = await f.create(created.requestKey); assert.equal(same.grant.id, id); assert.equal(same.grant.revokedAt, revoked.value.grant.revokedAt);
    assert.equal((await f.download(id)).status, 403); assert.equal(count(f, 'hub_agent_tokens'), 1);
  } finally {await f.close();}
});

test('issuance and revocation each roll back atomically if secret storage fails', async () => {
  const f = await fixture();
  try {
    const requestKey = randomUUID(), encrypt = f.repo.vault.encrypt.bind(f.repo.vault);
    f.repo.vault.encrypt = (value, context) => {if (context.startsWith('hub-agent:')) throw Error('controlled_sealing_failure'); return encrypt(value, context);};
    assert.equal((await f.call('/hub-api/agents', {requestKey, preset:'public-read'})).status, 500);
    assert.equal(count(f, 'hub_agent_tokens'), 0); assert.equal(Object.keys((await f.repo.read(f.tenants[0].scope)).grants).length, 0);
    f.repo.vault.encrypt = encrypt;
    const created = await f.create(requestKey), id = created.grant.id, key = keyFrom(await f.download(id));
    f.repo.db.exec("CREATE TRIGGER fixture_reject_retirement BEFORE UPDATE OF encrypted ON hub_agent_tokens BEGIN SELECT RAISE(ABORT,'controlled_retirement_failure'); END");
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {})).status, 500);
    assert.equal((await f.repo.read(f.tenants[0].scope)).grants[id].revokedAt, null); assert.equal((await f.broker.authenticate(key)).keyId, id);
    assert.notEqual(f.repo.db.prepare('SELECT encrypted FROM hub_agent_tokens').get().encrypted, '');
    f.repo.db.exec('DROP TRIGGER fixture_reject_retirement');
    assert.equal((await f.call('/hub-api/agents/' + id + '/revoke', {})).status, 200);
    assert.equal((await f.download(id)).status, 403);
  } finally {await f.close();}
});
