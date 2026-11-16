// SPDX-License-Identifier: Apache-2.0
import type {Express, Request, Response, RequestHandler} from 'express';
import type {NulunoAccessBroker} from '../core/broker';
import {accessDigest, type StandaloneRepository} from '../core/repository';
import {AccessError, type AccessGrant, type AccessSafeGrant, type AccessScope} from '../core/types';

const PRESET = 'public-read' as const;
const LIFETIME = 60 * 60 * 1000;
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
type TokenRow = {tenant_id:string; request_key:string; grant_id:string; request_hash:string; encrypted:string; expires_at:number};
type Handler = (req: Request, res: Response) => Promise<unknown>;
type HubOwner = {tenant_id:string};

function bodyWith(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function safeGrant(grant: AccessGrant): AccessSafeGrant {
  const {tokenHash: _secret, ...safe} = grant;
  return structuredClone(safe);
}
function sameScope(left: AccessScope, right: AccessScope) {
  return left.workspaceId === right.workspaceId && left.ownerId === right.ownerId && left.missionId === right.missionId;
}
function storedGrant(row: TokenRow, scope: AccessScope, grant: AccessGrant | undefined): AccessSafeGrant {
  // A hub row is an index, never independent authority to another tenant's key.
  if (!grant || row.tenant_id !== scope.workspaceId || row.grant_id !== grant.id || !sameScope(grant, scope) || grant.expiresAt !== row.expires_at || grant.managed !== false || grant.maxTasks !== 25 || grant.rules.length !== 1) throw new AccessError('access_scope_denied');
  const rule = grant.rules[0];
  if (rule.provider !== 'mastodon' || rule.actions.length !== 1 || rule.actions[0] !== 'read_public_status' || rule.accountIds.length !== 1 || rule.accountIds[0] !== 'public:mastodon.social' || rule.writeLimit !== 0) throw new AccessError('access_scope_denied');
  return safeGrant(grant);
}
function tokenContext(row: Pick<TokenRow,'tenant_id'|'request_key'|'grant_id'>) {
  return 'hub-agent:' + row.tenant_id + ':' + row.request_key + ':' + row.grant_id;
}

/** Owner-only public-read grants. Secrets are sealed separately from automatic
 * managed keys and decrypted only by an explicit, CSRF-protected download. */
export function mountHubAgentAccess(options: {
  app: Express;
  repo: StandaloneRepository;
  broker: NulunoAccessBroker;
  requireOwner: (req: Request, mutation?: boolean) => HubOwner;
  handle: (handler: Handler) => RequestHandler;
  origin: string;
  clock?: () => number;
}) {
  const {app, repo, broker, requireOwner, handle} = options, now = options.clock ?? Date.now;
  const base = new URL(options.origin);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.pathname !== '/' || base.search || base.hash) throw Error('invalid_hub_origin');
  const mcpUrl = base.origin + '/mcp';
  repo.db.exec(`CREATE TABLE IF NOT EXISTS hub_agent_tokens(
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    request_key TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    encrypted TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(tenant_id,request_key),
    UNIQUE(tenant_id,grant_id)
  )`);
  const saved = async (tenant: string, id: string) => {
    const scope = await repo.tenant(tenant);
    const row = repo.db.prepare('SELECT * FROM hub_agent_tokens WHERE tenant_id=? AND grant_id=?').get(scope.workspaceId, id) as TokenRow | undefined;
    if (!row) throw new AccessError('access_scope_denied');
    const grant = storedGrant(row, scope, (await repo.read(scope)).grants[row.grant_id]);
    return {scope, row, grant};
  };
  const noStore = (res: Response) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
  };

  app.get('/hub-api/agents', handle(async (req, res) => {
    const owner = requireOwner(req);
    const agents = await repo.atomic(async () => {
      const scope = await repo.tenant(owner.tenant_id), state = await repo.read(scope);
      const rows = repo.db.prepare('SELECT * FROM hub_agent_tokens WHERE tenant_id=? ORDER BY rowid DESC LIMIT 50').all(scope.workspaceId) as TokenRow[];
      return rows.map(row => {
        const grant = storedGrant(row, scope, state.grants[row.grant_id]);
        return {preset: PRESET, grant, connectionAvailable: grant.revokedAt === null && grant.expiresAt > now() && row.encrypted !== ''};
      });
    });
    noStore(res);
    return res.json({agents});
  }));

  app.post('/hub-api/agents', handle(async (req, res) => {
    const owner = requireOwner(req, true), body: unknown = req.body;
    if (!bodyWith(body, ['requestKey', 'preset']) || !uuid(body.requestKey) || typeof body.preset !== 'string' || body.preset.length > 100) throw new AccessError('access_invalid_input');
    const requestKey = body.requestKey.toLowerCase(), requestHash = accessDigest({preset: body.preset});
    const result = await repo.atomic(async () => {
      const scope = await repo.tenant(owner.tenant_id);
      const old = repo.db.prepare('SELECT * FROM hub_agent_tokens WHERE tenant_id=? AND request_key=?').get(scope.workspaceId, requestKey) as TokenRow | undefined;
      if (old) {
        if (old.request_hash !== requestHash) throw new AccessError('access_idempotency_conflict');
        return {preset: PRESET, grant: storedGrant(old, scope, (await repo.read(scope)).grants[old.grant_id])};
      }
      if (body.preset !== PRESET) throw new AccessError('access_invalid_input');
      const expiresAt = now() + LIFETIME;
      const issued = await broker.issue(scope, {label: '公開唯讀 Agent', managed: false, expiresAt, maxTasks: 25, rules: [{provider: 'mastodon', actions: ['read_public_status'], accountIds: ['public:mastodon.social'], writeLimit: 0}]});
      const row = {tenant_id: scope.workspaceId, request_key: requestKey, grant_id: issued.grant.id};
      const encrypted = JSON.stringify(repo.vault.encrypt(issued.key, tokenContext(row)));
      repo.db.prepare('INSERT INTO hub_agent_tokens(tenant_id,request_key,grant_id,request_hash,encrypted,expires_at) VALUES(?,?,?,?,?,?)').run(scope.workspaceId, requestKey, issued.grant.id, requestHash, encrypted, issued.grant.expiresAt);
      return {preset: PRESET, grant: issued.grant};
    });
    noStore(res);
    return res.json(result);
  }));

  app.post('/hub-api/agents/:id/connection', handle(async (req, res) => {
    const owner = requireOwner(req, true);
    if (!uuid(req.params.id) || !bodyWith(req.body, ['client']) || req.body.client !== 'mcp-http') throw new AccessError('access_invalid_input');
    const id = req.params.id.toLowerCase();
    const result = await repo.atomic(async () => {
      const {scope, row, grant} = await saved(owner.tenant_id, id);
      if (grant.revokedAt !== null) throw new AccessError('access_revoked');
      if (grant.expiresAt <= now()) throw new AccessError('access_expired');
      if (!row.encrypted) throw new AccessError('access_invalid_key');
      const key = repo.vault.decrypt(JSON.parse(row.encrypted), tokenContext(row));
      const principal = await broker.authenticate(key);
      if (principal.keyId !== grant.id || !sameScope(principal, scope)) throw new AccessError('access_scope_denied');
      // Transport-neutral MCP HTTP connection data; no claim of a universal
      // Codex/Claude configuration-file schema is made here.
      return {fileName: 'nuluno-public-read-mcp.json', contentType: 'application/json', configuration: {transport: 'streamable-http', url: mcpUrl, headers: {Authorization: 'Bearer ' + key}}};
    });
    noStore(res);
    return res.json(result);
  }));

  app.post('/hub-api/agents/:id/revoke', handle(async (req, res) => {
    const owner = requireOwner(req, true);
    if (!uuid(req.params.id) || !bodyWith(req.body, [])) throw new AccessError('access_invalid_input');
    const id = req.params.id.toLowerCase();
    const result = await repo.atomic(async () => {
      const {scope, row} = await saved(owner.tenant_id, id);
      const grant = await broker.revoke(scope, row.grant_id);
      repo.db.prepare("UPDATE hub_agent_tokens SET encrypted='' WHERE tenant_id=? AND grant_id=?").run(scope.workspaceId, row.grant_id);
      return {revoked: true, preset: PRESET, grant};
    });
    noStore(res);
    return res.json(result);
  }));
}
