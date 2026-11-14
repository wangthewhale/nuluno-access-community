import express, { type Request, type Response, type RequestHandler } from 'express';
import { z } from 'zod';
import { AccessError, type AccessScope, type AccessGrantOptions, type AccessSafeGrant, type AccessSafeTask, type AccessPrincipal, type AccessSubmit, type AccessProviderAdapter } from './types';

/** Transport port. Every agent method reauthorizes the SAME opaque Access key.
 * An existing Nuluno OAuth principal is never converted into this permission.
 */
export interface AccessTransportBroker {
  issue(scope: AccessScope, options: AccessGrantOptions): Promise<{ key: string; grant: AccessSafeGrant }>;
  listOwner(scope: AccessScope): Promise<AccessSafeGrant[]>;
  revoke(scope: AccessScope, keyId: string): Promise<AccessSafeGrant>;
  authenticate(key: string): Promise<AccessPrincipal>;
  getCapabilities(key: string): Promise<{ principal: AccessPrincipal; grant: AccessSafeGrant }>;
  status(key: string): Promise<unknown>;
  getTask(key: string, taskId: string): Promise<AccessSafeTask>;
  submit(key: string, input: AccessSubmit): Promise<AccessSafeTask>;
  advance(key: string, taskId: string, adapter: AccessProviderAdapter): Promise<AccessSafeTask>;
  reconcile(key: string, taskId: string, adapter: AccessProviderAdapter): Promise<AccessSafeTask>;
  listOwnerTasks?(scope: AccessScope): Promise<AccessSafeTask[]>;
  listOwnerActiveTasks?(scope: AccessScope): Promise<AccessSafeTask[]>;
}

export type AccessConnectionView = { provider: string; connected: boolean; accountId?: string; scopes?: string[] };
export type AccessRouteDependencies = {
  broker: AccessTransportBroker;
  adapterFor(provider: string): AccessProviderAdapter | undefined;
  origin: string;
  /** Resolves cookie/session and verifies the Mission belongs to this owner. */
  ownerScope(request: Request, missionId: string): Promise<AccessScope | null>;
  verifyCsrf(request: Request): Promise<boolean>;
  readOnlyAction?(provider:string,action:string):boolean;
  taskObservability?(key:string,taskId:string):Promise<unknown>;
  ownerConnections?(scope: AccessScope): Promise<AccessConnectionView[]>;
  ownerGoogleAuthorization?(scope: AccessScope, request: Request): Promise<{ url: string; expiresAt?: number }>;
  onKeyIssued?(scope: AccessScope, key: string, grant: AccessSafeGrant): Promise<void>;
  managedReady?(scope: AccessScope): Promise<boolean>;
  issueTransaction?<T>(scope: AccessScope, change: () => Promise<T>): Promise<T>;
  submitTransaction?<T>(key: string, change: () => Promise<T>): Promise<T>;
  onTaskSubmitted?(key: string, task: AccessSafeTask): Promise<void>;
  onTaskAdvanced?(key: string, task: AccessSafeTask): Promise<void>;
};

export const ACCESS_MAX_BODY = 32 * 1024;
const identifier = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
const provider = z.string().regex(/^[a-z][a-z0-9_-]{0,63}$/);
const action = z.string().regex(/^[A-Za-z0-9_.:-]{1,120}$/);
const account = z.string().trim().min(1).max(256).refine(s => !/[\u0000-\u001f\u007f]/.test(s));
export const accessGrantInput = z.object({
  label: z.string().trim().min(1).max(120),
  expiresAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  rules: z.array(z.object({ provider, actions: z.array(action).min(1).max(64), accountIds: z.array(account).min(1).max(64), writeLimit: z.number().int().min(0).max(10_000) }).strict()).min(1).max(32),
  maxTasks: z.number().int().min(1).max(100).optional(),
  managed: z.boolean().optional(),
}).strict();
export const accessSubmitInput = z.object({
  idempotencyKey: z.string().regex(/^[A-Za-z0-9_.:-]{8,160}$/), provider, action,
  accountId: account.optional(), payload: z.record(z.string().min(1).max(120), z.json()),
}).strict();
export const accessPublicReadInput = z.object({
  statusId: z.string().regex(/^\d{1,40}$/),
  idempotencyKey: z.string().regex(/^[A-Za-z0-9_.:-]{8,160}$/),
}).strict();
const emptyInput = z.object({}).strict();

export function accessBearer(header: string | null | undefined): string {
  const match = /^Bearer ([^\s,]+)$/i.exec(header ?? '');
  if (!match || match[1].length > 4096 || !/^nla2\.[A-Za-z0-9_-]+$/.test(match[1])) throw new AccessError('access_invalid_key');
  return match[1];
}

export function accessOriginAllowed(origin: string | null | undefined, configuredOrigin: string): boolean {
  if (!origin) return true; // CLI/MCP clients use Bearer authentication without Origin.
  try { const value = new URL(origin); return value.origin === new URL(configuredOrigin).origin && value.href === value.origin + '/'; }
  catch { return false; }
}

export function assertAccessBody(value: unknown): void {
  // express.json may already have run in the host; enforce these bounds again
  // before schema traversal or a broker/provider receives untrusted input.
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const item = pending.pop()!;
    if (++nodes > 2000 || item.depth > 12) throw new AccessError('access_invalid_input');
    if (typeof item.value === 'string' && item.value.length > 16_384) throw new AccessError('access_invalid_input');
    if (item.value && typeof item.value === 'object') {
      for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
  }
  try { if (Buffer.byteLength(JSON.stringify(value) ?? '') > ACCESS_MAX_BODY) throw new AccessError('access_invalid_input'); }
  catch { throw new AccessError('access_invalid_input'); }
}

const publicErrors: Readonly<Record<string, number>> = Object.freeze({
  access_invalid_key: 401, access_scope_denied: 403, access_revoked: 403, access_expired: 403,
  access_rule_denied: 403, access_limit_reached: 429, access_invalid_input: 400,
  access_idempotency_conflict: 409, access_task_not_found: 404, access_busy: 409,
  access_unknown_outcome: 503, access_reconciliation_required: 409,
  access_verification_rejected: 403, access_verification_consumed: 409,
  access_host_hold: 409, access_provider_unavailable: 503, access_internal: 503,
});
export function accessFailure(error: unknown): { status: number; body: { error: string } } {
  return error instanceof AccessError && Object.hasOwn(publicErrors, error.code)
    ? { status: publicErrors[error.code], body: { error: error.code } }
    : { status: 503, body: { error: 'access_internal' } };
}
export function sendAccessFailure(res: Response, error: unknown): void {
  const value = accessFailure(error);
  if (value.status === 401) res.setHeader('WWW-Authenticate', 'Bearer realm="nuluno-access"');
  res.status(value.status).json(value.body);
}

export async function accessTaskAction(deps: Pick<AccessRouteDependencies, 'broker' | 'adapterFor' | 'onTaskAdvanced'>, key: string, taskId: string, kind: 'advance' | 'reconcile'): Promise<AccessSafeTask> {
  const task = await deps.broker.getTask(key, taskId);
  const adapter = deps.adapterFor(task.provider);
  if (!adapter || adapter.provider !== task.provider) throw new AccessError('access_provider_unavailable');
  // Broker handles uncertain/inflight as reconciliation-only. This layer never
  // dispatches a provider itself, retries, or replaces an operation identity.
  const result = kind === 'advance' ? await deps.broker.advance(key, taskId, adapter) : await deps.broker.reconcile(key, taskId, adapter);
  await deps.onTaskAdvanced?.(key, result);
  return result;
}

export async function accessTaskSubmit(deps: Pick<AccessRouteDependencies, 'broker' | 'onTaskSubmitted' | 'submitTransaction'>, key: string, input: AccessSubmit): Promise<AccessSafeTask> {
  const { grant } = await deps.broker.getCapabilities(key);
  const submit = async () => {
    const task = await deps.broker.submit(key, input);
    await deps.onTaskSubmitted?.(key, task);
    return task;
  };
  if (!grant.managed) return submit();
  // A committed managed task must already have a confirmed durable cloud
  // alarm. Unknown arm rejects the SAME host transaction; it is not a task
  // that is committed but can only recover when the owner's browser returns.
  if (!deps.submitTransaction || !deps.onTaskSubmitted) throw new AccessError('access_provider_unavailable');
  return deps.submitTransaction(key, submit);
}

export async function accessReadOnlyTask(deps:Pick<AccessRouteDependencies,'broker'|'adapterFor'|'onTaskSubmitted'|'onTaskAdvanced'|'submitTransaction'|'readOnlyAction'>,key:string,input:AccessSubmit){
 if(!deps.readOnlyAction?.(input.provider,input.action))throw new AccessError('access_rule_denied');
 const task=await accessTaskSubmit(deps,key,input);if(['succeeded','failed','revoked'].includes(task.status))return task;
 try{return await accessTaskAction(deps,key,task.id,task.status==='uncertain'||task.status==='dispatching'?'reconcile':'advance');}catch(error){if(error instanceof AccessError&&error.code==='access_busy')return deps.broker.getTask(key,task.id);throw error;}
}

/** Fixed public GET only. Callers cannot substitute a provider, URL or action. */
export async function accessReadPublicStatus(deps:Pick<AccessRouteDependencies,'broker'|'adapterFor'|'onTaskSubmitted'|'onTaskAdvanced'|'submitTransaction'>,key:string,input:z.infer<typeof accessPublicReadInput>){
 const task=await accessTaskSubmit(deps,key,{idempotencyKey:input.idempotencyKey,provider:'mastodon',action:'read_public_status',accountId:'public:mastodon.social',payload:{statusId:input.statusId}});
 if(['succeeded','failed','revoked'].includes(task.status))return task;
 try{return await accessTaskAction(deps,key,task.id,task.status==='uncertain'||task.status==='dispatching'?'reconcile':'advance');}
 catch(error){if(error instanceof AccessError&&error.code==='access_busy')return deps.broker.getTask(key,task.id);throw error;}
}

export function createAccessRouter(deps: AccessRouteDependencies): express.Router {
  const router = express.Router();
  router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Pragma', 'no-cache');
    if (!accessOriginAllowed(req.header('origin'), deps.origin)) return res.status(403).json({ error: 'access_scope_denied' });
    if (Object.keys(req.query).length) return res.status(400).json({ error: 'access_invalid_input' });
    next();
  });
  router.use(express.json({ limit: ACCESS_MAX_BODY, strict: true, type: 'application/json' }));
  const handle = (fn: (req: Request, res: Response) => Promise<unknown>): RequestHandler => async (req, res) => {
    try { assertAccessBody(req.body); await fn(req, res); } catch (error) { sendAccessFailure(res, error); }
  };
  async function owner(req: Request, write = false): Promise<AccessScope> {
    const missionId = parse(identifier, req.params.missionId);
    const scope = await deps.ownerScope(req, missionId);
    if (!scope || scope.missionId !== missionId) throw new AccessError('access_scope_denied');
    if (write && !await deps.verifyCsrf(req)) throw new AccessError('access_scope_denied');
    return scope;
  }
  function parse<T>(schema: z.ZodType<T>, value: unknown): T {
    const result = schema.safeParse(value);
    if (!result.success) throw new AccessError('access_invalid_input');
    return result.data;
  }
  router.get('/owner/missions/:missionId/keys', handle(async (req, res) => {
    res.json({ keys: await deps.broker.listOwner(await owner(req)) });
  }));
  router.post('/owner/missions/:missionId/keys', handle(async (req, res) => {
    const scope = await owner(req, true);
    const input = parse(accessGrantInput, req.body);
    if (input.managed === true && (!deps.managedReady || !deps.issueTransaction || !deps.onKeyIssued || !await deps.managedReady(scope))) {
      throw new AccessError('access_provider_unavailable');
    }
    const issue = async () => {
      const issued = await deps.broker.issue(scope, input);
      if (input.managed === true) await deps.onKeyIssued!(scope, issued.key, issued.grant);
      return issued;
    };
    // Managed key+encrypted host envelope commit together via the host's real
    // conversation transaction. This transport never invents a memory fallback.
    const issued = input.managed === true ? await deps.issueTransaction!(scope, issue) : await issue();
    res.status(201).json(issued);
  }));
  router.post('/owner/missions/:missionId/keys/:keyId/revoke', handle(async (req, res) => {
    const scope = await owner(req, true); parse(emptyInput, req.body);
    res.json({ grant: await deps.broker.revoke(scope, parse(identifier, req.params.keyId)) });
  }));
  router.get('/owner/missions/:missionId/status', handle(async (req, res) => {
    const scope = await owner(req);
    const recent=deps.broker.listOwnerTasks?await deps.broker.listOwnerTasks(scope):[];
    const active=deps.broker.listOwnerActiveTasks?await deps.broker.listOwnerActiveTasks(scope):[];
    const tasks=[...new Map([...recent,...active].map(task=>[task.id,task])).values()].sort((a,b)=>a.createdAt-b.createdAt||a.id.localeCompare(b.id));
    res.json({ keys: await deps.broker.listOwner(scope), tasks,
      connections: deps.ownerConnections ? await deps.ownerConnections(scope) : [] });
  }));
  router.get('/owner/missions/:missionId/connections', handle(async (req, res) => {
    const scope = await owner(req);
    res.json({ connections: deps.ownerConnections ? await deps.ownerConnections(scope) : [] });
  }));
  router.post('/owner/missions/:missionId/google/authorize', handle(async (req, res) => {
    const scope = await owner(req, true); parse(emptyInput, req.body);
    if (!deps.ownerGoogleAuthorization) throw new AccessError('access_provider_unavailable');
    const value = await deps.ownerGoogleAuthorization(scope, req); const url = new URL(value.url);
    if (url.protocol !== 'https:' || url.username || url.password) throw new AccessError('access_internal');
    res.json(value);
  }));
  router.get('/status', handle(async (req, res) => res.json(await deps.broker.status(accessBearer(req.header('authorization'))))));
  router.get('/capabilities', handle(async (req, res) => res.json(await deps.broker.getCapabilities(accessBearer(req.header('authorization'))))));
  router.post('/read-public-status',handle(async(req,res)=>res.json(await accessReadPublicStatus(deps,accessBearer(req.header('authorization')),parse(accessPublicReadInput,req.body)))));
  router.post('/read-upstream-task',handle(async(req,res)=>res.json(await accessReadOnlyTask(deps,accessBearer(req.header('authorization')),parse(accessSubmitInput,req.body) as AccessSubmit))));
  router.post('/tasks', handle(async (req, res) => {
    const key = accessBearer(req.header('authorization'));
    const task = await accessTaskSubmit(deps, key, parse(accessSubmitInput, req.body) as AccessSubmit);
    res.status(201).json(task);
  }));
  router.get('/tasks/:taskId/flow', handle(async(req,res)=>{const key=accessBearer(req.header('authorization')),taskId=parse(identifier,req.params.taskId);await deps.broker.getTask(key,taskId);if(!deps.taskObservability)throw new AccessError('access_provider_unavailable');res.json(await deps.taskObservability(key,taskId));}));
  router.get('/tasks/:taskId', handle(async (req, res) => res.json(await deps.broker.getTask(accessBearer(req.header('authorization')), parse(identifier, req.params.taskId)))));
  for (const kind of ['advance', 'reconcile'] as const) router.post('/tasks/:taskId/' + kind, handle(async (req, res) => {
    parse(emptyInput, req.body);
    res.json(await accessTaskAction(deps, accessBearer(req.header('authorization')), parse(identifier, req.params.taskId), kind));
  }));
  router.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    const parser = error as { type?: string };
    if (parser?.type === 'entity.too.large') return res.status(413).json({ error: 'access_invalid_input' });
    if (parser?.type === 'entity.parse.failed') return res.status(400).json({ error: 'access_invalid_input' });
    sendAccessFailure(res, error);
  });
  return router;
}
