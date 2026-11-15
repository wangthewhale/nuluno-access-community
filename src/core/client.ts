import {ACCESS_VERSION} from '../version';
import type {AccessSubmit,AccessSafeTask} from './types';
/** Portable HTTPS client. Access keys are held in transport memory only.
 * No automatic retry can repeat a possibly dispatched provider operation.
 */
export type AccessClientOptions = {
  baseUrl: string;
  accessKey: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
};

export class AccessTransportError extends Error {
  readonly code: string;
  readonly status: number | null;
  readonly reconcileOnly: boolean;
  readonly requiresOwnerAuthorization: boolean;
  constructor(code: string, status: number | null, reconcileOnly = false, requiresOwnerAuthorization = false) {
    super(code);
    this.name = 'AccessTransportError';
    this.code = code;
    this.status = status;
    this.reconcileOnly = reconcileOnly;
    this.requiresOwnerAuthorization = requiresOwnerAuthorization;
  }
}

const MAX_RESPONSE = 128 * 1024;
const MAX_REQUEST = 32 * 1024;
const TASK_ID = /^[a-zA-Z0-9_-]{1,128}$/;
const SAFE_ERROR = /^access_[a-z0-9_]{1,100}$/;
const AUTH_ERRORS = new Set(['access_invalid_key','access_scope_denied','access_revoked','access_expired','access_rule_denied']);
export const ACCESS_USER_AGENT = `Nuluno-Access-Community/${ACCESS_VERSION} (+https://access.nuluno.com)`;

// Inspect only a bounded error projection. HTML pages, Ray IDs, IPs and
// credentials are neither returned in errors nor logged by this client.
async function responseProblem(response: Response): Promise<{code:string; authorization:boolean}|null> {
  if (![401,403].includes(response.status)) return null;
  const declared = response.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE)) return null;
  const copy = response.clone(), reader = copy.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const next = await reader.read(); if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE) { void reader.cancel().catch(()=>{}); return null; }
      chunks.push(next.value);
    }
  } catch { return null; }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
  const text = new TextDecoder().decode(bytes);
  const type = (response.headers.get('content-type')??'').split(';')[0].trim().toLowerCase();
  if (response.status===403 && type==='text/plain'
      && /cloudflare/i.test(response.headers.get('server')??'')
      && /^\s*error(?:\s+code)?\s*[:#]?\s*1010\s*$/i.test(text)) {
    return {code:'transport_client_identity_rejected',authorization:false};
  }
  if (response.status===403 && ['text/html','application/xhtml+xml'].includes(type)) {
    const plain = text.replace(/<[^>]*>/g,' ').replace(/&nbsp;/gi,' ');
    if ((/cloudflare/i.test(response.headers.get('server')??'') || /cloudflare/i.test(plain))
        && /\berror(?:\s+code)?\s*[:#]?\s*1010\b/i.test(plain)) {
      return {code:'transport_client_identity_rejected',authorization:false};
    }
    if (!response.headers.get('www-authenticate')
        && (/cloudflare/i.test(response.headers.get('server')??'') || /cloudflare/i.test(plain))
        && /attention\s+required/i.test(text) && /data-translate\s*=\s*["']block_headline["']/i.test(text)) {
      return {code:'transport_edge_rejected',authorization:false};
    }
  }
  if (type==='application/json') {
    let value; try { value=JSON.parse(text); } catch { return null; }
    if (value && typeof value.error==='string' && AUTH_ERRORS.has(value.error)) return {code:value.error,authorization:true};
  }
  return null;
}

/** Shared by the REST SDK and owner-configured stdio bridge. No retries/grants. */
export async function fetchWithAccessIdentity(input: string|URL|Request, init: RequestInit = {},
    fetchImpl: typeof globalThis.fetch = (input,init)=>globalThis.fetch(input,init)): Promise<Response> {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  new Headers(init.headers).forEach((value,key)=>headers.set(key,value));
  headers.set('user-agent',ACCESS_USER_AGENT);
  const response = await fetchImpl(input,{...init,headers});
  const problem = await responseProblem(response);
  if (problem) {
    await response.body?.cancel().catch(()=>{});
    throw new AccessTransportError(problem.code,response.status,
      !['GET','HEAD'].includes((init.method??(input instanceof Request?input.method:'GET')).toUpperCase()),problem.authorization);
  }
  return response;
}


async function boundedJson(response: Response): Promise<unknown> {
  const declared = response.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_RESPONSE)) {
    await response.body?.cancel();
    throw new AccessTransportError('access_response_too_large', response.status);
  }
  if (!response.body) throw new AccessTransportError('access_invalid_response', response.status);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_RESPONSE) {
        await reader.cancel();
        throw new AccessTransportError('access_response_too_large', response.status);
      }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new AccessTransportError('access_invalid_response', response.status); }
}

export class NulunoAccessClient {
  readonly #key: string;
  readonly #base: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeout: number;
  constructor(options: AccessClientOptions) {
    let url: URL;
    try { url = new URL(options.baseUrl); } catch { throw new AccessTransportError('access_invalid_base_url', null); }
    if (url.username || url.password || url.search || url.hash ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
      throw new AccessTransportError('access_invalid_base_url', null);
    }
    if (typeof options.accessKey !== 'string' || options.accessKey.length > 4096 || !/^nla2\.[A-Za-z0-9_-]+$/.test(options.accessKey)) throw new AccessTransportError('access_invalid_key', null);
    this.#key = options.accessKey;
    this.#base = url.href.replace(/\/$/, '');
    this.#fetch = options.fetch ?? ((input,init)=>globalThis.fetch(input,init));
    this.#timeout = options.timeoutMs ?? 20_000;
    if (!Number.isSafeInteger(this.#timeout) || this.#timeout < 100 || this.#timeout > 60_000) {
      throw new AccessTransportError('access_invalid_timeout', null);
    }
  }
  async #request<T>(path: string, body?: unknown): Promise<T> {
    let encoded: string | undefined;
    if (body !== undefined) {
      try { encoded = JSON.stringify(body); } catch { throw new AccessTransportError('access_invalid_request', null); }
      if (new TextEncoder().encode(encoded).byteLength > MAX_REQUEST) throw new AccessTransportError('access_request_too_large', null);
    }
    let response: Response;
    try {
      response = await fetchWithAccessIdentity(this.#base + path, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { authorization: 'Bearer ' + this.#key, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        body: encoded, redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(this.#timeout),
      },this.#fetch);
    } catch (error) {
      if (error instanceof AccessTransportError) throw error;
      // A timeout can happen after an authorized dispatch committed. The caller
      // must read/reconcile the SAME task; this client never retries a POST.
      throw new AccessTransportError('access_transport_unknown', null, body !== undefined);
    }
    let value: unknown;
    try { value = await boundedJson(response); }
    catch (error) {
      if (error instanceof AccessTransportError) throw new AccessTransportError(error.code, error.status, body !== undefined,error.requiresOwnerAuthorization);
      throw new AccessTransportError('access_transport_unknown', response.status, body !== undefined);
    }
    if (!response.ok) {
      const code = value && typeof value === 'object' && 'error' in value && typeof value.error === 'string' && SAFE_ERROR.test(value.error)
        ? value.error : 'access_request_failed';
      throw new AccessTransportError(code, response.status, response.status === 503);
    }
    return value as T;
  }
  status<T = unknown>(): Promise<T> { return this.#request('/status'); }
  capabilities<T = unknown>(): Promise<T> { return this.#request('/capabilities'); }
  readPublicStatus<T = AccessSafeTask>(input:{statusId:string;idempotencyKey:string}):Promise<T>{return this.#request('/read-public-status',input);}
  readUpstream<T = AccessSafeTask>(input:AccessSubmit):Promise<T>{return this.#request('/read-upstream-task',input);}
  submit<T = AccessSafeTask>(input: AccessSubmit): Promise<T> { return this.#request('/tasks', input); }
  flow<T = unknown>(taskId:string):Promise<T>{return this.#request('/tasks/'+taskPath(taskId)+'/flow');}
  getTask<T = AccessSafeTask>(taskId: string): Promise<T> { return this.#request('/tasks/' + taskPath(taskId)); }
  advance<T = AccessSafeTask>(taskId: string): Promise<T> { return this.#request('/tasks/' + taskPath(taskId) + '/advance', {}); }
  reconcile<T = AccessSafeTask>(taskId: string): Promise<T> { return this.#request('/tasks/' + taskPath(taskId) + '/reconcile', {}); }
}

function taskPath(id: string): string {
  if (typeof id !== 'string' || !TASK_ID.test(id)) throw new AccessTransportError('access_invalid_task_id', null);
  return encodeURIComponent(id);
}
