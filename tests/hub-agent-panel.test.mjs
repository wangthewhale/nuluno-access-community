// SPDX-License-Identifier: Apache-2.0
// Controlled DOM/API fixtures only: no browser, network or real account.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createAgentPanel} from '../src/account-hub/ui/agent-access.mjs';

const ORIGIN = 'http://127.0.0.1:18894', CSRF = 'CONTROLLED_OWNER_CSRF', ID = 'a29ae812-7103-48ef-9874-e011c51b0a34';
const RESTRICTED = 'CONTROLLED_RESTRICTED_AGENT_KEY', PRIVATE = 'CONTROLLED_FORBIDDEN_PROVIDER_CREDENTIAL';
const entry = () => ({preset:'public-read', grant:{id:ID, expiresAt:Date.UTC(2026,10,16,12), revokedAt:null}, connectionAvailable:true});
const response = (body, status=200) => new Response(JSON.stringify(body), {status, headers:{'content-type':'application/json'}});

function fixture({agents=[], handler}={}) {
  const elements = new Map(), calls = [], blobs = [], objectUrls = [], downloads = [], timers = [], revokedUrls = [];
  let uuidCalls = 0, forbiddenStorageAccess = 0;
  function element(tag='div', id='') {
    const listeners = new Map(); let text = '';
    return {tagName:tag.toUpperCase(), id, children:[], parent:null, disabled:false, className:'', href:'', download:'',
      get textContent(){return text + this.children.map(child => child.textContent).join('');},
      set textContent(value){text=String(value); for(const child of this.children) child.parent=null; this.children=[];},
      addEventListener(name, listener){listeners.set(name, listener);},
      append(...children){for(const child of children){child.remove(); child.parent=this; this.children.push(child);}},
      replaceChildren(...children){this.textContent=''; this.append(...children);},
      remove(){if(this.parent){this.parent.children=this.parent.children.filter(child => child!==this); this.parent=null;}},
      click(){if(tag==='a'){downloads.push({href:this.href, fileName:this.download}); return;} if(!this.disabled) return listeners.get('click')?.();},
      emit(name){if(this.disabled && name==='click') return; return listeners.get(name)?.();}
    };
  }
  for(const id of ['create-public-agent','agent-feedback','agent-list','refresh-agents']) elements.set(id, element(id.includes('agent') && ['create-public-agent','refresh-agents'].includes(id) ? 'button':'div', id));
  elements.get('create-public-agent').disabled=true;
  const document = {getElementById:id=>elements.get(id), createElement:tag=>element(tag), body:element('body')};
  class ControlledBlob {constructor(parts, options){this.parts=parts; this.type=options.type; blobs.push(this);} async text(){return this.parts.join('');}}
  const window = {location:{origin:ORIGIN}, crypto:{randomUUID(){uuidCalls++; return 'e1c410bb-7954-4f22-ad5b-40bb5f19610b';}}, Blob:ControlledBlob,
    URL:{createObjectURL(blob){assert.ok(blob instanceof ControlledBlob); const url='blob:controlled-fixture-' + (objectUrls.length+1); objectUrls.push(url); return url;}, revokeObjectURL:url=>revokedUrls.push(url)},
    setTimeout(fn, delay){timers.push({fn, delay}); return timers.length;},
    open(){throw Error('panel_must_not_open_permission_or_bootstrap_windows');}
  };
  for(const key of ['localStorage','sessionStorage']) Object.defineProperty(window, key, {get(){forbiddenStorageAccess++; throw Error('storage_access_forbidden');}});
  const state = {agents};
  const fetchImpl = async (path, options) => {
    assert.match(path, /^\/hub-api\//); assert.equal(options.credentials,'same-origin'); assert.equal(options.redirect,'error'); assert.equal(options.cache,'no-store');
    const call={path, method:options.method, headers:options.headers, body:options.body===undefined ? undefined : JSON.parse(options.body)}; calls.push(call);
    if(call.method==='POST') assert.equal(call.headers['x-hub-csrf'],CSRF);
    const custom = await handler?.(call, state); if(custom!==undefined) return custom;
    if(path==='/hub-api/state' && call.method==='GET') return response({csrf:CSRF});
    if(path==='/hub-api/agents' && call.method==='GET') return response({agents:state.agents});
    throw Error('unexpected_controlled_request');
  };
  const panel=createAgentPanel({document,window,fetchImpl});
  return {panel, state, document, element:id=>elements.get(id), calls, blobs, downloads, timers, objectUrls, revokedUrls,
    get uuidCalls(){return uuidCalls;}, get forbiddenStorageAccess(){return forbiddenStorageAccess;},
    posts:path=>calls.filter(call=>call.method==='POST' && (path===undefined || call.path===path)),
    rows:()=>elements.get('agent-list').children,
    buttons:()=>elements.get('agent-list').children.flatMap(row=>row.children[1].children),
    domText:()=>[...elements.values(),document.body].map(value=>value.textContent+' '+value.href+' '+value.download).join('\n')};
}

test('loading reads safe metadata without issuing an agent or placing response secrets in the DOM', async()=>{
  const agent=entry(); agent.key=RESTRICTED; agent.grant.tokenHash=PRIVATE; agent.providerCredentials={accessToken:PRIVATE};
  const f=fixture({agents:[agent]}); await f.panel.load();
  assert.deepEqual(f.calls.map(call=>call.method+' '+call.path),['GET /hub-api/state','GET /hub-api/agents']);
  assert.equal(f.posts().length,0); assert.equal(f.uuidCalls,0); assert.equal(f.blobs.length,0); assert.equal(f.downloads.length,0);
  assert.equal(f.rows().length,1); assert.match(f.element('agent-list').textContent,/公共資料只讀 agent/);
  assert.ok(!f.domText().includes(RESTRICTED)); assert.ok(!f.domText().includes(PRIVATE)); assert.ok(!f.domText().includes(ID));
  assert.equal(f.forbiddenStorageAccess,0);
});

test('double create is admitted once, and an unconfirmed response retries the same UUID without renewing a new request', async()=>{
  let release; const gate=new Promise(resolve=>{release=resolve;}); let attempts=0;
  const f=fixture({handler:async(call,state)=>{
    if(call.path==='/hub-api/agents' && call.method==='POST') {
      attempts++; if(attempts===1){await gate; return response({error:PRIVATE},503);}
      state.agents=[entry()]; return response({preset:'public-read',grant:entry().grant});
    }
  }});
  await f.panel.load(); const first=f.element('create-public-agent').click(); await f.panel.create();
  assert.equal(f.posts('/hub-api/agents').length,1); assert.equal(f.uuidCalls,1); assert.equal(f.element('create-public-agent').disabled,true);
  release(); await first; assert.equal(f.element('create-public-agent').disabled,false);
  assert.match(f.element('agent-feedback').textContent,/沿用同一次請求/); assert.ok(!f.domText().includes(PRIVATE));
  await f.element('create-public-agent').click();
  const posts=f.posts('/hub-api/agents'); assert.equal(posts.length,2); assert.deepEqual(posts[1].body,posts[0].body); assert.equal(posts[0].body.preset,'public-read'); assert.equal(f.uuidCalls,1);
  assert.equal(f.element('create-public-agent').disabled,true); await f.panel.create(); assert.equal(f.posts('/hub-api/agents').length,2);
});

test('only an explicit download posts for a restricted MCP connection and writes a standard, sanitized HTTP configuration Blob', async()=>{
  const f=fixture({agents:[entry()], handler:call=>call.path.endsWith('/connection') ? response({fileName:'ignored-client-specific-file.json', contentType:'application/json', configuration:{transport:'streamable-http', url:ORIGIN+'/mcp', headers:{Authorization:'Bearer '+RESTRICTED}, adminKey:PRIVATE, mcpServers:{private:PRIVATE}}}) : undefined});
  await f.panel.load(); assert.equal(f.posts().length,0); assert.equal(f.blobs.length,0);
  await f.buttons()[0].click();
  assert.deepEqual(f.posts().map(call=>({path:call.path,body:call.body})),[{path:'/hub-api/agents/'+ID+'/connection',body:{client:'mcp-http'}}]);
  assert.equal(f.blobs.length,1); assert.equal(f.blobs[0].type,'application/json');
  const configuration=JSON.parse(await f.blobs[0].text());
  assert.deepEqual(configuration,{transport:'streamable-http',url:ORIGIN+'/mcp',headers:{Authorization:'Bearer '+RESTRICTED}});
  assert.deepEqual(f.downloads,[{href:f.objectUrls[0],fileName:'nuluno-public-read-mcp.json'}]);
  assert.equal(f.document.body.children.length,0); assert.ok(!f.domText().includes(RESTRICTED)); assert.ok(!f.domText().includes(PRIVATE)); assert.equal(f.forbiddenStorageAccess,0);
  assert.equal(f.timers.length,1); assert.equal(f.timers[0].delay,1000); f.timers[0].fn(); assert.deepEqual(f.revokedUrls,f.objectUrls);
  for(const configuration of [{transport:'streamable-http',url:'https://evil.example/mcp',headers:{Authorization:'Bearer '+RESTRICTED}},{transport:'streamable-http',url:ORIGIN+'/mcp',headers:{Authorization:'Bearer '+RESTRICTED,'X-Admin-Key':PRIVATE}},{transport:'streamable-http',url:ORIGIN+'/mcp',headers:{Authorization:'Bearer '}}]) {
    const bad=fixture({agents:[entry()],handler:call=>call.path.endsWith('/connection') ? response({configuration}) : undefined});
    await bad.panel.load(); await bad.buttons()[0].click(); assert.equal(bad.blobs.length,0); assert.equal(bad.downloads.length,0); assert.ok(!bad.domText().includes(PRIVATE));
  }
  const source=await readFile(new URL('../src/account-hub/ui/agent-access.mjs',import.meta.url),'utf8'); assert.doesNotMatch(source,/localStorage|sessionStorage|console\s*\./);
});

test('revocation only occurs on explicit action, then readback disables revoked download and revoke controls', async()=>{
  const f=fixture({agents:[entry()],handler:(call,state)=>{
    if(call.path.endsWith('/revoke')) {state.agents=[{...entry(),grant:{...entry().grant,revokedAt:Date.UTC(2026,10,16,11)},connectionAvailable:false}]; return response({revoked:true});}
  }});
  await f.panel.load(); assert.equal(f.posts().length,0); assert.equal(f.buttons()[0].disabled,false); assert.equal(f.buttons()[1].disabled,false);
  await f.buttons()[1].click();
  assert.deepEqual(f.posts().map(call=>({path:call.path,body:call.body})),[{path:'/hub-api/agents/'+ID+'/revoke',body:{}}]);
  assert.match(f.element('agent-list').textContent,/已撤銷/); assert.match(f.element('agent-feedback').textContent,/原任務與紀錄會保留/);
  assert.equal(f.buttons()[0].disabled,true); assert.equal(f.buttons()[1].disabled,true); await f.buttons()[0].click(); await f.buttons()[1].click(); assert.equal(f.posts().length,1); assert.equal(f.blobs.length,0);
});

test('an unknown owner receives no automatic pairing, permission escalation or agent grant after 401', async()=>{
  const f=fixture({handler:()=>response({error:PRIVATE},401)}); await f.panel.load();
  await f.panel.create(); await f.panel.download(ID); await f.panel.revoke(ID); await f.element('create-public-agent').click();
  assert.deepEqual(f.calls.map(call=>call.method+' '+call.path),['GET /hub-api/state']);
  assert.equal(f.posts().length,0); assert.equal(f.uuidCalls,0); assert.equal(f.blobs.length,0); assert.equal(f.downloads.length,0); assert.equal(f.element('create-public-agent').disabled,true);
  assert.match(f.element('agent-feedback').textContent,/不會自動建立 agent 權限/); assert.ok(!f.domText().includes(PRIVATE)); assert.equal(f.forbiddenStorageAccess,0);
});
