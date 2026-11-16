import test from 'node:test';import assert from 'node:assert/strict';
import {createPairingPage} from '../src/account-hub/ui/pairing.mjs';
import {startOwnerPage} from '../src/account-hub/ui/owner-start.mjs';
import {readOwnerProof,storeOwnerProof,rememberOwnerProof,clearOwnerProof,withOwnerProof} from '../src/account-hub/ui/owner-proof.mjs';
const PAIR='P'.repeat(43),PROOF='O'.repeat(43),NEXT='N'.repeat(43);
const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json'}});
function storage(){const values=new Map();return {values,getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};}
function fixture({hash='#pair='+PAIR,oldProof=null}={}){
 const order=[],elements=new Map(),requests=[];const element=id=>{if(!elements.has(id))elements.set(id,{textContent:'',disabled:false,hidden:false,checked:false,dataset:{},setAttribute(){},removeAttribute(){},addEventListener(){},replaceChildren(){}});return elements.get(id);};
 const listeners=new Map();const window={listeners,dispatch(type){return listeners.get(type)?.();},sessionStorage:storage(),localStorage:storage(),location:{origin:'http://127.0.0.1:19876',hash,replace(path){order.push(['navigate',path]);}},history:{replaceState(_a,_b,path){order.push(['scrub',path]);window.location.hash='';}},addEventListener(type,fn){listeners.set(type,fn);},removeEventListener(type,fn){if(listeners.get(type)===fn)listeners.delete(type);},crypto:{randomUUID(){throw Error('No automatic grant expected');}}};
 if(oldProof)storeOwnerProof(window,oldProof,false);
 return {window,document:{getElementById:element},element,order,requests};
}

test('the dedicated activation shell clears the fragment before any API and works with an existing cookie regardless of old proof',async()=>{
 for(const oldProof of [null,PROOF]){
  const f=fixture({oldProof});const fetchImpl=async(path,init={})=>{f.requests.push({path,init});f.order.push(['fetch',path]);if(path.endsWith('/challenge'))return response({csrf:'CONTROLLED_CSRF'});assert.ok(path.endsWith('/complete'));assert.equal(JSON.parse(init.body).token,PAIR);return response({paired:true,ownerProof:NEXT});};
  const page=createPairingPage({...f,fetchImpl});assert.deepEqual(f.order,[['scrub','/account-hub/activate']]);assert.equal(f.window.location.hash,'');assert.equal(f.requests.length,0);assert.ok(!f.element('pairing-status').textContent.includes(PAIR));await page.activate();assert.equal(f.requests.length,2);assert.equal(readOwnerProof(f.window),NEXT);assert.deepEqual(f.order.at(-1),['navigate','/account-hub']);assert.ok(!JSON.stringify([...f.window.sessionStorage.values.values(),...f.window.localStorage.values.values()]).includes(PAIR));
 }
});

test('repeated activation gestures issue only one pairing POST and an uncertain result never resends the one-use token',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;}),f=fixture();let posts=0;
 const page=createPairingPage({...f,fetchImpl:async(path)=>{if(path.endsWith('/challenge')){await gate;return response({csrf:'CONTROLLED_CSRF'});}if(path.endsWith('/complete')){posts++;return response({error:'CONTROLLED_PRIVATE'},403);}return response({},401);}});
 const first=page.activate();await page.activate();release();await first;await page.activate();assert.equal(posts,1);assert.equal(f.element('activate-owner').disabled,true);assert.match(f.element('pairing-status').textContent,/不會自動重送/);assert.ok(!f.element('pairing-status').textContent.includes('CONTROLLED_PRIVATE'));assert.equal(readOwnerProof(f.window),null);
});

test('malformed, duplicate or unrelated secret fragments are removed without being echoed or sent anywhere',async()=>{
 for(const hash of ['#pair=short','#pair='+PAIR+'&pair='+PAIR,'#access_token=CONTROLLED_PRIVATE','#pair='+PAIR+'&other=CONTROLLED_PRIVATE']){const f=fixture({hash});let calls=0;const page=createPairingPage({...f,fetchImpl:async()=>{calls++;throw Error('No request expected');}});await page.activate();assert.equal(f.window.location.hash,'');assert.equal(calls,0);assert.equal(f.element('activate-owner').disabled,true);assert.ok(!f.element('pairing-status').textContent.includes('CONTROLLED_PRIVATE'));}
});

test('the only stored credential is an origin-scoped owner proof, moved by remember-device and never attached to another origin or a pairing request',async()=>{
 const f=fixture();storeOwnerProof(f.window,PROOF,false);assert.equal(f.window.sessionStorage.values.size,1);assert.equal(f.window.localStorage.values.size,0);rememberOwnerProof(f.window,true);assert.equal(f.window.sessionStorage.values.size,0);assert.equal(f.window.localStorage.values.size,1);
 const calls=[],fetchImpl=withOwnerProof(f.window,async(path,init)=>{calls.push({path,headers:new Headers(init.headers)});return response({});});await fetchImpl('/hub-api/state');await fetchImpl('/hub-api/agents',{method:'POST'});await fetchImpl('/hub-api/pairing/challenge');await fetchImpl('https://evil.test/hub-api/state');assert.equal(calls[0].headers.get('x-hub-owner-proof'),PROOF);assert.equal(calls[1].headers.get('x-hub-owner-proof'),PROOF);assert.equal(calls[2].headers.has('x-hub-owner-proof'),false);assert.equal(calls[3].headers.has('x-hub-owner-proof'),false);
 const otherOrigin=fixture();assert.equal(readOwnerProof(otherOrigin.window),null);rememberOwnerProof(f.window,false);assert.equal(f.window.localStorage.values.size,0);assert.equal(f.window.sessionStorage.values.size,1);clearOwnerProof(f.window);assert.equal(readOwnerProof(f.window),null);
});

test('a missing origin proof redirects to the dedicated activation page without making any owner API request',async()=>{
 const f=fixture({hash:''});let calls=0;await startOwnerPage({...f,fetchImpl:async()=>{calls++;throw Error('No owner proof');}});assert.equal(calls,0);assert.deepEqual(f.order,[['navigate','/account-hub/activate']]);
});

test('an owner page routes a valid pairing fragment to its activation shell before making owner API requests',async()=>{
 const f=fixture({oldProof:PROOF});let calls=0;await startOwnerPage({...f,fetchImpl:async()=>{calls++;throw Error('No request expected');}});assert.equal(calls,0);assert.equal(f.window.location.hash,'');assert.deepEqual(f.order,[['scrub','/account-hub'],['navigate','/account-hub/activate#pair='+PAIR]]);assert.equal(readOwnerProof(f.window),PROOF);
});

test('a fresh hash-only activation is consumed before any automatic API and enables the loaded shell',async()=>{
 const f=fixture({hash:''});let calls=0;const page=createPairingPage({...f,fetchImpl:async path=>{calls++;return response(path.endsWith('/challenge')?{csrf:'CONTROLLED_CSRF'}:{paired:true,ownerProof:NEXT});}});assert.equal(f.element('activate-owner').disabled,true);
 f.window.location.hash='#pair='+PAIR;f.window.dispatch('hashchange');assert.equal(f.window.location.hash,'');assert.equal(f.element('activate-owner').disabled,false);assert.equal(calls,0);await page.activate();assert.equal(calls,2);assert.equal(readOwnerProof(f.window),NEXT);page.dispose();assert.equal(f.window.listeners.has('hashchange'),false);
});

test('a new fragment during a challenge cancels the stale submission and requires a fresh gesture',async()=>{
 const f=fixture();let release;const gate=new Promise(resolve=>{release=resolve;}),bodies=[];let challenges=0;
 const page=createPairingPage({...f,fetchImpl:async(path,init={})=>{if(path.endsWith('/challenge')){challenges++;if(challenges===1)await gate;return response({csrf:'CONTROLLED_CSRF'});}bodies.push(JSON.parse(init.body));return response({paired:true,ownerProof:NEXT});}});
 const first=page.activate();f.window.location.hash='#pair='+NEXT;f.window.dispatch('hashchange');assert.equal(f.window.location.hash,'');assert.equal(f.element('activate-owner').disabled,true);await page.activate();assert.equal(challenges,1);release();await first;assert.equal(bodies.length,0);assert.equal(f.element('activate-owner').disabled,false);assert.equal(readOwnerProof(f.window),null);await page.activate();assert.deepEqual(bodies,[{token:NEXT}]);
});

test('a new fragment during an in-flight POST cannot store stale proof or start another POST until the old response settles',async()=>{
 const f=fixture();let release,postStarted;const gate=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{postStarted=resolve;}),bodies=[];
 const page=createPairingPage({...f,fetchImpl:async(path,init={})=>{if(path.endsWith('/challenge'))return response({csrf:'CONTROLLED_CSRF'});bodies.push(JSON.parse(init.body));if(bodies.length===1){postStarted();await gate;}return response({paired:true,ownerProof:NEXT});}});
 const first=page.activate();await started;f.window.location.hash='#pair='+NEXT;f.window.dispatch('hashchange');await page.activate();assert.equal(bodies.length,1);release();await first;assert.equal(readOwnerProof(f.window),null);assert.equal(f.order.some(x=>x[0]==='navigate'),false);assert.equal(f.element('activate-owner').disabled,false);await page.activate();assert.deepEqual(bodies,[{token:PAIR},{token:NEXT}]);assert.equal(readOwnerProof(f.window),NEXT);
});
