import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createAccountHub,safeAuthorizationUrl,safeReturnPath} from '../src/account-hub/ui/app.mjs';

// Controlled client/DOM/API contract checks only. No browser, real OAuth,
// private account, external request, or production connection is used.
const NOW=Date.UTC(2026,10,16,10),CSRF='CONTROLLED_CSRF_NOT_A_REAL_TOKEN_123456789';
const oauth='https://mastodon.social/oauth/authorize?client_id=CONTROLLED&state=CONTROLLED_STATE';
const initial=()=>({csrf:CSRF,mode:'isolated-local',project:{label:'我的隔離測試專案'},rememberDevice:false,context:{hasTask:true,returnPath:'/continue',label:'繼續目前的工作'},providers:[{id:'gmail',label:'Gmail',phase:'remembered',accountLabel:'controlled@example.test',canConnect:false,canDisconnect:true,note:'已連接，不用再次授權。'},{id:'mastodon',label:'Mastodon',phase:'not_connected',canConnect:true,canDisconnect:false,note:'尚未連接。'}],payment:{supported:false,note:'尚未支援'},advanced:{localOwnerMode:true,persistentVault:true,googleConfigured:true,googleCallback:'http://127.0.0.1:18894/oauth/google/callback',ownerLoginProductionReady:false}});
const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
function fixture({state=initial(),handler,popupBlocked=false}={}){
 const elements=new Map(),calls=[],popups=[],timeline=[],focusListeners=new Set(),pendingTimers=new Map();let clock=NOW,timerId=0;
 const element=id=>{if(!elements.has(id)){const listeners=new Map();elements.set(id,{id,textContent:'',hidden:false,disabled:false,checked:false,dataset:{},attributes:new Map(),className:'',addEventListener(name,fn){listeners.set(name,fn);},setAttribute(name,value){this.attributes.set(name,value);},removeAttribute(name){this.attributes.delete(name);},emit(name){return listeners.get(name)?.();}});}return elements.get(id);};
 const window={open(url,target,features){timeline.push('popup');assert.equal(url,'about:blank');assert.equal(target,'_blank');assert.match(features,/popup/);if(popupBlocked)return null;const popup={opener:'controlled-parent',closed:false,navigations:[],document:{title:'',body:{textContent:''}},close(){this.closed=true;},location:{replace(value){popup.navigations.push(value);}}};popups.push(popup);return popup;},addEventListener(name,listener){assert.equal(name,'focus');focusListeners.add(listener);},removeEventListener(name,listener){assert.equal(name,'focus');focusListeners.delete(listener);}};
 const fetchImpl=async(path,options)=>{assert.ok(path.startsWith('/hub-api/'));assert.equal(options.credentials,'same-origin');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');const call={path,method:options.method,headers:options.headers,body:options.body===undefined?undefined:JSON.parse(options.body)};calls.push(call);timeline.push(call.method+' '+path);if(handler){const custom=await handler(call,state);if(custom!==undefined)return custom;}if(path==='/hub-api/state')return response(state);throw Error('Unexpected controlled route: '+path);};
 const timers={setTimeout(fn,delay){const id=++timerId;pendingTimers.set(id,{fn,due:clock+delay});return id;},clearTimeout(id){pendingTimers.delete(id);}};
 const hub=createAccountHub({document:{getElementById:element},window,fetchImpl,timers,clock:()=>clock});
 return {hub,state,element,calls,popups,timeline,pendingTimers,focusListeners,setPopupBlocked(value){popupBlocked=value;},async advance(ms){const target=clock+ms;let count=0;while(true){const next=[...pendingTimers].sort((a,b)=>a[1].due-b[1].due)[0];if(!next||next[1].due>target)break;assert.ok(++count<20,'Polling must remain bounded');pendingTimers.delete(next[0]);clock=next[1].due;await next[1].fn();}clock=target;},posts:path=>calls.filter(call=>call.path===path&&call.method==='POST')};
}

test('remembered connection stays remembered without another request or popup, while advanced production-login status remains honest',async()=>{
 const state=initial();state.payment.supported=true;const f=fixture({state});await f.hub.load();
 assert.equal(f.element('gmail-badge').textContent,'已記住');assert.equal(f.element('gmail-connect').hidden,true);assert.equal(f.element('gmail-disconnect').hidden,false);assert.equal(f.element('gmail-account').textContent,'controlled@example.test');
 await f.hub.connect('gmail');assert.equal(f.calls.length,1);assert.equal(f.popups.length,0);assert.match(f.element('feedback').textContent,/不需要再次授權/);
 assert.equal(f.element('remember-device').checked,false);assert.equal(f.element('return-link').attributes.get('href'),'/continue');assert.match(f.element('advanced-login').textContent,/尚未完成/);assert.match(f.element('payment-note').textContent,/不會進行扣款/);f.hub.dispose();
});

test('authorization URLs and return links reject foreign origins, credentials, active protocols and secret-bearing return queries',()=>{
 assert.equal(safeAuthorizationUrl('mastodon',oauth),oauth);assert.equal(safeAuthorizationUrl('gmail','https://accounts.google.com/o/oauth2/v2/auth?client_id=CONTROLLED'),'https://accounts.google.com/o/oauth2/v2/auth?client_id=CONTROLLED');
 for(const value of ['javascript:alert(1)','http://mastodon.social/oauth/authorize','https://mastodon.social.evil.test/oauth/authorize','https://mastodon.social@evil.test/oauth/authorize','https://user:pass@mastodon.social/oauth/authorize','https://mastodon.social:8443/oauth/authorize','https://mastodon.social/auth/confirmation?confirmation_token=CONTROLLED','https://mastodon.social/oauth/authorize#CONTROLLED','https://accounts.google.com/o/oauth2/v2/auth'])assert.equal(safeAuthorizationUrl('mastodon',value),null);
 assert.equal(safeReturnPath('/continue?tab=accounts'),'/continue?tab=accounts');for(const value of ['//evil.test','https://evil.test','/\\evil.test','/continue?token=CONTROLLED','/continue?state=CONTROLLED','/continue#CONTROLLED','/continue\n'])assert.equal(safeReturnPath(value),null);
});

test('a synchronous blank window precedes the request, and an already-connected backend never opens an official URL',async()=>{
 const f=fixture({handler:(call,state)=>{if(call.path==='/hub-api/connect'){state.providers[1].phase='remembered';state.providers[1].canConnect=false;state.providers[1].canDisconnect=true;return response({status:'remembered',authorizationUrl:oauth});}}});await f.hub.load();
 await f.hub.connect('mastodon');assert.ok(f.timeline.indexOf('popup')<f.timeline.indexOf('POST /hub-api/connect'));assert.equal(f.popups.length,1);assert.equal(f.popups[0].opener,null);assert.equal(f.popups[0].closed,true);assert.deepEqual(f.popups[0].navigations,[]);assert.equal(f.element('mastodon-badge').textContent,'已記住');assert.equal(f.posts('/hub-api/connect').length,1);f.hub.dispose();
});

test('parallel clicks are admitted once and a blocked popup reopens the original authorization without another connect request',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});
 const f=fixture({popupBlocked:true,handler:async call=>{if(call.path==='/hub-api/connect'){await gate;return response({status:'requires_owner',authorizationUrl:oauth,expiresAt:NOW+60000});}}});await f.hub.load();
 const first=f.hub.connect('mastodon');assert.equal(f.posts('/hub-api/connect').length,1);await f.hub.connect('mastodon');assert.equal(f.posts('/hub-api/connect').length,1);release();await first;
 assert.match(f.element('feedback').textContent,/瀏覽器擋住/);assert.equal(f.element('mastodon-connect').textContent,'開啟官方授權');f.setPopupBlocked(false);await f.hub.connect('mastodon');assert.equal(f.posts('/hub-api/connect').length,1);assert.deepEqual(f.popups[0].navigations,[oauth]);f.hub.dispose();
});

test('foreign authorization targets and server errors fail closed without showing raw private error details',async()=>{
 for(const result of [response({status:'requires_owner',authorizationUrl:'https://evil.test/authorize?token=CONTROLLED_PRIVATE'}),response({error:'CONTROLLED_PRIVATE_PROVIDER_DETAILS'},503)]){
  const f=fixture({handler:call=>call.path==='/hub-api/connect'?result:undefined});await f.hub.load();await f.hub.connect('mastodon');assert.equal(f.popups[0].closed,true);assert.deepEqual(f.popups[0].navigations,[]);assert.match(f.element('feedback').textContent,/尚未確認/);assert.ok(!f.element('feedback').textContent.includes('CONTROLLED_PRIVATE'));assert.equal(f.posts('/hub-api/connect').length,1);assert.equal(f.pendingTimers.size,0);f.hub.dispose();
 }
});

test('automatic polling stops after five checks; focus only reads state and the original attempt, then records remembered state',async()=>{
 let complete=false;
 const f=fixture({handler:(call,state)=>{if(call.path==='/hub-api/connect'){Object.assign(state.providers[1],{phase:'needs_owner',canConnect:true,canDisconnect:true});return response({status:'pending',authorizationUrl:oauth,attemptId:'controlled-attempt',expiresAt:NOW+60000});}if(call.path==='/hub-api/attempt/controlled-attempt'){if(complete){state.providers[1].phase='remembered';state.providers[1].canConnect=false;return response({status:'remembered',returnPath:'/continue'});}return response({status:'requires_owner',note:'請完成官方確認。'});}}});await f.hub.load();await f.hub.connect('mastodon');await f.advance(10000);
 assert.equal(f.calls.filter(call=>call.path.includes('/attempt/')).length,5);assert.equal(f.pendingTimers.size,0);assert.equal(f.posts('/hub-api/connect').length,1);
 complete=true;await f.hub.focus();assert.equal(f.calls.filter(call=>call.path.includes('/attempt/')).length,6);assert.equal(f.posts('/hub-api/connect').length,1);assert.equal(f.element('mastodon-badge').textContent,'已記住');assert.equal(f.element('mastodon-connect').hidden,true);assert.match(f.element('feedback').textContent,/可以接續原本的工作/);f.hub.dispose();assert.equal(f.focusListeners.size,0);
});

test('disconnect and remember-device preferences use the server and CSRF, with failed preferences reverting visibly',async()=>{
 let failPreference=false;
 const f=fixture({handler:(call,state)=>{if(call.path==='/hub-api/disconnect'){state.providers[0].phase='not_connected';state.providers[0].canDisconnect=false;state.providers[0].canConnect=true;return response({status:'disconnected'});}if(call.path==='/hub-api/preferences'){if(failPreference)return response({error:'CONTROLLED_PRIVATE'},503);state.rememberDevice=call.body.rememberDevice;return response({status:'saved'});}}});await f.hub.load();f.element('remember-device').checked=true;await f.hub.preferences();assert.equal(f.state.rememberDevice,true);assert.equal(f.element('remember-device').checked,true);assert.match(f.element('feedback').textContent,/不是雲端登入/);
 failPreference=true;f.element('remember-device').checked=false;await f.hub.preferences();assert.equal(f.state.rememberDevice,true);assert.equal(f.element('remember-device').checked,true);assert.match(f.element('feedback').textContent,/尚未確認.*已保存.*原本設定/);
 await f.hub.disconnect('gmail');assert.equal(f.element('gmail-badge').textContent,'尚未連接');assert.equal(f.element('gmail-connect').hidden,false);assert.equal(f.posts('/hub-api/disconnect').length,1);for(const call of f.calls.filter(call=>call.method==='POST'))assert.equal(call.headers['x-hub-csrf'],CSRF);assert.deepEqual(f.posts('/hub-api/disconnect')[0].body,{provider:'gmail'});f.hub.dispose();
});

test('a preference acknowledgement without a successful state readback cannot be presented as saved',async()=>{
 let failReadback=false;const f=fixture({handler:call=>{if(call.path==='/hub-api/preferences'){failReadback=true;return response({status:'saved'});}if(call.path==='/hub-api/state'&&failReadback)return response({error:'CONTROLLED_PRIVATE'},503);}});await f.hub.load();f.element('remember-device').checked=true;await f.hub.preferences();assert.equal(f.element('remember-device').checked,false);assert.match(f.element('feedback').textContent,/尚未確認.*是否已保存/);assert.ok(!f.element('feedback').textContent.startsWith('已在這台裝置'));assert.equal(f.posts('/hub-api/preferences').length,1);f.hub.dispose();
});

test('an unknown connection exposes an explicit cancel action without automatically requesting another authorization',async()=>{
 const state=initial();Object.assign(state.providers[1],{phase:'needs_owner',canConnect:false,canDisconnect:true,note:'這次連接結果尚未確認，可以先取消這次連接。'});
 const f=fixture({state,handler:(call,current)=>{if(call.path==='/hub-api/disconnect'){Object.assign(current.providers[1],{phase:'not_connected',canConnect:true,canDisconnect:false});return response({disconnected:true,cancelled:true});}}});await f.hub.load();assert.equal(f.element('mastodon-connect').disabled,true);assert.equal(f.element('mastodon-disconnect').hidden,false);assert.equal(f.element('mastodon-disconnect').textContent,'取消這次連接');
 await f.hub.disconnect('mastodon');assert.equal(f.posts('/hub-api/disconnect').length,1);assert.equal(f.posts('/hub-api/connect').length,0);assert.equal(f.element('mastodon-connect').disabled,false);assert.equal(f.element('mastodon-disconnect').hidden,true);assert.match(f.element('feedback').textContent,/已取消這次.*原專案已保留/);f.hub.dispose();
});

test('a server-confirmed cancellation in another session discards a cached authorization URL before the next explicit connection',async()=>{
 let starts=0;const f=fixture({handler:(call,state)=>{if(call.path==='/hub-api/connect'){starts++;Object.assign(state.providers[1],{phase:'needs_owner',canConnect:true,canDisconnect:true});return response({status:'requires_owner',authorizationUrl:oauth+'&attempt='+starts,expiresAt:NOW+60000});}}});await f.hub.load();await f.hub.connect('mastodon');assert.equal(starts,1);Object.assign(f.state.providers[1],{phase:'not_connected',canConnect:true,canDisconnect:false});await f.hub.load();assert.equal(starts,1);assert.equal(f.element('mastodon-connect').textContent,'連接 Mastodon');await f.hub.connect('mastodon');assert.equal(starts,2);assert.deepEqual(f.popups.at(-1).navigations,[oauth+'&attempt=2']);f.hub.dispose();
});

test('normal markup offers no passwords, cards, owner keys or technical task controls; advanced details start collapsed',async()=>{
 const html=await readFile(new URL('../src/account-hub/ui/index.html',import.meta.url),'utf8'),script=await readFile(new URL('../src/account-hub/ui/app.mjs',import.meta.url),'utf8');
 assert.match(html,/<html lang="zh-Hant"/);assert.match(html,/<meta name="referrer" content="no-referrer">/);assert.match(html,/href="\/styles.css"/);assert.match(html,/src="\/owner-start.mjs"/);assert.match(html,/本機單人安裝/);assert.match(html,/在這台裝置記住目前專案/);assert.match(html,/<details class="advanced">/);assert.ok(!/<details[^>]*\bopen\b/.test(html));assert.ok(!/<input[^>]*type="(?:password|number|email)"/.test(html));assert.deepEqual([...html.matchAll(/<input\b[^>]*>/g)].map(match=>match[0]),['<input id="remember-device" type="checkbox" disabled>']);
 assert.ok(!/localStorage|sessionStorage|console\.|innerHTML|document\.write/.test(script));assert.ok(!/taskId|CSRF|writeLimit|ownerKey/.test(html));assert.match(html,/付款授權或代為付款/);assert.match(html,/<button class="secondary-button" type="button" disabled>尚未開放<\/button>/);
});
