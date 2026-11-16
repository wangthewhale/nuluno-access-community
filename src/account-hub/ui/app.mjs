const PROVIDERS=['gmail','mastodon'];
const PHASES=new Set(['remembered','needs_owner','expired','not_connected','configuration_required']);
const PHASE_LABELS={remembered:'已記住',needs_owner:'需要你確認',expired:'連接已失效',not_connected:'尚未連接',configuration_required:'需要準備'};
const LABELS={gmail:'Gmail',mastodon:'Mastodon'};
const note=(value,fallback='')=>typeof value==='string'&&value.length<=600?value:fallback;
const opaque=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,180}$/.test(value);

export function safeAuthorizationUrl(provider,value){
 if(typeof value!=='string'||value.length>12000)return null;
 try{const url=new URL(value);if(url.protocol!=='https:'||url.username||url.password||url.hash)return null;
  if(provider==='gmail'&&url.origin==='https://accounts.google.com'&&['/o/oauth2/v2/auth','/o/oauth2/auth'].includes(url.pathname))return url.href;
  if(provider==='mastodon'&&url.origin==='https://mastodon.social'&&url.pathname==='/oauth/authorize')return url.href;
 }catch{}return null;
}
export function safeReturnPath(value){
 if(typeof value!=='string'||value.length>2000||!value.startsWith('/')||value.startsWith('//')||value.includes('#')||/[\\\u0000-\u0020]/.test(value))return null;
 try{const url=new URL(value,'https://local.invalid');if(url.origin!=='https://local.invalid'||url.hash||[...url.searchParams.keys()].some(key=>/token|secret|password|passwd|state|code|key|csrf|nonce|session|credential|authorization|ticket|otp/i.test(key)))return null;return url.pathname+url.search;}catch{return null;}
}
function checkedState(value){
 if(!value||value.mode!=='isolated-local'||typeof value.csrf!=='string'||!value.csrf.length||value.csrf.length>512||/[\r\n]/.test(value.csrf)||typeof value.rememberDevice!=='boolean'||!Array.isArray(value.providers))throw Error('invalid_hub_state');
 const providers=PROVIDERS.map(id=>{const matches=value.providers.filter(item=>item?.id===id);if(matches.length!==1||!PHASES.has(matches[0].phase))throw Error('invalid_hub_state');return {...matches[0],canConnect:matches[0].canConnect===true,canDisconnect:matches[0].canDisconnect===true};});
 return {...value,providers};
}

export function createAccountHub({document,window,fetchImpl,timers={setTimeout,clearTimeout},clock=Date.now,rememberOwner=()=>{},clearOwner=()=>{}}){
 const element=id=>document.getElementById(id),busy=new Set(),authorizations=new Map(),attempts=new Map();
 let state=null,disposed=false,loading=null,focusPending=false;
 const feedback=(message,tone='neutral')=>{element('feedback').textContent=message;element('feedback').dataset.tone=tone;};
 const closePopup=popup=>{try{popup?.close();}catch{}};
 const openBlank=()=>{let popup=null;try{popup=window.open('about:blank','_blank','popup,width=560,height=720');if(popup){popup.opener=null;try{popup.document.title='連接帳號';popup.document.body.textContent='正在準備官方授權頁面…';}catch{}}}catch{}return popup;};
 const findProvider=id=>state?.providers.find(item=>item.id===id);
 async function api(path,{method='GET',body}={}){
  const headers={Accept:'application/json'};
  if(method==='POST'){if(!state)throw Error('hub_not_ready');headers['content-type']='application/json';headers['x-hub-csrf']=state.csrf;}
  const response=await fetchImpl(path,{method,headers,credentials:'same-origin',cache:'no-store',redirect:'error',...(body===undefined?{}:{body:JSON.stringify(body)})});
  if(!response.ok){const error=Error('hub_request_failed');error.status=response.status;throw error;}return response.json();
 }
 function stopAttempt(id){const current=attempts.get(id);if(current?.timer!==undefined)timers.clearTimeout(current.timer);attempts.delete(id);}
 function render(){
  if(!state)return;
  element('project-label').textContent=note(state.project?.label,'目前專案');
  for(const id of PROVIDERS){
   const provider=findProvider(id),badge=element(id+'-badge'),connect=element(id+'-connect'),disconnect=element(id+'-disconnect'),account=element(id+'-account');
   badge.textContent=PHASE_LABELS[provider.phase];badge.className='badge '+(provider.phase==='remembered'?'connected':provider.phase==='expired'?'error':['needs_owner','configuration_required'].includes(provider.phase)?'warning':'neutral');
   account.hidden=!provider.accountLabel;account.textContent=note(provider.accountLabel);
   element(id+'-note').textContent=note(provider.note,provider.phase==='remembered'?'已保存這次連接，不用再次授權。':'只會在你按下按鈕後開啟官方授權。');
   if(provider.phase==='remembered'){authorizations.delete(id);stopAttempt(id);}
   connect.hidden=provider.phase==='remembered';connect.disabled=busy.has(id)||!provider.canConnect;
   connect.textContent=busy.has(id)?'正在處理…':authorizations.has(id)?'開啟官方授權':provider.phase==='expired'?'重新連接 '+LABELS[id]:provider.phase==='needs_owner'?'繼續確認':provider.phase==='configuration_required'?'等待連接準備':'連接 '+LABELS[id];
   disconnect.hidden=!provider.canDisconnect;disconnect.disabled=busy.has(id);disconnect.textContent=provider.phase==='remembered'?'解除連接':'取消這次連接';
  }
  element('remember-device').checked=state.rememberDevice;element('remember-device').disabled=busy.has('preferences');
  const context=state.context??{},returnPath=safeReturnPath(context.returnPath);element('return-panel').hidden=context.hasTask!==true;element('return-label').textContent=note(context.label,'你的工作會保留，不用重新交代。');element('return-link').hidden=!returnPath;if(returnPath)element('return-link').setAttribute('href',returnPath);else element('return-link').removeAttribute('href');
  const advanced=state.advanced??{};element('advanced-mode').textContent=advanced.localOwnerMode===true?'本機管理模式':'目前本機預覽';element('advanced-vault').textContent=advanced.persistentVault===true?'由本機服務持續保存，可解除':'尚待確認';element('advanced-google').textContent=advanced.googleConfigured===true?'已準備':'尚待設定';element('advanced-callback').textContent=note(advanced.googleCallback,'尚待設定');element('advanced-login').textContent=advanced.ownerLoginProductionReady===true?'此預覽仍使用本機管理模式':'尚未完成；目前使用本機預覽';
  // Payment remains unsupported regardless of an unexpected server flag.
  element('payment-note').textContent='目前不會收取卡號，也不會進行扣款。';
 }
 async function load({quiet=false}={}){
  if(loading)return loading;
  element('refresh').disabled=true;
  loading=(async()=>{try{const next=checkedState(await api('/hub-api/state'));if(disposed)return;state=next;for(const provider of state.providers)if(provider.phase==='remembered'||!provider.canDisconnect&&['not_connected','expired','configuration_required'].includes(provider.phase)){authorizations.delete(provider.id);stopAttempt(provider.id);}render();if(!quiet)feedback('已更新連接狀態。已記住的帳號不需要再次授權。');return state;}catch{if(!disposed)feedback('目前無法讀取連接狀態。請按「重新整理」再確認；不會重新授權或重送工作。','error');return null;}finally{loading=null;element('refresh').disabled=false;}})();return loading;
 }
 async function checkAttempt(id,current){
  if(disposed||attempts.get(id)!==current)return;
  try{const result=await api('/hub-api/attempt/'+encodeURIComponent(current.id));if(disposed||attempts.get(id)!==current)return;
   if(result.status==='remembered'){authorizations.delete(id);stopAttempt(id);await load({quiet:true});feedback(LABELS[id]+' 已記住，可以接續原本的工作。','success');return;}
   if(result.status==='expired'){authorizations.delete(id);stopAttempt(id);await load({quiet:true});feedback('這次 '+LABELS[id]+' 連接已到期。需要時請明確按「重新連接」，不會自行重做授權。','error');return;}
   if(result.status!=='requires_owner')throw Error('invalid_attempt');
   if(typeof result.note==='string')feedback(note(result.note,'請在官方頁面完成確認。'));
  }catch{if(!disposed)feedback('尚未確認連接結果。請保留官方頁面，回來後按「重新整理」；不會自動重新授權。','error');}
 }
 function startPoll(id,attemptId){
  stopAttempt(id);const current={id:attemptId,count:0,startedAt:clock(),timer:undefined};attempts.set(id,current);
  const tick=async()=>{if(disposed||attempts.get(id)!==current)return;current.count++;await checkAttempt(id,current);if(attempts.get(id)===current&&current.count<5&&clock()-current.startedAt<5000)current.timer=timers.setTimeout(tick,1000);};
  current.timer=timers.setTimeout(tick,1000);
 }
 function navigateAuthorization(id,popup){
  const saved=authorizations.get(id);if(!saved)return false;
  if(saved.expiresAt!==undefined&&saved.expiresAt<=clock()){authorizations.delete(id);closePopup(popup);feedback('這次授權頁面已到期。請重新確認連接狀態；不會自動重做授權。','error');render();return false;}
  if(!popup){feedback('瀏覽器擋住了授權視窗。請按「開啟官方授權」開啟同一次連接，不用重新申請。','error');render();return false;}
  try{popup.location.replace(saved.url);feedback('請在 '+LABELS[id]+' 官方頁面完成確認，完成後回到這個頁面。');return true;}catch{closePopup(popup);feedback('尚未開啟官方頁面。請再次按「開啟官方授權」；不會建立另一筆連接。','error');render();return false;}
 }
 async function connect(id){
  const provider=findProvider(id);if(!provider||busy.has(id)||disposed)return;
  if(provider.phase==='remembered'){feedback(LABELS[id]+' 已記住，不需要再次授權。','success');return;}
  if(!provider.canConnect)return;
  // Synchronously reserve a blank window during this explicit user gesture.
  const popup=openBlank();if(authorizations.has(id)){navigateAuthorization(id,popup);return;}
  busy.add(id);render();
  try{const result=await api('/hub-api/connect',{method:'POST',body:{provider:id}});if(disposed){closePopup(popup);return;}
   if(result.status==='remembered'){closePopup(popup);authorizations.delete(id);stopAttempt(id);await load({quiet:true});feedback(LABELS[id]+' 已記住，不需要再次授權。','success');return;}
   if(result.status==='configuration_required'){closePopup(popup);await load({quiet:true});feedback(note(result.note,'連接設定尚未準備好，請查看進階設定。'),'error');return;}
   if(!['requires_owner','pending'].includes(result.status))throw Error('invalid_connect');
   if(result.authorizationUrl!==undefined){const url=safeAuthorizationUrl(id,result.authorizationUrl);if(!url)throw Error('untrusted_authorization_url');if(result.expiresAt!==undefined&&(!Number.isSafeInteger(result.expiresAt)||result.expiresAt<=clock()))throw Error('expired_authorization_url');authorizations.set(id,{url,...(result.expiresAt===undefined?{}:{expiresAt:result.expiresAt})});navigateAuthorization(id,popup);}else{closePopup(popup);feedback(note(result.note,'這次連接需要本人確認。請完成官方頁面的步驟，再回來重新整理。'));}
   if(opaque(result.attemptId))startPoll(id,result.attemptId);
  }catch{closePopup(popup);feedback('尚未確認這次連接是否完成。請先重新整理狀態；不會自行重做授權。','error');}
  finally{busy.delete(id);render();}
 }
 async function disconnect(id){
  const provider=findProvider(id);if(!provider?.canDisconnect||busy.has(id)||disposed)return;busy.add(id);render();
  try{await api('/hub-api/disconnect',{method:'POST',body:{provider:id}});authorizations.delete(id);stopAttempt(id);const confirmed=await load({quiet:true});if(!confirmed||findProvider(id)?.canDisconnect){feedback('尚未完整核對解除結果，請重新整理查看；不會重新授權。','error');return;}feedback(provider.phase==='remembered'?'已解除 '+LABELS[id]+' 連接。需要時可由你再次連接。':'已取消這次 '+LABELS[id]+' 連接，原專案已保留。需要時請由你重新連接。');}catch{feedback('尚未確認是否已解除連接。請重新整理查看，不會重複送出。','error');}finally{busy.delete(id);render();}
 }
 async function preferences(){
  if(!state||busy.has('preferences')||disposed)return;const rememberDevice=element('remember-device').checked;busy.add('preferences');render();
  try{await api('/hub-api/preferences',{method:'POST',body:{rememberDevice}});const confirmed=await load({quiet:true});if(!confirmed||confirmed.rememberDevice!==rememberDevice){feedback('尚未確認這個選擇是否已保存，畫面先保留目前設定。請重新整理查看。','error');return;}rememberOwner(rememberDevice);feedback(rememberDevice?'已在這台裝置記住目前專案；這不是雲端登入。':'已關閉這台裝置的專案記憶。');}catch{feedback('尚未確認這個選擇是否已保存，畫面先保留原本設定。請重新整理查看。','error');}finally{busy.delete('preferences');render();}
 }
 async function focus(){
  if(disposed||focusPending)return;focusPending=true;try{await load({quiet:true});for(const [id,current]of [...attempts])await checkAttempt(id,current);}finally{focusPending=false;}
 }
 for(const id of PROVIDERS){element(id+'-connect').addEventListener('click',()=>connect(id));element(id+'-disconnect').addEventListener('click',()=>disconnect(id));}
 element('remember-device').addEventListener('change',preferences);element('refresh').addEventListener('click',()=>load());window.addEventListener('focus',focus);element('device-signout')?.addEventListener('click',async()=>{try{await api('/hub-api/logout',{method:'POST',body:{}});}finally{clearOwner();window.location.replace('/account-hub/activate');}});
 return {load,connect,disconnect,preferences,focus,dispose(){disposed=true;for(const id of PROVIDERS)stopAttempt(id);authorizations.clear();window.removeEventListener('focus',focus);}};
}
