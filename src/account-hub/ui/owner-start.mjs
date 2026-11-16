// SPDX-License-Identifier: Apache-2.0
import {createAccountHub} from './app.mjs';
import {createAgentPanel} from './agent-access.mjs';
import {readOwnerProof,rememberOwnerProof,clearOwnerProof,withOwnerProof} from './owner-proof.mjs';
export async function startOwnerPage({document,window,fetchImpl}){
 let routed=false;
 function routeFragment(){
  if(!window.location.hash)return false;
  const fragment=window.location.hash;let token=null;
  try{window.history.replaceState(null,'','/account-hub');const values=new URLSearchParams(fragment.slice(1));if(values.getAll('pair').length===1&&[...values.keys()].length===1&&/^[A-Za-z0-9_-]{43}$/.test(values.get('pair')??''))token=values.get('pair');}catch{routed=true;window.location.replace('/account-hub/activate');return true;}
  if(token){routed=true;window.location.replace('/account-hub/activate#pair='+token);return true;}return false;
 }
 window.addEventListener('hashchange',routeFragment);
 if(routeFragment())return;
 if(!readOwnerProof(window)){window.location.replace('/account-hub/activate');return;}
 const ownedFetch=withOwnerProof(window,fetchImpl),hub=createAccountHub({document,window,fetchImpl:ownedFetch,rememberOwner:value=>rememberOwnerProof(window,value),clearOwner:()=>clearOwnerProof(window)});
 if(!await hub.load()){clearOwnerProof(window);window.location.replace('/account-hub/activate');return;}
 if(routed)return;const panel=createAgentPanel({document,window,fetchImpl:ownedFetch});await panel.load();
}
if(typeof window!=='undefined'&&typeof document!=='undefined')void startOwnerPage({document,window,fetchImpl:window.fetch.bind(window)});
