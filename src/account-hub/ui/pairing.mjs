// SPDX-License-Identifier: Apache-2.0
import {storeOwnerProof,withOwnerProof} from './owner-proof.mjs';
export function createPairingPage({document,window,fetchImpl,saveProof=value=>storeOwnerProof(window,value,false)}){
 let token=null,activeRequest=false,generation=0;
 const button=document.getElementById('activate-owner'),status=document.getElementById('pairing-status');
 function consumeFragment(){
  generation++;token=null;
  // A same-document hash navigation does not execute this module again.
  // Consume and clear every new fragment synchronously before any request.
  try{const fragment=window.location.hash;window.history.replaceState(null,'','/account-hub/activate');const values=new URLSearchParams(fragment.startsWith('#')?fragment.slice(1):fragment);if(values.getAll('pair').length===1&&[...values.keys()].length===1&&/^[A-Za-z0-9_-]{43}$/.test(values.get('pair')??''))token=values.get('pair');}catch{try{window.location.replace('/account-hub/activate');}catch{}}
  button.disabled=!token||activeRequest;
  status.textContent=token?(activeRequest?'正在核對前一次啟用。新連結已保留，請稍候再按啟用。':'啟用連結已準備好。請本人按下按鈕，開啟這台裝置的管理權限。'):'沒有可用的啟用連結。請使用本人終端產生的新連結，不用輸入任何平台密碼。';
 }
 consumeFragment();window.addEventListener('hashchange',consumeFragment);
 async function activate(){
  if(!token||activeRequest)return;activeRequest=true;const current=generation;let material=token;token=null;button.disabled=true;status.textContent='正在啟用這台裝置…';
  try{
   const challenge=await fetchImpl('/hub-api/pairing/challenge',{credentials:'same-origin',cache:'no-store',redirect:'error',headers:{accept:'application/json'}});if(!challenge.ok)throw Error('pairing_not_ready');const value=await challenge.json();if(current!==generation)return;if(typeof value.csrf!=='string'||!value.csrf||value.csrf.length>512||/[\r\n]/.test(value.csrf))throw Error('pairing_not_ready');
   const result=await fetchImpl('/hub-api/pairing/complete',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{accept:'application/json','content-type':'application/json','x-hub-csrf':value.csrf},body:JSON.stringify({token:material})});material=null;if(!result.ok)throw Error('pairing_not_completed');const completed=await result.json();if(current!==generation)return;if(completed.paired!==true||typeof completed.ownerProof!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(completed.ownerProof))throw Error('pairing_not_completed');saveProof(completed.ownerProof);window.location.replace('/account-hub');
  }catch{
   material=null;if(current!==generation)return;
   // A lost response is not permission to reuse the token. Only check whether
   // its owner session was already delivered; never repeat the pairing POST.
   try{const check=await withOwnerProof(window,fetchImpl)('/hub-api/state',{credentials:'same-origin',cache:'no-store',redirect:'error',headers:{accept:'application/json'}});if(current!==generation)return;if(check.ok){window.location.replace('/account-hub');return;}}catch{}
   if(current!==generation)return;status.textContent='尚未確認啟用成功。連結可能已使用或到期；請回本人終端取得新連結，不會自動重送。';
  }finally{material=null;activeRequest=false;if(current!==generation){button.disabled=!token;status.textContent=token?'啟用連結已準備好。請本人按下按鈕，開啟這台裝置的管理權限。':'沒有可用的啟用連結。請使用本人終端產生的新連結，不用輸入任何平台密碼。';}}
 }
 button.addEventListener('click',activate);return {activate,dispose(){token=null;generation++;window.removeEventListener('hashchange',consumeFragment);}};
}
if(typeof window!=='undefined'&&typeof document!=='undefined')createPairingPage({document,window,fetchImpl:window.fetch.bind(window)});
