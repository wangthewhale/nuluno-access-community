// SPDX-License-Identifier: Apache-2.0
export function createAgentPanel({document,window,fetchImpl}){
 const el=id=>document.getElementById(id),button=el('create-public-agent'),feedback=el('agent-feedback'),list=el('agent-list');
 let csrf=null,busy=false,requestKey=null,created=false;
 const message=text=>{feedback.textContent=text;};
 async function api(path,body){const response=await fetchImpl(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{accept:'application/json',...(body===undefined?{}:{'content-type':'application/json','x-hub-csrf':csrf??''})},...(body===undefined?{}:{body:JSON.stringify(body)})});if(!response.ok)throw Error('agent_operation_not_confirmed');return response.json();}
 function controls(){button.disabled=!csrf||busy||created;button.textContent=created?'已建立這次連接':busy?'正在處理…':'建立公共只讀連接';}
 function action(label,handler,disabled=false){const item=document.createElement('button');item.type='button';item.className='secondary-button';item.textContent=label;item.disabled=disabled;item.addEventListener('click',handler);return item;}
 async function refresh(){
  const result=await api('/hub-api/agents');if(!Array.isArray(result.agents))throw Error('invalid_agent_list');
  const rows=[];for(const item of result.agents){const grant=item.grant;if(item.preset!=='public-read'||!grant||typeof grant.id!=='string'||!/^[0-9a-f-]{36}$/i.test(grant.id))continue;
   const row=document.createElement('div');row.className='agent-row';const copy=document.createElement('div'),title=document.createElement('strong'),description=document.createElement('p');title.textContent='公共資料只讀 agent';description.className='provider-note';description.textContent=grant.revokedAt!==null?'已撤銷':item.connectionAvailable?'有效至 '+new Date(grant.expiresAt).toLocaleString('zh-TW'):'已到期或尚無可用連接資料';copy.append(title,description);const actions=document.createElement('div');actions.className='card-actions';actions.append(action('下載 MCP 連接資料',()=>download(grant.id),!item.connectionAvailable),action('撤銷連接',()=>revoke(grant.id),grant.revokedAt!==null));row.append(copy,actions);rows.push(row);
  }
  if(rows.length)list.replaceChildren(...rows);else{list.replaceChildren();list.textContent='尚未建立 AI agent 連接。';}
 }
 async function load(){try{const state=await api('/hub-api/state');if(typeof state.csrf!=='string'||!state.csrf||/[\r\n]/.test(state.csrf))throw Error('owner_not_ready');csrf=state.csrf;await refresh();message('只在你按下建立時，才會授予這個 agent 公共資料的讀取權限。');}catch{csrf=null;message('尚未讀取本人授權狀態。請重新整理帳號中心，不會自動建立 agent 權限。');}finally{controls();}}
 async function create(){
  if(!csrf||busy||created)return;busy=true;controls();
  try{requestKey??=window.crypto.randomUUID();const result=await api('/hub-api/agents',{requestKey,preset:'public-read'});if(result.preset!=='public-read'||!result.grant?.id)throw Error('grant_not_confirmed');created=true;await refresh();message('已建立公共只讀連接。按下載，再依你的 agent 使用的格式連接。');}catch{message(created?'建立已收到，但尚未更新列表。請按更新列表核對，不會再建立另一份權限。':'尚未完整核對建立結果。再按時會沿用同一次請求，不會重建或延長原授權。');}finally{busy=false;controls();}
 }
 async function download(id){
  if(!csrf||busy)return;busy=true;controls();
  try{const result=await api('/hub-api/agents/'+encodeURIComponent(id)+'/connection',{client:'mcp-http'}),configuration=result.configuration;
   if(configuration?.transport!=='streamable-http'||configuration.url!==window.location.origin+'/mcp'||typeof configuration.headers?.Authorization!=='string'||!configuration.headers.Authorization.startsWith('Bearer ')||!configuration.headers.Authorization.slice(7).trim()||/[\r\n]/.test(configuration.headers.Authorization)||Object.keys(configuration.headers).length!==1)throw Error('connection_not_confirmed');
   const safe={transport:'streamable-http',url:configuration.url,headers:{Authorization:configuration.headers.Authorization}};
   const blob=new window.Blob([JSON.stringify(safe,null,2)+'\n'],{type:'application/json'}),url=window.URL.createObjectURL(blob),anchor=document.createElement('a');anchor.href=url;anchor.download='nuluno-public-read-mcp.json';document.body.append(anchor);anchor.click();anchor.remove();window.setTimeout(()=>window.URL.revokeObjectURL(url),1000);message('已準備下載這個 agent 的短效連接資料。請保密保存，只交給你要使用的 agent。');
  }catch{message('目前無法下載。授權可能已到期或撤銷；請更新列表，不會自行建立新的權限。');}finally{busy=false;controls();}
 }
 async function revoke(id){
  if(!csrf||busy)return;busy=true;controls();
  try{const result=await api('/hub-api/agents/'+encodeURIComponent(id)+'/revoke',{});if(result.revoked!==true)throw Error('revocation_not_confirmed');await refresh();message('已撤銷這個 agent 的連接；原任務與紀錄會保留。');}catch{message('尚未完整核對撤銷結果。請更新列表確認，不會建立替代權限。');}finally{busy=false;controls();}
 }
 button.addEventListener('click',create);el('refresh-agents').addEventListener('click',()=>refresh().catch(()=>message('尚未讀取最新列表，請稍後再確認。')));return {load,create,download,revoke};
}
