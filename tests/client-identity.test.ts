/** Actual loopback HTTP + stdio processes; no external grants or providers. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {NulunoAccessClient,AccessTransportError,ACCESS_USER_AGENT} from '../src/core/client';

const key='nla2.controlled_identity_fixture_not_production';
const sensitive='private-ip-192.0.2.42 '+key;
async function fixture(){
 const received:{path:string;headers:Record<string,unknown>;body:string}[]=[];
 let status=200,type='application/json',body='{"id":"original-task","status":"succeeded"}',serverName='cloudflare',challenge='';
 const server=createServer(async(req,res)=>{
  const parts:Buffer[]=[];for await(const part of req)parts.push(Buffer.from(part));
  received.push({path:req.url!,headers:req.headers,body:Buffer.concat(parts).toString()});
  res.writeHead(status,{'content-type':type,...(serverName?{server:serverName}:{}),...(challenge?{'www-authenticate':challenge}:{})});res.end(body);
 });
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 const origin='http://127.0.0.1:'+(server.address() as any).port;
 return {origin,received,set(s:number,t:string,b:string,server='cloudflare',auth=''){status=s;type=t;body=b;serverName=server;challenge=auth;},
  client:new NulunoAccessClient({baseUrl:origin+'/api/access/v1',accessKey:key}),
  close:()=>new Promise<void>(r=>server.close(()=>r()))};
}

test('SDK identifies its exact version while preserving original opaque authorization and POST identity',async()=>{
 const f=await fixture();try{
  const input={statusId:'123',idempotencyKey:'original-public-request'};
  const result=await f.client.readPublicStatus(input);assert.equal(result.id,'original-task');
  assert.equal(f.received.length,1);assert.equal(f.received[0].path,'/api/access/v1/read-public-status');
  assert.equal(f.received[0].headers['user-agent'],ACCESS_USER_AGENT);
  assert.equal(f.received[0].headers.authorization,'Bearer '+key);assert.deepEqual(JSON.parse(f.received[0].body),input);
 }finally{await f.close();}
});

test('a confirmed Cloudflare HTML Error 1010 is transport identity, not owner authorization, and is never retried',async()=>{
 const f=await fixture();try{
  f.set(403,'text/html; charset=utf-8','<html>Cloudflare<h1>Error <span>1010</span></h1>'+sensitive+'</html>');
  await assert.rejects(f.client.readPublicStatus({statusId:'123',idempotencyKey:'same-original'}),(error:unknown)=>{
   assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'transport_client_identity_rejected');
   assert.equal(error.status,403);assert.equal(error.requiresOwnerAuthorization,false);assert.equal(error.reconcileOnly,true);
   assert.equal(String(error).includes(key),false);assert.equal(JSON.stringify(error).includes('192.0.2'),false);return true;
  });
  assert.equal(f.received.length,1);assert.equal(JSON.parse(f.received[0].body).idempotencyKey,'same-original');
 }finally{await f.close();}
});

test('the actual text/plain error code 1010 requires Cloudflare server identity and the exact plain error',async()=>{
 const f=await fixture();try{
  f.set(403,'text/plain; charset=UTF-8','error code: 1010\n');
  await assert.rejects(f.client.status(),(error:unknown)=>{
   assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'transport_client_identity_rejected');
   assert.equal(error.requiresOwnerAuthorization,false);assert.equal(String(error).includes('error code:'),false);return true;
  });
  for(const [body,server] of [['error code: 1010\n',''],['error code: 1010\n'+sensitive,'cloudflare']]){
   f.set(403,'text/plain; charset=UTF-8',body,server);
   await assert.rejects(f.client.status(),(error:unknown)=>{
    assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'access_invalid_response');
    assert.equal(error.requiresOwnerAuthorization,false);assert.equal(String(error).includes(key),false);return true;
   });
  }
 }finally{await f.close();}
});

test('a recognized Cloudflare block page without an auth challenge is an edge rejection',async()=>{
 const f=await fixture();try{
  const body='<html><title>Attention Required! | Cloudflare</title><h1 data-translate="block_headline">Sorry, you have been blocked</h1>'+sensitive+'</html>';
  f.set(403,'text/html',body);
  await assert.rejects(f.client.status(),(error:unknown)=>{
   assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'transport_edge_rejected');assert.equal(error.requiresOwnerAuthorization,false);
   assert.equal(String(error).includes(key),false);return true;
  });
  f.set(403,'text/html',body,'cloudflare','Bearer realm="actual-auth-challenge"');
  await assert.rejects(f.client.status(),(error:unknown)=>{
   assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'access_invalid_response');return true;
  });
 }finally{await f.close();}
});

test('structured 401 invalid key and 403 revoked/scope denial remain real authorization errors',async()=>{
 const f=await fixture();try{
  for(const [status,code] of [[401,'access_invalid_key'],[403,'access_revoked'],[403,'access_scope_denied']] as const){
   f.set(status,'application/json',JSON.stringify({error:code,message:'Cloudflare Error 1010 '+sensitive}));
   await assert.rejects(f.client.status(),(error:unknown)=>{
    assert.ok(error instanceof AccessTransportError);assert.equal(error.code,code);assert.equal(error.status,status);
    assert.equal(error.requiresOwnerAuthorization,true);assert.equal(String(error).includes(key),false);return true;
   });
  }
  assert.equal(f.received.length,3);
 }finally{await f.close();}
});

test('incidental numbers and non-Cloudflare HTML cannot assert a client-identity cause',async()=>{
 const f=await fixture();try{
  for(const body of ['<html>Cloudflare catalog contains 1010 items '+sensitive+'</html>','<html>Error 1010 '+sensitive+'</html>']){
   // First has no error code; second has no Cloudflare body or server marker.
   f.set(403,'text/html',body,body.includes('Cloudflare')?'cloudflare':'');
   await assert.rejects(f.client.status(),(error:unknown)=>{
    assert.ok(error instanceof AccessTransportError);assert.equal(error.code,'access_invalid_response');
    assert.equal(error.requiresOwnerAuthorization,false);assert.equal(String(error).includes(key),false);return true;
   });
  }
 }finally{await f.close();}
});

async function bridge(origin:string):Promise<{code:number|null;stdout:string;stderr:string}>{
 const script=fileURLToPath(new URL('../scripts/mcp-stdio-bridge.mjs',import.meta.url));
 const child=spawn(process.execPath,[script],{env:{PATH:process.env.PATH??'',NULUNO_ACCESS_MCP_URL:origin+'/mcp',NULUNO_ACCESS_KEY:key},stdio:['pipe','pipe','pipe']});
 let stdout='',stderr='';child.stdout.on('data',b=>stdout+=b);child.stderr.on('data',b=>stderr+=b);
 return new Promise((resolve,reject)=>{
  const timeout=setTimeout(()=>{child.kill('SIGKILL');reject(Error('bridge_fixture_timeout'));},8000);
  child.once('error',error=>{clearTimeout(timeout);reject(error);});
  child.once('exit',code=>{clearTimeout(timeout);resolve({code,stdout,stderr});});
 });
}

test('stdio uses the same truthful UA and emits only safe identity-versus-authorization failure metadata',async()=>{
 const f=await fixture();try{
  const cases=[{status:403,type:'text/html',body:'<html>Cloudflare Error 1010 '+sensitive+'</html>',code:'transport_client_identity_rejected',authorization:false},
   {status:403,type:'text/plain; charset=UTF-8',body:'error code: 1010\n',code:'transport_client_identity_rejected',authorization:false},
   {status:403,type:'text/html',body:'<title>Attention Required! | Cloudflare</title><h1 data-translate="block_headline">Blocked</h1>'+sensitive,code:'transport_edge_rejected',authorization:false},
   {status:401,type:'application/json',body:JSON.stringify({error:'access_invalid_key',private:sensitive}),code:'access_invalid_key',authorization:true},
   {status:403,type:'application/json',body:JSON.stringify({error:'access_revoked',private:sensitive}),code:'access_revoked',authorization:true}];
  for(const input of cases){
   f.set(input.status,input.type,input.body);const before=f.received.length,result=await bridge(f.origin);
   assert.equal(result.code,1);assert.equal(result.stdout,'');
   const safe=JSON.parse(result.stderr.trim());assert.equal(safe.error,input.code);assert.equal(safe.requiresOwnerAuthorization,input.authorization);
   assert.equal(safe.status,input.status);assert.equal(result.stderr.includes(key),false);assert.equal(result.stderr.includes('192.0.2'),false);
   assert.equal(f.received.length,before+1);assert.equal(f.received.at(-1)!.headers['user-agent'],ACCESS_USER_AGENT);
   assert.equal(f.received.at(-1)!.headers.authorization,'Bearer '+key);
  }
 }finally{await f.close();}
});
