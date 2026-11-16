// SPDX-License-Identifier: Apache-2.0
// Only this origin-bound browser access proof may use browser storage. OAuth
// state, pairing tokens, platform credentials and agent keys never go here.
const NAME='nuluno_access_owner_proof_v1';
const valid=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value);
export function readOwnerProof(window){for(const storage of ['sessionStorage','localStorage'])try{const value=window[storage].getItem(NAME);if(valid(value))return value;}catch{}return null;}
export function storeOwnerProof(window,value,remember=false){if(!valid(value))throw Error('invalid_owner_proof');const target=remember?'localStorage':'sessionStorage';window[target].setItem(NAME,value);window[remember?'sessionStorage':'localStorage'].removeItem(NAME);}
export function rememberOwnerProof(window,remember){const proof=readOwnerProof(window);if(!proof)throw Error('owner_proof_missing');storeOwnerProof(window,proof,remember);}
export function clearOwnerProof(window){for(const name of ['sessionStorage','localStorage'])try{window[name].removeItem(NAME);}catch{}}
export function withOwnerProof(window,fetchImpl){return (input,init={})=>{const url=new URL(String(input),window.location.origin),headers=new Headers(init.headers);if(url.origin===window.location.origin&&url.pathname.startsWith('/hub-api/')&&!url.pathname.startsWith('/hub-api/pairing/')){const proof=readOwnerProof(window);if(proof)headers.set('x-hub-owner-proof',proof);}return fetchImpl(input,{...init,headers});};}
