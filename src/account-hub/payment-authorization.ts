/** No processor is installed. Merchant checkout is not spending authority. */
export type PaymentSpendBounds=Readonly<{currency:string;perTransactionMicros:number;totalMicros:number;validFrom:number;expiresAt:number;merchantAllowlist:readonly string[]}>;
export type OwnerPaymentAuthorization=Readonly<{purpose:'agent_payment';ownerSubjectRef:string;providerId:string;providerTokenRef:string;bounds:PaymentSpendBounds}>;
export type SafePaymentCapability=Readonly<{supported:boolean;note:string}>;
export interface PaymentAuthorizationPort{
 capability():SafePaymentCapability;
 /** Host-only. Credential references are never returned in MCP/task results. */
 authorize(input:OwnerPaymentAuthorization):Promise<{authorizationId:string;providerId:string;bounds:PaymentSpendBounds}>;
 revoke(authorizationId:string):Promise<void>;
}
export function validatePaymentAuthorization(input:unknown,installedProviderIds:readonly string[],now=Date.now()):OwnerPaymentAuthorization{
 const v=input as OwnerPaymentAuthorization;
 if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).some(k=>!['purpose','ownerSubjectRef','providerId','providerTokenRef','bounds'].includes(k))||v.purpose!=='agent_payment'||!installedProviderIds.includes(v.providerId)||typeof v.ownerSubjectRef!=='string'||!/^[A-Za-z0-9_-]{8,120}$/.test(v.ownerSubjectRef)||typeof v.providerTokenRef!=='string'||!/^[A-Za-z][A-Za-z0-9:_-]{10,240}$/.test(v.providerTokenRef)||/^(?:cs_|pi_|sk_|pk_|tok_|pm_|seti_)/.test(v.providerTokenRef))throw Error('unsupported_payment_authorization');
 const b=v.bounds;if(!b||Object.keys(b).some(k=>!['currency','perTransactionMicros','totalMicros','validFrom','expiresAt','merchantAllowlist'].includes(k))||!/^[A-Z]{3}$/.test(b.currency)||![b.perTransactionMicros,b.totalMicros,b.validFrom,b.expiresAt].every(Number.isSafeInteger)||b.perTransactionMicros<=0||b.totalMicros<b.perTransactionMicros||b.validFrom>now||b.expiresAt<=now||b.expiresAt-b.validFrom>30*86400000||!Array.isArray(b.merchantAllowlist)||b.merchantAllowlist.length<1||b.merchantAllowlist.length>20||b.merchantAllowlist.some(m=>typeof m!=='string'||!/^[-A-Za-z0-9:_.]{1,120}$/.test(m)))throw Error('invalid_payment_bounds');return structuredClone(v);
}
export const unsupportedPaymentPort:PaymentAuthorizationPort=Object.freeze({capability:()=>({supported:false,note:'尚未安裝 AI 代付服務。目前不收取卡號，也不會代付；產品收款功能不是這裡的付款授權。'}),authorize:async()=>{throw Error('payment_provider_not_installed');},revoke:async()=>{throw Error('payment_provider_not_installed');}});
