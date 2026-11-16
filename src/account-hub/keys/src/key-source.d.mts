export type InstallationKeySource='macos-file-keychain'|'operator-env';
export interface InstallationKeyOptions{
 source?:InstallationKeySource;
 allowCreate?:boolean;
 /** Trusted process-startup injection only; never HTTP/MCP input. */
 environment?:Readonly<Record<string,string|undefined>>;
 expectedInstallationId?:string;
 /** Trusted installer path/hash only; never agent-selectable. */
 keychainHelper?:Readonly<{executable:string;sha256:string}>;
}
export declare const MASTER_KEY_ENV:'NULUNO_ACCESS_MASTER_KEY';
export declare const INSTALLATION_FILE:'installation-key.json';
export declare const INSTALLATION_BINDING_FILE:'installation-key-binding.json';
export declare class KeySourceError extends Error{readonly code:string;constructor(code:string);}
export declare class InstallationKeys{
 private constructor();
 readonly installationId:string;
 readonly keySource:InstallationKeySource;
 readonly adminKey:string;
 readonly vaultKey:string;
 readonly sessionKey:string;
 destroy():void;
 toJSON():ReturnType<typeof publicInstallationMetadata>;
}
export declare function loadInstallationKeys(stateDir:string,options?:InstallationKeyOptions):Promise<InstallationKeys>;
export declare function publicInstallationMetadata(keys:InstallationKeys):Readonly<{schema:'nuluno-access-installation-key-v1';installationId:string;keySource:InstallationKeySource;secretMaterialReturned:false}>;
