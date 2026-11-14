import crypto from "node:crypto";

export type EncryptedCredential = { ciphertext: string; iv: string; tag: string };

export class CredentialVault {
  private readonly key: Buffer;

  constructor(keyMaterial: string) {
    if (keyMaterial.length < 32) throw new Error("credential_vault_key_too_short");
    this.key = crypto.createHash("sha256").update(`nuluno-credential-v1:${keyMaterial}`).digest();
  }

  encrypt(value: string, context: string): EncryptedCredential {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(context, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return {
      ciphertext: ciphertext.toString("base64url"),
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
  }

  decrypt(value: EncryptedCredential, context: string) {
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, Buffer.from(value.iv, "base64url"));
    decipher.setAAD(Buffer.from(context, "utf8"));
    decipher.setAuthTag(Buffer.from(value.tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(value.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  }
}
