/** WebAuthn passkey helpers: registration and authentication against the
 * Identity API. The browser speaks WebAuthn; the API speaks JSON. */

import { api } from "$lib/api/client";

function toBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** The WebAuthn API requires binary fields as ArrayBuffers; the Identity API
 * sends them base64url-encoded. Decode before handing options to the
 * browser. */
function decodeCreationOptions(options: PublicKeyCredentialCreationOptions): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as unknown as string),
    user: { ...options.user, id: base64UrlToBuffer(options.user.id as unknown as string) },
    excludeCredentials: options.excludeCredentials?.map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id as unknown as string),
    })),
  };
}

function decodeRequestOptions(options: PublicKeyCredentialRequestOptions): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge as unknown as string),
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      id: base64UrlToBuffer(cred.id as unknown as string),
    })),
  };
}

export function supportsPasskeys(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

/** Register a new passkey for the signed-in user. Throws on failure. */
export async function registerPasskey(name: string): Promise<void> {
  if (!supportsPasskeys()) throw new Error("This browser does not support passkeys");

  const { options } = await api.post<{ options: PublicKeyCredentialCreationOptions }>(
    "/api/passkeys/register/start",
  );

  const credential = (await navigator.credentials.create({
    publicKey: decodeCreationOptions(options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey registration was cancelled");

  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = (response.getTransports?.() ?? []) as string[];

  await api.post("/api/passkeys/register/finish", {
    name,
    id: credential.id,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      attestationObject: toBase64Url(response.attestationObject),
      transports,
    },
  });
}

/** Authenticate with a passkey; on success the API sets the session cookie. */
export async function authenticatePasskey(): Promise<void> {
  if (!supportsPasskeys()) throw new Error("This browser does not support passkeys");

  const { options } = await api.post<{ options: PublicKeyCredentialRequestOptions }>(
    "/api/passkeys/auth/start",
  );

  const credential = (await navigator.credentials.get({
    publicKey: decodeRequestOptions(options),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey authentication was cancelled");

  const response = credential.response as AuthenticatorAssertionResponse;

  await api.post("/api/passkeys/auth/finish", {
    id: credential.id,
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
      authenticatorData: toBase64Url(response.authenticatorData),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
    },
  });
}
