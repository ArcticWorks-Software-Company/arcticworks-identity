/** Typed error carrying the Identity API error code. */

export type IdentityErrorCode =
  | "validation_failed"
  | "not_found"
  | "conflict"
  | "unauthorized"
  | "forbidden"
  | "reauth_required"
  | "token_invalid"
  | "email_not_verified"
  | "rate_limited"
  | "gone"
  | "internal"
  | "invalid_grant"
  | "invalid_client"
  | "network";

export class IdentityError extends Error {
  readonly code: IdentityErrorCode;
  readonly status?: number;

  constructor(code: IdentityErrorCode, message: string, status?: number) {
    super(message);
    this.name = "IdentityError";
    this.code = code;
    this.status = status;
  }
}

export function errorFromResponse(status: number, body: unknown): IdentityError {
  const payload = (body ?? {}) as { error?: { code?: string; message?: string } };
  const code = (payload.error?.code ?? "internal") as IdentityErrorCode;
  return new IdentityError(code, payload.error?.message ?? `Identity API error (${status})`, status);
}
