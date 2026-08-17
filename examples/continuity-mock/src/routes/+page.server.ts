import { decodeJwtPayload } from "@arcticworks/identity-sdk";
import type { PageServerLoad } from "./$types";
import { decodeSessionCookie, permissionClient } from "$lib/identity";

function loginErrorMessage(code: string | null, description: string | null): string | undefined {
  if (!code) return undefined;
  if (description) return description;

  switch (code) {
    case "access_denied":
      return "Your ArcticWorks Identity account does not have access to Continuity. Ask an organization administrator to add your account, then try again.";
    case "invalid_request":
      return "Identity could not process the sign-in request. Please start the sign-in process again.";
    default:
      return `Identity could not sign you in (${code}). Please try again or contact an administrator.`;
  }
}

export const load: PageServerLoad = async ({ cookies, url }) => {
  const loginError = loginErrorMessage(
    url.searchParams.get("loginError"),
    url.searchParams.get("loginErrorDescription"),
  );
  const raw = cookies.get("mock_session");
  if (!raw) return { signedIn: false, loginError };

  try {
    const session = decodeSessionCookie(raw);
    if (session.expiresAt < Date.now() / 1000) return { signedIn: false, loginError };

    // Decode the id_token claims for display (mock only; real products must
    // validate signatures or use the UserInfo endpoint server-side).
    const claims = session.idToken
      ? decodeJwtPayload<{ sub: string; name?: string; email?: string; email_verified?: boolean; org?: string }>(session.idToken)
      : undefined;

    // Permission check through the documented endpoint using our service
    // account. Every check is scoped to an organization and denies by default.
    let permission = "not checked";
    let allowed = false;
    let checked = false;
    if (claims?.sub && claims?.org) {
      checked = true;
      permission = "continuity.document.read";
      allowed = await permissionClient()
        .checkPermission({
          organizationId: claims.org,
          userId: claims.sub,
          permission,
        })
        .catch(() => false);
    }

    return { signedIn: true, session, claims, permission, allowed, checked, loginError };
  } catch {
    return { signedIn: false, loginError };
  }
};
