import type { OAuthProviderConfig } from "../core/types.js";

export function buildAuthorizationUrl(
  config: OAuthProviderConfig,
  params: { state: string; codeChallenge: string },
): string {
  const url = new URL(config.authorizeUrl);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", config.scope);
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function exchangeCodeForToken(
  config: OAuthProviderConfig,
  params: { code: string; codeVerifier: string },
): Promise<{ access_token: string; token_type: string }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code_verifier: params.codeVerifier,
  });

  const res = await fetch(config.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Échec de l'échange du code OAuth2 (${res.status}): ${text}`);
  }

  return res.json() as Promise<{ access_token: string; token_type: string }>;
}

export async function fetchUserProfile(config: OAuthProviderConfig, accessToken: string): Promise<any> {
  const res = await fetch(config.userInfoUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    throw new Error(`Impossible de récupérer le profil utilisateur (${res.status}).`);
  }
  return res.json();
}
