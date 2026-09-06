import type { OAuthProviderConfig } from "../core/types.js";

interface PresetOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export function googleProvider(opts: PresetOptions): OAuthProviderConfig {
  return {
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    redirectUri: opts.redirectUri,
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    scope: "openid email profile",
    mapProfile: (profile) => ({
      id: profile.sub,
      email: profile.email,
      name: profile.name,
    }),
  };
}

export function githubProvider(opts: PresetOptions): OAuthProviderConfig {
  return {
    clientId: opts.clientId,
    clientSecret: opts.clientSecret,
    redirectUri: opts.redirectUri,
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userInfoUrl: "https://api.github.com/user",
    scope: "read:user user:email",
    mapProfile: (profile) => ({
      id: String(profile.id),
      email: profile.email,
      name: profile.name ?? profile.login,
    }),
  };
}

/**
 * Any standards-compliant OAuth2 provider (Microsoft Entra, GitLab, a
 * homegrown identity server…) can be wired in the same way — just fill in
 * its endpoints and how to read its userinfo response.
 */
export function genericProvider(
  opts: PresetOptions & {
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    scope: string;
    mapProfile: OAuthProviderConfig["mapProfile"];
  },
): OAuthProviderConfig {
  return { ...opts };
}
