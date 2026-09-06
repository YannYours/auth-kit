import type { AuthKitConfig, AuthUser, StorageAdapter, TokenPair, OAuthProviderConfig } from "./types.js";
import { hashPassword, verifyPassword, assertPasswordStrength } from "../utils/password.js";
import { signAccessToken, verifyAccessToken } from "../utils/jwt.js";
import { generateRandomToken, generatePkcePair } from "../utils/tokens.js";
import { buildAuthorizationUrl, exchangeCodeForToken, fetchUserProfile } from "../providers/oauth2.client.js";

const DEFAULT_ACCESS_TTL = 15 * 60; // 15 min
const DEFAULT_REFRESH_TTL = 30 * 24 * 60 * 60; // 30 days

interface PendingOAuthState {
  provider: string;
  codeVerifier: string;
  createdAt: number;
}

/**
 * NOTE — Déploiements multi-instance / serverless :
 * `pendingOAuth` est une Map en mémoire. Dans une architecture à plusieurs
 * réplicas (load balancer, serverless functions), le callback OAuth peut
 * atterrir sur une instance différente de celle qui a initié le flux, ce
 * qui provoquera un "État OAuth invalide" même pour un utilisateur légitime.
 *
 * Solution : implémenter un `OAuthStateStore` externe (Redis, base de
 * données partagée) et le passer à `AuthKit`. En attendant, ce comportement
 * est documenté dans le README comme limitation connue.
 */

export class AuthKit {
  readonly storage: StorageAdapter;
  private readonly jwtSecret: string;
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly oauthProviders: Record<string, OAuthProviderConfig>;
  private readonly pendingOAuth = new Map<string, PendingOAuthState>();

  constructor(config: AuthKitConfig) {
    if (!config.jwtSecret || config.jwtSecret.length < 16) {
      throw new Error("jwtSecret doit faire au moins 16 caractères.");
    }
    this.storage = config.storage;
    this.jwtSecret = config.jwtSecret;
    this.accessTtl = config.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TTL;
    this.refreshTtl = config.refreshTokenTtlSeconds ?? DEFAULT_REFRESH_TTL;
    this.oauthProviders = config.oauthProviders ?? {};
  }

  // ---------- Email / password ----------

  async register(email: string, password: string, name?: string): Promise<AuthUser> {
    assertPasswordStrength(password);
    const existing = await this.storage.findUserByEmail(email);
    if (existing) throw new Error("Un compte existe déjà avec cet e-mail.");

    const passwordHash = await hashPassword(password);
    return this.storage.createUser({ email, passwordHash, name, providers: {} });
  }

  async login(email: string, password: string): Promise<{ user: AuthUser; tokens: TokenPair }> {
    const user = await this.storage.findUserByEmail(email);
    if (!user?.passwordHash) throw new Error("Identifiants invalides.");

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) throw new Error("Identifiants invalides.");

    return { user, tokens: await this.issueTokens(user) };
  }

  // ---------- Tokens ----------

  async issueTokens(user: AuthUser): Promise<TokenPair> {
    const accessToken = signAccessToken(this.jwtSecret, { sub: user.id, email: user.email }, this.accessTtl);
    const refreshToken = generateRandomToken();

    await this.storage.saveRefreshToken({
      token: refreshToken,
      userId: user.id,
      expiresAt: Date.now() + this.refreshTtl * 1000,
      revoked: false,
    });

    return { accessToken, refreshToken, expiresIn: this.accessTtl };
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    const record = await this.storage.findRefreshToken(refreshToken);
    if (!record || record.revoked || record.expiresAt < Date.now()) {
      throw new Error("Jeton de rafraîchissement invalide ou expiré.");
    }

    const user = await this.storage.findUserById(record.userId);
    if (!user) throw new Error("Utilisateur introuvable.");

    // Rotation: the old refresh token is burned as soon as it's used once.
    await this.storage.revokeRefreshToken(refreshToken);
    return this.issueTokens(user);
  }

  async logout(refreshToken: string): Promise<void> {
    await this.storage.revokeRefreshToken(refreshToken);
  }

  async logoutAllDevices(userId: string): Promise<void> {
    await this.storage.revokeAllRefreshTokensForUser(userId);
  }

  verifyAccessToken(token: string) {
    return verifyAccessToken(this.jwtSecret, token);
  }

  // ---------- OAuth2 ----------

  hasProvider(name: string): boolean {
    return name in this.oauthProviders;
  }

  /** Step 1: build the redirect URL the browser should be sent to. */
  startOAuth(providerName: string): { url: string; state: string } {
    const config = this.requireProvider(providerName);
    const state = generateRandomToken(24);
    const { verifier, challenge } = generatePkcePair();

    this.pendingOAuth.set(state, { provider: providerName, codeVerifier: verifier, createdAt: Date.now() });
    this.cleanupExpiredState();

    const url = buildAuthorizationUrl(config, { state, codeChallenge: challenge });
    return { url, state };
  }

  /** Step 2: handle the provider's callback (?code=...&state=...). */
  async completeOAuth(providerName: string, code: string, state: string): Promise<{ user: AuthUser; tokens: TokenPair }> {
    const config = this.requireProvider(providerName);
    const pending = this.pendingOAuth.get(state);
    if (!pending || pending.provider !== providerName) {
      throw new Error("État OAuth invalide ou expiré — recommencez la connexion.");
    }
    this.pendingOAuth.delete(state);

    const tokenResponse = await exchangeCodeForToken(config, { code, codeVerifier: pending.codeVerifier });
    const rawProfile = await fetchUserProfile(config, tokenResponse.access_token);
    const profile = config.mapProfile(rawProfile);

    let user = await this.storage.findUserByProvider(providerName, profile.id);

    if (!user) {
      user = await this.storage.findUserByEmail(profile.email);
      if (user) {
        await this.storage.linkProvider(user.id, providerName, profile.id);
      } else {
        user = await this.storage.createUser({
          email: profile.email,
          name: profile.name,
          providers: { [providerName]: profile.id },
        });
      }
    }

    return { user, tokens: await this.issueTokens(user) };
  }

  private requireProvider(name: string): OAuthProviderConfig {
    const config = this.oauthProviders[name];
    if (!config) throw new Error(`Fournisseur OAuth2 inconnu : "${name}".`);
    return config;
  }

  private cleanupExpiredState() {
    const maxAgeMs = 10 * 60 * 1000; // 10 min to complete the round trip
    for (const [state, pending] of this.pendingOAuth) {
      if (Date.now() - pending.createdAt > maxAgeMs) this.pendingOAuth.delete(state);
    }
  }
}
