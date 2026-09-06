export interface AuthUser {
  id: string;
  email: string;
  passwordHash?: string;
  name?: string;
  providers: Record<string, string>; // e.g. { google: "sub-id-123" }
  createdAt: string;
}

export interface RefreshTokenRecord {
  token: string;
  userId: string;
  expiresAt: number;
  revoked: boolean;
}

/**
 * Storage is fully pluggable. Ship your own adapter (Postgres, Mongo, Redis…)
 * by implementing this interface — the rest of the module never talks to a
 * database directly.
 */
export interface StorageAdapter {
  findUserByEmail(email: string): Promise<AuthUser | null>;
  findUserById(id: string): Promise<AuthUser | null>;
  findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null>;
  createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser>;
  linkProvider(userId: string, provider: string, providerId: string): Promise<void>;

  saveRefreshToken(record: RefreshTokenRecord): Promise<void>;
  findRefreshToken(token: string): Promise<RefreshTokenRecord | null>;
  revokeRefreshToken(token: string): Promise<void>;
  revokeAllRefreshTokensForUser(userId: string): Promise<void>;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scope: string;
  redirectUri: string;
  /** Map the provider's raw userinfo payload to { id, email, name } */
  mapProfile: (profile: any) => { id: string; email: string; name?: string };
}

export interface AuthKitConfig {
  storage: StorageAdapter;
  jwtSecret: string;
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
  oauthProviders?: Record<string, OAuthProviderConfig>;
}
