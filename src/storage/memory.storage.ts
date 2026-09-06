import { randomUUID } from "node:crypto";
import type { AuthUser, RefreshTokenRecord, StorageAdapter } from "../core/types.js";

/**
 * Default adapter used out of the box and for tests/demos. Swap it for a
 * real database by implementing StorageAdapter — nothing else in the module
 * needs to change.
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private usersById = new Map<string, AuthUser>();
  private usersByEmail = new Map<string, string>();
  private refreshTokens = new Map<string, RefreshTokenRecord>();

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const id = this.usersByEmail.get(email.toLowerCase());
    return id ? (this.usersById.get(id) ?? null) : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    return this.usersById.get(id) ?? null;
  }

  async findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null> {
    for (const user of this.usersById.values()) {
      if (user.providers[provider] === providerId) return user;
    }
    return null;
  }

  async createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser> {
    const newUser: AuthUser = {
      ...user,
      id: randomUUID(),
      createdAt: new Date().toISOString(),
    };
    this.usersById.set(newUser.id, newUser);
    this.usersByEmail.set(newUser.email.toLowerCase(), newUser.id);
    return newUser;
  }

  async linkProvider(userId: string, provider: string, providerId: string): Promise<void> {
    const user = this.usersById.get(userId);
    if (!user) throw new Error("User not found");
    user.providers[provider] = providerId;
  }

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    this.refreshTokens.set(record.token, record);
  }

  async findRefreshToken(token: string): Promise<RefreshTokenRecord | null> {
    return this.refreshTokens.get(token) ?? null;
  }

  async revokeRefreshToken(token: string): Promise<void> {
    const record = this.refreshTokens.get(token);
    if (record) record.revoked = true;
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    for (const record of this.refreshTokens.values()) {
      if (record.userId === userId) record.revoked = true;
    }
  }
}
