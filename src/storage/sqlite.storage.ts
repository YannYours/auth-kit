import { randomUUID } from "node:crypto";
import type { AuthUser, RefreshTokenRecord, StorageAdapter } from "../core/types.js";

/**
 * Persistent storage adapter backed by SQLite (via better-sqlite3), stored
 * in a single file on disk. This is the adapter to reach for by default in
 * production if you don't already have your own database — no separate
 * server to run, survives restarts and deploys (as long as the file lives
 * on a persistent volume).
 *
 * `better-sqlite3` is an optional peer dependency: install it yourself
 * (`npm install better-sqlite3`) before using this adapter. Everything
 * else in auth-kit works without it.
 *
 * For anything beyond a single-instance deployment (multiple app servers,
 * serverless, horizontal scaling), implement `StorageAdapter` against your
 * real database (Postgres, MySQL, MongoDB…) instead — SQLite is file-based
 * and does not fan out across machines.
 */
export class SqliteStorageAdapter implements StorageAdapter {
  private db: import("better-sqlite3").Database;

  private constructor(db: import("better-sqlite3").Database) {
    this.db = db;
  }

  static async create(filePath: string): Promise<SqliteStorageAdapter> {
    let Database: typeof import("better-sqlite3");
    try {
      Database = (await import("better-sqlite3")).default;
    } catch {
      throw new Error(
        "SqliteStorageAdapter nécessite 'better-sqlite3'. Installez-le avec : npm install better-sqlite3",
      );
    }

    const db = new Database(filePath);
    db.pragma("journal_mode = WAL");

    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        name TEXT,
        providers TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
    `);

    return new SqliteStorageAdapter(db);
  }

  private rowToUser(row: any): AuthUser {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash ?? undefined,
      name: row.name ?? undefined,
      providers: JSON.parse(row.providers),
      createdAt: row.created_at,
    };
  }

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const row = this.db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
    return row ? this.rowToUser(row) : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(id);
    return row ? this.rowToUser(row) : null;
  }

  async findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null> {
    // json_extract evite le scan complet : seules les lignes dont le champ
    // providers contient la cle `provider` avec la valeur exacte sont lues.
    const row = this.db
      .prepare("SELECT * FROM users WHERE json_extract(providers, '$.' || ?) = ?")
      .get(provider, providerId);
    return row ? this.rowToUser(row) : null;
  }

  async createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser> {
    const newUser: AuthUser = {
      ...user,
      id: randomUUID(),
      createdAt: new Date().toISOString(),
    };

    this.db
      .prepare(
        `INSERT INTO users (id, email, password_hash, name, providers, created_at)
         VALUES (@id, @email, @passwordHash, @name, @providers, @createdAt)`,
      )
      .run({
        id: newUser.id,
        email: newUser.email.toLowerCase(),
        passwordHash: newUser.passwordHash ?? null,
        name: newUser.name ?? null,
        providers: JSON.stringify(newUser.providers),
        createdAt: newUser.createdAt,
      });

    return newUser;
  }

  async linkProvider(userId: string, provider: string, providerId: string): Promise<void> {
    const user = await this.findUserById(userId);
    if (!user) throw new Error("User not found");
    user.providers[provider] = providerId;
    this.db.prepare("UPDATE users SET providers = ? WHERE id = ?").run(JSON.stringify(user.providers), userId);
  }

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO refresh_tokens (token, user_id, expires_at, revoked)
         VALUES (@token, @userId, @expiresAt, @revoked)`,
      )
      .run({
        token: record.token,
        userId: record.userId,
        expiresAt: record.expiresAt,
        revoked: record.revoked ? 1 : 0,
      });
  }

  async findRefreshToken(token: string): Promise<RefreshTokenRecord | null> {
    const row = this.db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(token) as any;
    if (!row) return null;
    return {
      token: row.token,
      userId: row.user_id,
      expiresAt: row.expires_at,
      revoked: !!row.revoked,
    };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    this.db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?").run(token);
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    this.db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?").run(userId);
  }
}