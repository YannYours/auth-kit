import { randomUUID } from "node:crypto";
import type { AuthUser, RefreshTokenRecord, StorageAdapter } from "../core/types.js";

/**
 * Adaptateur de stockage pour PostgreSQL (via `pg` — node-postgres).
 *
 * Peer dependency optionnelle : installez-la vous-même.
 *   npm install pg
 *   npm install --save-dev @types/pg
 *
 * Schéma attendu — exécutez ce SQL une fois (migration ou init script) :
 *
 *   CREATE TABLE IF NOT EXISTS auth_users (
 *     id          TEXT PRIMARY KEY,
 *     email       TEXT UNIQUE NOT NULL,
 *     password_hash TEXT,
 *     name        TEXT,
 *     providers   JSONB NOT NULL DEFAULT '{}',
 *     created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
 *   );
 *
 *   CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
 *     token       TEXT PRIMARY KEY,
 *     user_id     TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
 *     expires_at  BIGINT NOT NULL,
 *     revoked     BOOLEAN NOT NULL DEFAULT FALSE
 *   );
 *
 *   CREATE INDEX IF NOT EXISTS idx_art_user ON auth_refresh_tokens(user_id);
 *   CREATE INDEX IF NOT EXISTS idx_art_revoked ON auth_refresh_tokens(revoked) WHERE NOT revoked;
 *
 * Usage :
 *   import { Pool } from "pg";
 *   const pool = new Pool({ connectionString: process.env.DATABASE_URL });
 *   const storage = new PostgresStorageAdapter(pool);
 */
export class PostgresStorageAdapter implements StorageAdapter {
  constructor(
    // Accepte un Pool ou un Client — le Pool est recommandé en prod.
    private readonly pool: import("pg").Pool | import("pg").Client,
  ) {}

  // ---------- helpers ----------

  private async query<T extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<T[]> {
    let pg: typeof import("pg");
    try {
      pg = await import("pg");
      void pg; // import réussi, on utilise this.pool directement
    } catch {
      throw new Error(
        "PostgresStorageAdapter nécessite 'pg'. Installez-le avec : npm install pg",
      );
    }
    const result = await this.pool.query(sql, params);
    return result.rows as T[];
  }

  private rowToUser(row: Record<string, unknown>): AuthUser {
    return {
      id: row.id as string,
      email: row.email as string,
      passwordHash: (row.password_hash as string | null) ?? undefined,
      name: (row.name as string | null) ?? undefined,
      // JSONB est déjà parsé par pg — pas besoin de JSON.parse
      providers: (row.providers as Record<string, string>) ?? {},
      createdAt:
        row.created_at instanceof Date
          ? row.created_at.toISOString()
          : (row.created_at as string),
    };
  }

  // ---------- users ----------

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const rows = await this.query(
      "SELECT * FROM auth_users WHERE email = $1",
      [email.toLowerCase()],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const rows = await this.query(
      "SELECT * FROM auth_users WHERE id = $1",
      [id],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null> {
    // JSONB path lookup : providers->>'google' = '12345'
    const rows = await this.query(
      "SELECT * FROM auth_users WHERE providers->>$1 = $2",
      [provider, providerId],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser> {
    const id = randomUUID();
    const rows = await this.query(
      `INSERT INTO auth_users (id, email, password_hash, name, providers)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        id,
        user.email.toLowerCase(),
        user.passwordHash ?? null,
        user.name ?? null,
        JSON.stringify(user.providers),
      ],
    );
    return this.rowToUser(rows[0]);
  }

  async linkProvider(userId: string, provider: string, providerId: string): Promise<void> {
    // jsonb_set est atomique — pas de read-modify-write et pas de race condition.
    await this.query(
      `UPDATE auth_users
       SET providers = jsonb_set(providers, $1::text[], $2::jsonb)
       WHERE id = $3`,
      [
        `{${provider}}`,          // path array littéral Postgres
        JSON.stringify(providerId),
        userId,
      ],
    );
  }

  // ---------- refresh tokens ----------

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.query(
      `INSERT INTO auth_refresh_tokens (token, user_id, expires_at, revoked)
       VALUES ($1, $2, $3, $4)`,
      [record.token, record.userId, record.expiresAt, record.revoked],
    );
  }

  async findRefreshToken(token: string): Promise<RefreshTokenRecord | null> {
    const rows = await this.query(
      "SELECT * FROM auth_refresh_tokens WHERE token = $1",
      [token],
    );
    if (!rows[0]) return null;
    const row = rows[0];
    return {
      token: row.token as string,
      userId: row.user_id as string,
      expiresAt: Number(row.expires_at),
      revoked: row.revoked as boolean,
    };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    await this.query(
      "UPDATE auth_refresh_tokens SET revoked = TRUE WHERE token = $1",
      [token],
    );
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.query(
      "UPDATE auth_refresh_tokens SET revoked = TRUE WHERE user_id = $1",
      [userId],
    );
  }
}
