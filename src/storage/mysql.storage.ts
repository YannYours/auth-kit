import { randomUUID } from "node:crypto";
import type { AuthUser, RefreshTokenRecord, StorageAdapter } from "../core/types.js";

/**
 * Adaptateur de stockage pour MySQL ≥ 8.0 / MariaDB ≥ 10.6 (via `mysql2`).
 * JSON_EXTRACT et JSON_SET sont disponibles depuis MySQL 5.7.8 ; si vous
 * tournez sur une version antérieure, passez par Prisma ou Sequelize.
 *
 * Peer dependency optionnelle : installez-la vous-même.
 *   npm install mysql2
 *
 * Schéma attendu :
 *
 *   CREATE TABLE IF NOT EXISTS auth_users (
 *     id            VARCHAR(36)  PRIMARY KEY,
 *     email         VARCHAR(320) UNIQUE NOT NULL,
 *     password_hash TEXT,
 *     name          VARCHAR(128),
 *     providers     JSON         NOT NULL DEFAULT ('{}'),
 *     created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
 *   );
 *
 *   CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
 *     token      VARCHAR(128) PRIMARY KEY,
 *     user_id    VARCHAR(36)  NOT NULL,
 *     expires_at BIGINT       NOT NULL,
 *     revoked    TINYINT(1)   NOT NULL DEFAULT 0,
 *     CONSTRAINT fk_art_user FOREIGN KEY (user_id)
 *       REFERENCES auth_users(id) ON DELETE CASCADE,
 *     INDEX idx_art_user   (user_id),
 *     INDEX idx_art_revoked (revoked)
 *   );
 *
 * Usage :
 *   import mysql from "mysql2/promise";
 *   const pool = mysql.createPool({ uri: process.env.DATABASE_URL });
 *   const storage = new MysqlStorageAdapter(pool);
 */
export class MysqlStorageAdapter implements StorageAdapter {
  constructor(
    // Accepte un Pool ou une Connection mysql2/promise
    private readonly pool: import("mysql2/promise").Pool | import("mysql2/promise").Connection,
  ) {}

  // ---------- helpers ----------

  private async query<T>(sql: string, params: import("mysql2").FieldPacket[] | import("mysql2/promise").QueryOptions["values"] = []): Promise<T[]> {
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const [rows] = await (this.pool as any).execute(sql, params);
      return rows as T[];
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        err.message.includes("Cannot find module")
      ) {
        throw new Error(
          "MysqlStorageAdapter nécessite 'mysql2'. Installez-le avec : npm install mysql2",
        );
      }
      throw err;
    }
  }

  private rowToUser(row: Record<string, unknown>): AuthUser {
    return {
      id: row.id as string,
      email: row.email as string,
      passwordHash: (row.password_hash as string | null) ?? undefined,
      name: (row.name as string | null) ?? undefined,
      // mysql2 retourne les colonnes JSON comme string — on parse
      providers:
        typeof row.providers === "string"
          ? JSON.parse(row.providers)
          : (row.providers as Record<string, string>),
      createdAt:
        row.created_at instanceof Date
          ? row.created_at.toISOString()
          : (row.created_at as string),
    };
  }

  // ---------- users ----------

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const rows = await this.query<Record<string, unknown>>(
      "SELECT * FROM auth_users WHERE email = ?",
      [email.toLowerCase()],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const rows = await this.query<Record<string, unknown>>(
      "SELECT * FROM auth_users WHERE id = ?",
      [id],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null> {
    // JSON_UNQUOTE(JSON_EXTRACT(providers, '$.google')) = '12345'
    const rows = await this.query<Record<string, unknown>>(
      "SELECT * FROM auth_users WHERE JSON_UNQUOTE(JSON_EXTRACT(providers, CONCAT('$.', ?))) = ?",
      [provider, providerId],
    );
    return rows[0] ? this.rowToUser(rows[0]) : null;
  }

  async createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser> {
    const id = randomUUID();
    const now = new Date().toISOString();
    await this.query(
      `INSERT INTO auth_users (id, email, password_hash, name, providers, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        id,
        user.email.toLowerCase(),
        user.passwordHash ?? null,
        user.name ?? null,
        JSON.stringify(user.providers),
        now,
      ],
    );
    return {
      ...user,
      id,
      email: user.email.toLowerCase(),
      createdAt: now,
    };
  }

  async linkProvider(userId: string, provider: string, providerId: string): Promise<void> {
    // JSON_SET est atomique au niveau de la colonne.
    await this.query(
      "UPDATE auth_users SET providers = JSON_SET(providers, CONCAT('$.', ?), ?) WHERE id = ?",
      [provider, providerId, userId],
    );
  }

  // ---------- refresh tokens ----------

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.query(
      `INSERT INTO auth_refresh_tokens (token, user_id, expires_at, revoked)
       VALUES (?, ?, ?, ?)`,
      [record.token, record.userId, record.expiresAt, record.revoked ? 1 : 0],
    );
  }

  async findRefreshToken(token: string): Promise<RefreshTokenRecord | null> {
    const rows = await this.query<Record<string, unknown>>(
      "SELECT * FROM auth_refresh_tokens WHERE token = ?",
      [token],
    );
    if (!rows[0]) return null;
    const row = rows[0];
    return {
      token: row.token as string,
      userId: row.user_id as string,
      expiresAt: Number(row.expires_at),
      revoked: Boolean(row.revoked),
    };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    await this.query(
      "UPDATE auth_refresh_tokens SET revoked = 1 WHERE token = ?",
      [token],
    );
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.query(
      "UPDATE auth_refresh_tokens SET revoked = 1 WHERE user_id = ?",
      [userId],
    );
  }
}
