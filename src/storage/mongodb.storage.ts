import { randomUUID } from "node:crypto";
import type { AuthUser, RefreshTokenRecord, StorageAdapter } from "../core/types.js";

/**
 * Adaptateur de stockage pour MongoDB (via le driver officiel `mongodb`).
 *
 * Peer dependency optionnelle : installez-la vous-même.
 *   npm install mongodb
 *
 * Collections créées automatiquement au premier usage :
 *   - `auth_users`          — index unique sur `email`, index sur `providers.<name>`
 *   - `auth_refresh_tokens` — index sur `userId`, TTL index sur `expiresAt` pour
 *                             purge automatique des tokens expirés
 *
 * Usage :
 *   import { MongoClient } from "mongodb";
 *   const client = new MongoClient(process.env.MONGODB_URI!);
 *   await client.connect();
 *   const db = client.db("myapp");
 *   const storage = await MongoStorageAdapter.create(db);
 */

// Shapes des documents MongoDB (sans _id Mongo — on utilise notre propre id)
interface UserDoc {
  id: string;
  email: string;
  passwordHash?: string;
  name?: string;
  providers: Record<string, string>;
  createdAt: string;
}

interface RefreshTokenDoc {
  token: string;
  userId: string;
  expiresAt: number;       // epoch ms — utilisé aussi par le TTL index
  expiresAtDate: Date;     // Date object pour le TTL index MongoDB
  revoked: boolean;
}

export class MongoStorageAdapter implements StorageAdapter {
  private constructor(
    private readonly users: import("mongodb").Collection<UserDoc>,
    private readonly tokens: import("mongodb").Collection<RefreshTokenDoc>,
  ) {}

  /**
   * Crée l'adaptateur et s'assure que les index existent.
   * À appeler une fois au démarrage de l'application.
   */
  static async create(db: import("mongodb").Db): Promise<MongoStorageAdapter> {
    let mongodb: typeof import("mongodb");
    try {
      mongodb = await import("mongodb");
      void mongodb;
    } catch {
      throw new Error(
        "MongoStorageAdapter nécessite 'mongodb'. Installez-le avec : npm install mongodb",
      );
    }

    const users = db.collection<UserDoc>("auth_users");
    const tokens = db.collection<RefreshTokenDoc>("auth_refresh_tokens");

    // Index users
    await users.createIndex({ email: 1 }, { unique: true });
    // Index partiel sur les providers : un index par fournisseur connu est
    // impossible sans savoir lesquels existent. On utilise un index sparse
    // générique sur le champ providers — Mongo fera un scan de sous-doc,
    // ce qui est acceptable pour des collections d'utilisateurs typiques.
    // Pour des volumes très importants, créez un index explicite par fournisseur :
    //   await users.createIndex({ "providers.google": 1 }, { sparse: true });
    await users.createIndex({ "providers": 1 }, { sparse: true });

    // Index refresh tokens
    await tokens.createIndex({ userId: 1 });
    // TTL index : MongoDB supprime automatiquement les documents dont
    // `expiresAtDate` est dans le passé (vérification toutes les 60 s).
    await tokens.createIndex({ expiresAtDate: 1 }, { expireAfterSeconds: 0 });

    return new MongoStorageAdapter(users, tokens);
  }

  // ---------- helpers ----------

  private docToUser(doc: UserDoc): AuthUser {
    return {
      id: doc.id,
      email: doc.email,
      passwordHash: doc.passwordHash,
      name: doc.name,
      providers: doc.providers ?? {},
      createdAt: doc.createdAt,
    };
  }

  // ---------- users ----------

  async findUserByEmail(email: string): Promise<AuthUser | null> {
    const doc = await this.users.findOne({ email: email.toLowerCase() });
    return doc ? this.docToUser(doc) : null;
  }

  async findUserById(id: string): Promise<AuthUser | null> {
    const doc = await this.users.findOne({ id });
    return doc ? this.docToUser(doc) : null;
  }

  async findUserByProvider(provider: string, providerId: string): Promise<AuthUser | null> {
    // Requête sur le sous-champ dynamique : providers.google = "12345"
    const doc = await this.users.findOne({ [`providers.${provider}`]: providerId });
    return doc ? this.docToUser(doc) : null;
  }

  async createUser(user: Omit<AuthUser, "id" | "createdAt">): Promise<AuthUser> {
    const newUser: UserDoc = {
      ...user,
      email: user.email.toLowerCase(),
      id: randomUUID(),
      createdAt: new Date().toISOString(),
    };
    await this.users.insertOne(newUser);
    return this.docToUser(newUser);
  }

  async linkProvider(userId: string, provider: string, providerId: string): Promise<void> {
    await this.users.updateOne(
      { id: userId },
      { $set: { [`providers.${provider}`]: providerId } },
    );
  }

  // ---------- refresh tokens ----------

  async saveRefreshToken(record: RefreshTokenRecord): Promise<void> {
    await this.tokens.insertOne({
      ...record,
      expiresAtDate: new Date(record.expiresAt), // nécessaire pour le TTL index
    });
  }

  async findRefreshToken(token: string): Promise<RefreshTokenRecord | null> {
    const doc = await this.tokens.findOne({ token });
    if (!doc) return null;
    return {
      token: doc.token,
      userId: doc.userId,
      expiresAt: doc.expiresAt,
      revoked: doc.revoked,
    };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    await this.tokens.updateOne({ token }, { $set: { revoked: true } });
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.tokens.updateMany({ userId }, { $set: { revoked: true } });
  }
}
