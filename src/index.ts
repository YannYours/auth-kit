export { AuthKit } from "./core/AuthKit.js";
export { MemoryStorageAdapter } from "./storage/memory.storage.js";
export { SqliteStorageAdapter } from "./storage/sqlite.storage.js";
export { PostgresStorageAdapter } from "./storage/postgres.storage.js";
export { MysqlStorageAdapter } from "./storage/mysql.storage.js";
export { MongoStorageAdapter } from "./storage/mongodb.storage.js";
export { createAuthRouter } from "./routes/createAuthRouter.js";
export { requireAuth } from "./middleware/requireAuth.js";
export { googleProvider, githubProvider, genericProvider } from "./providers/presets.js";

export type {
  AuthUser,
  StorageAdapter,
  RefreshTokenRecord,
  TokenPair,
  OAuthProviderConfig,
  AuthKitConfig,
} from "./core/types.js";
export type { AuthenticatedRequest } from "./middleware/requireAuth.js";
export type { AuthRouterOptions } from "./routes/createAuthRouter.js";
