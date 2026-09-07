# @yannyours/auth-kit

Module d'authentification Node.js autonome : e-mail/mot de passe + OAuth2
(Google, GitHub, ou n'importe quel fournisseur standard) avec PKCE, JWT
access/refresh avec rotation, et un adaptateur de stockage enfichable.

## Installation

```bash
npm install @yannyours/auth-kit
```

Pour le stockage SQLite (inclus, pour déploiements single-instance) :

```bash
npm install better-sqlite3
```

## Démarrage rapide

```ts
import express from "express";
import { AuthKit, SqliteStorageAdapter, createAuthRouter, requireAuth } from "@yannyours/auth-kit";
import type { AuthenticatedRequest } from "@yannyours/auth-kit";

const storage = await SqliteStorageAdapter.create("./auth.db");

const authKit = new AuthKit({
  storage,
  jwtSecret: process.env.JWT_SECRET!, // min 16 chars — variable d'env obligatoire
});

const app = express();
app.use(express.json());
app.use("/auth", createAuthRouter(authKit));

// Route protégée
app.get("/api/profile", requireAuth(authKit), (req: AuthenticatedRequest, res) => {
  res.json({ userId: req.auth!.userId, email: req.auth!.email });
});

app.listen(3000);
```

Variables d'environnement minimales (copier `.env.example`) :

```
JWT_SECRET=une-chaine-aleatoire-longue-min-32-chars
```

## Endpoints exposés par `createAuthRouter`

| Méthode | Route                       | Accès | Description |
|---------|-----------------------------|-------|-------------|
| POST    | `/register`                 | Public | `{ email, password, name? }` → `{ user }` |
| POST    | `/login`                    | Public | `{ email, password }` → tokens |
| POST    | `/refresh`                  | Public | `{ refreshToken }` → nouveaux tokens (rotation) |
| POST    | `/logout`                   | Public | `{ refreshToken }` → révoque ce token |
| GET     | `/me`                       | Auth  | `Authorization: Bearer <token>` → `{ user }` |
| GET     | `/oauth/:provider`          | Public | Redirige vers le fournisseur OAuth2 |
| GET     | `/oauth/:provider/callback` | Public | Échange le code, renvoie tokens |

## OAuth2 (Google, GitHub, custom)

```ts
import { googleProvider, githubProvider, genericProvider } from "@yannyours/auth-kit";

const authKit = new AuthKit({
  storage,
  jwtSecret: process.env.JWT_SECRET!,
  oauthProviders: {
    google: googleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: "https://monapp.com/auth/oauth/google/callback",
    }),
    github: githubProvider({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      redirectUri: "https://monapp.com/auth/oauth/github/callback",
    }),
  },
});
```

Variables d'environnement supplémentaires :

```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

Tout fournisseur OAuth2 standard (Microsoft Entra, GitLab, Okta…) peut être
ajouté via `genericProvider` :

```ts
const microsoft = genericProvider({
  clientId: "...",
  clientSecret: "...",
  redirectUri: "https://monapp.com/auth/oauth/microsoft/callback",
  authorizeUrl: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  tokenUrl:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  userInfoUrl:  "https://graph.microsoft.com/oidc/userinfo",
  scope: "openid email profile",
  mapProfile: (p) => ({ id: p.sub, email: p.email, name: p.name }),
});
```

## Adaptateurs de stockage

@yannyours/auth-kit inclut quatre adaptateurs prêts à l'emploi. Seul `express` est une
dépendance obligatoire — chaque adaptateur de base de données est une peer
dependency optionnelle : installez uniquement ce que vous utilisez.

### SQLite — single-instance, zéro infrastructure

```bash
npm install better-sqlite3
```

```ts
import { SqliteStorageAdapter } from "@yannyours/auth-kit";
const storage = await SqliteStorageAdapter.create("./auth.db");
```

Idéal pour un déploiement sur une seule machine (VPS, Raspberry Pi, container
avec volume persistant). Pas adapté au multi-instance ou au serverless.

---

### PostgreSQL

```bash
npm install pg
```

```ts
import { Pool } from "pg";
import { PostgresStorageAdapter } from "@yannyours/auth-kit";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const storage = new PostgresStorageAdapter(pool);
```

Schéma à exécuter une fois (migration ou init script) :

```sql
CREATE TABLE IF NOT EXISTS auth_users (
  id            TEXT        PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  name          TEXT,
  providers     JSONB       NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
  token      TEXT   PRIMARY KEY,
  user_id    TEXT   NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL,
  revoked    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_art_user    ON auth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_art_revoked ON auth_refresh_tokens(revoked) WHERE NOT revoked;
```

L'adaptateur tire parti du type JSONB natif de Postgres : `findUserByProvider`
utilise l'opérateur `->>` (accès direct au sous-champ) sans scan complet.
`linkProvider` utilise `jsonb_set` — atomique, pas de read-modify-write.

---

### MySQL / MariaDB

```bash
npm install mysql2
```

```ts
import mysql from "mysql2/promise";
import { MysqlStorageAdapter } from "@yannyours/auth-kit";

const pool = mysql.createPool({ uri: process.env.DATABASE_URL });
const storage = new MysqlStorageAdapter(pool);
```

Schéma :

```sql
CREATE TABLE IF NOT EXISTS auth_users (
  id            VARCHAR(36)  PRIMARY KEY,
  email         VARCHAR(320) UNIQUE NOT NULL,
  password_hash TEXT,
  name          VARCHAR(128),
  providers     JSON         NOT NULL DEFAULT ('{}'),
  created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
);

CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
  token      VARCHAR(128) PRIMARY KEY,
  user_id    VARCHAR(36)  NOT NULL,
  expires_at BIGINT       NOT NULL,
  revoked    TINYINT(1)   NOT NULL DEFAULT 0,
  CONSTRAINT fk_art_user FOREIGN KEY (user_id)
    REFERENCES auth_users(id) ON DELETE CASCADE,
  INDEX idx_art_user    (user_id),
  INDEX idx_art_revoked (revoked)
);
```

Requiert MySQL ≥ 8.0 ou MariaDB ≥ 10.6 pour les fonctions `JSON_EXTRACT` /
`JSON_SET` utilisées par `findUserByProvider` et `linkProvider`.

---

### MongoDB

```bash
npm install mongodb
```

```ts
import { MongoClient } from "mongodb";
import { MongoStorageAdapter } from "@yannyours/auth-kit";

const client = new MongoClient(process.env.MONGODB_URI!);
await client.connect();
const storage = await MongoStorageAdapter.create(client.db("myapp"));
```

Les collections `auth_users` et `auth_refresh_tokens` sont créées
automatiquement au premier appel de `create()`, avec :
- Index unique sur `email`
- Index sur `providers` pour les lookups OAuth2
- **TTL index** sur `expiresAtDate` : MongoDB purge automatiquement les
  refresh tokens expirés (vérification toutes les 60 s)

---

### Adapter personnalisé (Prisma, Drizzle, Sequelize…)

Implémentez l'interface `StorageAdapter` et passez-la à `AuthKit` :

```ts
import type { StorageAdapter } from "@yannyours/auth-kit";

class MonPrismaAdapter implements StorageAdapter {
  async findUserByEmail(email: string) { return prisma.authUser.findUnique({ where: { email } }); }
  async findUserById(id: string)       { return prisma.authUser.findUnique({ where: { id } }); }
  // … 7 autres méthodes
}

const authKit = new AuthKit({ storage: new MonPrismaAdapter(), jwtSecret: "…" });
```

## Sécurité — ce qui est déjà géré

- **bcrypt** (12 rounds) — mots de passe jamais stockés en clair.
- **JWT access token** courte durée (15 min par défaut) + **refresh token**
  opaque longue durée, stocké et révocable côté serveur.
- **Rotation des refresh tokens** — chaque `/refresh` invalide l'ancien token ;
  un token volé rejoué après usage légitime est automatiquement rejeté.
- **PKCE S256** sur tous les flux OAuth2 — protection contre l'interception du
  code d'autorisation, y compris avec les providers qui ne l'exigent pas.
- **State OAuth2** généré et vérifié côté serveur, expiré à 10 min — anti-CSRF
  sans cookie.
- **Rate limiting** intégré sur `/login` (IP + email, 10 req/15 min) et
  `/register` (IP, 5 req/h), configurable ou désactivable :

```ts
createAuthRouter(authKit, {
  rateLimit: {
    login: { windowMs: 10 * 60 * 1000, max: 5 },
    register: false, // déjà géré en amont
  },
});
```

- **Validation des inputs** — format email vérifié, mot de passe limité à
  1024 chars (protection DoS bcrypt), `name` tronqué à 128 chars.

## Limitations connues

**Multi-instance / serverless** : les états OAuth en attente (`pendingOAuth`)
sont stockés en mémoire. Dans une architecture avec plusieurs réplicas ou en
serverless, le callback OAuth peut atterrir sur une instance différente de
celle qui a initié le flux, causant un rejet légitime. Pour ce cas d'usage,
externaliser l'état OAuth dans Redis ou une base partagée, et implémenter un
`OAuthStateStore` dédié.

## Développement local

```bash
git clone https://github.com/YannYours/auth-kit
cd auth-kit
npm install
cp .env.example .env   # renseigner JWT_SECRET au minimum
npm run dev            # serveur de démo sur http://localhost:3000
npm run build          # compile src/ → dist/
npm run typecheck      # vérification TypeScript sans émettre
```

## Licence

MIT — voir [LICENSE](./LICENSE).