# Changelog

Toutes les modifications notables sont documentées ici.
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).
Versioning : [Semantic Versioning](https://semver.org/lang/fr/).

## [1.0.0] — 2026-09-06

### Ajouté
- Authentification email/mot de passe avec bcrypt (12 rounds)
- OAuth2 avec PKCE S256 — presets Google, GitHub, provider générique
- JWT access token (15 min) + refresh token opaque avec rotation
- Rate limiting intégré sur `/login` (IP + email) et `/register` (IP)
- Middleware `requireAuth` pour Express
- `StorageAdapter` — interface pluggable, zéro couplage à une base
- `MemoryStorageAdapter` — pour les tests et le dev local
- `SqliteStorageAdapter` — single-instance, via `better-sqlite3`
- `PostgresStorageAdapter` — via `pg`, JSONB natif
- `MysqlStorageAdapter` — via `mysql2`, JSON_EXTRACT/JSON_SET
- `MongoStorageAdapter` — via `mongodb`, TTL index sur refresh tokens
- Validation des inputs : format email, longueur password (8–1024 chars)
