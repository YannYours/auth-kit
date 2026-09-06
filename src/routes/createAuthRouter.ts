import { Router } from "express";
import type { AuthKit } from "../core/AuthKit.js";
import { requireAuth, type AuthenticatedRequest } from "../middleware/requireAuth.js";
import { loginRateLimiter, registerRateLimiter } from "../rateLimiters.js";

// RFC 5322 simplified — rejects the most obviously malformed addresses
// without pulling in an external dependency.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(email: unknown): string {
  if (typeof email !== "string" || !EMAIL_RE.test(email.trim())) {
    throw new Error("Adresse e-mail invalide.");
  }
  return email.trim().toLowerCase();
}

function validatePassword(password: unknown): string {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("Le mot de passe est requis.");
  }
  return password;
}

function validateString(value: unknown, field: string, maxLength = 256): string {
  if (typeof value !== "string") throw new Error(`${field} doit être une chaîne.`);
  const trimmed = value.trim().slice(0, maxLength);
  if (trimmed.length === 0) throw new Error(`${field} ne peut pas être vide.`);
  return trimmed;
}

function publicUser(user: { id: string; email: string; name?: string }) {
  return { id: user.id, email: user.email, name: user.name };
}

export interface AuthRouterOptions {
  /**
   * Rate limiting is ON by default for /login and /register — the two
   * endpoints most exposed to brute-force and mass-account-creation abuse.
   * Pass `false` to disable one entirely (e.g. you already rate-limit
   * upstream at a gateway/CDN level), or an object to tune the thresholds.
   */
  rateLimit?: {
    login?: false | { windowMs?: number; max?: number };
    register?: false | { windowMs?: number; max?: number };
  };
}

/**
 * Mounts:
 *   POST /register   (rate-limited: 5 / heure / IP par défaut)
 *   POST /login       (rate-limited: 10 / 15 min / IP+email par défaut)
 *   POST /refresh
 *   POST /logout
 *   GET  /me
 *   GET  /oauth/:provider            -> redirects to the provider
 *   GET  /oauth/:provider/callback   -> exchanges the code, returns tokens
 */
export function createAuthRouter(authKit: AuthKit, options: AuthRouterOptions = {}): Router {
  const router = Router();

  const loginLimitConfig = options.rateLimit?.login;
  const registerLimitConfig = options.rateLimit?.register;

  const registerMiddlewares =
    registerLimitConfig === false ? [] : [registerRateLimiter(registerLimitConfig)];
  const loginMiddlewares = loginLimitConfig === false ? [] : [loginRateLimiter(loginLimitConfig)];

  router.post("/register", ...registerMiddlewares, async (req, res) => {
    try {
      const body = req.body ?? {};
      const email = validateEmail(body.email);
      const password = validatePassword(body.password);
      const name = body.name != null ? validateString(body.name, "name", 128) : undefined;
      const user = await authKit.register(email, password, name);
      res.status(201).json({ user: publicUser(user) });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  router.post("/login", ...loginMiddlewares, async (req, res) => {
    try {
      const body = req.body ?? {};
      const email = validateEmail(body.email);
      const password = validatePassword(body.password);
      const { user, tokens } = await authKit.login(email, password);
      res.json({ user: publicUser(user), ...tokens });
    } catch (err) {
      res.status(401).json({ error: (err as Error).message });
    }
  });

  router.post("/refresh", async (req, res) => {
    try {
      const { refreshToken } = req.body ?? {};
      if (typeof refreshToken !== "string" || refreshToken.length === 0) {
        return res.status(400).json({ error: "refreshToken est requis." });
      }
      const tokens = await authKit.refresh(refreshToken);
      res.json(tokens);
    } catch (err) {
      res.status(401).json({ error: (err as Error).message });
    }
  });

  router.post("/logout", async (req, res) => {
    const { refreshToken } = req.body ?? {};
    if (typeof refreshToken === "string" && refreshToken.length > 0) {
      await authKit.logout(refreshToken);
    }
    res.status(204).end();
  });

  router.get("/me", requireAuth(authKit), async (req: AuthenticatedRequest, res) => {
    const user = await authKit.storage.findUserById(req.auth!.userId);
    if (!user) return res.status(404).json({ error: "Utilisateur introuvable." });
    res.json({ user: publicUser(user) });
  });

  router.get("/oauth/:provider", (req, res) => {
    const { provider } = req.params;
    if (!authKit.hasProvider(provider)) {
      return res.status(404).json({ error: `Fournisseur inconnu : ${provider}` });
    }
    const { url } = authKit.startOAuth(provider);
    // `state` is generated and tracked server-side (see AuthKit.startOAuth)
    // and re-checked in the callback below, which is what actually prevents
    // CSRF here — no cookie needed.
    res.redirect(url);
  });

  router.get("/oauth/:provider/callback", async (req, res) => {
    const { provider } = req.params;
    const { code, state } = req.query as { code?: string; state?: string };

    if (!code || !state) {
      return res.status(400).json({ error: "Requête OAuth invalide : code ou state manquant." });
    }

    try {
      const { user, tokens } = await authKit.completeOAuth(provider, code, state);
      res.json({ user: publicUser(user), ...tokens });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  return router;
}