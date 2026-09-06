import rateLimit from "express-rate-limit";

/**
 * Limits brute-force attempts against /login. Keyed on IP + the submitted
 * email, so one attacker can't lock out a real user by spamming their
 * address from many IPs, and a single IP can't hammer many accounts either.
 *
 * Tune `windowMs` / `max` to your traffic; defaults are deliberately strict
 * since this guards a credential-checking endpoint.
 */
export function loginRateLimiter(options?: { windowMs?: number; max?: number }) {
  return rateLimit({
    windowMs: options?.windowMs ?? 15 * 60 * 1000, // 15 min
    max: options?.max ?? 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => `${req.ip}:${(req.body?.email ?? "").toLowerCase()}`,
    message: { error: "Trop de tentatives de connexion. Réessayez plus tard." },
  });
}

/** Limits account creation per IP to slow down mass-registration abuse. */
export function registerRateLimiter(options?: { windowMs?: number; max?: number }) {
  return rateLimit({
    windowMs: options?.windowMs ?? 60 * 60 * 1000, // 1h
    max: options?.max ?? 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Trop de comptes créés depuis cette adresse. Réessayez plus tard." },
  });
}