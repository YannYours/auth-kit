import type { Request, Response, NextFunction } from "express";
import type { AuthKit } from "../core/AuthKit.js";

export interface AuthenticatedRequest extends Request {
  auth?: { userId: string; email: string };
}

export function requireAuth(authKit: AuthKit) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Jeton d'accès manquant." });
    }

    try {
      const payload = authKit.verifyAccessToken(header.slice("Bearer ".length));
      req.auth = { userId: payload.sub, email: payload.email };
      next();
    } catch {
      return res.status(401).json({ error: "Jeton d'accès invalide ou expiré." });
    }
  };
}
