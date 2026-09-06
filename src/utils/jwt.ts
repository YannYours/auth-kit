import jwt from "jsonwebtoken";

export interface AccessTokenPayload {
  sub: string;
  email: string;
  type: "access";
}

export function signAccessToken(secret: string, payload: { sub: string; email: string }, ttlSeconds: number): string {
  return jwt.sign({ ...payload, type: "access" }, secret, { expiresIn: ttlSeconds });
}

export function verifyAccessToken(secret: string, token: string): AccessTokenPayload {
  const decoded = jwt.verify(token, secret);
  if (typeof decoded === "string" || decoded.type !== "access") {
    throw new Error("Jeton invalide.");
  }
  return decoded as AccessTokenPayload;
}
