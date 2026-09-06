import { randomBytes, createHash } from "node:crypto";

export function generateRandomToken(bytes = 48): string {
  return randomBytes(bytes).toString("base64url");
}

/** PKCE code_verifier / code_challenge pair (S256), used for every OAuth2 flow here. */
export function generatePkcePair() {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}
