import bcrypt from "bcryptjs";

const SALT_ROUNDS = 12;

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}

export function assertPasswordStrength(password: string): void {
  if (password.length < 8) {
    throw new Error("Le mot de passe doit contenir au moins 8 caractères.");
  }
  if (password.length > 1024) {
    // bcrypt tronque silencieusement au-delà de 72 octets ; un mot de passe
    // extrêmement long peut aussi être utilisé comme vecteur DoS (hachage lent).
    throw new Error("Le mot de passe ne peut pas dépasser 1024 caractères.");
  }
}
