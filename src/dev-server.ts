import express from "express";
import {
  AuthKit,
  MemoryStorageAdapter,
  createAuthRouter,
  requireAuth,
  googleProvider,
  githubProvider,
  type AuthenticatedRequest,
} from "./index.js";

const app = express();
app.use(express.json());

const authKit = new AuthKit({
  storage: new MemoryStorageAdapter(),
  jwtSecret: process.env.JWT_SECRET ?? "dev-secret-change-me-please-32chars",
  accessTokenTtlSeconds: 15 * 60,
  refreshTokenTtlSeconds: 30 * 24 * 60 * 60,
  oauthProviders: {
    ...(process.env.GOOGLE_CLIENT_ID && {
      google: googleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        redirectUri: "http://localhost:3000/auth/oauth/google/callback",
      }),
    }),
    ...(process.env.GITHUB_CLIENT_ID && {
      github: githubProvider({
        clientId: process.env.GITHUB_CLIENT_ID!,
        clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        redirectUri: "http://localhost:3000/auth/oauth/github/callback",
      }),
    }),
  },
});

app.use("/auth", createAuthRouter(authKit));

// Example protected route.
app.get("/api/profile", requireAuth(authKit), (req: AuthenticatedRequest, res) => {
  res.json({ message: `Bonjour ${req.auth!.email}`, userId: req.auth!.userId });
});

app.listen(3000, () => {
  console.log("Serveur de démo sur http://localhost:3000");
  console.log("Essayez : POST /auth/register, POST /auth/login, GET /auth/oauth/google");
});
