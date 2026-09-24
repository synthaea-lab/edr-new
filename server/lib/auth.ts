import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";

export const auth = betterAuth({
  database: {
    provider: "postgresql",
    url: process.env.DATABASE_URL!,
  },
  emailAndPassword: {
    enabled: true,
  },
  plugins: [
    organization({
      // Organization = Tenant
      allowUserToCreateOrganization: false, // Admin-only tenant creation
    }),
  ],
  trustedOrigins: [
    "http://localhost:3000",
    "http://localhost:8443",
  ],
});

export type Session = typeof auth.$Infer.Session;
