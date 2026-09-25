import { NextRequest } from "next/server";

/**
 * Extracts tenant ID from request headers.
 * Middleware injects x-tenant-id from session.
 */
export async function getTenantId(req: NextRequest): Promise<string> {
  const tenantId = req.headers.get("x-tenant-id");

  if (!tenantId) {
    throw new Error("No tenant context - authentication required");
  }

  return tenantId;
}

/**
 * Extracts user ID from request headers.
 * Middleware injects x-user-id from session.
 */
export async function getUserId(req: NextRequest): Promise<string> {
  const userId = req.headers.get("x-user-id");

  if (!userId) {
    throw new Error("No user context - authentication required");
  }

  return userId;
}

/**
 * Verifies that the request came through the nginx proxy.
 * Prevents header spoofing attacks where clients send mTLS headers directly.
 *
 * SECURITY: This check is critical for agent authentication.
 * Without it, anyone can bypass mTLS by sending fake X-Client-Cert-* headers.
 *
 * @throws Error if proxy authentication fails
 */
export function verifyProxyAuth(req: NextRequest): void {
  const proxySecret = req.headers.get("X-Proxy-Secret");
  const expectedSecret = process.env.NGINX_PROXY_SECRET;

  if (!expectedSecret) {
    throw new Error(
      "NGINX_PROXY_SECRET not configured - proxy authentication disabled"
    );
  }

  // Constant-time comparison to prevent timing attacks
  if (!proxySecret || !timingSafeEqual(proxySecret, expectedSecret)) {
    throw new Error("Invalid proxy authentication - request did not come from nginx");
  }
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Standard !== operator leaks information through execution time.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return mismatch === 0;
}

/**
 * Extracts enrollment ID from mTLS certificate subject.
 * Example: CN=agent-abc123,O=synthaea -> agent-abc123
 */
export function extractEnrollmentId(certSubject: string): string {
  const match = certSubject.match(/CN=([^,]+)/);
  return match ? match[1] : "";
}
