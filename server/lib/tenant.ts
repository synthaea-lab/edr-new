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
 * Extracts enrollment ID from mTLS certificate subject.
 * Example: CN=agent-abc123,O=synthaea -> agent-abc123
 */
export function extractEnrollmentId(certSubject: string): string {
  const match = certSubject.match(/CN=([^,]+)/);
  return match ? match[1] : "";
}
