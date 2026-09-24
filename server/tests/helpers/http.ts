/**
 * Helper to create mTLS headers for testing agent endpoints.
 */
export function createMtlsHeaders(enrollmentId: string) {
  return {
    "X-Client-Cert-Verified": "SUCCESS",
    "X-Client-Cert-Subject": `CN=${enrollmentId},O=synthaea`,
    "Content-Type": "application/json",
  };
}

/**
 * Helper to create tenant context headers for testing API endpoints.
 */
export function createTenantHeaders(tenantId: string, userId?: string) {
  return {
    "x-tenant-id": tenantId,
    "x-user-id": userId || "test-user-id",
    "Content-Type": "application/json",
  };
}

/**
 * Helper to create a detection payload.
 */
export function createDetectionPayload(overrides?: {
  timestamp_ns?: number;
  technique?: string;
  severity?: "low" | "medium" | "high" | "critical";
}) {
  return {
    timestamp_ns: overrides?.timestamp_ns || Date.now() * 1_000_000,
    technique: overrides?.technique || "T1059.001",
    severity: overrides?.severity || "high",
    event: {
      type: "exec",
      pid: 1234,
      comm: "bash",
    },
    meta: {
      hostname: "test-host",
    },
  };
}
