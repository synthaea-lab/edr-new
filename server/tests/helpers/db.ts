import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Cleans the test database by deleting all records.
 * Respects foreign key constraints by deleting in correct order.
 */
export async function cleanDatabase() {
  // Delete in order respecting foreign keys
  await prisma.auditLog.deleteMany();
  await prisma.case.deleteMany();
  await prisma.detection.deleteMany();
  await prisma.contentRelease.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.tenant.deleteMany();
}

/**
 * Creates a test tenant with a unique name.
 */
export async function createTestTenant(name?: string) {
  return prisma.tenant.create({
    data: {
      name: name || `Test Tenant ${Date.now()}`,
    },
  });
}

/**
 * Creates a test agent enrolled to a tenant.
 */
export async function createTestAgent(
  tenantId: string,
  enrollmentId?: string,
  overrides?: Partial<{
    ring: string;
    hostname: string;
    version: string;
    lastSeen: Date;
  }>
) {
  return prisma.agent.create({
    data: {
      tenantId,
      enrollmentId: enrollmentId || `agent-test-${Date.now()}`,
      hostname: overrides?.hostname || "test-host",
      version: overrides?.version || "0.1.0",
      ring: overrides?.ring || "prod",
      lastSeen: overrides?.lastSeen || new Date(),
    },
  });
}

/**
 * Creates a test detection.
 */
export async function createTestDetection(
  tenantId: string,
  agentId: string,
  overrides?: Partial<{
    technique: string;
    severity: string;
    timestamp: Date;
  }>
) {
  return prisma.detection.create({
    data: {
      tenantId,
      agentId,
      timestamp: overrides?.timestamp || new Date(),
      technique: overrides?.technique || "T1059.001",
      severity: overrides?.severity || "high",
      event: { test: "data" },
      meta: { test: "meta" },
    },
  });
}

/**
 * Creates a test case.
 */
export async function createTestCase(
  tenantId: string,
  overrides?: Partial<{
    title: string;
    severity: string;
    status: string;
  }>
) {
  return prisma.case.create({
    data: {
      tenantId,
      title: overrides?.title || "Test Case",
      description: "Test case description",
      severity: overrides?.severity || "high",
      status: overrides?.status || "open",
    },
  });
}

export { prisma };
