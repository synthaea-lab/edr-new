import { describe, it, expect, beforeEach, afterAll } from "vitest";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestDetection,
  createTestCase,
  prisma,
} from "../helpers/db";

describe("Tenancy Isolation", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("should isolate agents by tenant", async () => {
    const tenant1 = await createTestTenant("Tenant A");
    const tenant2 = await createTestTenant("Tenant B");

    await createTestAgent(tenant1.id, "agent-a-1");
    await createTestAgent(tenant1.id, "agent-a-2");
    await createTestAgent(tenant2.id, "agent-b-1");

    const tenant1Agents = await prisma.agent.findMany({
      where: { tenantId: tenant1.id },
    });

    const tenant2Agents = await prisma.agent.findMany({
      where: { tenantId: tenant2.id },
    });

    expect(tenant1Agents).toHaveLength(2);
    expect(tenant2Agents).toHaveLength(1);
  });

  it("should isolate detections by tenant", async () => {
    const tenant1 = await createTestTenant("Tenant A");
    const tenant2 = await createTestTenant("Tenant B");

    const agent1 = await createTestAgent(tenant1.id);
    const agent2 = await createTestAgent(tenant2.id);

    await createTestDetection(tenant1.id, agent1.id);
    await createTestDetection(tenant1.id, agent1.id);
    await createTestDetection(tenant2.id, agent2.id);

    const tenant1Detections = await prisma.detection.findMany({
      where: { tenantId: tenant1.id },
    });

    const tenant2Detections = await prisma.detection.findMany({
      where: { tenantId: tenant2.id },
    });

    expect(tenant1Detections).toHaveLength(2);
    expect(tenant2Detections).toHaveLength(1);
  });

  it("should isolate cases by tenant", async () => {
    const tenant1 = await createTestTenant("Tenant A");
    const tenant2 = await createTestTenant("Tenant B");

    await createTestCase(tenant1.id);
    await createTestCase(tenant1.id);
    await createTestCase(tenant2.id);

    const tenant1Cases = await prisma.case.findMany({
      where: { tenantId: tenant1.id },
    });

    const tenant2Cases = await prisma.case.findMany({
      where: { tenantId: tenant2.id },
    });

    expect(tenant1Cases).toHaveLength(2);
    expect(tenant2Cases).toHaveLength(1);
  });

  it("should cascade delete on tenant deletion", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id);
    await createTestCase(tenant.id);

    // Verify data exists
    const beforeAgents = await prisma.agent.count({ where: { tenantId: tenant.id } });
    const beforeDetections = await prisma.detection.count({ where: { tenantId: tenant.id } });
    const beforeCases = await prisma.case.count({ where: { tenantId: tenant.id } });

    expect(beforeAgents).toBe(1);
    expect(beforeDetections).toBe(1);
    expect(beforeCases).toBe(1);

    // Delete tenant
    await prisma.tenant.delete({ where: { id: tenant.id } });

    // Verify cascade deletion
    const afterAgents = await prisma.agent.count({ where: { tenantId: tenant.id } });
    const afterDetections = await prisma.detection.count({ where: { tenantId: tenant.id } });
    const afterCases = await prisma.case.count({ where: { tenantId: tenant.id } });

    expect(afterAgents).toBe(0);
    expect(afterDetections).toBe(0);
    expect(afterCases).toBe(0);
  });

  it("should prevent cross-tenant data access", async () => {
    const tenant1 = await createTestTenant("Tenant A");
    const tenant2 = await createTestTenant("Tenant B");

    const agent1 = await createTestAgent(tenant1.id);

    // Try to query tenant2's agents - should be empty
    const tenant2Agents = await prisma.agent.findMany({
      where: { tenantId: tenant2.id },
    });

    expect(tenant2Agents).toHaveLength(0);
    expect(tenant2Agents.map((a) => a.id)).not.toContain(agent1.id);
  });
});
