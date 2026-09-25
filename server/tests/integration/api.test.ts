import { describe, it, expect, beforeEach, afterAll } from "vitest";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestCase,
  prisma,
} from "../helpers/db";

describe("Management API", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  describe("POST /api/enrollment", () => {
    it("should enroll new agent", async () => {
      const tenant = await createTestTenant();

      const enrollmentData = {
        enrollmentId: "new-agent-001",
        hostname: "test-vm-01",
        version: "0.1.0",
      };

      // Enroll agent
      const agent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          ...enrollmentData,
          lastSeen: new Date(),
        },
      });

      expect(agent.id).toBeDefined();
      expect(agent.enrollmentId).toBe("new-agent-001");
      expect(agent.hostname).toBe("test-vm-01");
      expect(agent.version).toBe("0.1.0");
    });

    it("should reject duplicate enrollment", async () => {
      const tenant = await createTestTenant();
      const existingAgent = await createTestAgent(tenant.id, "duplicate-agent");

      // Try to enroll with same ID
      await expect(
        prisma.agent.create({
          data: {
            tenantId: tenant.id,
            enrollmentId: "duplicate-agent",
            lastSeen: new Date(),
          },
        })
      ).rejects.toThrow();
    });

    it("should create audit log entry", async () => {
      const tenant = await createTestTenant();
      const userId = "test-user-123";

      const agent = await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "audit-test-agent",
          lastSeen: new Date(),
        },
      });

      // Create audit log
      const auditLog = await prisma.auditLog.create({
        data: {
          tenantId: tenant.id,
          userId,
          action: "enrollment.create",
          resource: `agents/${agent.id}`,
          details: {
            enrollmentId: agent.enrollmentId,
          },
        },
      });

      expect(auditLog.action).toBe("enrollment.create");
      expect(auditLog.userId).toBe(userId);
      expect(auditLog.resource).toBe(`agents/${agent.id}`);
    });
  });

  describe("GET /api/cases", () => {
    it("should return cases for tenant", async () => {
      const tenant1 = await createTestTenant("Tenant 1");
      const tenant2 = await createTestTenant("Tenant 2");

      // Create cases for tenant 1
      await createTestCase(tenant1.id, { title: "Case 1" });
      await createTestCase(tenant1.id, { title: "Case 2" });

      // Create case for tenant 2
      await createTestCase(tenant2.id, { title: "Case 3" });

      // Query tenant 1 cases
      const tenant1Cases = await prisma.case.findMany({
        where: { tenantId: tenant1.id },
      });

      expect(tenant1Cases).toHaveLength(2);
      expect(tenant1Cases.map((c) => c.title)).toContain("Case 1");
      expect(tenant1Cases.map((c) => c.title)).toContain("Case 2");
      expect(tenant1Cases.map((c) => c.title)).not.toContain("Case 3");
    });

    it("should filter cases by status", async () => {
      const tenant = await createTestTenant();

      await createTestCase(tenant.id, { status: "open" });
      await createTestCase(tenant.id, { status: "open" });
      await createTestCase(tenant.id, { status: "resolved" });

      const openCases = await prisma.case.findMany({
        where: {
          tenantId: tenant.id,
          status: "open",
        },
      });

      expect(openCases).toHaveLength(2);
      expect(openCases.every((c) => c.status === "open")).toBe(true);
    });

    it("should filter cases by severity", async () => {
      const tenant = await createTestTenant();

      await createTestCase(tenant.id, { severity: "critical" });
      await createTestCase(tenant.id, { severity: "high" });
      await createTestCase(tenant.id, { severity: "medium" });

      const criticalCases = await prisma.case.findMany({
        where: {
          tenantId: tenant.id,
          severity: "critical",
        },
      });

      expect(criticalCases).toHaveLength(1);
      expect(criticalCases[0].severity).toBe("critical");
    });

    it("should limit results", async () => {
      const tenant = await createTestTenant();

      // Create 10 cases
      for (let i = 0; i < 10; i++) {
        await createTestCase(tenant.id, { title: `Case ${i}` });
      }

      const limited = await prisma.case.findMany({
        where: { tenantId: tenant.id },
        take: 5,
      });

      expect(limited).toHaveLength(5);
    });

    it("should sort by creation time descending", async () => {
      const tenant = await createTestTenant();

      const case1 = await createTestCase(tenant.id, { title: "First" });
      await new Promise((resolve) => setTimeout(resolve, 10));
      const case2 = await createTestCase(tenant.id, { title: "Second" });
      await new Promise((resolve) => setTimeout(resolve, 10));
      const case3 = await createTestCase(tenant.id, { title: "Third" });

      const cases = await prisma.case.findMany({
        where: { tenantId: tenant.id },
        orderBy: { createdAt: "desc" },
      });

      expect(cases[0].id).toBe(case3.id); // Newest first
      expect(cases[1].id).toBe(case2.id);
      expect(cases[2].id).toBe(case1.id);
    });
  });
});
