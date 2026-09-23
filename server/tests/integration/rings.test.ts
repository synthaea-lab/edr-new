import { describe, it, expect, beforeEach, afterAll } from "vitest";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  prisma,
} from "../helpers/db";

describe("Canary Ring Infrastructure", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  describe("Ring Assignment", () => {
    it("should assign agents to default 'prod' ring on enrollment", async () => {
      const tenant = await createTestTenant("Test Tenant");
      const agent = await createTestAgent(tenant.id, "agent-1");

      expect(agent.ring).toBe("prod");
    });

    it("should allow updating agent ring assignment", async () => {
      const tenant = await createTestTenant("Test Tenant");
      const agent = await createTestAgent(tenant.id, "agent-1");

      const updated = await prisma.agent.update({
        where: { id: agent.id },
        data: { ring: "canary_0" },
      });

      expect(updated.ring).toBe("canary_0");
    });

    it("should query agents by ring", async () => {
      const tenant = await createTestTenant("Test Tenant");

      await createTestAgent(tenant.id, "agent-prod-1", { ring: "prod" });
      await createTestAgent(tenant.id, "agent-prod-2", { ring: "prod" });
      await createTestAgent(tenant.id, "agent-canary-1", { ring: "canary_0" });
      await createTestAgent(tenant.id, "agent-canary-2", { ring: "canary_1" });

      const prodAgents = await prisma.agent.findMany({
        where: { tenantId: tenant.id, ring: "prod" },
      });

      const canary0Agents = await prisma.agent.findMany({
        where: { tenantId: tenant.id, ring: "canary_0" },
      });

      expect(prodAgents).toHaveLength(2);
      expect(canary0Agents).toHaveLength(1);
    });

    it("should isolate ring queries by tenant", async () => {
      const tenant1 = await createTestTenant("Tenant A");
      const tenant2 = await createTestTenant("Tenant B");

      await createTestAgent(tenant1.id, "agent-a", { ring: "canary_0" });
      await createTestAgent(tenant2.id, "agent-b", { ring: "canary_0" });

      const tenant1Canary = await prisma.agent.findMany({
        where: { tenantId: tenant1.id, ring: "canary_0" },
      });

      const tenant2Canary = await prisma.agent.findMany({
        where: { tenantId: tenant2.id, ring: "canary_0" },
      });

      expect(tenant1Canary).toHaveLength(1);
      expect(tenant2Canary).toHaveLength(1);
      expect(tenant1Canary[0].id).not.toBe(tenant2Canary[0].id);
    });
  });

  describe("Content Releases", () => {
    it("should create content release for ring", async () => {
      const tenant = await createTestTenant("Test Tenant");

      const release = await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 1,
          manifestUrl: "https://example.com/manifests/content-canary_0-v1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date(),
        },
      });

      expect(release.ring).toBe("canary_0");
      expect(release.releaseVersion).toBe(1);
      expect(release.status).toBe("active");
    });

    it("should enforce unique constraint on tenant + ring + version", async () => {
      const tenant = await createTestTenant("Test Tenant");

      await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 1,
          manifestUrl: "https://example.com/manifest-v1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date(),
        },
      });

      // Attempt duplicate
      await expect(
        prisma.contentRelease.create({
          data: {
            tenantId: tenant.id,
            ring: "canary_0",
            releaseVersion: 1,
            manifestUrl: "https://example.com/manifest-v1-dup.json",
            manifestSha256: "b".repeat(64),
            releasedAt: new Date(),
          },
        })
      ).rejects.toThrow();
    });

    it("should query latest release for ring", async () => {
      const tenant = await createTestTenant("Test Tenant");

      // Create multiple releases
      await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 1,
          manifestUrl: "https://example.com/v1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date("2026-09-20"),
        },
      });

      await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 2,
          manifestUrl: "https://example.com/v2.json",
          manifestSha256: "b".repeat(64),
          releasedAt: new Date("2026-09-21"),
        },
      });

      await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 3,
          manifestUrl: "https://example.com/v3.json",
          manifestSha256: "c".repeat(64),
          releasedAt: new Date("2026-09-22"),
        },
      });

      // Query latest
      const latest = await prisma.contentRelease.findFirst({
        where: {
          tenantId: tenant.id,
          ring: "canary_0",
          status: "active",
        },
        orderBy: { releaseVersion: "desc" },
      });

      expect(latest?.releaseVersion).toBe(3);
    });

    it("should isolate content releases by tenant", async () => {
      const tenant1 = await createTestTenant("Tenant A");
      const tenant2 = await createTestTenant("Tenant B");

      await prisma.contentRelease.create({
        data: {
          tenantId: tenant1.id,
          ring: "prod",
          releaseVersion: 10,
          manifestUrl: "https://example.com/t1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date(),
        },
      });

      await prisma.contentRelease.create({
        data: {
          tenantId: tenant2.id,
          ring: "prod",
          releaseVersion: 5,
          manifestUrl: "https://example.com/t2.json",
          manifestSha256: "b".repeat(64),
          releasedAt: new Date(),
        },
      });

      const tenant1Latest = await prisma.contentRelease.findFirst({
        where: { tenantId: tenant1.id, ring: "prod" },
        orderBy: { releaseVersion: "desc" },
      });

      const tenant2Latest = await prisma.contentRelease.findFirst({
        where: { tenantId: tenant2.id, ring: "prod" },
        orderBy: { releaseVersion: "desc" },
      });

      expect(tenant1Latest?.releaseVersion).toBe(10);
      expect(tenant2Latest?.releaseVersion).toBe(5);
    });
  });

  describe("Ring Status Updates", () => {
    it("should mark release as halted", async () => {
      const tenant = await createTestTenant("Test Tenant");

      const release = await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 1,
          manifestUrl: "https://example.com/v1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date(),
        },
      });

      const halted = await prisma.contentRelease.update({
        where: { id: release.id },
        data: { status: "halted" },
      });

      expect(halted.status).toBe("halted");
    });

    it("should support rollback workflow", async () => {
      const tenant = await createTestTenant("Test Tenant");

      // Create v1 and v2
      const v1 = await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 1,
          manifestUrl: "https://example.com/v1.json",
          manifestSha256: "a".repeat(64),
          releasedAt: new Date("2026-09-20"),
          status: "active",
        },
      });

      const v2 = await prisma.contentRelease.create({
        data: {
          tenantId: tenant.id,
          ring: "canary_0",
          releaseVersion: 2,
          manifestUrl: "https://example.com/v2.json",
          manifestSha256: "b".repeat(64),
          releasedAt: new Date("2026-09-21"),
          status: "active",
        },
      });

      // Simulate rollback: mark v2 as rolled_back, reactivate v1
      await prisma.contentRelease.update({
        where: { id: v2.id },
        data: { status: "rolled_back" },
      });

      await prisma.contentRelease.update({
        where: { id: v1.id },
        data: { status: "active" },
      });

      // Query latest active
      const latest = await prisma.contentRelease.findFirst({
        where: {
          tenantId: tenant.id,
          ring: "canary_0",
          status: "active",
        },
        orderBy: { releaseVersion: "desc" },
      });

      expect(latest?.releaseVersion).toBe(1);
    });
  });

  describe("Ring Health Metrics", () => {
    it("should count healthy vs silent agents in ring", async () => {
      const tenant = await createTestTenant("Test Tenant");

      // Create agents with different last-seen timestamps
      const now = new Date();
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
      const tenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000);

      await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "agent-healthy-1",
          ring: "canary_0",
          lastSeen: now,
          createdAt: now,
        },
      });

      await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "agent-healthy-2",
          ring: "canary_0",
          lastSeen: fiveMinutesAgo,
          createdAt: now,
        },
      });

      await prisma.agent.create({
        data: {
          tenantId: tenant.id,
          enrollmentId: "agent-silent-1",
          ring: "canary_0",
          lastSeen: tenMinutesAgo,
          createdAt: now,
        },
      });

      // Count healthy (last-seen within 5 minutes)
      const silenceThreshold = new Date(now.getTime() - 5 * 60 * 1000);
      const healthy = await prisma.agent.count({
        where: {
          tenantId: tenant.id,
          ring: "canary_0",
          lastSeen: { gte: silenceThreshold },
        },
      });

      const total = await prisma.agent.count({
        where: { tenantId: tenant.id, ring: "canary_0" },
      });

      expect(total).toBe(3);
      expect(healthy).toBe(2);
    });
  });
});
