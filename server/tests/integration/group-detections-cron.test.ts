import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { NextRequest } from "next/server";
import {
  cleanDatabase,
  createTestTenant,
  createTestAgent,
  createTestDetection,
  prisma,
} from "../helpers/db";
import { GET } from "@/app/api/cron/group-detections/route";

function cronRequest() {
  return new NextRequest("http://localhost/api/cron/group-detections", {
    headers: { Authorization: `Bearer ${process.env.CRON_SECRET}` },
  });
}

describe("GET /api/cron/group-detections", () => {
  beforeEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await cleanDatabase();
    await prisma.$disconnect();
  });

  it("attaches related detections from the same agent to one case", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      timestamp: t0,
    });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.003",
      timestamp: new Date(t0.getTime() + 5 * 60 * 1000),
    });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(1);
    expect(body.detectionsGrouped).toBe(2);

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
    const grouped = await prisma.detection.findMany({ where: { tenantId: tenant.id } });
    expect(grouped.every((d) => d.caseId === cases[0].id)).toBe(true);
  });

  it("creates separate cases for unrelated techniques", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agent.id, { technique: "T1105", timestamp: t0 });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(2);
  });

  it("does not group detections from different agents", async () => {
    const tenant = await createTestTenant();
    const agentA = await createTestAgent(tenant.id, "agent-a");
    const agentB = await createTestAgent(tenant.id, "agent-b");
    const t0 = new Date();
    await createTestDetection(tenant.id, agentA.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agentB.id, { technique: "T1059.001", timestamp: t0 });

    const res = await GET(cronRequest());
    const body = await res.json();

    expect(body.casesCreated).toBe(2);
  });

  it("bumps the case severity to the worst evidence it contains", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      severity: "medium",
      timestamp: t0,
    });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.001",
      severity: "critical",
      timestamp: new Date(t0.getTime() + 60_000),
    });

    await GET(cronRequest());

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases[0].severity).toBe("critical");
  });

  it("is idempotent across repeated runs", async () => {
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001" });

    await GET(cronRequest());
    const secondRun = await GET(cronRequest());
    const body = await secondRun.json();

    expect(body.detectionsGrouped).toBe(0);
    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);
  });

  it("rejects the call when CRON_SECRET is unset", async () => {
    const saved = process.env.CRON_SECRET;
    delete process.env.CRON_SECRET;
    try {
      const res = await GET(cronRequest());
      expect(res.status).toBe(500);
    } finally {
      process.env.CRON_SECRET = saved;
    }
  });
});
