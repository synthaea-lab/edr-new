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

  it("does not let the grouping window drift past the case's first detection", async () => {
    // Regression test: matching used to be evaluated against whichever
    // detection was added to the case most recently, letting a chain of
    // detections each 20 minutes apart merge into one case spanning far
    // more than the 30 minute window. The window must be anchored to the
    // case's earliest detection instead.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    const STEP_MS = 20 * 60 * 1000;
    for (let i = 0; i < 4; i++) {
      await createTestDetection(tenant.id, agent.id, {
        technique: "T1059.001",
        timestamp: new Date(t0.getTime() + i * STEP_MS),
      });
    }

    const res = await GET(cronRequest());
    const body = await res.json();

    // t0, t0+20m join case 1 (both within 30m of t0). t0+40m is 40m from
    // t0 -> starts case 2; t0+60m is 20m from case 2's start -> joins it.
    expect(body.casesCreated).toBe(2);
    const cases = await prisma.case.findMany({
      where: { tenantId: tenant.id },
      include: { detections: true },
      orderBy: { createdAt: "asc" },
    });
    expect(cases).toHaveLength(2);
    expect(cases[0].detections).toHaveLength(2);
    expect(cases[1].detections).toHaveLength(2);
  });

  it("does not double-group detections under concurrent invocations", async () => {
    // Regression test: without a lock serializing the sweep, two overlapping
    // invocations (retry, duplicated trigger) could each independently
    // group the same ungrouped detections into their own separate case.
    const tenant = await createTestTenant();
    const agent = await createTestAgent(tenant.id);
    const t0 = new Date();
    await createTestDetection(tenant.id, agent.id, { technique: "T1059.001", timestamp: t0 });
    await createTestDetection(tenant.id, agent.id, {
      technique: "T1059.003",
      timestamp: new Date(t0.getTime() + 5 * 60 * 1000),
    });

    const [res1, res2] = await Promise.all([GET(cronRequest()), GET(cronRequest())]);
    const [body1, body2] = await Promise.all([res1.json(), res2.json()]);

    const cases = await prisma.case.findMany({ where: { tenantId: tenant.id } });
    expect(cases).toHaveLength(1);

    const totalGrouped = (body1.detectionsGrouped ?? 0) + (body2.detectionsGrouped ?? 0);
    expect(totalGrouped).toBe(2);

    const grouped = await prisma.detection.findMany({ where: { tenantId: tenant.id } });
    expect(grouped.every((d) => d.caseId === cases[0].id)).toBe(true);
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
