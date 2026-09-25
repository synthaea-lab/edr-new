import { NextRequest, NextResponse } from "next/server";
import { verifyCronRequest } from "@/lib/cron-auth";
import { prisma } from "@/lib/prisma";
import { isRelatedTechnique, outranksSeverity, withinTimeWindow } from "@/lib/case-grouping";

interface CandidateCase {
  id: string;
  severity: string;
  detections: { agentId: string; timestamp: Date; technique: string }[];
}

/**
 * GET /api/cron/group-detections
 *
 * Cron endpoint (issue #50): groups ungrouped detections (`caseId: null`)
 * into a Case per tenant, so the case store has an evidence graph for
 * narrative generation to work from. Heuristic: same agent + within a 30
 * minute window + related MITRE technique attaches to an existing open
 * case; otherwise a new case is created. Idempotent — re-running only ever
 * touches detections still at `caseId: null`.
 *
 * Authentication: Bearer token (CRON_SECRET)
 * Response: { tenantsChecked, casesCreated, detectionsGrouped }
 */
export async function GET(req: NextRequest) {
  try {
    const denied = verifyCronRequest(req);
    if (denied) {
      return denied;
    }

    const tenants = await prisma.tenant.findMany({ select: { id: true } });

    let casesCreated = 0;
    let detectionsGrouped = 0;

    for (const tenant of tenants) {
      const ungrouped = await prisma.detection.findMany({
        where: { tenantId: tenant.id, caseId: null },
        orderBy: { timestamp: "asc" },
      });

      if (ungrouped.length === 0) {
        continue;
      }

      const openCases: CandidateCase[] = await prisma.case.findMany({
        where: { tenantId: tenant.id, status: "open" },
        select: {
          id: true,
          severity: true,
          detections: { select: { agentId: true, timestamp: true, technique: true } },
        },
      });

      for (const detection of ungrouped) {
        const match = openCases.find((c) =>
          c.detections.some(
            (d) =>
              d.agentId === detection.agentId &&
              withinTimeWindow(d.timestamp, detection.timestamp) &&
              isRelatedTechnique(d.technique, detection.technique)
          )
        );

        let targetCase: CandidateCase;
        if (match) {
          targetCase = match;
        } else {
          const agent = await prisma.agent.findUnique({
            where: { id: detection.agentId },
            select: { hostname: true },
          });
          const created = await prisma.case.create({
            data: {
              tenantId: tenant.id,
              title: `${detection.technique} activity on ${agent?.hostname ?? detection.agentId}`,
              severity: detection.severity,
              status: "open",
            },
            select: { id: true, severity: true },
          });
          targetCase = { ...created, detections: [] };
          openCases.push(targetCase);
          casesCreated++;
        }

        await prisma.detection.update({
          where: { id: detection.id },
          data: { caseId: targetCase.id },
        });
        detectionsGrouped++;

        if (outranksSeverity(detection.severity, targetCase.severity)) {
          await prisma.case.update({
            where: { id: targetCase.id },
            data: { severity: detection.severity },
          });
          targetCase.severity = detection.severity;
        }

        targetCase.detections.push({
          agentId: detection.agentId,
          timestamp: detection.timestamp,
          technique: detection.technique,
        });
      }
    }

    return NextResponse.json({
      tenantsChecked: tenants.length,
      casesCreated,
      detectionsGrouped,
    });
  } catch (error) {
    console.error("Detection grouping error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
