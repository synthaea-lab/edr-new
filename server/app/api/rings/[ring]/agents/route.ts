import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

const VALID_RINGS = ["canary_0", "canary_1", "canary_2", "prod"];

/**
 * GET /api/rings/{ring}/agents
 * List all agents in a specific ring (tenant-scoped)
 *
 * Query params:
 * - status: "healthy" | "silent" (filter by heartbeat status)
 * - limit: number (default: 100, max: 1000)
 *
 * Response: { ring: string, agents: Agent[], count: number }
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { ring: string } }
) {
  try {
    const tenantId = await getTenantId(req);
    const { ring } = params;

    // Validate ring parameter
    if (!VALID_RINGS.includes(ring)) {
      return NextResponse.json(
        { error: "Invalid ring", validRings: VALID_RINGS },
        { status: 400 }
      );
    }

    const { searchParams } = new URL(req.url);
    const status = searchParams.get("status");
    const limit = parseInt(searchParams.get("limit") || "100", 10);

    // Build where clause
    const where: any = {
      tenantId,
      ring,
    };

    // Filter by heartbeat status
    if (status === "healthy") {
      // Healthy: heartbeat within last 5 minutes
      const healthyThreshold = new Date(Date.now() - 5 * 60 * 1000);
      where.lastSeen = { gte: healthyThreshold };
    } else if (status === "silent") {
      // Silent: no heartbeat for >5 minutes
      const silentThreshold = new Date(Date.now() - 5 * 60 * 1000);
      where.lastSeen = { lt: silentThreshold };
    }

    const agents = await prisma.agent.findMany({
      where,
      orderBy: { lastSeen: "desc" },
      take: Math.min(limit, 1000),
      select: {
        id: true,
        enrollmentId: true,
        hostname: true,
        version: true,
        ring: true,
        lastSeen: true,
        createdAt: true,
      },
    });

    return NextResponse.json({
      ring,
      agents,
      count: agents.length,
    });
  } catch (error) {
    console.error("Ring agents query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
