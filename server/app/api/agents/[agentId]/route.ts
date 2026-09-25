import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

/**
 * GET /api/agents/{agentId}
 * Query agent details including ring assignment (tenant-scoped)
 *
 * Response: { agent: Agent }
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { agentId: string } }
) {
  try {
    const tenantId = await getTenantId(req);
    const { agentId } = params;

    const agent = await prisma.agent.findFirst({
      where: {
        id: agentId,
        tenantId,
      },
      include: {
        tenant: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({ agent });
  } catch (error) {
    console.error("Agent query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
