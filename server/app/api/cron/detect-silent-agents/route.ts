import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const SILENCE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutes

export async function GET(req: NextRequest) {
  try {
    // Verify cron auth token
    const authHeader = req.headers.get("Authorization");
    const expectedToken = `Bearer ${process.env.CRON_SECRET}`;

    if (!authHeader || authHeader !== expectedToken) {
      return NextResponse.json(
        { error: "Unauthorized - invalid cron secret" },
        { status: 401 }
      );
    }

    const threshold = new Date(Date.now() - SILENCE_THRESHOLD_MS);

    // Find silent agents
    const silentAgents = await prisma.agent.findMany({
      where: {
        lastSeen: { lt: threshold },
      },
      include: { tenant: true },
    });

    let casesCreated = 0;

    // Create cases for silent agents
    for (const agent of silentAgents) {
      // Check if we already have an open case for this agent
      const existingCase = await prisma.case.findFirst({
        where: {
          tenantId: agent.tenantId,
          title: { contains: agent.id },
          status: "open",
        },
      });

      if (!existingCase) {
        await prisma.case.create({
          data: {
            tenantId: agent.tenantId,
            title: `Agent Silent: ${agent.hostname || agent.id}`,
            description: `Agent has not sent heartbeat for >5 minutes. Last seen: ${agent.lastSeen.toISOString()}. Enrollment ID: ${agent.enrollmentId}`,
            severity: "high",
            status: "open",
          },
        });
        casesCreated++;
      }
    }

    return NextResponse.json({
      silentAgents: silentAgents.length,
      casesCreated,
      threshold: threshold.toISOString(),
    });
  } catch (error) {
    console.error("Silent agent detection error:", error);

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
