import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId } from "@/lib/tenant";
import { z } from "zod";

// Validation schema for detection payload
const DetectionSchema = z.object({
  timestamp_ns: z.number(),
  technique: z.string(),
  severity: z.enum(["low", "medium", "high", "critical"]),
  event: z.record(z.any()),
  meta: z.record(z.any()),
});

export async function POST(req: NextRequest) {
  try {
    // Verify mTLS authentication
    const certVerified = req.headers.get("X-Client-Cert-Verified");
    const certSubject = req.headers.get("X-Client-Cert-Subject");

    if (certVerified !== "SUCCESS" || !certSubject) {
      return NextResponse.json(
        { error: "Unauthorized - mTLS authentication required" },
        { status: 401 }
      );
    }

    // Extract agent enrollment ID from certificate
    const enrollmentId = extractEnrollmentId(certSubject);

    if (!enrollmentId) {
      return NextResponse.json(
        { error: "Invalid certificate subject" },
        { status: 400 }
      );
    }

    // Find agent (with tenant context)
    const agent = await prisma.agent.findUnique({
      where: { enrollmentId },
      include: { tenant: true },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    // Parse and validate detection payload
    const body = await req.json();
    const detection = DetectionSchema.parse(body);

    // Store detection
    await prisma.detection.create({
      data: {
        tenantId: agent.tenantId,
        agentId: agent.id,
        timestamp: new Date(detection.timestamp_ns / 1_000_000),
        technique: detection.technique,
        severity: detection.severity,
        event: detection.event,
        meta: detection.meta,
      },
    });

    // Update agent last-seen timestamp
    await prisma.agent.update({
      where: { id: agent.id },
      data: { lastSeen: new Date() },
    });

    return NextResponse.json({ status: "accepted" });
  } catch (error) {
    console.error("Detection ingest error:", error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid payload", details: error.errors },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
