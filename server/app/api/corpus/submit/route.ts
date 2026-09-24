import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId } from "@/lib/tenant";
import { z } from "zod";

const CorpusSampleSchema = z.object({
  timestamp: z.string().datetime(),
  eventType: z.string(),
  event: z.record(z.any()), // Normalized schema::Event
});

const CorpusSubmissionSchema = z.object({
  corpusVersion: z.number().int().min(1),
  samples: z.array(CorpusSampleSchema).min(1).max(1000), // Max 1000 samples per batch
});

/**
 * POST /api/corpus/submit
 * Agent endpoint: Submit benign telemetry samples for T3 corpus curation
 *
 * Authentication: mTLS (X-Client-Cert-Verified + X-Client-Cert-Subject)
 * Request body: { corpusVersion: number, samples: Array<CorpusSample> }
 * Response: { status: "accepted", samplesAccepted: number }
 */
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

    const enrollmentId = extractEnrollmentId(certSubject);
    if (!enrollmentId) {
      return NextResponse.json(
        { error: "Invalid certificate subject" },
        { status: 400 }
      );
    }

    // Find agent to get tenant context
    const agent = await prisma.agent.findUnique({
      where: { enrollmentId },
      select: { id: true, tenantId: true },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    // Parse request body
    const body = await req.json();
    const validation = CorpusSubmissionSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { corpusVersion, samples } = validation.data;

    // Find or create corpus version
    let version = await prisma.corpusVersion.findUnique({
      where: {
        tenantId_version: {
          tenantId: agent.tenantId,
          version: corpusVersion,
        },
      },
    });

    if (!version) {
      // Create new corpus version
      version = await prisma.corpusVersion.create({
        data: {
          tenantId: agent.tenantId,
          version: corpusVersion,
          sampleCount: 0,
          status: "collecting",
          collectionStart: new Date(),
        },
      });
    }

    // Check if corpus version is still accepting samples
    if (version.status !== "collecting") {
      return NextResponse.json(
        {
          error: "Corpus version is finalized",
          message: `Version ${corpusVersion} is no longer accepting samples (status: ${version.status})`,
        },
        { status: 409 }
      );
    }

    // Insert samples in batch
    const sampleRecords = samples.map((sample) => ({
      tenantId: agent.tenantId,
      corpusVersionId: version.id,
      agentId: agent.id,
      timestamp: new Date(sample.timestamp),
      eventType: sample.eventType,
      event: sample.event,
    }));

    await prisma.corpusSample.createMany({
      data: sampleRecords,
    });

    // Update sample count
    await prisma.corpusVersion.update({
      where: { id: version.id },
      data: {
        sampleCount: { increment: samples.length },
      },
    });

    return NextResponse.json({
      status: "accepted",
      samplesAccepted: samples.length,
      corpusVersion,
      totalSamples: version.sampleCount + samples.length,
    });
  } catch (error) {
    console.error("Corpus submission error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
