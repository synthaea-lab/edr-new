import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { extractEnrollmentId } from "@/lib/tenant";
import type { ContentManifest } from "@/lib/content-manifest";

const VALID_RINGS = ["canary_0", "canary_1", "canary_2", "prod"];

/**
 * GET /api/content/manifest/{ring}
 * Agent endpoint: Fetch latest content manifest for assigned ring
 *
 * Authentication: mTLS (X-Client-Cert-Verified + X-Client-Cert-Subject)
 * Response: ContentManifest JSON (signed)
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { ring: string } }
) {
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

    // Validate ring parameter
    const { ring } = params;
    if (!VALID_RINGS.includes(ring)) {
      return NextResponse.json(
        { error: "Invalid ring", validRings: VALID_RINGS },
        { status: 400 }
      );
    }

    // Find agent to get tenant context
    const agent = await prisma.agent.findUnique({
      where: { enrollmentId },
      select: { id: true, tenantId: true, ring: true },
    });

    if (!agent) {
      return NextResponse.json(
        { error: "Agent not enrolled" },
        { status: 403 }
      );
    }

    // Verify agent is in requested ring (prevent ring spoofing)
    if (agent.ring !== ring) {
      return NextResponse.json(
        {
          error: "Ring mismatch",
          message: `Agent is assigned to ring '${agent.ring}', cannot fetch manifest for '${ring}'`,
        },
        { status: 403 }
      );
    }

    // Find latest active content release for this tenant + ring
    const release = await prisma.contentRelease.findFirst({
      where: {
        tenantId: agent.tenantId,
        ring,
        status: "active",
      },
      orderBy: { releaseVersion: "desc" },
    });

    if (!release) {
      return NextResponse.json(
        { error: "No content release available for ring" },
        { status: 404 }
      );
    }

    // Fetch manifest from storage (manifestUrl)
    // For now, return a placeholder - in production, fetch from object store
    const manifest: ContentManifest = {
      schema_version: 1,
      release_version: release.releaseVersion,
      ring: ring as any,
      released_at: release.releasedAt.toISOString(),
      entries: [],
      signature: "placeholder_signature",
    };

    // TODO: Fetch actual manifest from release.manifestUrl
    // const response = await fetch(release.manifestUrl);
    // const manifest = await response.json();

    return NextResponse.json(manifest);
  } catch (error) {
    console.error("Content manifest fetch error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
