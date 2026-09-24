import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId, getUserId } from "@/lib/tenant";
import { z } from "zod";

const CreateReleaseSchema = z.object({
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]),
  manifestUrl: z.string().url(),
  manifestSha256: z.string().regex(/^[a-f0-9]{64}$/),
  releasedAt: z.string().datetime().optional(),
});

/**
 * POST /api/content/release
 * Admin endpoint: Create new content release for a ring
 *
 * Authentication: better-auth session (admin only)
 * Request body: { ring, manifestUrl, manifestSha256, releasedAt? }
 * Response: { release: ContentRelease }
 */
export async function POST(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const userId = await getUserId(req);

    // Parse request body
    const body = await req.json();
    const validation = CreateReleaseSchema.safeParse(body);

    if (!validation.success) {
      return NextResponse.json(
        { error: "Invalid request", details: validation.error.errors },
        { status: 400 }
      );
    }

    const { ring, manifestUrl, manifestSha256, releasedAt } = validation.data;

    // Find highest release version for this tenant + ring
    const latestRelease = await prisma.contentRelease.findFirst({
      where: { tenantId, ring },
      orderBy: { releaseVersion: "desc" },
    });

    const nextVersion = (latestRelease?.releaseVersion || 0) + 1;

    // Create new release
    const release = await prisma.contentRelease.create({
      data: {
        tenantId,
        ring,
        releaseVersion: nextVersion,
        manifestUrl,
        manifestSha256,
        status: "active",
        releasedAt: releasedAt ? new Date(releasedAt) : new Date(),
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        tenantId,
        userId,
        action: "content.release.create",
        resource: `content_releases/${release.id}`,
        details: {
          ring,
          releaseVersion: nextVersion,
          manifestUrl,
        },
      },
    });

    return NextResponse.json({
      status: "created",
      release,
    });
  } catch (error) {
    console.error("Content release creation error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/content/release
 * Admin endpoint: List content releases for tenant
 *
 * Query params:
 * - ring: Filter by ring (optional)
 * - status: Filter by status (optional)
 * - limit: Number of results (default: 50, max: 1000)
 *
 * Response: { releases: ContentRelease[] }
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);

    const ring = searchParams.get("ring");
    const status = searchParams.get("status");
    const limit = parseInt(searchParams.get("limit") || "50", 10);

    const releases = await prisma.contentRelease.findMany({
      where: {
        tenantId,
        ...(ring && { ring }),
        ...(status && { status }),
      },
      orderBy: [{ ring: "asc" }, { releaseVersion: "desc" }],
      take: Math.min(limit, 1000),
    });

    return NextResponse.json({ releases });
  } catch (error) {
    console.error("Content releases query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
