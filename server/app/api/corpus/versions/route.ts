import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

/**
 * GET /api/corpus/versions
 * Admin endpoint: List corpus versions for tenant
 *
 * Query params:
 * - status: Filter by status (collecting, finalized, archived)
 * - limit: Number of results (default: 50, max: 1000)
 *
 * Response: { versions: CorpusVersion[] }
 */
export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);

    const status = searchParams.get("status");
    const limit = parseInt(searchParams.get("limit") || "50", 10);

    const versions = await prisma.corpusVersion.findMany({
      where: {
        tenantId,
        ...(status && { status }),
      },
      orderBy: { version: "desc" },
      take: Math.min(limit, 1000),
      select: {
        id: true,
        version: true,
        sampleCount: true,
        exportUrl: true,
        exportSha256: true,
        status: true,
        collectionStart: true,
        collectionEnd: true,
        createdAt: true,
      },
    });

    return NextResponse.json({ versions });
  } catch (error) {
    console.error("Corpus versions query error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
