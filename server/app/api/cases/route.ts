import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getTenantId } from "@/lib/tenant";

export async function GET(req: NextRequest) {
  try {
    const tenantId = await getTenantId(req);
    const { searchParams } = new URL(req.url);

    const status = searchParams.get("status");
    const severity = searchParams.get("severity");
    const limit = parseInt(searchParams.get("limit") || "50", 10);

    const cases = await prisma.case.findMany({
      where: {
        tenantId,
        ...(status && { status }),
        ...(severity && { severity }),
      },
      orderBy: { createdAt: "desc" },
      take: Math.min(limit, 1000), // Cap at 1000
    });

    return NextResponse.json({ cases });
  } catch (error) {
    console.error("Cases query error:", error);

    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
