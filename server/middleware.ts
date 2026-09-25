import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { buildIdentityHeaders } from "@/lib/tenant";

export async function middleware(req: NextRequest) {
  // Public routes - no authentication required
  if (
    req.nextUrl.pathname.startsWith("/api/ingest") ||
    req.nextUrl.pathname.startsWith("/api/auth") ||
    req.nextUrl.pathname.startsWith("/api/health") ||
    req.nextUrl.pathname === "/login" ||
    req.nextUrl.pathname === "/"
  ) {
    return NextResponse.next();
  }

  // Check session for protected routes
  const session = await auth.api.getSession({
    headers: req.headers,
  });

  // Redirect to login if no session
  if (!session) {
    return NextResponse.redirect(new URL("/login", req.url));
  }

  // Inject tenant context for protected routes
  const headers = buildIdentityHeaders(req.headers, {
    tenantId: session.session.activeOrganizationId,
    userId: session.user.id,
  });

  return NextResponse.next({
    request: { headers },
  });
}

export const config = {
  matcher: [
    "/console/:path*",
    "/api/((?!ingest|auth|health).*)",
  ],
};
