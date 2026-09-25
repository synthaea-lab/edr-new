import { timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

export type CronAuthResult = "ok" | "unconfigured" | "unauthorized";

/**
 * Checks a cron call's `Authorization` header against `CRON_SECRET`.
 *
 * Fails closed: an unset or empty secret is "unconfigured", never a match.
 * Building the expected value as `` `Bearer ${process.env.CRON_SECRET}` ``
 * instead turns an unset secret into the literal string "Bearer undefined",
 * which anyone can send.
 *
 * The comparison is constant-time. The length check up front leaks only the
 * header's length, not how many leading bytes match.
 */
export function checkCronAuth(
  authHeader: string | null,
  secret: string | undefined
): CronAuthResult {
  if (!secret) {
    return "unconfigured";
  }
  if (!authHeader) {
    return "unauthorized";
  }
  const expected = Buffer.from(`Bearer ${secret}`);
  const received = Buffer.from(authHeader);
  if (received.length !== expected.length) {
    return "unauthorized";
  }
  return timingSafeEqual(received, expected) ? "ok" : "unauthorized";
}

/**
 * Route guard for the `/api/cron/*` endpoints. Returns the error response to
 * send, or `null` when the call is authorized.
 */
export function verifyCronRequest(req: NextRequest): NextResponse | null {
  switch (checkCronAuth(req.headers.get("Authorization"), process.env.CRON_SECRET)) {
    case "ok":
      return null;
    case "unconfigured":
      console.error("CRON_SECRET environment variable is not configured");
      return NextResponse.json(
        { error: "Server misconfiguration - CRON_SECRET not set" },
        { status: 500 }
      );
    case "unauthorized":
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
}
