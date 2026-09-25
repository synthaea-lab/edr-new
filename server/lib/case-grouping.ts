/**
 * Pure decision logic for the detection-grouping heuristic (issue #50),
 * separated from the Prisma calls in app/api/cron/group-detections/route.ts
 * so it's unit-testable without a database.
 *
 * This is the honest limit of what's derivable from the single `technique`
 * string field actually stored on `Detection` — no MITRE tactic taxonomy
 * lookup exists in this codebase, so "related" means "same technique" or
 * "same base technique" (the part before the sub-technique dot).
 */

export const GROUPING_TIME_WINDOW_MS = 30 * 60 * 1000; // 30 minutes

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** The MITRE base technique: "T1059.001" -> "T1059". No dot -> itself. */
export function baseTechnique(technique: string): string {
  return technique.split(".")[0];
}

/** Same technique, or same base (sub-)technique. */
export function isRelatedTechnique(a: string, b: string): boolean {
  return a === b || baseTechnique(a) === baseTechnique(b);
}

export function withinTimeWindow(a: Date, b: Date, windowMs: number = GROUPING_TIME_WINDOW_MS): boolean {
  return Math.abs(a.getTime() - b.getTime()) <= windowMs;
}

/** Higher-severity-wins comparison; unknown severities never outrank a known one. */
export function outranksSeverity(candidate: string, current: string): boolean {
  const candidateRank = SEVERITY_RANK[candidate] ?? -1;
  const currentRank = SEVERITY_RANK[current] ?? -1;
  return candidateRank > currentRank;
}
