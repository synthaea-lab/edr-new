/**
 * Content Manifest Schema (extends ADR-0015 for non-binary artifacts)
 *
 * Supports canary-ring deployment of rules, models, and policy without
 * requiring binary updates. Mirrors updater manifest format for consistency.
 *
 * Related: Issue #30 (updater rings), Issue #49 (per-site model adaptation)
 */

import { z } from "zod";

/**
 * Content types supported by the content distribution system
 */
export const ContentType = z.enum([
  "rule",   // Sigma YAML detection rule
  "model",  // ML model (pickle + model_record.json)
  "policy", // JSON policy configuration
]);

export type ContentType = z.infer<typeof ContentType>;

/**
 * Single content artifact entry
 */
export const ContentEntry = z.object({
  path: z.string(),           // Relative path: rules/beacon.sigma, models/cmdline-iforest-linux.pkl
  type: ContentType,          // Content type for validation
  sha256: z.string(),         // SHA-256 hash (hex) for integrity verification
  size: z.number(),           // File size in bytes
  metadata: z.record(z.any()).optional(), // Optional metadata (e.g., model version, MITRE technique)
});

export type ContentEntry = z.infer<typeof ContentEntry>;

/**
 * Content manifest — signed list of artifacts for a specific ring
 *
 * Example filename: content-canary_0-v42.json
 * Schema mirrors ADR-0015 binary manifest for consistency
 */
export const ContentManifest = z.object({
  schema_version: z.literal(1),           // Schema version (strict validation, reject unknown)
  release_version: z.number().int().min(1), // Monotone counter (anti-rollback)
  ring: z.enum(["canary_0", "canary_1", "canary_2", "prod"]), // Target ring
  released_at: z.string(),                // ISO 8601 UTC timestamp
  entries: z.array(ContentEntry),         // List of content artifacts
  signature: z.string(),                  // Ed25519 signature (hex) over canonical JSON
});

export type ContentManifest = z.infer<typeof ContentManifest>;

/**
 * Canonical JSON for signing (matches ADR-0015 Decision 2)
 * - 2-space indent
 * - Sorted keys
 * - No signature field in signed payload
 */
export function canonicalJSON(manifest: Omit<ContentManifest, "signature">): string {
  return JSON.stringify(manifest, Object.keys(manifest).sort(), 2);
}

/**
 * Verify manifest signature using Ed25519 public key
 * Returns true if signature is valid, false otherwise
 */
export async function verifySignature(
  manifest: ContentManifest,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    // Remove signature from manifest for canonical JSON
    const { signature, ...payload } = manifest;
    const canonical = canonicalJSON(payload);

    // Convert hex signature to bytes
    const signatureBytes = hexToBytes(signature);

    // Verify using Web Crypto API (Ed25519)
    const key = await crypto.subtle.importKey(
      "raw",
      publicKey,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(canonical);

    return await crypto.subtle.verify(
      "Ed25519",
      key,
      signatureBytes,
      data
    );
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

/**
 * Check if release version is newer than current
 * Prevents rollback attacks per ADR-0015 Decision 5
 */
export function isNewerRelease(
  current: number,
  candidate: number
): boolean {
  return candidate > current;
}

/**
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Content manifest storage path pattern
 * Example: manifests/content-canary_0-v42.json
 */
export function contentManifestPath(ring: string, version: number): string {
  return `manifests/content-${ring}-v${version}.json`;
}

/**
 * Content artifact storage path pattern
 * Example: artifacts/rules/beacon.sigma
 */
export function contentArtifactPath(entry: ContentEntry): string {
  return `artifacts/${entry.path}`;
}

/**
 * Example content manifest for canary_0 ring
 */
export const EXAMPLE_MANIFEST: ContentManifest = {
  schema_version: 1,
  release_version: 42,
  ring: "canary_0",
  released_at: "2026-09-23T16:00:00Z",
  entries: [
    {
      path: "rules/beacon.sigma",
      type: "rule",
      sha256: "a".repeat(64),
      size: 1234,
      metadata: { technique: "T1071.001", severity: "high" },
    },
    {
      path: "models/cmdline-iforest-linux/0.3.0/model.pkl",
      type: "model",
      sha256: "b".repeat(64),
      size: 10485760, // 10 MB
      metadata: { version: "0.3.0", escape_rate: 0.08 },
    },
    {
      path: "models/cmdline-iforest-linux/0.3.0/model_record.json",
      type: "model",
      sha256: "c".repeat(64),
      size: 2048,
      metadata: { version: "0.3.0" },
    },
    {
      path: "policy/site-policy-v5.json",
      type: "policy",
      sha256: "d".repeat(64),
      size: 512,
      metadata: { version: 5 },
    },
  ],
  signature: "0".repeat(128), // Ed25519 signature (64 bytes hex)
};
