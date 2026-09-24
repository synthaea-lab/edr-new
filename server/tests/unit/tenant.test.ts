import { describe, it, expect } from "vitest";
import { extractEnrollmentId } from "@/lib/tenant";

describe("tenant helpers", () => {
  describe("extractEnrollmentId", () => {
    it("should extract enrollment ID from certificate subject", () => {
      const subject = "CN=agent-test-001,O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-test-001");
    });

    it("should handle subject with multiple fields", () => {
      const subject =
        "C=US,ST=CA,L=SF,O=synthaea,OU=Agents,CN=agent-prod-123";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-prod-123");
    });

    it("should return empty string for invalid subject", () => {
      const subject = "O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("");
    });

    it("should return empty string for empty subject", () => {
      const subject = "";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("");
    });

    it("should handle subject with CN containing special characters", () => {
      const subject = "CN=agent-test-001.example.com,O=synthaea";
      const result = extractEnrollmentId(subject);
      expect(result).toBe("agent-test-001.example.com");
    });
  });
});
