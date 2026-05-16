import { describe, it, expect } from "vitest";
import { fmtNumber, fmtLatency, truncateHash } from "../lib/format";

describe("fmtNumber", () => {
  it("formats numbers with commas", () => {
    expect(fmtNumber(1847)).toBe("1,847");
  });
  it("returns em-dash for null", () => {
    expect(fmtNumber(null)).toBe("—");
  });
  it("returns em-dash for undefined", () => {
    expect(fmtNumber(undefined)).toBe("—");
  });
});

describe("fmtLatency", () => {
  it("appends ms suffix", () => {
    expect(fmtLatency(42)).toBe("42ms");
  });
  it("returns em-dash for null", () => {
    expect(fmtLatency(null)).toBe("—");
  });
});

describe("truncateHash", () => {
  it("truncates long hashes", () => {
    const hash = "a".repeat(64);
    const result = truncateHash(hash, 8);
    expect(result).toBe("aaaaaaaa…aaaaaaaa");
  });
  it("leaves short hashes intact", () => {
    expect(truncateHash("abc123", 8)).toBe("abc123");
  });
});
