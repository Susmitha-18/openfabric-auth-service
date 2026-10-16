
import { describe, expect, it } from "vitest";
import { mapHttpMethod } from "../src/utils/httpMethodMapper.js";
import { normalizeResourcePath } from "../src/utils/resourceMatcher.js";

describe("HTTP method mapping", () => {
  it("maps GET to read", () => {
    expect(mapHttpMethod("GET")).toBe("read");
  });

  it("maps POST, PUT, and PATCH to write", () => {
    expect(mapHttpMethod("POST")).toBe("write");
    expect(mapHttpMethod("PUT")).toBe("write");
    expect(mapHttpMethod("PATCH")).toBe("write");
  });

  it("maps DELETE to delete", () => {
    expect(mapHttpMethod("DELETE")).toBe("delete");
  });

  it("rejects unsupported methods", () => {
    expect(mapHttpMethod("OPTIONS")).toBeNull();
  });

  it("handles lowercase methods", () => {
    expect(mapHttpMethod("get")).toBe("read");
  });
});

describe("Resource path validation", () => {
  it("normalizes a valid wallet path", () => {
    expect(
      normalizeResourcePath("/wallets/wallet-789/transactions")
    ).toEqual({
      path: "wallets/wallet-789/transactions",
      segments: ["wallets", "wallet-789", "transactions"],
    });
  });

  it("accepts a single resource", () => {
    expect(normalizeResourcePath("/transactions")?.path).toBe(
      "transactions"
    );
  });

  it("rejects a path without a leading slash", () => {
    expect(normalizeResourcePath("transactions")).toBeNull();
  });

  it("rejects repeated slashes", () => {
    expect(normalizeResourcePath("/wallets//transactions")).toBeNull();
  });

  it("rejects query strings", () => {
    expect(normalizeResourcePath("/transactions?page=1")).toBeNull();
  });

  it("rejects path traversal", () => {
    expect(normalizeResourcePath("/transactions/../accounts")).toBeNull();
  });
});
