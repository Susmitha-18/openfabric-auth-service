/**
 * Edge-case and security tests for the OpenFabric authorization service.
 *
 * Covers:
 *   A. Request-validation and input hygiene
 *   B. JWT security (mocked - no live Cognito dependency)
 *   C. Wildcard and resource-boundary attacks
 *   D. Permission-precedence scenarios
 *   E. HTTP method mapping completeness
 *   F. Database / failure scenarios (via mocks)
 *   G. HTTP security and API behaviour
 *   H. Resource path normalisation edge cases
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

// Mock all external I/O before the app is imported
vi.mock("../src/services/tokenValidation.service.js", () => ({
  validateAccessToken: vi.fn(),
}));
vi.mock("../src/repositories/user.repository.js", () => ({
  getUserByCognitoSub: vi.fn(),
}));
vi.mock("../src/repositories/permission.repository.js", () => ({
  getPermissionsByUserId: vi.fn(),
}));

import app from "../src/app.js";
import { validateAccessToken } from "../src/services/tokenValidation.service.js";
import { getUserByCognitoSub } from "../src/repositories/user.repository.js";
import { getPermissionsByUserId } from "../src/repositories/permission.repository.js";
import { authorizePermission, type UserPermission } from "../src/services/authorization.service.js";
import { mapHttpMethod } from "../src/utils/httpMethodMapper.js";
import { normalizeResourcePath } from "../src/utils/resourceMatcher.js";

function setupHappyPathMocks() {
  vi.mocked(validateAccessToken).mockResolvedValue({
    userId: "user123",
    subject: "sub-abc",
    claims: { sub: "sub-abc" },
  });
  vi.mocked(getUserByCognitoSub).mockReturnValue({
    id: "user123",
    cognito_sub: "sub-abc",
  });
  vi.mocked(getPermissionsByUserId).mockReturnValue([
    { user_id: "user123", action: "read", resource: "transactions", effect: "allow" },
  ]);
}

// A. Request Validation
describe("A. Request validation", () => {
  beforeEach(() => { vi.clearAllMocks(); setupHappyPathMocks(); });

  it("rejects a missing access_token", async () => {
    const res = await request(app).post("/authorize").send({ method: "GET", path: "/transactions" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("rejects a whitespace-only access_token", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "   ", method: "GET", path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects a missing method", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects a missing path", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET" });
    expect(res.status).toBe(400);
  });

  it("rejects an empty path string", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "" });
    expect(res.status).toBe(400);
  });

  it("rejects access_token as array", async () => {
    const res = await request(app).post("/authorize").send({ access_token: ["tok"], method: "GET", path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects access_token as number", async () => {
    const res = await request(app).post("/authorize").send({ access_token: 42, method: "GET", path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects access_token as null", async () => {
    const res = await request(app).post("/authorize").send({ access_token: null, method: "GET", path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects method as object", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: {}, path: "/transactions" });
    expect(res.status).toBe(400);
  });

  it("handles empty request body safely", async () => {
    const res = await request(app).post("/authorize").send({});
    expect(res.status).toBe(400);
    expect(res.body.decision).not.toBe("ALLOW");
  });

  it("handles malformed JSON safely", async () => {
    const res = await request(app).post("/authorize").set("Content-Type", "application/json").send("{bad json");
    expect(res.status).toBe(400);
    expect(res.body.decision).not.toBe("ALLOW");
  });

  it("rejects TRACE as unsupported method", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "TRACE", path: "/transactions" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Unsupported HTTP method");
  });

  it("rejects HEAD as unsupported method", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "HEAD", path: "/transactions" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Unsupported HTTP method");
  });

  it("rejects OPTIONS as unsupported method", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "OPTIONS", path: "/transactions" });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Unsupported HTTP method");
  });

  it("rejects path without leading slash", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects repeated slashes in path", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/wallets//transactions" });
    expect(res.status).toBe(400);
  });

  it("rejects trailing slash in path", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions/" });
    expect(res.status).toBe(400);
  });

  it("rejects URL-encoded path", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/wallets%2Ftransactions" });
    expect(res.status).toBe(400);
  });

  it("rejects path traversal", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions/../accounts" });
    expect(res.status).toBe(400);
  });

  it("rejects path with query string", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions?page=1" });
    expect(res.status).toBe(400);
  });

  it("never returns ALLOW for any invalid input combination", async () => {
    const badInputs = [
      { access_token: "", method: "GET", path: "/transactions" },
      { access_token: "tok", method: "", path: "/transactions" },
      { access_token: "tok", method: "TRACE", path: "/transactions" },
      { access_token: "tok", method: "GET", path: "" },
      { access_token: "tok", method: "GET", path: "no-leading-slash" },
    ];
    for (const body of badInputs) {
      const res = await request(app).post("/authorize").send(body);
      expect(res.body.decision).not.toBe("ALLOW");
    }
  });
});

// B. JWT Security (mocked)
describe("B. JWT security (mocked)", () => {
  beforeEach(() => { vi.clearAllMocks(); setupHappyPathMocks(); });

  it("rejects an expired token", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("JWTExpired: token is expired"));
    const res = await request(app).post("/authorize").send({ access_token: "expired.tok.en", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects an invalid signature", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("JWSSignatureVerificationFailed"));
    const res = await request(app).post("/authorize").send({ access_token: "tampered.tok.en", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects a wrong-issuer token", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error('unexpected "iss" claim value'));
    const res = await request(app).post("/authorize").send({ access_token: "wrong.iss.tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects a token with wrong client_id", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("Token was issued to a different app client"));
    const res = await request(app).post("/authorize").send({ access_token: "wrong.client.tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects an ID token (wrong token_use)", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("Token must be a Cognito access token"));
    const res = await request(app).post("/authorize").send({ access_token: "id.token.here", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects a token missing the sub claim", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("Token does not contain a valid user subject"));
    const res = await request(app).post("/authorize").send({ access_token: "no.sub.tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("rejects when JWKS endpoint is unavailable", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("Failed to fetch JWKS: network error"));
    const res = await request(app).post("/authorize").send({ access_token: "any.tok.en", method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    expect(res.body.decision).toBe("DENY");
  });

  it("does not expose token content in 401 response", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("JWTExpired"));
    const sensitiveToken = "header.payload.signature-secret-abc";
    const res = await request(app).post("/authorize").send({ access_token: sensitiveToken, method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    const body = JSON.stringify(res.body);
    expect(body).not.toContain(sensitiveToken);
    expect(body).not.toContain("signature-secret-abc");
  });
});

// C. Wildcard and resource-boundary attacks
describe("C. Wildcard and resource-boundary attacks", () => {
  function check(perms: UserPermission[], action: "read" | "write" | "delete", resource: string) {
    return authorizePermission(perms, action, resource);
  }

  const walletWildcard: UserPermission[] = [
    { user_id: "u", action: "read", resource: "wallets/*", effect: "allow" },
  ];

  it("wallets/* matches wallets/wallet-789 (direct child)", () => {
    expect(check(walletWildcard, "read", "wallets/wallet-789").decision).toBe("ALLOW");
  });

  it("wallets/* matches wallets/wallet-789/transactions (nested descendant)", () => {
    expect(check(walletWildcard, "read", "wallets/wallet-789/transactions").decision).toBe("ALLOW");
  });

  it("wallets/* does NOT match wallets-evil/account (prefix boundary)", () => {
    expect(check(walletWildcard, "read", "wallets-evil/account").decision).toBe("DENY");
  });

  it("wallets/* DOES match plain wallets resource (trailing wildcard matches zero segments)", () => {
    // Implementation: a trailing * can match zero remaining segments, so wallets/* matches wallets.
    // This is documented behavior; the test confirms the implementation is consistent.
    expect(check(walletWildcard, "read", "wallets").decision).toBe("ALLOW");
  });

  it("global * matches any resource", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "read", resource: "*", effect: "allow" }];
    expect(check(perms, "read", "anything/deeply/nested").decision).toBe("ALLOW");
  });

  it("global * does not grant write when only read wildcard exists", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "read", resource: "*", effect: "allow" }];
    expect(check(perms, "write", "transactions").decision).toBe("DENY");
  });

  it("parent-only exact allow does not cascade to child (no wildcard)", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "read", resource: "wallets", effect: "allow" }];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("parent deny inherits to child resource", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "delete", resource: "transactions", effect: "deny" }];
    expect(check(perms, "delete", "transactions/txn-456").decision).toBe("DENY");
  });

  it("child-only permission does not grant access to parent", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "read", resource: "wallets/wallet-789/transactions", effect: "allow" }];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("wallets-extra/* does not match wallets/wallet-789", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "read", resource: "wallets-extra/*", effect: "allow" }];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("wallets/*/transactions/* matches a specific transaction", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "write", resource: "wallets/*/transactions/*", effect: "allow" }];
    expect(check(perms, "write", "wallets/wallet-456/transactions/txn-999").decision).toBe("ALLOW");
  });

  it("wallets/*/transactions/* does not match wallets/wallet-456 (too short)", () => {
    const perms: UserPermission[] = [{ user_id: "u", action: "write", resource: "wallets/*/transactions/*", effect: "allow" }];
    expect(check(perms, "write", "wallets/wallet-456").decision).toBe("DENY");
  });
});

// D. Permission-precedence scenarios
describe("D. Permission-precedence scenarios", () => {
  function check(perms: UserPermission[], action: "read" | "write" | "delete", resource: string) {
    return authorizePermission(perms, action, resource);
  }

  it("D1: exact allow with no conflict -> ALLOW", () => {
    expect(check([{ user_id: "u", action: "read", resource: "transactions", effect: "allow" }], "read", "transactions").decision).toBe("ALLOW");
  });

  it("D2: exact deny with no conflict -> DENY", () => {
    expect(check([{ user_id: "u", action: "read", resource: "transactions", effect: "deny" }], "read", "transactions").decision).toBe("DENY");
  });

  it("D3: broad allow + more-specific deny -> DENY", () => {
    const perms: UserPermission[] = [
      { user_id: "u", action: "read", resource: "*", effect: "allow" },
      { user_id: "u", action: "read", resource: "wallets/wallet-789", effect: "deny" },
    ];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("D4: broad deny + more-specific allow -> ALLOW", () => {
    const perms: UserPermission[] = [
      { user_id: "u", action: "read", resource: "*", effect: "deny" },
      { user_id: "u", action: "read", resource: "wallets/wallet-789", effect: "allow" },
    ];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("ALLOW");
  });

  it("D5: equal-specificity conflict -> deny wins", () => {
    const perms: UserPermission[] = [
      { user_id: "u", action: "read", resource: "wallets/*", effect: "allow" },
      { user_id: "u", action: "read", resource: "wallets/*", effect: "deny" },
    ];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("D6: multiple matching wildcards - most-specific wins (deny)", () => {
    const perms: UserPermission[] = [
      { user_id: "u", action: "read", resource: "*", effect: "allow" },
      { user_id: "u", action: "read", resource: "wallets/*", effect: "deny" },
    ];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("D7: parent allow vs child deny -> child deny wins", () => {
    const perms: UserPermission[] = [
      { user_id: "u", action: "read", resource: "wallets/*", effect: "allow" },
      { user_id: "u", action: "read", resource: "wallets/wallet-789", effect: "deny" },
    ];
    expect(check(perms, "read", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("D8: no matching permission -> default DENY with correct reason", () => {
    const result = check([], "read", "transactions");
    expect(result.decision).toBe("DENY");
    expect(result.reason).toMatch(/default deny/i);
  });

  it("D9: unknown user (empty permissions) -> DENY", () => {
    expect(check([], "write", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("D10: permission with invalid effect is never treated as ALLOW", () => {
    const perms = [{ user_id: "u", action: "read" as const, resource: "transactions", effect: "invalid" as "allow" | "deny" }];
    const result = check(perms, "read", "transactions");
    expect(result.decision).toBe("DENY");
  });
});

// E. HTTP method mapping
describe("E. HTTP method mapping completeness", () => {
  it("GET -> read", () => expect(mapHttpMethod("GET")).toBe("read"));
  it("POST -> write", () => expect(mapHttpMethod("POST")).toBe("write"));
  it("PUT -> write", () => expect(mapHttpMethod("PUT")).toBe("write"));
  it("PATCH -> write", () => expect(mapHttpMethod("PATCH")).toBe("write"));
  it("DELETE -> delete", () => expect(mapHttpMethod("DELETE")).toBe("delete"));
  it("lowercase get -> read", () => expect(mapHttpMethod("get")).toBe("read"));
  it("lowercase delete -> delete", () => expect(mapHttpMethod("delete")).toBe("delete"));
  it("mixed-case Patch -> write", () => expect(mapHttpMethod("Patch")).toBe("write"));
  it("TRACE -> null", () => expect(mapHttpMethod("TRACE")).toBeNull());
  it("HEAD -> null", () => expect(mapHttpMethod("HEAD")).toBeNull());
  it("OPTIONS -> null", () => expect(mapHttpMethod("OPTIONS")).toBeNull());
  it("CONNECT -> null", () => expect(mapHttpMethod("CONNECT")).toBeNull());
  it("empty string -> null", () => expect(mapHttpMethod("")).toBeNull());
  it("random string -> null", () => expect(mapHttpMethod("NOTAVERB")).toBeNull());
});

// F. Database and failure scenarios
describe("F. Database and failure scenarios", () => {
  beforeEach(() => { vi.clearAllMocks(); setupHappyPathMocks(); });

  it("returns DENY (403) when user mapping does not exist", async () => {
    vi.mocked(getUserByCognitoSub).mockReturnValue(undefined);
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(403);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.user_id).toBeNull();
  });

  it("returns DENY (200) when user has no permissions", async () => {
    vi.mocked(getPermissionsByUserId).mockReturnValue([]);
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("DENY");
  });

  it("returns DENY (500) when user lookup throws", async () => {
    vi.mocked(getUserByCognitoSub).mockImplementation(() => { throw new Error("DB connection lost"); });
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(500);
    expect(res.body.decision).toBe("DENY");
    expect(res.body.reason).not.toContain("DB connection");
    expect(JSON.stringify(res.body)).not.toContain("stack");
  });

  it("returns DENY (500) when permissions lookup throws", async () => {
    vi.mocked(getPermissionsByUserId).mockImplementation(() => { throw new Error("SQLite SQLITE_BUSY"); });
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(500);
    expect(res.body.decision).toBe("DENY");
  });

  it("database errors never result in ALLOW", async () => {
    vi.mocked(getPermissionsByUserId).mockImplementation(() => { throw new Error("Simulated DB failure"); });
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.body.decision).not.toBe("ALLOW");
  });

  it("error response does not expose stack trace or SQL detail", async () => {
    vi.mocked(getPermissionsByUserId).mockImplementation(() => { throw new Error("SQLITE_CANTOPEN: unable to open database file"); });
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    const body = JSON.stringify(res.body);
    expect(body).not.toContain("SQLITE_CANTOPEN");
    expect(body).not.toContain("Error:");
  });
});

// G. HTTP security and API behaviour
describe("G. HTTP security and API behaviour", () => {
  beforeEach(() => { vi.clearAllMocks(); setupHappyPathMocks(); });

  it("health endpoint returns 200 OK", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("OK");
  });

  it("response includes X-Content-Type-Options: nosniff (helmet)", async () => {
    const res = await request(app).get("/api/health");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("response includes X-Frame-Options or CSP header (helmet)", async () => {
    const res = await request(app).get("/api/health");
    const hasFrameOptions = "x-frame-options" in res.headers;
    const hasCSP = "content-security-policy" in res.headers;
    expect(hasFrameOptions || hasCSP).toBe(true);
  });

  it("ALLOW response includes user_id, reason, and matched_permissions", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("ALLOW");
    expect(typeof res.body.user_id).toBe("string");
    expect(typeof res.body.reason).toBe("string");
    expect(Array.isArray(res.body.matched_permissions)).toBe(true);
  });

  it("DENY response does not leak SQL or internal details", async () => {
    vi.mocked(getPermissionsByUserId).mockReturnValue([]);
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe("DENY");
    const body = JSON.stringify(res.body);
    expect(body).not.toContain("SELECT");
    expect(body).not.toContain("sqlite");
  });

  it("POST /authorize is reachable (not 404)", async () => {
    const res = await request(app).post("/authorize").send({ access_token: "tok", method: "GET", path: "/transactions" });
    expect(res.status).not.toBe(404);
  });

  it("401 response body does not echo the actual submitted token value", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(new Error("expired"));
    // Use a clearly unique sentinel value unlikely to appear in any reason string.
    const uniqueSentinel = "UNIQUE_SENTINEL_TOKEN_VALUE_xyz987";
    const res = await request(app).post("/authorize").send({ access_token: uniqueSentinel, method: "GET", path: "/transactions" });
    expect(res.status).toBe(401);
    // The actual submitted token value must not appear in the response body.
    expect(JSON.stringify(res.body)).not.toContain(uniqueSentinel);
  });
});

// H. Resource path normalisation edge cases
describe("H. Resource path normalisation edge cases", () => {
  it("accepts /transactions", () => expect(normalizeResourcePath("/transactions")).not.toBeNull());
  it("rejects path without leading slash", () => expect(normalizeResourcePath("transactions")).toBeNull());
  it("rejects empty string", () => expect(normalizeResourcePath("")).toBeNull());
  it("rejects repeated slashes", () => expect(normalizeResourcePath("/wallets//transactions")).toBeNull());
  it("rejects trailing slash", () => expect(normalizeResourcePath("/transactions/")).toBeNull());
  it("rejects query string", () => expect(normalizeResourcePath("/transactions?page=1")).toBeNull());
  it("rejects fragment", () => expect(normalizeResourcePath("/transactions#section")).toBeNull());
  it("rejects dot segment", () => expect(normalizeResourcePath("/wallets/./transactions")).toBeNull());
  it("rejects double-dot segment", () => expect(normalizeResourcePath("/wallets/../transactions")).toBeNull());
  it("rejects percent-encoded characters", () => expect(normalizeResourcePath("/wallets%2Ftransactions")).toBeNull());
  it("rejects null byte in path", () => expect(normalizeResourcePath("/transactions\x00evil")).toBeNull());
  it("rejects backslash in path", () => expect(normalizeResourcePath("/wallets\\transactions")).toBeNull());
  it("accepts a valid nested path with correct segments", () => {
    const result = normalizeResourcePath("/wallets/wallet-789/transactions");
    expect(result).not.toBeNull();
    expect(result?.path).toBe("wallets/wallet-789/transactions");
    expect(result?.segments).toEqual(["wallets", "wallet-789", "transactions"]);
  });
});
