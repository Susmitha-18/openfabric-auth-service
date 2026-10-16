import { describe, expect, it } from "vitest";
import {
  authorizePermission,
  type UserPermission,
} from "../src/services/authorization.service.js";

const permissions: UserPermission[] = [
  { user_id: "user123", action: "read", resource: "transactions", effect: "allow" },
  { user_id: "user123", action: "write", resource: "transactions", effect: "allow" },
  { user_id: "user123", action: "delete", resource: "transactions", effect: "deny" },
  { user_id: "user123", action: "read", resource: "accounts", effect: "allow" },

  { user_id: "user456", action: "read", resource: "wallets/*", effect: "allow" },
  { user_id: "user456", action: "write", resource: "wallets/wallet-789", effect: "allow" },
  { user_id: "user456", action: "read", resource: "wallets/wallet-789/transactions", effect: "allow" },

  { user_id: "user789", action: "write", resource: "wallets/*/transactions/*", effect: "allow" },

  { user_id: "admin789", action: "read", resource: "*", effect: "allow" },
  { user_id: "admin789", action: "write", resource: "*", effect: "allow" },
  { user_id: "admin789", action: "delete", resource: "*", effect: "allow" },
];

function check(userId: string, action: "read" | "write" | "delete", resource: string) {
  return authorizePermission(
    permissions.filter((permission) => permission.user_id === userId),
    action,
    resource
  );
}

describe("OpenFabric assignment scenarios", () => {
  it("allows user123 to read transactions", () => {
    expect(check("user123", "read", "transactions").decision).toBe("ALLOW");
  });

  it("denies user123 deleting a transaction through parent deny inheritance", () => {
    expect(check("user123", "delete", "transactions/txn-456").decision).toBe("DENY");
  });

  it("allows user456 to read wallet transactions", () => {
    expect(check("user456", "read", "wallets/wallet-789/transactions").decision).toBe("ALLOW");
  });

  it("allows user789 to write a specific wallet transaction", () => {
    expect(check("user789", "write", "wallets/wallet-456/transactions/txn-999").decision).toBe("ALLOW");
  });

  it("allows user789 to write to the transactions collection", () => {
    expect(check("user789", "write", "wallets/wallet-789/transactions").decision).toBe("ALLOW");
  });

  it("denies user456 writing wallet transactions without a matching permission", () => {
    expect(check("user456", "write", "wallets/wallet-789/transactions").decision).toBe("DENY");
  });

  it("allows admin789 to delete nested account settings", () => {
    expect(check("admin789", "delete", "accounts/acc-123/settings").decision).toBe("ALLOW");
  });

  it("allows user456 to read a wallet through the wildcard", () => {
    expect(check("user456", "read", "wallets/wallet-999").decision).toBe("ALLOW");
  });

  it("denies access by default when no rule matches", () => {
    expect(check("user123", "write", "accounts").decision).toBe("DENY");
  });

  it("lets a more-specific allow override a broad deny", () => {
    const result = authorizePermission(
      [
        { user_id: "test", action: "read", resource: "*", effect: "deny" },
        { user_id: "test", action: "read", resource: "wallets/wallet-789", effect: "allow" },
      ],
      "read",
      "wallets/wallet-789"
    );

    expect(result.decision).toBe("ALLOW");
  });

  it("lets deny win when equally specific rules conflict", () => {
    const result = authorizePermission(
      [
        { user_id: "test", action: "read", resource: "wallets/*", effect: "allow" },
        { user_id: "test", action: "read", resource: "wallets/*", effect: "deny" },
      ],
      "read",
      "wallets/wallet-789"
    );

    expect(result.decision).toBe("DENY");
  });

  it("denies when the requested action has no matching permission", () => {
    expect(check("user456", "delete", "wallets/wallet-789").decision).toBe("DENY");
  });

  it("allows user456 to read a nested wallet resource through wallets/*", () => {
  expect(
    check("user456", "read", "wallets/wallet-999/transactions").decision
  ).toBe("ALLOW");
});

it("allows user456 to read a deeply nested wallet resource through wallets/*", () => {
  expect(
    check(
      "user456",
      "read",
      "wallets/wallet-999/transactions/txn-456"
    ).decision
  ).toBe("ALLOW");
});

it("allows user789 to write a wallet transactions collection through the trailing wildcard", () => {
  expect(
    check("user789", "write", "wallets/wallet-789/transactions").decision
  ).toBe("ALLOW");
});
it("lets a more-specific deny override a broad allow", () => {
  const result = authorizePermission(
    [
      { user_id: "test", action: "read", resource: "*", effect: "allow" },
      {
        user_id: "test",
        action: "read",
        resource: "wallets/wallet-789",
        effect: "deny",
      },
    ],
    "read",
    "wallets/wallet-789"
  );

  expect(result.decision).toBe("DENY");
});
});