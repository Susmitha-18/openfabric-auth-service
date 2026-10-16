
import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

// Mock external dependencies before importing the app.
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

describe("POST /authorize integration tests", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(validateAccessToken).mockResolvedValue({
      userId: "user123",
      subject: "subject-123",
      claims: { sub: "subject-123" },
    });

    vi.mocked(getUserByCognitoSub).mockReturnValue({
      id: "user123",
      cognito_sub: "subject-123",
    });

    vi.mocked(getPermissionsByUserId).mockReturnValue([
      {
        user_id: "user123",
        action: "read",
        resource: "transactions",
        effect: "allow",
      },
    ]);
  });

  it("returns ALLOW for a permitted request", async () => {
    const response = await request(app)
      .post("/authorize")
      .send({
        access_token: "test-token",
        method: "GET",
        path: "/transactions",
      });

    expect(response.status).toBe(200);
    expect(response.body.decision).toBe("ALLOW");
    expect(response.body.user_id).toBe("user123");
    expect(response.body.matched_permissions).toHaveLength(1);
  });

  it("returns DENY when no permission matches", async () => {
    const response = await request(app)
      .post("/authorize")
      .send({
        access_token: "test-token",
        method: "DELETE",
        path: "/transactions",
      });

    expect(response.status).toBe(200);
    expect(response.body.decision).toBe("DENY");
  });

  it("returns 400 when required fields are missing", async () => {
    const response = await request(app)
      .post("/authorize")
      .send({
        method: "GET",
        path: "/transactions",
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBeDefined();
  });

  it("returns 400 for an unsupported HTTP method", async () => {
    const response = await request(app)
      .post("/authorize")
      .send({
        access_token: "test-token",
        method: "TRACE",
        path: "/transactions",
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toBe("Unsupported HTTP method");
  });

  it("returns 401 for an invalid access token", async () => {
    vi.mocked(validateAccessToken).mockRejectedValue(
      new Error("Invalid token"),
    );

    const response = await request(app)
      .post("/authorize")
      .send({
        access_token: "invalid-token",
        method: "GET",
        path: "/transactions",
      });

    expect(response.status).toBe(401);
    expect(response.body.decision).toBe("DENY");
  });

  it("returns 403 when the user mapping does not exist", async () => {
    vi.mocked(getUserByCognitoSub).mockReturnValue(undefined);

    const response = await request(app)
      .post("/authorize")
      .send({
        access_token: "test-token",
        method: "GET",
        path: "/transactions",
      });

    expect(response.status).toBe(403);
    expect(response.body.decision).toBe("DENY");
    expect(response.body.user_id).toBeNull();
  });
});
