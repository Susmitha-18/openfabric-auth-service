
import { describe, expect, it } from "vitest";
import { validateAccessToken } from "../src/services/tokenValidation.service.js";

describe("Cognito token validation", () => {
  it("rejects an empty access token", async () => {
    await expect(validateAccessToken("")).rejects.toThrow(
      "Access token is required"
    );
  });

  it("rejects a malformed token", async () => {
    await expect(
      validateAccessToken("not-a-valid-jwt")
    ).rejects.toThrow();
  });
});
