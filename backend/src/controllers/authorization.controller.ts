
import type { Request, Response } from "express";
import { validateAccessToken } from "../services/tokenValidation.service.js";
import { getUserByCognitoSub } from "../repositories/user.repository.js";
import { getPermissionsByUserId } from "../repositories/permission.repository.js";
import { authorizePermission } from "../services/authorization.service.js";
import { mapHttpMethod } from "../utils/httpMethodMapper.js";
import { normalizeResourcePath } from "../utils/resourceMatcher.js";

export async function authorizeRequest(
  req: Request,
  res: Response
): Promise<void> {
  const { access_token, method, path } = req.body ?? {};

  if (
    typeof access_token !== "string" ||
    !access_token.trim() ||
    typeof method !== "string" ||
    typeof path !== "string"
  ) {
    res.status(400).json({
      error: "access_token, method, and path are required as strings",
    });
    return;
  }

  const action = mapHttpMethod(method);

  if (!action) {
    res.status(400).json({ error: "Unsupported HTTP method" });
    return;
  }

  const normalizedResource = normalizeResourcePath(path);

  if (!normalizedResource) {
    res.status(400).json({ error: "Invalid resource path" });
    return;
  }

  // Verify the token before trusting any identity information.
  let authenticatedUser;
  try {
    authenticatedUser = await validateAccessToken(access_token);
  } catch {
    res.status(401).json({
      decision: "DENY",
      reason: "Invalid or expired access token",
      matched_permissions: [],
    });
    return;
  }

  try {
    // Match the verified Cognito subject to an application user.
    const applicationUser = getUserByCognitoSub(
      authenticatedUser.subject
    );

    if (!applicationUser) {
      res.status(403).json({
        decision: "DENY",
        reason: "No application user mapping exists for this identity",
        user_id: null,
        matched_permissions: [],
      });
      return;
    }

    // Use the mapped application ID, never a caller-supplied user ID.
    const permissions = getPermissionsByUserId(applicationUser.id);

    const result = authorizePermission(
      permissions,
      action,
      normalizedResource.path
    );

    res.status(200).json({
      decision: result.decision,
      user_id: applicationUser.id,
      reason: result.reason,
      matched_permissions: result.matched_permissions,
    });
  } catch {
    res.status(500).json({
      decision: "DENY",
      reason: "Internal authorization error",
      matched_permissions: [],
    });
  }
}
