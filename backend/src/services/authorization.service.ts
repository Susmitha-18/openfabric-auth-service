
import type { PermissionAction } from "../utils/httpMethodMapper.js";

export type PermissionEffect = "allow" | "deny";

export interface UserPermission {
  user_id: string;
  action: PermissionAction;
  resource: string;
  effect: PermissionEffect;
}

export interface AuthorizationResult {
  decision: "ALLOW" | "DENY";
  reason: string;
  matched_permissions: UserPermission[];
}

interface PermissionMatch {
  permission: UserPermission;
  specificity: number;
}

// Remove leading and trailing slashes from permission resources.
function normalizePermissionResource(resource: string): string {
  if (resource === "*") {
    return "*";
  }

  return resource.replace(/^\/+|\/+$/g, "");
}

// Match a permission against a requested resource.
function matchResourcePattern(
  pattern: string,
  requestedResource: string,
  effect: PermissionEffect
): boolean {
  if (pattern === "*") {
    return true;
  }

  const patternSegments = normalizePermissionResource(pattern).split("/");
  const resourceSegments = normalizePermissionResource(
    requestedResource
  ).split("/");

  if (
    patternSegments.some((segment) => segment.length === 0) ||
    resourceSegments.some((segment) => segment.length === 0)
  ) {
    return false;
  }

  for (let i = 0; i < patternSegments.length; i++) {
    const patternSegment = patternSegments[i];

    // A trailing wildcard can match zero remaining segments.
    if (i >= resourceSegments.length) {
      return (
        i === patternSegments.length - 1 &&
        patternSegment === "*"
      );
    }

    if (
      patternSegment !== "*" &&
      patternSegment !== resourceSegments[i]
    ) {
      return false;
    }
  }

  // Exact parent denies inherit; wildcard patterns can cover descendants.
  // Exact parent allows do not automatically grant access to child resources.
  return (
    patternSegments.length === resourceSegments.length ||
    effect === "deny" ||
    patternSegments.includes("*")
  );
}

// More literal segments and then more path segments mean higher specificity.
function calculateSpecificity(pattern: string): number {
  if (pattern === "*") {
    return 0;
  }

  const segments = normalizePermissionResource(pattern).split("/");
  const literalCount = segments.filter(
    (segment) => segment !== "*"
  ).length;

  return literalCount * 100 + segments.length;
}

// Decide whether the supplied permissions authorize the requested action.
export function authorizePermission(
  permissions: UserPermission[],
  action: PermissionAction,
  requestedResource: string
): AuthorizationResult {
  const resource = normalizePermissionResource(requestedResource);

  if (
    !resource ||
    resource.split("/").some(
      (segment) =>
        segment.length === 0 ||
        segment === "." ||
        segment === ".."
    )
  ) {
    return {
      decision: "DENY",
      reason: "Invalid resource",
      matched_permissions: [],
    };
  }

  const matches: PermissionMatch[] = permissions
    .filter(
      (permission) =>
        permission.action === action &&
        matchResourcePattern(
          permission.resource,
          resource,
          permission.effect
        )
    )
    .map((permission) => ({
      permission,
      specificity: calculateSpecificity(permission.resource),
    }));

  // No applicable permission means default deny.
  if (matches.length === 0) {
    return {
      decision: "DENY",
      reason: "No matching permission; default deny",
      matched_permissions: [],
    };
  }

  // Keep only the most-specific applicable permissions.
  const highestSpecificity = Math.max(
    ...matches.map((match) => match.specificity)
  );

  const mostSpecificMatches = matches.filter(
    (match) => match.specificity === highestSpecificity
  );

  const matchedPermissions = mostSpecificMatches.map(
    (match) => match.permission
  );

  // Deny wins when equally specific rules conflict.
  // Any permission whose effect is not exactly "allow" is treated as deny-safe
  // so that a corrupt or unknown database value never accidentally grants access.
  if (
    mostSpecificMatches.some(
      (match) => match.permission.effect === "deny"
    )
  ) {
    return {
      decision: "DENY",
      reason: "A matching deny permission takes precedence",
      matched_permissions: matchedPermissions,
    };
  }

  if (
    !mostSpecificMatches.every(
      (match) => match.permission.effect === "allow"
    )
  ) {
    return {
      decision: "DENY",
      reason: "A permission with an unrecognized effect was treated as deny",
      matched_permissions: matchedPermissions,
    };
  }

  return {
    decision: "ALLOW",
    reason: "A matching allow permission grants access",
    matched_permissions: matchedPermissions,
  };
}
