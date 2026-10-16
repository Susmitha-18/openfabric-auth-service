
import db from "../config/database.js";
import type {
  UserPermission,
  PermissionEffect,
} from "../services/authorization.service.js";
import type { PermissionAction } from "../utils/httpMethodMapper.js";

/**
 * Fetch all permissions assigned to a specific user.
 */
export function getPermissionsByUserId(
  userId: string
): UserPermission[] {
  if (!userId || userId.trim().length === 0) {
    return [];
  }

  const query = db.prepare(`
    SELECT user_id, action, resource, effect
    FROM user_permissions
    WHERE user_id = ?
    ORDER BY id ASC
  `);

  const rows = query.all(userId) as Array<{
    user_id: string;
    action: string;
    resource: string;
    effect: string;
  }>;

  return rows.map((row) => ({
    user_id: row.user_id,
    action: row.action as PermissionAction,
    resource: row.resource,
    effect: row.effect as PermissionEffect,
  }));
}
