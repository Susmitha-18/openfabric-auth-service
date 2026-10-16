
import db from "../config/database.js";

export interface ApplicationUser {
  id: string;
  cognito_sub: string;
}

/**
 * Find an application user using the verified Cognito subject.
 */
export function getUserByCognitoSub(
  cognitoSub: string
): ApplicationUser | undefined {
  if (!cognitoSub || cognitoSub.trim().length === 0) {
    return undefined;
  }

  const query = db.prepare(`
    SELECT id, cognito_sub
    FROM users
    WHERE cognito_sub = ?
  `);

  return query.get(cognitoSub) as ApplicationUser | undefined;
}

/**
 * Create a mapping between a Cognito identity and an application user.
 * The application ID must be assigned by trusted backend logic.
 */
export function createUserMapping(
  applicationUserId: string,
  cognitoSub: string
): void {
  if (
    !applicationUserId?.trim() ||
    !cognitoSub?.trim()
  ) {
    throw new Error("Application user ID and Cognito subject are required");
  }

  const query = db.prepare(`
    INSERT INTO users (id, cognito_sub)
    VALUES (?, ?)
  `);

  query.run(applicationUserId, cognitoSub);
}
