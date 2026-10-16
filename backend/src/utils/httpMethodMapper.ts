
export type PermissionAction = "read" | "write" | "delete";

// Convert HTTP methods into permission actions.
export function mapHttpMethod(method: string): PermissionAction | null {
  const normalizedMethod = method.trim().toUpperCase();

  switch (normalizedMethod) {
    case "GET":
      return "read";

    case "POST":
    case "PUT":
    case "PATCH":
      return "write";

    case "DELETE":
      return "delete";

    default:
      return null;
  }
}
