
export interface NormalizedResource {
  path: string;
  segments: string[];
}

// Validate and normalize a resource URL path.
export function normalizeResourcePath(
  inputPath: string
): NormalizedResource | null {
  if (
    typeof inputPath !== "string" ||
    !inputPath.startsWith("/") ||
    inputPath.includes("?") ||
    inputPath.includes("#") ||
    inputPath.includes("\\") ||
    inputPath.includes("\0")
  ) {
    return null;
  }

  // Reject encoded paths to avoid ambiguous path representations.
  if (/%[0-9a-f]{2}/i.test(inputPath)) {
    return null;
  }

  const rawSegments = inputPath.split("/").slice(1);

  // Reject empty segments, including repeated or trailing slashes.
  if (
    rawSegments.length === 0 ||
    rawSegments.some((segment) => segment.length === 0)
  ) {
    return null;
  }

  // Reject dot segments and whitespace-only segments.
  if (
    rawSegments.some(
      (segment) =>
        segment === "." ||
        segment === ".." ||
        segment.trim().length === 0
    )
  ) {
    return null;
  }

  // Permit only simple resource identifiers.
  const validSegment = /^[a-zA-Z0-9_-]+$/;

  if (!rawSegments.every((segment) => validSegment.test(segment))) {
    return null;
  }

  return {
    path: rawSegments.join("/"),
    segments: rawSegments,
  };
}
