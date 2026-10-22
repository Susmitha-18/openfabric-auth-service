
import fs from "node:fs";
import path from "node:path";
import db from "./database.js";

const schemaPath = path.resolve(process.cwd(), "database", "schema.sql");
const seedPath = path.resolve(process.cwd(), "database", "seed.sql");

try {
  // Create missing tables and indexes without deleting existing data.
  db.exec(fs.readFileSync(schemaPath, "utf8"));

  // Add expires_at to existing databases, only if missing.
  const columns = db
    .prepare("PRAGMA table_info(user_permissions)")
    .all() as { name: string }[];

  const hasExpiresAt = columns.some(
    (column) => column.name === "expires_at"
  );

  if (!hasExpiresAt) {
    db.exec(
      "ALTER TABLE user_permissions ADD COLUMN expires_at TEXT NULL"
    );
    console.log("Added expires_at column.");
  } else {
    console.log("expires_at column already exists.");
  }

  // Seed sample permissions only when the table is empty.
  const count = db
    .prepare("SELECT COUNT(*) AS count FROM user_permissions")
    .get() as { count: number };

  if (count.count === 0) {
    db.exec(fs.readFileSync(seedPath, "utf8"));
    console.log("Sample permissions inserted.");
  } else {
    console.log("Sample permissions already exist; skipping seed.");
  }

  // Show application-user mapping status.
  const userCount = db
    .prepare("SELECT COUNT(*) AS count FROM users")
    .get() as { count: number };

  console.log(`Application user mappings: ${userCount.count}`);
  console.log(
    `Database initialized at: ${path.resolve(
      process.cwd(),
      "data",
      "permissions.db"
    )}`
  );
} catch (error) {
  console.error("Database initialization failed:", error);
  process.exitCode = 1;
} finally {
  db.close();
}
