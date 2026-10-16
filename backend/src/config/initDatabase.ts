
import fs from "node:fs";
import path from "node:path";
import db from "./database.js";

const schemaPath = path.resolve(process.cwd(), "database", "schema.sql");
const seedPath = path.resolve(process.cwd(), "database", "seed.sql");

try {
  // Create any missing tables and indexes without deleting existing data.
  db.exec(fs.readFileSync(schemaPath, "utf8"));

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

  // Show the application-user mapping table status.
  const userCount = db
    .prepare("SELECT COUNT(*) AS count FROM users")
    .get() as { count: number };

  console.log(`Application user mappings: ${userCount.count}`);
  console.log(
    `Database initialized at: ${path.resolve(process.cwd(), "data", "permissions.db")}`
  );
} catch (error) {
  console.error("Database initialization failed:", error);
  process.exitCode = 1;
} finally {
  db.close();
}
