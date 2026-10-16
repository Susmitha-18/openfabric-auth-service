
import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";

// Store the database file in the backend/data folder.
const dataDirectory = path.resolve(process.cwd(), "data");

fs.mkdirSync(dataDirectory, { recursive: true });

const databasePath = path.join(dataDirectory, "permissions.db");

const db = new Database(databasePath);

db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

export default db;
