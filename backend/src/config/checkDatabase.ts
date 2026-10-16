
import db from "./database.js";

const result = db
  .prepare("SELECT COUNT(*) AS total FROM user_permissions")
  .get() as { total: number };

console.log("Total permissions:", result.total);

const permissions = db
  .prepare(
    "SELECT user_id, action, resource, effect FROM user_permissions ORDER BY id"
  )
  .all();

console.table(permissions);

db.close();
