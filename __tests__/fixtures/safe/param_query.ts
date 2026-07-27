// SAFE — parameterized query, tainted value only in the params array
import { db } from './db'
export function getUser(req: any) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id])
}
