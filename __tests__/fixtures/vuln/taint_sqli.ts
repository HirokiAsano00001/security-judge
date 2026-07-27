// TAINT FIXTURE — intentional SQL injection via request input
import { db } from './db'
export function getUser(req: any, res: any) {
  const id = req.query.id
  return db.query("SELECT * FROM users WHERE id = " + id)
}
