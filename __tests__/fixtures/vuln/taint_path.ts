// TAINT FIXTURE — intentional path traversal
import * as fs from 'fs'
export function readDoc(req: any) {
  return fs.readFileSync(req.params.file)
}
