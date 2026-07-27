// SAFE — input coerced/encoded before reaching sinks
export function safe(req: any, res: any) {
  const id = parseInt(req.query.id, 10)
  const url = encodeURIComponent(req.query.next)
  res.redirect("/go?to=" + url)
  return id
}
