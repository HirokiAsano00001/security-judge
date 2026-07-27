export interface SourceDef {
  /** Dotted member-path prefix that marks attacker-controlled input. */
  prefix: string
  /** Human label used in findings. */
  label: string
}

/**
 * Attacker-controlled input sources. Matched by dotted-path prefix, so `req.query`
 * matches `req.query`, `req.query.id`, and `req.query["id"]`. `process.env` is
 * intentionally excluded — it is trusted configuration, not attacker input.
 */
export const SOURCES: readonly SourceDef[] = [
  { prefix: 'req.query', label: 'req.query' },
  { prefix: 'req.body', label: 'req.body' },
  { prefix: 'req.params', label: 'req.params' },
  { prefix: 'req.headers', label: 'req.headers' },
  { prefix: 'req.cookies', label: 'req.cookies' },
  { prefix: 'request.query', label: 'request.query' },
  { prefix: 'request.body', label: 'request.body' },
  { prefix: 'request.params', label: 'request.params' },
  { prefix: 'ctx.request.body', label: 'ctx.request.body' },
  { prefix: 'ctx.query', label: 'ctx.query' },
  { prefix: 'process.argv', label: 'process.argv' },
  { prefix: 'location.search', label: 'location.search' },
  { prefix: 'location.hash', label: 'location.hash' },
]

/** Return the matching source label for a dotted member path, or undefined. */
export function matchSource(path: string): string | undefined {
  for (const s of SOURCES) {
    if (path === s.prefix || path.startsWith(`${s.prefix}.`)) return s.label
  }
  return undefined
}
