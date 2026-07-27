import { type Provenance } from './types.js'

/**
 * Immutable taint environment: variable name → provenance of its tainted value.
 * All mutators return a new map (per the repo's immutability rule).
 */
export type TaintEnv = ReadonlyMap<string, Provenance>

export const EMPTY_ENV: TaintEnv = new Map()

export function withVar(env: TaintEnv, name: string, prov: Provenance): TaintEnv {
  const next = new Map(env)
  next.set(name, prov)
  return next
}

export function withoutVar(env: TaintEnv, name: string): TaintEnv {
  if (!env.has(name)) return env
  const next = new Map(env)
  next.delete(name)
  return next
}

export function lookup(env: TaintEnv, name: string): Provenance | undefined {
  return env.get(name)
}

/** Append an intermediate hop line to a provenance (records a variable it passed through). */
export function appendHop(prov: Provenance, line: number): Provenance {
  return { ...prov, hops: [...prov.hops, line] }
}
