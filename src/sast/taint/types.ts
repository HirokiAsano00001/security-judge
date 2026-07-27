import { type FindingCategory, type FindingSeverity } from '../../types/index.js'

/** Vulnerability classes the built-in taint engine can confirm via source → sink flow. */
export type VulnKind =
  | 'SQLI'
  | 'RCE'
  | 'XSS'
  | 'PATH_TRAVERSAL'
  | 'OPEN_REDIRECT'
  | 'SSTI'

/** How a tainted value reached a given point: where it entered and the intermediate hops. */
export interface Provenance {
  /** Human label of the source, e.g. "req.query". */
  sourceLabel: string
  /** 1-based line where the tainted value entered the program. */
  sourceLine: number
  /** 1-based lines of intermediate variable assignments the taint passed through, in order. */
  hops: readonly number[]
}

/** Result of evaluating whether an expression is tainted. */
export interface TaintResult {
  tainted: boolean
  prov?: Provenance
}

/** Static description of a sink and how it maps into the Judge's Finding model. */
export interface SinkDef {
  vulnKind: VulnKind
  /** Human label used in findings, e.g. "db.query". */
  label: string
  cweId: string
  owaspCategory: string
  category: FindingCategory
  /** Baseline severity; a confirmed taint flow elevates the emitted finding to CRITICAL. */
  severity: FindingSeverity
}

/** A confirmed source → sink data-flow within a single file. */
export interface Flow {
  sink: SinkDef
  /** 1-based line of the sink call/assignment. */
  sinkLine: number
  prov: Provenance
  fileName: string
}
