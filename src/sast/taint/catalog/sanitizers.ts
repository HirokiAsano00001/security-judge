import { lastSegment } from '../ast_util.js'

/**
 * Callee paths whose result is considered untainted regardless of input. Numeric
 * coercion and encoding neutralize injection; name-heuristic escapers cover common
 * project helpers.
 */
const EXACT_SANITIZERS = new Set([
  'parseInt',
  'parseFloat',
  'Number',
  'encodeURIComponent',
  'encodeURI',
  'escape',
  'Math.floor',
  'Math.ceil',
  'Math.round',
  'Math.abs',
])

/** Method/function names (last segment) that sanitize when called. */
const SEGMENT_SANITIZERS = new Set([
  'sanitize', // DOMPurify.sanitize, validator.sanitize
  'escape', // validator.escape, _.escape
  'escapeHtml',
  'escapeHTML',
  'encode', // he.encode
])

const NAME_HEURISTIC = /^(escape|sanitize|encode|htmlescape|escapehtml)/i

/** True if a call to this dotted callee path removes taint from its arguments. */
export function isSanitizer(calleePath: string): boolean {
  if (EXACT_SANITIZERS.has(calleePath)) return true
  const seg = lastSegment(calleePath)
  if (SEGMENT_SANITIZERS.has(seg)) return true
  if (NAME_HEURISTIC.test(seg)) return true
  return false
}
