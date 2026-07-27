import { describe, it, expect } from 'vitest'
import { parseSource } from '../../src/sast/taint/parse.js'
import { analyzeSourceFile } from '../../src/sast/taint/engine.js'
import { type Flow } from '../../src/sast/taint/types.js'

function run(code: string): Flow[] {
  return analyzeSourceFile(parseSource(code, 'test.ts'), 'test.ts')
}

describe('taint engine', () => {
  it('direct source → sink (0 hops)', () => {
    const flows = run(`db.query("SELECT * FROM u WHERE id=" + req.query.id)`)
    expect(flows).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('SQLI')
    expect(flows[0].sink.cweId).toBe('CWE-89')
    expect(flows[0].prov.hops).toHaveLength(0)
    expect(flows[0].prov.sourceLabel).toBe('req.query')
  })

  it('variable-via source → sink (1 hop)', () => {
    const flows = run(`const id = req.query.id;\ndb.query("SELECT " + id)`)
    expect(flows).toHaveLength(1)
    expect(flows[0].prov.hops).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('SQLI')
  })

  it('concatenation chain accumulates hops (2 hops)', () => {
    const flows = run(`const a = req.body.x;\nconst b = "p" + a;\ndb.query(b)`)
    expect(flows).toHaveLength(1)
    expect(flows[0].prov.hops).toHaveLength(2)
  })

  it('template literal interpolation is tainted', () => {
    const flows = run('db.query(`SELECT * FROM u WHERE id=${req.params.id}`)')
    expect(flows).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('SQLI')
  })

  it('sanitizer (parseInt / encodeURIComponent) removes taint → no flow', () => {
    expect(run(`const id = parseInt(req.query.id);\ndb.query("SELECT " + id)`)).toHaveLength(0)
    expect(run(`const u = encodeURIComponent(req.query.u);\nres.redirect(u)`)).toHaveLength(0)
  })

  it('parameterized query is safe (tainted value in non-injectable arg)', () => {
    const flows = run(`db.query("SELECT * FROM u WHERE id = ?", [req.query.id])`)
    expect(flows).toHaveLength(0)
  })

  it('reassignment to a static value kills stale taint', () => {
    const flows = run(`let x = req.query.id;\nx = "static";\ndb.query("SELECT " + x)`)
    expect(flows).toHaveLength(0)
  })

  it('non-source member access is not tainted (req.method, process.env)', () => {
    expect(run(`db.query("SELECT " + req.method)`)).toHaveLength(0)
    expect(run(`db.query("SELECT " + process.env.TABLE)`)).toHaveLength(0)
  })

  it('detects all six vulnerability kinds in one file', () => {
    const code = [
      `db.query("SELECT " + req.query.id)`,
      `eval(req.body.code)`,
      `el.innerHTML = req.query.h`,
      `fs.readFileSync(req.params.f)`,
      `res.redirect(req.query.url)`,
      `ejs.render(req.body.tpl)`,
    ].join('\n')
    const kinds = new Set(run(code).map((f) => f.sink.vulnKind))
    expect(kinds).toEqual(new Set(['SQLI', 'RCE', 'XSS', 'PATH_TRAVERSAL', 'OPEN_REDIRECT', 'SSTI']))
  })

  it('assignment sink through an unresolved base (getElementById().innerHTML)', () => {
    const flows = run(`document.getElementById('x').innerHTML = req.query.h`)
    expect(flows).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('XSS')
  })

  it('tracks taint inside an arrow-function route handler', () => {
    const code = `app.get('/u', (req, res) => {\n  const id = req.query.id;\n  db.query("SELECT " + id)\n})`
    const flows = run(code)
    expect(flows).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('SQLI')
  })

  it('alias propagation: const q = req.query; q.id', () => {
    const flows = run(`const q = req.query;\ndb.query("SELECT " + q.id)`)
    expect(flows).toHaveLength(1)
  })

  it('pass-through string method keeps taint (.toLowerCase)', () => {
    const flows = run(`const id = req.query.id.toLowerCase();\ndb.query("SELECT " + id)`)
    expect(flows).toHaveLength(1)
  })

  it('regex.exec is NOT treated as RCE', () => {
    expect(run(`const m = /ab/.exec(req.query.id)`)).toHaveLength(0)
  })

  it('child_process.exec with tainted arg is RCE', () => {
    const flows = run(`child_process.exec("ls " + req.query.dir)`)
    expect(flows).toHaveLength(1)
    expect(flows[0].sink.vulnKind).toBe('RCE')
    expect(flows[0].sink.cweId).toBe('CWE-78')
  })
})
