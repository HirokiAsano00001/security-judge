// TAINT FIXTURE — intentional DOM XSS
export function render(req: any) {
  const el = document.getElementById('out')
  el.innerHTML = req.query.html
}
