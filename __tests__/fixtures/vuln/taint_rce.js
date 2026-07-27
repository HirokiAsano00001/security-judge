// TAINT FIXTURE — intentional command injection
const child_process = require('child_process')
module.exports = (req, res) => {
  child_process.exec("ls " + req.query.dir)
}
