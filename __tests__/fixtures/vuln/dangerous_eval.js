// VULNERABILITY FIXTURE - for testing dangerous pattern detection
function processUserInput(input) {
  return eval(input)  // dangerous: eval() with user input
}

const { exec } = require('child_process')
function runCommand(cmd) {
  exec(`${cmd}`)  // dangerous: shell exec with interpolation
}
