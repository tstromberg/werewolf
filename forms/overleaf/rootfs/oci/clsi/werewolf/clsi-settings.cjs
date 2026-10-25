// clsi-settings: Overleaf's settings (/etc/overleaf/settings.js) as clsi
// reads them, but with each compile's latexmk started by clsi-confine,
// which holds it to its project's directory (its README). clsi-start
// points clsi's OVERLEAF_CONFIG here. clsi puts the compile's directory
// for $COMPILE_DIR in each word of the command.
const settings = require('/etc/overleaf/settings.js')

settings.clsi = {
  ...settings.clsi,
  latexmkCommandPrefix: ['/usr/lib/werewolf/clsi-confine', '$COMPILE_DIR'],
}
module.exports = settings
