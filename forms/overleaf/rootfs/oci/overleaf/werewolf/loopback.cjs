// loopback: history-v1 listens on its port alone (app.js:
// app.listen(port, ...)), which Node takes for every address, and reads
// no LISTEN_ADDRESS, as Overleaf's other services do. The form declares
// every one loopback. overleaf-start requires this before history-v1's
// app.js: a listen on a port that names no host gets 127.0.0.1, where
// each of its clients reaches it (HISTORY_V1_HOST).
const net = require('node:net')

const listen = net.Server.prototype.listen
net.Server.prototype.listen = function (...args) {
  if (typeof args[0] === 'number' && typeof args[1] !== 'string') args.splice(1, 0, '127.0.0.1')
  return listen.apply(this, args)
}
