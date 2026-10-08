// The node form's application until yours replaces it: one line of text
// on :8080, to show Node.js runs here, leashed.
const http = require('node:http');

const port = 8080;
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(`werewolf: Node.js ${process.version} is answering\n`);
}).listen(port, () => console.log(`app: listening on :${port}`));
