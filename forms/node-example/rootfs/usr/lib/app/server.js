'use strict';

const http = require('node:http');

const server = http.createServer((req, res) => {
  const path = req.url.split('?')[0];
  let status = 200;
  let body;
  if (req.method !== 'GET') {
    status = 405;
    res.setHeader('Allow', 'GET');
    body = 'method not allowed\n';
  } else if (path === '/health') {
    body = 'ok\n';
  } else if (path === '/') {
    body = 'Hello from Node.js on werewolf!\n';
  } else {
    status = 404;
    body = 'not found\n';
  }
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
});
server.requestTimeout = 5000;
server.headersTimeout = 5000;
server.listen(8080, '0.0.0.0', () => console.log('app: listening on :8080'));
