const http = require('http');

let n = 0;
const logs = [];

const server = http.createServer((req, res) => {
  // Expose a tiny “status” endpoint for harness polling
  if (req.url === '/__status') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ n, logs }));
    return;
  }

  n++;
  const entry = {
    n,
    method: req.method,
    url: req.url,
    headers: req.headers,
    ts: Date.now(),
  };
  logs.push(entry);
  console.log(`[${n}] ${req.method} ${req.url}`);
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('ok\n');
});

server.listen(3000, '127.0.0.1', () => {
  console.log('listening on http://127.0.0.1:3000');
});
