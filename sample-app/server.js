// Test app for the kshrd.app proxy. Shows what the app receives through nginx and
// keeps a live WebSocket open. No dependencies, so there is nothing to install.
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');

const PORT = Number(process.env.PORT) || 4000;
const page = fs.readFileSync(path.join(__dirname, 'index.html'));
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const server = http.createServer((req, res) => {
  if (req.url === '/api/info') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      host: req.headers.host,
      forwardedProto: req.headers['x-forwarded-proto'] ?? null,
      forwardedHost: req.headers['x-forwarded-host'] ?? null,
      forwardedFor: req.headers['x-forwarded-for'] ?? null,
      httpVersionToApp: req.httpVersion,
      appPort: PORT,
    }));
    return;
  }
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(page);
});

// Unmasked text frame, which is what a server sends. Payloads here are under 126 bytes.
function textFrame(text) {
  const payload = Buffer.from(text);
  return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
}

server.on('upgrade', (req, socket) => {
  const accept = crypto.createHash('sha1')
    .update(req.headers['sec-websocket-key'] + WS_GUID)
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );

  const timer = setInterval(() => socket.write(textFrame(new Date().toLocaleTimeString())), 1000);
  socket.on('close', () => clearInterval(timer));
  socket.on('error', () => socket.destroy());
});

server.listen(PORT, () => console.log(`Sample app listening on http://localhost:${PORT}`));
