// Knock — TCP connect scanner + web UI. Zero dependencies (Node 16+).
const http = require('http'), net = require('net'), os = require('os'), fs = require('fs'), path = require('path');
const dns = require('dns').promises;
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || '127.0.0.1';
const ALLOW_PUBLIC = process.env.ALLOW_PUBLIC === '1';   // default: private/loopback targets only
const PUB = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
const HTTPP = new Set([80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888]);
const active = new Map();

function isPrivate(ip) {
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l);
}

function parsePorts(spec) {
  const set = new Set();
  for (const part of String(spec).split(',')) {
    const m = part.trim().match(/^(\d+)(?:-(\d+))?$/);
    if (!m) return null;
    const a = +m[1], b = +(m[2] || m[1]);
    if (a < 1 || b > 65535 || a > b) return null;
    for (let i = a; i <= b; i++) set.add(i);
  }
  return set.size ? [...set].sort((x, y) => x - y) : null;
}

const clean = s => s.replace(/[^\x20-\x7e\r\n]/g, '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
function bannerText(raw) {
  const lines = clean(raw);
  const server = lines.find(l => /^server:/i.test(l));
  return (server || lines[0] || '').slice(0, 120);
}

function probe(ip, port, timeout, grab) {
  return new Promise(resolve => {
    const t0 = Date.now(), s = new net.Socket();
    let finished = false, connected = false, buf = '', timer;
    const end = (state, banner) => {
      if (finished) return; finished = true; clearTimeout(timer); s.destroy();
      resolve({ port, state, ms: Date.now() - t0, banner: banner || '' });
    };
    s.setTimeout(timeout);
    s.once('connect', () => {
      connected = true; s.setTimeout(0);
      if (!grab) return end('open');
      timer = setTimeout(() => end('open', bannerText(buf)), 700);
      if (HTTPP.has(port)) s.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
    });
    s.on('data', d => { buf += d.toString('latin1'); if (buf.length > 512) end('open', bannerText(buf)); });
    s.once('timeout', () => end('filtered'));
    s.once('close', () => end(connected ? 'open' : 'closed', bannerText(buf)));
    s.once('error', e => end(connected ? 'open' : e.code === 'ECONNREFUSED' ? 'closed' : 'filtered', bannerText(buf)));
    s.connect(port, ip);
  });
}

async function scan(req, res, q) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  const send = (e, d) => res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
  const fail = m => { send('scanerror', { message: m }); res.end(); };
  const target = (q.get('target') || '').trim(), ports = parsePorts(q.get('ports') || '');
  const timeout = Math.min(5000, Math.max(100, +q.get('timeout') || 1000));
  const conc = Math.min(500, Math.max(1, +q.get('concurrency') || 100));
  const grab = q.get('banner') === '1';
  if (q.get('consent') !== '1') return fail('Confirm that you have permission to scan this target.');
  if (!ports) return fail('Invalid port list. Use values such as 22,80,443 or 1-1024.');
  if (!/^[a-zA-Z0-9.\-:]{1,253}$/.test(target)) return fail('Enter a valid hostname or IP address.');
  let ip;
  try { ip = net.isIP(target) ? target : (await dns.lookup(target)).address; }
  catch { return fail(`Could not resolve "${target}".`); }
  if (!ALLOW_PUBLIC && !isPrivate(ip)) return fail(`${ip} is a public address. This server only scans private and loopback addresses. Start it with ALLOW_PUBLIC=1 to change that.`);
  const who = req.socket.remoteAddress;
  if ((active.get(who) || 0) >= 2) return fail('Two scans are already running. Stop one first.');
  active.set(who, (active.get(who) || 0) + 1);

  let aborted = false, i = 0, done = 0, open = 0, closed = 0, filtered = 0, last = 0;
  res.on('close', () => { aborted = true; });
  const total = ports.length, t0 = Date.now();
  send('start', { ip, total });
  const worker = async () => {
    while (!aborted && i < total) {
      const r = await probe(ip, ports[i++], timeout, grab);
      done++; r.state === 'open' ? open++ : r.state === 'closed' ? closed++ : filtered++;
      if (r.state === 'open') send('port', r);
      if (Date.now() - last > 120) { last = Date.now(); send('progress', { done, open, closed, filtered }); }
    }
  };
  await Promise.all(Array.from({ length: Math.min(conc, total) }, worker));
  active.set(who, active.get(who) - 1);
  if (!aborted) { send('progress', { done, open, closed, filtered }); send('done', { ip, total, open, closed, filtered, ms: Date.now() - t0 }); res.end(); }
}

http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/api/scan') return scan(req, res, url.searchParams);
  if (url.pathname === '/api/info') {
    const local = Object.values(os.networkInterfaces()).flat().filter(n => n.family === 'IPv4' && !n.internal).map(n => n.address);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ allowPublic: ALLOW_PUBLIC, local }));
  }
  const file = path.normalize(path.join(PUB, url.pathname === '/' ? 'index.html' : url.pathname));
  if (!file.startsWith(PUB)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, HOST, () => console.log(`Knock is running at http://${HOST}:${PORT}  (public targets ${ALLOW_PUBLIC ? 'ALLOWED' : 'blocked'})`));
