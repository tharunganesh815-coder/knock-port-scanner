const $ = s => document.querySelector(s);
const PRESETS = {
  top: '7,9,13,21-23,25,26,37,53,79-81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443-445,465,513-515,543,544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152-49157',
  common: '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017',
  web: '80,81,443,3000,5000,8000,8008,8080,8081,8443,8888'
};
// port: [service, risk 0-3, advice]
const SV = {
  21:['FTP',3,'Sends logins in clear text. Use SFTP or FTPS, or close it.'],22:['SSH',1,'Use key authentication and disable root login.'],
  23:['Telnet',3,'Unencrypted remote shell. Replace it with SSH.'],25:['SMTP',2,'Make sure it is not an open relay.'],53:['DNS',1,'Restrict recursion to trusted clients.'],
  80:['HTTP',1,'Redirect to HTTPS where possible.'],110:['POP3',2,'Unencrypted mail. Use POP3S on 995.'],111:['RPCbind',2,'Rarely needed. Firewall it.'],
  135:['MS RPC',3,'Windows RPC. Keep it off untrusted networks.'],139:['NetBIOS',3,'Legacy file sharing. Block it at the firewall.'],
  143:['IMAP',2,'Unencrypted mail. Use IMAPS on 993.'],389:['LDAP',2,'Use LDAPS and require authentication.'],443:['HTTPS',0,'Keep TLS versions and certificates current.'],
  445:['SMB',3,'Common ransomware path. Block it from untrusted networks.'],465:['SMTPS',0,'Mail submission over TLS.'],587:['Submission',0,'Mail submission. Require authentication and STARTTLS.'],
  631:['IPP',1,'Printer sharing. Disable if unused.'],993:['IMAPS',0,'Encrypted IMAP.'],995:['POP3S',0,'Encrypted POP3.'],1433:['MS SQL',3,'Databases should not be reachable from clients. Restrict by IP.'],
  1521:['Oracle',3,'Restrict database access to application servers.'],1723:['PPTP',2,'Outdated VPN protocol. Move to WireGuard or IPsec.'],1900:['UPnP',2,'Can expose devices. Disable if not needed.'],
  2049:['NFS',2,'Restrict exports to specific hosts.'],3000:['Dev server',1,'Development servers should not be exposed.'],3306:['MySQL',3,'Bind to localhost or restrict by IP.'],
  3389:['RDP',3,'Prime brute-force target. Put it behind a VPN and enable NLA.'],5000:['Dev server',1,'Development servers should not be exposed.'],
  5060:['SIP',2,'Check for toll-fraud exposure.'],5357:['WSDAPI',1,'Windows device discovery.'],5432:['PostgreSQL',3,'Bind to localhost or restrict by IP.'],
  5900:['VNC',3,'Weak authentication by default. Tunnel it through SSH or a VPN.'],6379:['Redis',3,'Often unauthenticated. Bind to localhost and set a password.'],
  8000:['HTTP alt',1,'Check what is being served.'],8080:['HTTP alt',1,'Check what is being served.'],8443:['HTTPS alt',0,'Alternate HTTPS port.'],8888:['HTTP alt',1,'Often a notebook or admin tool. Verify access control.'],
  9100:['JetDirect',2,'Raw printing. Restrict to print servers.'],9200:['Elasticsearch',3,'Frequently exposed without auth. Restrict access.'],
  11211:['Memcached',3,'Abused for amplification attacks. Never expose it.'],27017:['MongoDB',3,'Require authentication and restrict by IP.']
};
const info = p => SV[p] || ['unknown', 0, 'No guidance for this port. Confirm which application owns it.'];
const RISK = ['Info', 'Low', 'Review', 'Risky'], RCOL = ['--low', '--low', '--med', '--high'];

function parsePorts(spec) {
  const set = new Set();
  for (const part of spec.split(',')) {
    const m = part.trim().match(/^(\d+)(?:-(\d+))?$/); if (!m) return null;
    const a = +m[1], b = +(m[2] || m[1]); if (a < 1 || b > 65535 || a > b) return null;
    for (let i = a; i <= b; i++) set.add(i);
  }
  return set.size ? [...set].sort((x, y) => x - y) : null;
}

let ports = [], results = [], es = null, running = false, t0 = 0, timer = null, prog = 0, dots = [], hl = null, lastScan = null;

// ---------- form ----------
const portsInput = $('#ports');
function setPreset(key) {
  document.querySelectorAll('#presets button').forEach(b => b.classList.toggle('on', b.dataset.p === key));
  portsInput.value = PRESETS[key] || key; countPorts();
}
function countPorts() { const p = parsePorts(portsInput.value); $('#portCount').textContent = p ? `${p.length.toLocaleString()} ports to scan` : 'Invalid port list'; }
$('#presets').onclick = e => e.target.dataset.p && setPreset(e.target.dataset.p);
portsInput.oninput = () => { document.querySelectorAll('#presets button').forEach(b => b.classList.remove('on')); countPorts(); };
$('#timeout').oninput = e => $('#toOut').textContent = e.target.value + ' ms';
$('#conc').oninput = e => $('#coOut').textContent = e.target.value;
setPreset('top');

fetch('/api/info').then(r => r.json()).then(i => {
  $('#mode').textContent = i.allowPublic ? 'Public targets allowed' : 'Private networks only';
  $('#chips').innerHTML = ['127.0.0.1', ...i.local].map(ip => `<button type="button">${ip}</button>`).join('');
  $('#chips').onclick = e => e.target.tagName === 'BUTTON' && ($('#target').value = e.target.textContent);
}).catch(() => {});

function showErr(m) { const e = $('#err'); e.textContent = m; e.hidden = !m; }
function setRunning(v) { running = v; $('#go').hidden = v; $('#stop').hidden = !v; }

// ---------- scanning ----------
$('#form').onsubmit = ev => {
  ev.preventDefault(); showErr('');
  ports = parsePorts(portsInput.value);
  if (!ports) return showErr('Invalid port list. Use values such as 22,80,443 or 1-1024.');
  if (!$('#consent').checked) return showErr('Confirm that you have permission to scan this target.');
  results = []; dots = []; prog = 0; render(); updateStats({ done: 0, closed: 0, filtered: 0 });
  const q = new URLSearchParams({ target: $('#target').value, ports: portsInput.value, timeout: $('#timeout').value, concurrency: $('#conc').value, banner: $('#banner').checked ? 1 : 0, consent: 1 });
  $('#status').textContent = 'Resolving target…'; $('#sub').textContent = $('#target').value;
  setRunning(true); t0 = performance.now(); timer = setInterval(tick, 100); loop();
  es = new EventSource('/api/scan?' + q);
  es.addEventListener('start', e => { const d = JSON.parse(e.data); lastScan = { target: $('#target').value, ip: d.ip }; $('#status').textContent = `Scanning ${d.ip}`; $('#sub').textContent = `${d.total.toLocaleString()} ports · ${$('#target').value}`; });
  es.addEventListener('port', e => { const r = JSON.parse(e.data); results.push(r); const idx = ports.indexOf(r.port); dots.push({ port: r.port, idx, born: performance.now() }); render(); });
  es.addEventListener('progress', e => { const d = JSON.parse(e.data); prog = d.done / ports.length; updateStats(d); });
  es.addEventListener('done', e => { const d = JSON.parse(e.data); prog = 1; updateStats({ done: d.total, closed: d.closed, filtered: d.filtered }); finish(`Scan complete · ${results.length} open`, `${d.ip} · ${(d.ms / 1000).toFixed(1)}s`); });
  es.addEventListener('scanerror', e => { showErr(JSON.parse(e.data).message); finish('Scan failed', 'Check the message on the left.'); });
  es.onerror = () => { if (running) { showErr('Lost connection to the scan server.'); finish('Scan interrupted', ''); } };
};
$('#stop').onclick = () => finish('Scan stopped', `${results.length} open ports found so far`);
function finish(a, b) { if (es) es.close(); es = null; clearInterval(timer); setRunning(false); $('#status').textContent = a; $('#sub').textContent = b; draw(); }
function tick() { $('#sTime').textContent = ((performance.now() - t0) / 1000).toFixed(1) + 's'; }
function updateStats(d) { $('#sDone').textContent = d.done.toLocaleString(); $('#sClosed').textContent = d.closed.toLocaleString(); $('#sFilt').textContent = d.filtered.toLocaleString(); $('#bar').style.width = (prog * 100) + '%'; }

// ---------- table ----------
function render() {
  const f = $('#filter').value.toLowerCase(), only = $('#riskOnly').checked;
  const rows = results.slice().sort((a, b) => a.port - b.port).filter(r => { const [n, k] = info(r.port); return (!only || k >= 2) && (!f || String(r.port).includes(f) || n.toLowerCase().includes(f)); });
  $('#cnt').textContent = results.length;
  $('#empty').hidden = results.length > 0;
  $('#empty').textContent = results.length ? '' : (running ? 'Listening for answers…' : 'No open ports found. Nothing answered on the scanned ports.');
  if (!results.length && !running && !lastScan) $('#empty').textContent = 'No results yet. Pick a target, confirm permission, and start a scan.';
  $('#rows').innerHTML = rows.map(r => { const [n, k, adv] = info(r.port); return `<tr class="r" tabindex="0" data-p="${r.port}"><td class="p">${r.port}/tcp</td><td>${n}</td><td><span class="pill r${k}">${RISK[k]}</span></td><td class="ban">${esc(r.banner) || '—'}</td><td class="p">${r.ms} ms</td></tr><tr class="note" data-n="${r.port}" hidden><td colspan="5">${adv}</td></tr>`; }).join('');
  draw();
}
const esc = s => String(s || '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
$('#filter').oninput = $('#riskOnly').onchange = render;
$('#rows').onclick = e => { const tr = e.target.closest('tr.r'); if (tr) { const n = document.querySelector(`tr[data-n="${tr.dataset.p}"]`); n.hidden = !n.hidden; } };
$('#rows').onmouseover = e => { const tr = e.target.closest('tr.r'); hl = tr ? +tr.dataset.p : null; draw(); };
$('#rows').onmouseleave = () => { hl = null; draw(); };

// ---------- export ----------
function save(name, type, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); }
const stamp = () => (lastScan ? lastScan.ip : 'scan') + '-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
const full = () => results.slice().sort((a, b) => a.port - b.port).map(r => ({ port: r.port, protocol: 'tcp', state: 'open', service: info(r.port)[0], risk: RISK[info(r.port)[1]], banner: r.banner, latency_ms: r.ms }));
$('#expJson').onclick = () => results.length && save(`knock-${stamp()}.json`, 'application/json', JSON.stringify({ target: lastScan, scanned_at: new Date().toISOString(), open_ports: full() }, null, 2));
$('#expCsv').onclick = () => results.length && save(`knock-${stamp()}.csv`, 'text/csv', 'port,protocol,state,service,risk,banner,latency_ms\n' + full().map(r => [r.port, r.protocol, r.state, r.service, r.risk, JSON.stringify(r.banner), r.latency_ms].join(',')).join('\n'));

// ---------- radar ----------
const cv = $('#radar'), ctx = cv.getContext('2d'), tip = $('#tip'), still = matchMedia('(prefers-reduced-motion: reduce)').matches;
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
let W = 0;
function size() { const r = cv.getBoundingClientRect(), d = devicePixelRatio || 1; W = r.width; cv.width = r.width * d; cv.height = r.width * d; ctx.setTransform(d, 0, 0, d, 0, 0); draw(); }
new ResizeObserver(size).observe(cv);
const ring = p => p < 1024 ? 0 : p < 49152 ? 1 : 2;
function pos(d) {
  const n = Math.max(ports.length, 1), a = -Math.PI / 2 + (d.idx / n) * Math.PI * 2, c = W / 2, base = [0.40, 0.66, 0.90][ring(d.port)] * c;
  const r = base + ((d.port * 7) % 9 - 4) * 0.012 * c; return { x: c + Math.cos(a) * r, y: c + Math.sin(a) * r, a };
}
function draw() {
  if (!W) return; const c = W / 2, now = performance.now();
  ctx.clearRect(0, 0, W, W);
  ctx.strokeStyle = css('--line'); ctx.lineWidth = 1;
  [0.40, 0.66, 0.90].forEach(f => { ctx.beginPath(); ctx.arc(c, c, f * c, 0, 7); ctx.stroke(); });
  for (let i = 0; i < 48; i++) { const a = i / 48 * Math.PI * 2, l = i % 4 ? 0.02 : 0.04; ctx.beginPath(); ctx.moveTo(c + Math.cos(a) * c * .97, c + Math.sin(a) * c * .97); ctx.lineTo(c + Math.cos(a) * c * (.97 - l), c + Math.sin(a) * c * (.97 - l)); ctx.stroke(); }
  if (prog > 0) { // swept (scanned) area
    const a1 = -Math.PI / 2, a2 = a1 + prog * Math.PI * 2, g = ctx.createConicGradient ? ctx.createConicGradient(a1, c, c) : null;
    ctx.beginPath(); ctx.moveTo(c, c); ctx.arc(c, c, c * .97, a1, a2); ctx.closePath();
    ctx.fillStyle = 'rgba(127,180,255,.07)'; ctx.fill();
    if (running) { ctx.strokeStyle = css('--accent'); ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(c, c); ctx.lineTo(c + Math.cos(a2) * c * .97, c + Math.sin(a2) * c * .97); ctx.stroke(); }
  }
  dots.forEach(d => {
    const p = pos(d), k = info(d.port)[1], col = css(RCOL[k]), age = now - d.born;
    if (age < 1400 && !still) { ctx.strokeStyle = col; ctx.globalAlpha = 1 - age / 1400; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(p.x, p.y, 5 + age / 60, 0, 7); ctx.stroke(); ctx.globalAlpha = 1; }
    ctx.fillStyle = col; ctx.beginPath(); ctx.arc(p.x, p.y, d.port === hl ? 8 : 5, 0, 7); ctx.fill();
    d.px = p.x; d.py = p.y;
  });
  ctx.fillStyle = css('--text'); ctx.textAlign = 'center'; ctx.font = `800 ${c * .26}px Manrope, system-ui, sans-serif`; ctx.fillText(results.length, c, c + c * .06);
  ctx.fillStyle = css('--mute'); ctx.font = `500 ${c * .065}px Manrope, system-ui, sans-serif`; ctx.fillText('open ports', c, c + c * .17);
  ctx.font = `${c * .04}px IBM Plex Mono, monospace`; ['well-known', 'registered', 'dynamic'].forEach((t, i) => ctx.fillText(t, c, c - [0.40, 0.66, 0.90][i] * c + c * .055));
}
function loop() { draw(); if (running || dots.some(d => performance.now() - d.born < 1400)) requestAnimationFrame(loop); }
cv.onmousemove = e => {
  const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
  const d = dots.find(d => Math.hypot(d.px - x, d.py - y) < 10);
  tip.hidden = !d; cv.style.cursor = d ? 'pointer' : 'default';
  if (d) { tip.textContent = `${d.port}/tcp · ${info(d.port)[0]}`; tip.style.left = d.px + 'px'; tip.style.top = d.py + 'px'; }
};
cv.onmouseleave = () => tip.hidden = true;
cv.onclick = e => { const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top, d = dots.find(d => Math.hypot(d.px - x, d.py - y) < 10); if (d) { const row = document.querySelector(`tr.r[data-p="${d.port}"]`); if (row) { row.scrollIntoView({ block: 'center', behavior: 'smooth' }); row.click(); row.focus(); } } };
render();
