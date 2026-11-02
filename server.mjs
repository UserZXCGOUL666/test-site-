import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs/promises';
import dns from 'node:dns/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const bootedAt = new Date().toISOString();
const bootId = crypto.randomUUID();
const start = performance.now();
const PORT = Number(process.env.PORT || 3000);
// For this temporary diagnostics app, generate a private token when the platform
// does not offer a documented environment-variable editor. It is printed once
// to private application logs. Do not use this pattern for production secrets.
const generatedToken = !process.env.DIAG_TOKEN;
const DIAG_TOKEN = process.env.DIAG_TOKEN || crypto.randomBytes(24).toString('hex');
const rootDir = path.dirname(fileURLToPath(import.meta.url));
const indexHtml = await fs.readFile(path.join(rootDir, 'public', 'index.html'));

function json(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY'
  });
  res.end(JSON.stringify(body));
}
function auth(req) {
  if (!DIAG_TOKEN) return false;
  const got = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
  const a = Buffer.from(got);
  const b = Buffer.from(DIAG_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function readNum(file) {
  try {
    const raw = (await fs.readFile(file, 'utf8')).trim();
    if (raw === 'max') return null;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? n : null;
  } catch { return null; }
}
function shortError(err) { return err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network_error'; }
async function getServerReport() {
  const memLimit = (await readNum('/sys/fs/cgroup/memory.max')) ?? (await readNum('/sys/fs/cgroup/memory/memory.limit_in_bytes'));
  const memCurrent = (await readNum('/sys/fs/cgroup/memory.current')) ?? (await readNum('/sys/fs/cgroup/memory/memory.usage_in_bytes'));
  const usage = process.memoryUsage();
  let disk = null;
  try {
    const s = await fs.statfs('/app');
    disk = { bytesTotal: s.blocks * s.bsize, bytesFree: s.bavail * s.bsize };
  } catch {}
  return {
    checkedAt: new Date().toISOString(), bootedAt, bootId,
    uptimeSeconds: Math.round((performance.now() - start) / 1000),
    nodeVersion: process.version, platform: process.platform, architecture: process.arch,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    cpuCountVisible: os.availableParallelism?.() ?? os.cpus().length,
    cpuLoadAverage: os.loadavg().map(x => Math.round(x * 100) / 100),
    memory: { rssBytes: usage.rss, heapUsedBytes: usage.heapUsed, heapTotalBytes: usage.heapTotal, cgroupLimitBytes: memLimit, cgroupCurrentBytes: memCurrent },
    disk,
    note: 'Visible CPU count, filesystem and disk size may reflect container/host, not paid plan. IP geolocation does not prove physical data residency.'
  };
}
async function tryFetch(url, opts={}) {
  const t0 = performance.now();
  try {
    const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(6000), redirect: 'follow' });
    await res.arrayBuffer();
    return { ok: true, status: res.status, ms: Math.round(performance.now() - t0) };
  } catch (e) {
    return { ok: false, error: shortError(e), ms: Math.round(performance.now() - t0) };
  }
}
async function dnsProbe(domain) {
  const t0 = performance.now();
  try {
    const records = await dns.lookup(domain, { all: true });
    return { ok: true, ms: Math.round(performance.now() - t0), addressesFound: records.length, ipv4: records.some(r=>r.family===4), ipv6: records.some(r=>r.family===6) };
  } catch (e) { return { ok: false, error: 'dns_lookup_failed', ms: Math.round(performance.now() - t0) }; }
}
async function networkReport() {
  const [yandex, bitrix, outbound, dnsBitrix, dnsYandex, postEcho] = await Promise.all([
    tryFetch('https://ya.ru', { method: 'GET' }),
    tryFetch('https://www.bitrix24.ru', { method: 'GET' }),
    tryFetch('https://api.ipify.org?format=json'),
    dnsProbe('www.bitrix24.ru'), dnsProbe('ya.ru'),
    tryFetch('https://postman-echo.com/post', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ probe:'apploy-probe', fakeData:true }) })
  ]);
  let outboundIp = null;
  if (outbound.ok) {
    try {
      const r = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(6000) });
      const parsed = await r.json();
      if (/^(?:[\da-f:.]+)$/i.test(parsed.ip)) outboundIp = parsed.ip;
    } catch {}
  }
  return { checkedAt:new Date().toISOString(), outboundIp,
    checks: { yandex_https:yandex, bitrix24_public_https:bitrix, ip_lookup_https:outbound, bitrix24_dns:dnsBitrix, yandex_dns:dnsYandex, https_post_to_public_test_service:postEcho },
    note:'Only test data are sent to postman-echo.com. This does NOT test your private Bitrix webhook, nor whether a CRM lead was created. Outbound IP may belong to NAT/proxy; its location is only an estimate.' };
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY' });
    res.end(indexHtml);
    return;
  }
  if (url.pathname === '/health' && req.method === 'GET') { json(res, 200, {ok:true}); return; }
  if (!url.pathname.startsWith('/api/')) { json(res,404,{error:'not_found'}); return; }
  if (!DIAG_TOKEN) { json(res,503,{error:'set_DIAG_TOKEN_environment_variable'}); return; }
  if (!auth(req)) { json(res,401,{error:'authorization_required'}); return; }
  if (url.pathname === '/api/ping' && req.method === 'GET') {
    json(res,200,{ok:true,ts:new Date().toISOString(),bootId,bootedAt,uptimeSeconds:Math.round((performance.now()-start)/1000)});
    return;
  }
  if (url.pathname === '/api/server' && req.method === 'GET') { json(res,200,await getServerReport()); return; }
  if (url.pathname === '/api/network' && req.method === 'GET') { json(res,200,await networkReport()); return; }
  if (url.pathname === '/api/echo' && req.method === 'POST') {
    let size=0; let text='';
    try {
      for await (const chunk of req) {
        size+=chunk.length;
        if (size>16384) {json(res,413,{error:'payload_too_large'});return;}
        text+=chunk.toString('utf8');
      }
      const data=JSON.parse(text);
      if (!data || typeof data !== 'object' || Array.isArray(data)) {json(res,400,{error:'json_object_required'});return;}
      json(res,200,{ok:true,bytes:size,receivedFieldNames:Object.keys(data).slice(0,12),stored:false,forwardedToBitrix:false,bootId});
    } catch {json(res,400,{error:'invalid_json'});}
    return;
  }
  json(res,405,{error:'method_not_allowed'});
});
server.requestTimeout = 12000;
server.headersTimeout = 12000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Probe listening on ${PORT}; boot ${bootId}; DIAG_TOKEN set: true; generated: ${generatedToken}`);
  if (generatedToken) console.log(`TEMPORARY_DIAG_TOKEN_FOR_PRIVATE_LOGS_ONLY=${DIAG_TOKEN}`);
});
