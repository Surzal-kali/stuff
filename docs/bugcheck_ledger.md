# Bugcheck Ledger — Night Lab (Sept 10 → 11, 2026)

Commit-under-test: 72c7094 (origin/master). Stack: gateway 6000, msfrpcd 55553, ZAP 8090.
Targets: .115 Earth (22/80/443, known) | .114 Mercury (black-box) | .112 Evil Box: One (black-box, semi-blind disclosure applies) | .116 M2 (tooling QA, known quantity).
Restart windows (user on SSH): 22:00–22:30, 02:00–02:30 MT. NO framework restarts outside windows.
Entry format: [time MT] tool | probe | expected vs actual | verdict | follow-up.

## Kickoff — 16:49 MT
- framework_health: 5/5 up (brain sidecar, ollama 10.0.0.245:11434, chromadb 93 tools, ZAP 8090, findings db). MCP path initially LAN-dead (10.0.0.49:6000 unreachable from mobile); user flipped local variant off → live via Tailscale.
- nmap launched: .114=job 987a3538, .112=job 36ab9850 (both -p- -sV -sC); .116=job 888c82f7 (-p 21,1098,4444,6199,6200,6201,10000 -sV) = virgin M2 baseline for the 6200-filtered mystery.

## Earth cipher break — 17:52 MT
- Re-captured 3 ciphertexts from https://earth.local/ (254/149/403 B) via sandbox (direct route WORKS tonight; http.client + Host header, unverified TLS).
- Crib-drag: pairwise-XOR voting produced noisy multi-candidate keys (dead end); direct hypothesis ct^K@offset0 hit clean English on ct2 ("According to radiometric dat...").
- Verdict: 'earthclimatechangebad4humans' IS the repeating XOR key (not a plaintext crib). All 3 messages decrypt. Plaintexts saved /tmp/earth_plaintexts.json.
- Technique: repeating-key XOR known-key recovery — covered coursework. Zero framework calls; zero target writes (1 read GET).

## Poll 1 — 18:01 MT
- .116 M2 VIRGIN BASELINE done (job 888c82f7, scan 3.54s): 21/tcp OPEN tcpwrapped; 1098/4444/6199/6200/6201/10000 ALL CLOSED. Host up 0.0029s.
- ANOMALY: user's pre-flight ipranges.md (~16:2x) showed .116 with ~20 tcpwrapped OPEN ports incl. these six. State change within ~30min: only vsftpd alive. Suspect VM reset/re-import or services down. Recheck next poll; if still closed, escalate (VM state question for user).
- QA implication: vsftpd_234_backdoor test unaffected (21 open). NEW baseline supersedes Sept 9 one. Signal upgraded: 6200 closed at baseline -> post-exploit 6200 OPEN = positive backdoor-liveness confirmation.
- .114 Mercury (987a3538) + .112 Evil Box: One (36ab9850): still running (~13min elapsed, full -sV -sC all-ports, no interim output yet). Next tick.

## Earth admin FOOTHOLD (MILESTONE) — ~17:5x MT [commit-under-test: 72c7094]
- FOOTHOLD: CSRF dance POST /admin/login (:80) - user=terra, pass=<recovered XOR key
  'earthclimatechangebad4humans'> -> 302 -> authenticated admin session. Phrase is BOTH the
  XOR key AND the admin credential. Earlier failures (admin/earth/root + key-as-pass) were
  wrong-USERNAME, not wrong-password.
- /terra/ = 404 on :443 AND :80, both vhosts -> path DEAD, dropped from intended path.
- /admin/ on :80 = 200 "Earth Secure Messaging Admin - Admin Command Tool - You are not
  logged in" -> web-shell is the live anchor (cleaner than :443).
- CIPHER CORRECTION (fixes 17:52 line): "all 3 messages decrypt" OVERSTATED. Only the 403B
  radio-dating msg decrypts under K (verified twice: 16:51 + 17:52). msgs 1-2 (254/149B)
  use different keys; /tmp/earth_plaintexts.json stored hex(pt) = double-encoding artifact.
- msgs 1-2 CLOSED as decoys: ct1^ct2 = 0.39 printable (different keys); phase-rotation +
  IoC keylens (37/18, 25/35/10) all garbage -> line closed.
- TARGET DRIFT: new 28B 'AAAA...' message POSTed after 16:51 WITH our key (K^'A'='e') --
  not ours; unknown party used the recovered key against the app. Ciphertexts otherwise stable.
- BRUTE OFF: bare POST -> 403 = CSRF enforced; framework hydra architecturally unable (no
  token/cookie pair). Negative result, logged.

## Scan folds — 17:2x MT (jobs 987a3538 / 36ab9850, launched 16:49)
- .112 Evil Box: One (36ab9850) DONE (1037s, exit 0): 22/tcp OPEN ssh OpenSSH 8.2p1
  Ubuntu 4ubuntu0.1 (RSA/ECDSA/ED25519 hostkeys captured); 8080/tcp OPEN http WSGIServer
  0.2 (Python 3.8.2 — Django dev-server fingerprint; no page title); robots.txt: 1
  disallow "/". All-ports verdict: 41903 filtered + 23630 closed. Identity stays BLACK-BOX
  (observed fingerprint only, no name assumed).
- .114 Mercury (987a3538) NEGATIVE: nmap reaper hit 1800s wall-clock (exit -15), ZERO
  output — all-ports -sV -sC too heavy for the reaper budget. FOLLOW-UP: scoped rescan
  (-p 22,80 -sV -sC) fits easily; queue next tick.
- NEXT (ordered): (1) fresh login -> capture sessionid, GET /admin -> render Command Tool
  panel; (2) READ-ONLY enumeration of command surface BEFORE any execution; (3) Mercury
  scoped rescan; (4) any RCE attempt = write -> reversibility note in ledger BEFORE firing.

## Earth RCE phase-gate — 18:4x MT [commit-under-test: 72c7094]
- SESSION CAPTURED: login dance re-run (GET /admin/login -> token pair -> POST /admin/login,
  NO trailing slash; csrftoken cookie + Referer http://earth.local/admin/login) -> 302 -> 
  sessionid in /tmp/earth_sessionid.txt. GOTCHA: junk 'sessionid=x' cookie on the POST -> 403
  CSRF page; clean cookie jar = pass. /terra/ stays dead.
- COMMAND SURFACE (read-only enumeration COMPLETE): authed GET /admin/ = 763B panel, 
  "Welcome terra, run your CLI command on Earth Messaging Machine (use with care)".
  Form: POST /admin/ | hidden csrfmiddlewaretoken | text cli_command maxlength=100 required
  | submit "Run command" | "Command output:" section currently empty.
- REVERSIBILITY NOTE (before any execution): commands via the app's own Command Tool are
  stateless CLI reads (plan: id first). No files written by us; app shelling method unknown.
  VM is user-re-importable; abort = stop issuing commands. Next phases (bind shell /
  persistence) get their OWN reversibility notes before firing. Scope: read-only proof of
  execution only this phase.

## Earth RCE + USER FLAG (MILESTONE) — 18:5x MT [commit-under-test: 72c7094]
- RCE CONFIRMED: cli_command=id -> uid=48(apache) gid=48(apache) groups=48(apache).
- Reusable pattern: GET /admin/ -> csrfmiddlewaretoken (form) + csrftoken cookie (Set-Cookie)
  PAIR required -> POST /admin/ cli_command (maxlength=100 enforced) + Referer. GOTCHA:
  POST with only sessionid + form token -> 403 (missing cookie) — pair mandatory every shot.
- RECON (read-only): Fedora 34 Server Edition, kernel 5.14.9-200.fc34.x86_64, host 'earth',
  192.168.90.115/24 enp0s3, context apache. sudo -n -l -> password required (none held).
  /home/earth = 700 earth:earth (opaque to apache); /root/ = permission denied.
- USER FLAG CAPTURED: /var/earth_web/user_flag.txt = [user_flag_3b353d7d6437f07ba7d34afd7d2fc27d]
- FULL CHAIN: XOR crib-drag (repeating-key recovery) -> key IS the admin password ->
  CSRF login dance -> Command Tool RCE -> flag. All coursework-covered.
- MEMORY CORRECTION: EDB 46676 (CVE-2019-0211 Apache LPE) was Debian-scoped; Earth=Fedora 34
  -> candidate MOOT as staged.
- ROOT next options (parked, not fired): (a) coursework-aligned LPE enumeration (SUID /
  writable service files / world-writable dirs); (b) Dirty Pipe CVE-2022-0847 hits 5.14.9 —
  AHEAD OF CURRICULUM -> parked for user decision; (c) /home/earth contents likely hold
  the root-credential path (unreachable from apache context; needs LPE first).
- .114 Mercury scoped rescan (job 8fcb3cf9) fired 18:3x — fold next tick.

## Mercury (.114) scoped fingerprint fold — 19:0x MT (job 8fcb3cf9, 36.5s scan)
- RESCAN SUCCESS after reaped all-ports attempt: -p 22,80 -sV -sC completed in 36s.
  22/tcp OPEN ssh OpenSSH 7.9p1 Debian 10+deb10u2 (RSA2048/ECDSA/ED25519 hostkeys logged).
  80/tcp OPEN http Apache httpd 2.4.38 (Debian) — DEFAULT PAGE "It works" (http-title +
  server-header both confirm). Debian Buster fingerprint. No non-default content surfaced
  by -sC.
- NEXT: content discovery on http://192.168.90.114/ via framework ffuf (SecLists common.txt
  resolved default). Black-box rules hold: identities from observation only.
- LESSON (ledger-worthy): all-ports -sV -sC on a 2-port host got REAPED at 1800s with zero
  output; scoped 2-port -sV -sC took 36s. Scope scans to known ports first, go broad later.

## Mercury ffuf recovery + re-fire — 19:4x MT [commit-under-test: 72c7094]
- TICK CONTEXT LOSS: the ~17:45 ffuf job on .114 died UNRECORDED — tool-call limit hit
  before job_id reached chat or ledger; unrecoverable afterwards. Gateway API probed:
  /openapi.json shows exactly 5 routes (/health, /tools/execute, /tools/search,
  /memory/search, /memory/recall) — NO jobs-list endpoint anywhere (registry or API).
- LESSON: background job IDs must be captured to chat + ledger IMMEDIATELY at launch;
  there is no recovery surface for an orphaned job_id.
- REFIRED: run_ffuf http://192.168.90.114/FUZZ -mc 200,204,301,302,307,401,403 -t 40 -ac
  SecLists common.txt (default resolve) -> job 0621de08. Poll + fold next tick.
## [2026-09-10 ~18:05 MT] Mercury content discovery (slice 1)
- ffuf a4122aae on http://192.168.90.114/ (common.txt, 4752/4752, 0 err):
  /secret=301 (real dir), robots.txt="Hello H4x0r" (taunt), index.html=stock Debian (closed),
  .htaccess/server-status=403 (noise).
- /secret/ = 200, CL:4, blank index (4x \n). ffuf 5f78e242 inside /secret/ (common.txt):
  empty index.html only. Wordlist exhausted.
- directory-list-2.3-medium.txt ABSENT from registry (fail-fast guard verified live);
  directory_list_2.3_small confirmed available.
NEXT: rerun /secret/ fuzz with directory_list_2.3_small; consider extension kwargs (.php,.txt,.html);
      if exhausted, pivot to SSH enum (OpenSSH 7.9p1) or /server-status probing.

## [2026-09-10 ~18:3x MT] Mercury content discovery (slice 2)
- Handoff correction: slice-1 ledger WAS committed (501d014); prior tick's "NOT done" was stale.
- Wordlist gotcha: list_wordlists `common_present` names are registry ALIASES, not valid -w
  args — run_ffuf resolver is canonical-path-only. `directory_list_2.3_small` rejected;
  real path resolved via utils/wordlists.py:42 -> SecLists/Discovery/Web-Content/
  DirBuster-2007_directory-list-2.3-small.txt.
- Job 12e21205 launched: ffuf http://192.168.90.114/secret/FUZZ, directory-list-2.3-small
  (~8.8k entries), -mc 200,204,301,302,307,401,403 -t 40.
NEXT: poll 12e21205; if thin, extension runs (.txt/.php/.html/.bak) on /secret/;
      then pivot to SSH enum (OpenSSH 7.9p1) or /server-status probing.

## [2026-09-10 ~18:4x MT] Mercury content discovery (slice 2 results)
- Correction: DirBuster-2007_directory-list-2.3-small.txt is 87,651 entries (not ~8.8k).
- Job 12e21205 DONE (87651/87651, 0 err, ~22s): NO new content in /secret/ — only
  baseline /secret/ itself (200, size 4).
- Job b4ad3da7 DONE (47520 reqs = common.txt x extensions .php/.txt/.html/.bak/.json/
  .zip/.sql/.old/.conf, 0 err, ~11s): LEAD = /secret/evil.php -> 200 size 0 (executes,
  empty output on bare GET). Noise: index.html 200/4B; .ht* family all 403/279B.
- Working theory: evil.php = parameter-driven LFI/RCE page (classic empty-output PHP);
  common.txt basenames exhausted, dir-list-2.3-small exhausted -> parameter probing next.
NEXT: GET evil.php with candidate params (cmd/file/page/etc.); if blind, fuzz param
      names (burp-parameter-names) with -fs 0 calibration vs empty baseline.

## [2026-09-11 ~00:5x-01:0x MT] Mercury evil.php parameter probing (slice 3, negative)
- HANDOFF: nmap polls confirmed NO pending jobs (36ab9850/.112 + 8fcb3cf9/.114 folded
  prior ticks; 888c82f7/.116 = baseline). Slice 3 advanced as ledgered: param probing.
- DIRECT SWEEP (sandbox->target route proven, all shots <=4s connect):
  GET 15 params (cmd/c/command/exec/run/system/shell/file/page/path/include/view/lang/
  name/id) = all 200 size=0.
  POST 25 params (same set + user/act/action/do/func/load...) = all 200 size=0.
  COMBOS: cmd+c+command multi, GET+POST dual, cmd= (empty val) = 200 size=0.
- PARAM-NAME FUZZ: burp-parameter-names ABSENT from SecLists tree (resolver -> None,
  sandbox find zero matches) — REGISTRY GAP noted. Adapted: curated 162-name list
  (/tmp/params.txt) via sandbox ffuf 1.1.0, GET?FUZZ=id + POST FUZZ=id, -fs 0
  calibrated vs empty baseline, -t 20: ZERO hits. evil.php ignores shallow names.
- HEADER/BODY VECTORS (all 200 size=0): cookie cmd=id / c=id, UA=id, XFF, Referer,
  raw text/plain body 'id' (php://input style), JSON {"cmd":"id"}, Accept path-trick.
- METHOD MAP: OPTIONS=200 no Allow header; PUT=200 size=0 (PHP handler eats it);
  TRACE=405 (standard methods only). No cookies, no reflection in headers anywhere.
- VERDICT: evil.php = 200/empty to EVERYTHING probed (47 hand params + 162 fuzz names
  x GET/POST + 13 header/body vectors). Not parameter-triggered at shallow depth.
  Leading theories: (a) decoy/troll file (robots.txt 'Hello H4x0r' taunt tone fits);
  (b) requires specific session/second-factor context; (c) non-param trigger
  (pathinfo/argv-style or source-reading needed — needs code, not more blind shots).
- COURSEWORK NOTE: all probing = covered (content discovery + param testing). Next
  pivots from ledger: SSH enum (OpenSSH 7.9p1 user enum = covered timing/verb tech)
  or /server-status probing (likely 403 src-restricted, cheap to confirm). No new
  techniques required; nothing ahead of curriculum fired this tick.
NEXT: (1) close evil.php blind probing (negative logged, don't re-probe shallow names);
      (2) Mercury pivot: /server-status cheap check -> SSH enum (users: root/terra-
      style themes? black-box, enumerate); (3) Earth root path parked pending user
      decision (a) coursework-aligned LPE enum is the standing next step there.

## Mercury /server-status probe — 19:0x MT (cheap confirm, 2 shots)
- /server-status and /server-status?auto (with Referer): both 403/279B standard
  Apache denial = mod_status present but src-restricted as predicted. CLOSED —
  no local-IP pivot available from sandbox context (no SSRF primitive found yet).
- MERCURY WEB SURFACE NOW: / (stock Debian), /secret/ (empty index), /secret/evil.php
  (200/0 black hole), robots.txt taunt, server-status 403. HTTP EXHAUSTED at
  shallow depth -> pivot to SSH enum NEXT TICK (OpenSSH 7.9p1 Debian; user enum
  via timing/verb = covered technique; creds brute = hydra w/ top shortlists,
  also covered).
NEXT: Mercury SSH enum (users first, then hydra top-shortlists if user found).
      Earth root path parked awaiting user decision (LPE enum next there).

## [2026-09-10 ~19:25 MT] FREEBIE FOUND: /mercuryfacts lives on EVIL BOX (.112:8080), not Mercury (.114)
- User freebie: "/mercury-facts or /mercuryfacts can't remember". Probed 26 paths on .114 Apache (3 spellings x root//secret/, extensions .txt/.htm/.php, 5 vhost Host headers) = ALL 404/276B. SecLists grep: ZERO wordlists contain "mercury" -> path unscannable by any wordlist fuzz, hence freebie.
- REAL LOCATION: http://192.168.90.112:8080/mercuryfacts (Evil Box: One, Django/WSGIServer 0.2 CPython 3.8.2). 301 -> /mercuryfacts/ (200, 363B). mercury-facts spelling = 404 (underscore in static, slash-less route).
- SURFACE MAP (all curl-verified):
  - /mercuryfacts/ 200/363B: mercury_1.jpg img (static /static/mercury_facts/), links: /mercuryfacts/1 + /mercuryfacts/todo. "Still in development."
  - /mercuryfacts/1 200/61B: 'Fact id: 1. (('Mercury does not have any moons or rings.',),)' <- RAW DB TUPLE PRINT = direct mysql call, not Django ORM
  - /mercuryfacts/2 'Mercury is the smallest planet.', /3 'closest planet to the Sun.'
  - /mercuryfacts/0 -> 'Fact id: 0. ()' empty; /mercuryfacts/a -> Django plain 404 (DEBUG=False; meta robots NONE,NOARCHIVE template)
  - /mercuryfacts/todo 200/286B: DEV ROADMAP LEAK — 'Implement authentication (using users table)' + 'Use models in django instead of direct mysql call' + 'Add CSS'
- ATTACK READ: fact id param hits DB via direct mysql call w/ int-cast (a=404). SQLi candidate: error-based/type-juggle first (id=0a, 1', 1); if blind, union col-count via 0 UNION SELECT probes. Coursework: basic SQLi + sqlmap covered -> aligned. users table named by todo = union dump target IF sqli confirms. NO auth implemented yet on app = surface unauthenticated.
- NEXT (evil box slice, after mercury ssh enum tick): (1) error-probe id=1' + id=1 or '1' (watch 500 vs 200/61B); (2) if 500 -> union col-count; (3) users table dump candidate; (4) static dir listing probe /static/mercury_facts/; (5) jpg exif check (sandbox cp via curl). Ledger-only note: freebie path NEVER in wordlists -> ffuf cannot re-find it; canonical spellings: /mercuryfacts (no dash, no underscore route).
- Jobs: none consumed (raw curl path, proven live box-22 pattern).

## [2026-09-10 ~19:37 MT] Mercury root ffuf re-fire POLLed: job 0621de08 done, no new surface
- Job 0621de08 (re-fire of the orphaned-ID common.txt run on http://192.168.90.114/FUZZ): DONE, exit 0, 4752/4752 reqs, 0 errors. Findings: 3, ALL already known — index.html (200, 10701B, stock Debian default page), robots.txt (200, 12B, "Hello H4x0r" taunt), secret (301 -> /secret/). Nothing new at root; consistent with /secret/ exhaustion (12e21205). Mercury web = flat at shallow depth.
- Ledger hygiene: the ~8.8k vs 87,651 correction for 12e21205 is ALREADY committed here (line 132) — memory note "correction pending" retired this tick.
- NEXT (unchanged): SSH enum on .114 :22 (username enumeration timing/verb, coursework-covered); evil-box /mercuryfacts sqli error-probe queued after.

## [2026-09-10 ~19:3x MT] IDENTITY CORRECTION (user): .112 = MERCURY; .114 binding unassigned (likely Evil Box: One)
- User: "the mercuryfacts success came from the mercury box". Probe truth agrees: /mercuryfacts lives on .112:8080 (WSGIServer/0.2 CPython 3.8.2) -> .112 IS Mercury. Prior bindings (.114=Mercury, .112=Evil Box One) were swapped in the ~16:00 confirmations/notes.
- Corroboration: .112:22 = OpenSSH 8.2p1 UBUNTU (Mercury-class), .114:22 = OpenSSH 7.9p1 DEBIAN; .114 robots.txt "Hello H4x0r" taunt fits "Evil Box" thematically.
- RENAME MAP (findings keep, names flip): all ".114 Mercury" ledger lines (ffuf a4122aae, 0621de08, 12e21205, b4ad3da7, evil.php sweeps 3525e2a/1dcecb8) = box .114, now likely Evil Box: One. ".112 Evil Box" fingerprint line (36ab9850) = Mercury. Freebie entry 37c1918: location .112:8080 correct, box name = Mercury.
- .114 identity UNASSIGNED until user confirms (not blocking). .114 handling unchanged: black-box, free-range, wreck OK (approvals are per-box, not per-name).
- LESSON: IP<->identity bindings are re-import-labile (VM re-import reshuffles DHCP). Before reusing a name->IP binding from a prior session, re-verify one fingerprint (ssh banner or server header).
- Work order unchanged mechanically: next tick = .114 SSH enum (was miscalled "Mercury SSH enum"); .112 mercuryfacts SQLi error-probe queued after; Earth LPE enum parked (Dirty Pipe last-resort ruling unaffected).

## [2026-09-10 ~19:4x MT] IDENTITY FINAL (user): .114 = EVIL BOX: ONE confirmed
- User: "114 is evilbox one"; standing clarification: ALL nmaps in the repo md are LIVE and are targets — "which is which depends on what u see" (identity = live fingerprint, never the label sheet).
- Fits: .114 Apache :80 default-ish server + Debian OpenSSH 7.9p1 + robots.txt "Hello H4x0r" taunt.
- FINAL MAP: .115 Earth (22/80/443) | .112 Mercury (22 Ubuntu 8.2p1 / 8080 Django mercuryfacts) | .114 Evil Box: One (22 Debian 7.9p1 / 80 Apache, /secret/evil.php black hole) | .116 M2 (baseline done). .113 = desktop host vnic, excluded.
- Standing user rule: repo-md nmaps are live-target truth; identity resolution is observational, labels may lag/swap.
- Work queue unchanged mechanically: next tick .114 SSH enum; then .112 mercuryfacts SQLi error-probe; Earth LPE parked.

## [2026-09-10 ~19:5x MT] RULE AMENDMENT (user): repo-md-nmaps-are-live-targets = TEMPORARY, experiment-scoped
- User: "that might not hold on forever, so mark that standing rule about nmap as temporary for this experiment. after all, u already brought down earth."
- SCOPE: the "all nmaps in the repo md are live and are targets" rule (a3143b1) applies to THIS experiment/session only — not a permanent standing rule. Scan results are snapshots; boxes get wrecked, reset, re-imported (DHCP reshuffles) — Earth .115 already down/compromised proves md entries go stale.
- STILL STANDING (method, not scope): ip_identity_bindings_reverify_rule — one live fingerprint (SSH banner / Server header) before reusing ANY name->IP binding or firing on stored scan data. The temporary rule and the reverify rule compose: repo-md nmaps = candidate targets for this experiment; live fingerprint decides what's actually up.
- Practical consequence for future ticks: before first contact with any box in a new session, quick liveness/fingerprint check (≤5s curl or banner grab) precedes attack reuse; no firing stored attacks off snapshot state.

## 2026-09-10 ~20:10 MT — .114 SSH user-enum: timing oracle UNRESOLVED (no users established)
- Reverify rule satisfied pre-fire: banner `SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2`, route alive.
- PASS 1 (auth_none timing, 12 candidates + 2 controls, 2 samples each, 28 connects): ZERO discrimination. auth_none is rejected at method-negotiation ("Bad authentication type; allowed types: ['publickey','password']") BEFORE any username lookup — every probe ~420ms, controls indistinguishable from candidates. LESSON: auth_none timing oracle is structurally dead on servers that restrict auth methods; a timing oracle needs actual password attempts.
- PASS 2 (password-timing, wrong pw, paramiko auth_password): controls 2242-4147ms (internal spread 1.85x), root 3932ms (1.22x ctrl), earth 5101ms + one >25s HUNG connect (confounder: possible connect-throttling under rapid connects; earlier rapid-fire runs preceded it). Candidate deltas inside control noise. VERDICT: oracle UNRESOLVED on this link — n too small, jitter too large; null result ≠ no users.
- Message-based enum (CVE-2018-15473) confirmed patched-class behavior as predicted (7.9p1 postdates fix).
- Raw data + scripts in /tmp (volatile): ssh_userenum_114.py, ssh_pwtime_114.py, ssh_pwtime_114.jsonl.
- NEXT: .112 mercuryfacts SQLi error-probe (id=1'/0a discriminator), then M2 QA interleave per runbook.

## 2026-09-11 ~02:5x MT — MERCURY (.112) MILESTONE: USER FLAG + ROOT EXEC PROVEN
- CHAIN (all coursework-clean): Django DEBUG SQLi /mercuryfacts/<id>/ (param unquoted; expression eval proven 2-1=1) → union 1-col → information_schema (facts,users) → plaintext creds → SSH webmaster :22 (8.2p1 Ubuntu-4ubuntu0.1, hostname mercury — binding live-verified) → user_flag.txt → notes.txt b64 → linuxmaster → sudoers (root:root) SETENV: /usr/bin/check_syslog.sh → script runs `tail` bare → sudo -S PATH=/tmp hijack → uid=0.
- USER FLAG: [user_flag_8339915c9a454657bd60ee58776f4ccd] (/home/webmaster/user_flag.txt)
- ROOT EXEC PROVEN: /tmp/pwned.txt = "uid=0(root) gid=0(root)"; /root listing captured (root_flag.txt 1228B, .mysql_history present).
- KEY TECHNIQUE: sudo SETENV tag → command-line `PATH=/tmp` assignment OVERRIDES secure_path stomp (explicit per-invocation env wins; first shot w/o -S also failed: terminal required). check_syslog.sh = `tail -n 10 /var/log/syslog` (39B root:root 755, bare command).
- ROOT FLAG PENDING: read blocked by (a) sudoers whitelist (only check_syslog.sh — sudo cat/tail denied), (b) sshd channel-open timeouts after rapid paramiko connect flood ("No existing session", "Timeout opening channel"). Next tick: known-good hijack shot, /tmp/tail copies flag to /tmp.
- LESSON: fresh paramiko connection PER COMMAND → sshd resource pressure; one connection + reused channel, pace shots.
- SECONDARY INTEL: Django SECRET_KEY + MySQL PASSWORD 8cSQK0HMJtNxaJwsKwgDwo (settings.py, in memory). linuxmaster pw from notes.txt b64: mercurymeandiameteris4880km. john/laura/sam = null decoys (user freebie; do NOT test SSH).
- ARTIFACTS ON BOX: /tmp/tail (hijack script), /tmp/pwned.txt, /tmp/pwned2.txt, /tmp/sudo_err.txt — cleanup on user call (root shell would restore /tmp/tail; trivial).

## 2026-09-11 ~03:0x MT — MERCURY (.112) COMPLETE: ROOT FLAG CAPTURED
- Poll: 888c82f7 done, baseline reconfirmed (21/tcp tcpwrapped open; 1098/4444/6199/6200/6201/10000 closed). No pending nmap jobs; 987a3538/36ab9850 already folded per prior ticks.
- Shot: single connection + single channel (OP lesson applied — no per-command reconnects), /tmp/tail overwritten to `cat /root/root_flag.txt > /tmp/pwned3.txt`, fired `sudo -S PATH=/tmp:/usr/bin:/bin /usr/bin/check_syslog.sh` as linuxmaster, read side-effect file. CLEAN FIRST TRY after prior tick's channel-open-timeout flood — pacing fix confirmed as the unlock.
- ROOT FLAG: [root_flag_69426d9fda579afbffd9c2d47ca31d90] (1228B file = flag + ASCII banner "Congratulations on completing Mercury!!!", SirFlash@protonmail.com).
- MERCURY STATUS: FULLY DONE (user_flag_8339915c9a454657bd60ee58776f4ccd + root exec + root flag). Chain end-to-end coursework-clean: DEBUG SQLi → union → info_schema → plaintext creds → SSH → notes b64 → sudo SETENV PATH hijack.
- Artifacts on box: /tmp/tail STILL HIJACKED (59B; original = `tail -n 10 /var/log/syslog`, 39B root:root 755 — restore trivial under root shell); /tmp/pwned3.txt. Cleanup on user call. Paramiko __del__ AttributeError post-close = cosmetic.
- OPEN FRONTS: (1) Earth .115 LPE enum PARKED awaiting user decision (Dirty Pipe last-resort ruling unchanged); (2) .114 Evil Box One — web exhausted, SSH timing enum null; next = hydra top-shortlists vs themed user candidates (coursework-covered) or park; (3) M2 QA interleave runbook: re-fire GLM wrong invocation → guards + no-compat-reject → 6200 rescan vs 888c82f7 baseline → no-payload dispatch test.
NEXT: user call on front priority; M2 QA runbook is self-contained if no preference.

## 2026-09-11 ~21:26 MT — Wind-down: findings DB populated + rendered (Kai)
- report_finding x6 → F-018..F-023: F-020 P1 SQLi /mercuryfacts (CWE-89), F-022 P1 sudo SETENV PATH hijack (CWE-427), F-023 P1 Earth admin RCE key-as-cred (CWE-78), F-019 P3 plaintext creds (CWE-256), F-018 P3 vsftpd 2.3.4 unfired (CWE-121), F-021 P4 evil.php black hole.
- render_findings → 23 findings (20 open/3 closed) → findings_md/findings_20260911_032600.md (prod).
- DB housekeeping candidates flagged for user: F-011 duplicate of F-009; F-001/F-002/F-003 stale .110 addresses (M2 moved to .116); F-005 Apache 2.4.38 CVE finding predates binding swap; F-017 self-test already closed.
- Hourly cron 349f1d5c canceled at wind-down (lab concluded: Mercury COMPLETE, Earth parked w/ user flag, M2 in-case, Evil Box One survivor).
- 2026-09-11 ~19:35 MT | amass keyed falsifier #3 beff364c (subdomain_enum mona.co, default root config w/ 6 keys: zoomeye/virustotal/urlscan/shodan-free/publicwww/netlas) post-reset | prior: 968137b1 honest-zero (surzal config, no keys visible to root), cfd4645e -config surzal probe (worthless by design, reaped by reset). Success signature = minutes-long run vs 25s fail-fast. Ground truth: 13 alive names (crt.sh). crt.sh degraded service-side tonight (404@17.6s / silent-timeout on sandbox probes).
