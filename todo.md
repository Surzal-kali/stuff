# TODO — Framework Next Steps (updated Sept 15, 2026)

> After adding ANY new tool: re-run bootstrap/reindex so the registry embeds it —
> undiscovered tools are invisible to the secretary (see memory_tools lesson).
>
> Cleanup Sept 15: completed phase items and the landed T-001..T-004 tickets
> (all four landed in 0529b4c, verified) removed. Open acceptance criteria and
> genuinely unfinished work retained below.

## Open acceptance criteria (from landed phases)
- [ ] e2e runner ends every chain with ≥1 Finding; render_findings output saved
      as an e2e artifact (Phase 1 acceptance)
- [ ] Blind SSRF/XSS lab test for collaborator: inject collab URL, trigger,
      collab_poll shows the callback with matching qname ID (Phase 3 acceptance)

## Recon leftovers
- [ ] subfinder as optional secondary wrapper (deferred; amass covers v1 + brute
      + alts — revisit only if a real gap appears)
- [ ] Profile filtering: bounty profile (nmap, subfinder, ZAP, repeater, memory,
      report) vs lab profile (everything) — verify whether registry already does
      this before building
- [ ] Map Finding severity to per-program severity scales (H1 ranges, Intigriti
      CVSS 0.1-10, Adobe Tier 1-3) for render_findings drafts

## Browser & JS surface (bug bounty + career lane)
- [ ] **static JS route extractor** (BUILD FIRST — cheap 80%, no browser):
      fetch .js bundles + regex endpoints/API routes (linkfinder-style),
      ~50-line auxiliary, zero heavy deps, sandbox-workable today.
- [ ] **playwright integration** (desktop/framework host ONLY — phone sandbox is
      permanently out: Sept 13 install got the app killed; standing rule).
      Lane = framework tools (like amass/nmap), NOT deny-all secretary
      containers — browser needs egress. Tools: playwright_fetch (one-shot
      rendered-DOM envelope: final URL, status, title, text, links, forms,
      JS-discovered routes) + playwright_crawl (launch/poll pair, nmap.py
      pattern: bounded pages/depth/time). Auth'd crawling via persisted
      storageState; login secrets env/deploy-time injection ONLY. Scope gate at
      dispatch non-negotiable — browser fires real traffic. Envelope carries
      "challenge_detected" (Cloudflare-class walls: expect partial success,
      never fake it). STEALTH PATCHES = ARMS RACE — skip; stay vanilla + honest
      negatives. Use case: JS-heavy bounty surfaces (SPA recon, auth'd crawling,
      bugbounty-arsenal.net), UNMJobs/Workday-class form flows (career lane).

## Phase 4 — Credential motion (lab chain)
- [ ] Responder analog v1: CAPTURE-ONLY LLMNR/NBT-NS poisoner in listeners/plugins;
      captured NTLMv2 -> remember_text (poisoning = Network+/CEH territory)
- [ ] GPP cpassword tool: smb_read_file Groups.xml + decrypt cpassword (published
      AES key); hint chain: smb_scanner null session -> gpp_cpassword
- [ ] samrdump / lookupsid wrappers (SAMR/SID enum) feeding target lists
- [ ] Next hints: document the pass-the-hash flow in descriptions:
      secretsdump -hashes :<NTLM> -> psexec_exec
- [ ] Acceptance: poison -> capture -> secretsdump -hashes -> psexec_exec,
      fully secretary-driven

## Parked — do NOT implement until covered in coursework
- [ ] GetNPUsers (AS-REP roast) — parked Sept 8
- [ ] GetUserSPNs (Kerberoast) — parked Sept 8
- [ ] ntlmrelayx (relay) — may be ahead of coverage; revisit with coursework
- [ ] dpapi (blob decryption) — post-exploit crypto, likely ahead

## Backlog / big rocks
- [ ] radare2 composite wrapper: r2 subprocess, command allowlist
      (aaa, afl, pdf, iz, axt...), r2ghidra for decompile — THE big work-up
- [ ] SET integration
- [ ] Vector search over sanitized module descriptions (Qdrant or 2nd ChromaDB
      collection) — the scaling lever for thousands of modules
- [ ] MCP layer (radare2/Burp/Ghidra): one gateway tool per server, curated
      subsets only — no wholesale registration
