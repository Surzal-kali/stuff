# TODO — Framework Next Steps (Sept 8, 2026)

> After adding ANY new tool: re-run bootstrap/reindex so the registry embeds it —
> undiscovered tools are invisible to the secretary (see memory_tools lesson).

## Phase 0 — Hygiene / carryover
- [x] Doc drift sweep: README/AGENTS still say gemma4:12b (5 spots); tests/ referenced
      but absent; AGENTS.md architecture section still describes core.py monolith
- [x] E2E runner turns 13/14: assert memory tools are REGISTERED before run; make any
      skipped turn fail loudly (no false greens)
- [ ] Verify trivial cruft from 81b5738 review is gone (unused target_root in
      registry.discover_local_tools, unused imports, stale comments) — deferred
      (unused imports kept for expansion)

## Phase 1 — Finding envelope ("report card") — the output contract
- [x] `Finding` model in daharness/models.py:
      { id, title, severity: P1..P4, cwe, asset,
        evidence: {request, response, excerpt},
        repro: [], tool_chain: [], memory_ref, ts }
- [x] `report_finding` @framework_tool — terminal action for any chain;
      writes to a findings store (SQLite ids.db) + remember_text (one-line pointer,
      not full payload — keeps model context clean)
- [x] findings → markdown renderer as `render_findings` @framework_tool — doubles as
      bug-bounty submission draft and lab documentation from the same source of truth;
      callable mid-session for progress review
- [x] Add `next: list[str]` to ToolManifest (next-action hints); populate for
      existing tools, e.g.:
        - secretsdump  -> "psexec_exec with -hashes :<NTLM>"
        - zap_alerts   -> "report_finding"
        - searchsploiting -> metasploiting
- [ ] Acceptance: e2e runner ends every chain with ≥1 Finding; renderer output
      saved as an e2e artifact

## Phase 2 — Subdomain & content recon (bounty surface)
- [x] amass wrapper (subprocess + flag allowlist, pattern = nmap.py);
      passive-first (passive is default in amass v5; `-passive` flag deprecated)
- [x] `subdomain_enum(target)` composite -> {subdomains[], alive[], out_of_scope[]}
      — scope check enforced INSIDE the tool (.scope file in workspace root;
      lab mode = no scope file = everything in scope)
- [ ] subfinder as optional secondary wrapper (deferred; amass covers v1 + brute + alts)
- [ ] Content discovery v1: wordlist-driven path fuzz reusing repeater ergonomics,
      pointed at a scope-gated real target (not the echo server)
- [x] Next hints: subdomain_enum -> "nmap -iL <alive>" -> "zap_open_url"
- [ ] Acceptance: "map *.example.com, fuzz the blog, flag IDOR-looking params"
      runs with zero code changes

## Phase 3 — Collaborator analog
- [x] Multi-protocol listener in listeners/collaborator.py:
        - HTTP on 80
        - HTTPS on 443
        - DNS on UDP 53: answer all queries with fixed IP, LOG FULL QNAME
          (payload ID rides in the subdomain — the qname IS the signal)
- [x] Register listener as typed handle in utils/handles.py — "collab" kind
      added to VALID_KINDS; orchestrator owns it like MSF/listener sessions
- [x] `collab_generate()` -> {id, url, dns_name}
- [x] `collab_poll(since)` -> [{proto, src_ip, qname, path, host, user_agent, ts, excerpt}]
- [x] Lab DNS: built-in DNS listener on port 53 IS the resolver for *.oob.lab
      (no dnsmasq needed); real-world OOB = one delegated NS record (config, not code)
- [ ] Acceptance: blind SSRF/XSS lab test — inject collab URL, trigger, poll
      shows the callback with matching qname ID

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

## Bug bounty mode (after Phases 1–3)
- [ ] Scope gate at dispatch: paste program policy -> structured scope data;
      EXECUTOR-level assert(target ∈ scope) before any tool fires (trust the
      executor, not the description)
- [ ] Profile filtering: bounty profile (nmap, subfinder, ZAP, repeater, memory,
      report) vs lab profile (everything) — registry never surfaces lab tools
      in bounty mode
- [ ] Map Finding severity to per-program severity scales
