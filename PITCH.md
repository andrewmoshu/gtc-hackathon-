# CodeSentinel — Elevator Pitch

> **Not a scanner. A researcher.**

---

## The Problem

Security audits take **weeks** and cost **$50K+**. Existing automated scanners run checklists — they catch the obvious stuff but miss the vulnerabilities that actually get exploited. Real security research requires a human who reads the code, traces data flows, looks up CVE databases, and thinks like an attacker.

---

## The Solution

**CodeSentinel** is an autonomous AI security researcher for code repositories.

Paste a GitHub URL. In under 2 minutes, 4 parallel AI agents investigate your entire codebase — not running a checklist, but **actively researching**: reading files, grepping for patterns, querying CVE databases, tracing user input to dangerous sinks.

You watch it work in real-time.

---

## How It Works

```
1. CLONE       → Shallow-clone the repo
2. SCAN        → Deterministic scanners find secrets + known CVEs (zero hallucination)
3. INVESTIGATE → 4 parallel AI hunters autonomously research the code:
                  - Injection specialist (SQLi, XSS, command injection)
                  - Auth & access control specialist
                  - Web security specialist (CSRF, SSRF, path traversal)
                  - Config & crypto specialist
4. VERIFY      → Verifier agent filters false positives
5. PATCH       → Patcher agent generates fixes
```

Each hunter has **full shell access** to the repo and runs commands autonomously — `grep`, `cat`, `find` — just like a human researcher. Every tool call streams live to the dashboard.

---

## What Makes This Different

| Traditional Scanners | CodeSentinel |
|---|---|
| Run a fixed checklist | Investigates like a human researcher |
| Pattern matching only | Traces data flows across files |
| No reasoning about context | Understands framework protections |
| One pass, done | Follows investigation threads dynamically |
| Static report at the end | Live investigation feed — watch it think |

---

## Tech Stack

- **AI**: NVIDIA Nemotron Super (120B) — 1M token context holds the entire repo
- **Backend**: FastAPI + SSE streaming
- **Frontend**: React + Tailwind — terminal-style "war room" dashboard
- **Tools**: CWE database, OSV.dev CVE API, web search, shell access
- **Architecture**: Multi-agent orchestration with parallel execution

---

## Live Demo Highlights

1. **Instant results** — Secret scanner + CVE checker fire in parallel, findings appear in seconds
2. **Watch the AI work** — Investigation feed shows every command, every database query, every reasoning step in real-time
3. **4 agents, simultaneously** — Each focused on a different attack class, all investigating in parallel
4. **Click any finding** — See the vulnerable code, the explanation, the data flow trace, and the auto-generated patch
5. **Attack graph** — Visual map of how vulnerabilities connect across the codebase

---

## By The Numbers

- **4** parallel AI investigators
- **6** scanning layers (2 deterministic + 4 AI)
- **< 2 min** for a full security audit
- **$0** vs $50K+ for a manual audit

---

## The Wow Moment

> The audience watches an AI read code, run shell commands, query vulnerability databases, and report findings — all streaming live. It's not generating text. It's **investigating**.

---

## Team

GTC 2026 Vibe Hack | Built with NVIDIA Nemotron Super

*"Security audits take weeks and cost $50K+. We didn't build a scanner — we built an autonomous security researcher."*
