# PRD: CodeSentinel — Multi-Agent Codebase Security Auditor

**GTC 2026 Vibe Hack | Thursday, March 19 | Team of 2–3**
**Model: NVIDIA Nemotron 3 Super (120B/12B active) via build.nvidia.com API**

---

## 1. One-Liner

A multi-layered security auditor that combines deterministic scanning (secrets detection, CVE database cross-referencing via OSV.dev) with Nemotron Super's 1M-token context window for deep code-level vulnerability discovery — visualized as a live attack surface graph with auto-generated patches.

---

## 2. Why This Wins

| Judging Criteria | How We Nail It |
|---|---|
| **Technical depth** | Multi-agent orchestration with tool-equipped autonomous Hunter agent — not a checklist, a researcher |
| **Nemotron Super showcase** | 1M context window (full repo ingestion), tool use (CWE/OSV/web search), thinking mode for deep reasoning |
| **Live demo impact** | Audience watches an AI security researcher actively investigate: querying databases, searching for exploits, tracing data flows — then the attack graph lights up |
| **Real-world value** | Security auditing is a $10B+ market; this is a credible product concept |
| **Novelty** | Nobody else will show an LLM autonomously researching vulnerabilities with tools — everyone else will do prompt-and-summarize |

---

## 3. How It Works

### 3.1 User Flow

```
1. User pastes a GitHub repo URL (or picks from suggestions)
2. System clones repo, flattens into a single context payload
3. Deterministic layers fire immediately (in parallel):
   - Secret scanner: regex-based credential detection
   - Dependency scanner: OSV.dev API cross-reference
   → First findings appear on dashboard within seconds
4. Orchestrator dispatches LLM agents (sequential):
   - Recon agent maps attack surface
   - Hunter agent begins autonomous investigation:
     → Uses tools freely (CWE lookup, OSV query, web search)
     → Each tool call streams to dashboard in real-time
     → Investigates as many threads as needed, no artificial limit
   - Patcher agent generates fixes for ALL finding types
5. Dashboard shows everything in real-time:
   - File tree with risk coloring
   - Attack surface graph (nodes light up red as vulns found)
   - Agent investigation feed (tool calls, reasoning, findings)
   - Vulnerability cards grouped by source (secret/CVE/code/config)
6. User clicks a vulnerability → code, explanation, severity, patch,
   AND the agent's full investigation trail (tool calls + reasoning)
7. Export: download security report (markdown or JSON)
```

### 3.2 Scanning Layers: Deterministic + AI

CodeSentinel uses a layered approach. The first two layers are deterministic (no LLM, no hallucination risk) and provide a guaranteed safety net of real findings. The remaining layers use Nemotron Super for deep reasoning — the impressive part.

```
LAYER 1 — SECRET SCANNER (deterministic, regex-based)
  ↓ Runs instantly, always finds something in real repos
LAYER 2 — DEPENDENCY CVE CHECK (deterministic, OSV.dev API)
  ↓ Cross-references exact package versions against known CVEs
LAYER 3 — RECON AGENT (Nemotron, 1M context)
  ↓ Maps attack surface, entry points, data flows
LAYER 4 — HUNTER AGENT (Nemotron, thinking ON, TOOL-EQUIPPED)
  ↓ Autonomous security researcher with tools: CWE lookup,
  ↓ OSV query, web search. Investigates as deep as it needs to.
  ↓ No hardcoded checklist — the agent decides what to look for.
LAYER 5 — PATCHER AGENT (Nemotron, thinking mode ON)
  ↓ Generates fixes for all findings across all layers
LAYER 6 — VERIFIER AGENT (Nemotron, stretch goal)
  ↓ Double-checks patches for correctness
```

### 3.3 Agent & Scanner Details

#### Layer 1: Secret Scanner (No LLM — Regex)
- **Input:** All files in repo
- **Output:** List of exposed secrets with file path and line number
- **How it works:** Regex patterns matching known secret formats. No API calls, no LLM, runs in <1 second.
- **Patterns to detect:**
  - AWS keys (`AKIA[0-9A-Z]{16}`)
  - Generic API keys/tokens (`api_key`, `secret`, `token`, `password` in config/env files)
  - Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
  - Database connection strings with embedded credentials
  - JWT secrets, Stripe keys, GitHub tokens, Slack webhooks
  - `.env` files committed to repo
  - Hardcoded passwords in source code
- **Why this matters:** Always finds something. Demo-friendly ("found your AWS key on line 42"). Zero hallucination risk. Gives the audience a visceral reaction.

#### Layer 2: Dependency CVE Scanner (No LLM — OSV.dev API)
- **Input:** Package manifests (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `Gemfile.lock`)
- **Output:** Known CVEs for each vulnerable dependency, with severity and advisory links
- **How it works:** Extract dependency names and pinned versions, query OSV.dev API:
  ```
  POST https://api.osv.dev/v1/query
  {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}
  ```
  No auth needed. Free. Returns CVE IDs, severity scores, affected version ranges, and fix versions.
- **Output per finding:**
  ```json
  {
    "source": "osv",
    "package": "lodash",
    "installed_version": "4.17.20",
    "cve_id": "CVE-2021-23337",
    "severity": "HIGH",
    "title": "Prototype Pollution in lodash",
    "fix_version": "4.17.21",
    "advisory_url": "https://osv.dev/vulnerability/..."
  }
  ```
- **Why this matters:** Verifiable, credible, nobody can question these findings. Links back to real CVE databases. The Patcher agent can recommend version bumps.

#### Layer 3: Recon Agent (Nemotron Super)
- **Input:** Full repo contents (files, directory structure, dependency manifests)
- **Output:** Structured attack surface map
- **Tasks:**
  - Identify entry points (API routes, CLI handlers, form processors)
  - Map data flows (user input → processing → storage/output)
  - Classify files by risk tier (auth, crypto, input handling, config, etc.)
  - Detect Dockerfile / docker-compose / IaC misconfigurations (running as root, exposed ports, secrets in build args, privileged containers, permissive CORS)
- **Nemotron feature used:** 1M context to hold the entire repo + reasoning about cross-file relationships

#### Layer 4: Hunter Agent (Nemotron Super, Thinking ON, Tool-Equipped)

This is the star of the show. The Hunter is not a checklist runner — it's an **autonomous security researcher** with tools it can call whenever it needs more information. It decides what to investigate, how deep to go, and when it's done.

- **Input:** Attack surface map from Recon + full repo context
- **Output:** List of code-level vulnerabilities with evidence, CWE classifications, and external references
- **Mental framework:** The agent's system prompt gives it broad security knowledge (OWASP awareness, common vulnerability patterns) as starting intuition, but it is NOT limited to any checklist. It follows its own investigation threads.
- **Nemotron features used:** Thinking mode ON for deep reasoning, native tool use for autonomous investigation

##### Hunter Agent Tools

The Hunter agent has access to the following tools and can call them as many times as it needs:

**Tool 1: `cwe_lookup`**
Query the MITRE CWE database (933+ weakness types) to classify and enrich findings.
```json
{
  "name": "cwe_lookup",
  "description": "Search the MITRE Common Weakness Enumeration database. Use this when you identify a suspicious code pattern and want to classify it properly, find related weaknesses, or understand the full attack surface of a weakness type.",
  "parameters": {
    "query": "string — search term (e.g., 'SQL injection', 'race condition', 'deserialization')",
    "cwe_id": "string (optional) — specific CWE ID for direct lookup (e.g., 'CWE-89')"
  },
  "returns": {
    "cwe_id": "CWE-89",
    "name": "Improper Neutralization of Special Elements used in an SQL Command",
    "description": "...",
    "severity": "HIGH",
    "common_consequences": ["..."],
    "detection_methods": ["..."],
    "mitigations": ["..."],
    "related_cwes": ["CWE-564", "CWE-943"],
    "real_world_examples": ["CVE-2024-XXXX"]
  }
}
```
**Implementation:** Pre-download the CWE XML/JSON corpus from MITRE (it's ~5MB) and serve it locally. No external API call needed at runtime — instant responses. The agent can browse the full taxonomy, follow `related_cwes` chains, and discover weakness patterns it wasn't explicitly looking for.

**Tool 2: `osv_query`**
Query the OSV.dev vulnerability database for specific packages, even ones not in manifests.
```json
{
  "name": "osv_query",
  "description": "Query the Open Source Vulnerability database for known CVEs affecting a specific package and version. Use this when you see a dependency imported in code, a vendored library, or want to check if a specific version of a framework has known issues.",
  "parameters": {
    "package_name": "string",
    "ecosystem": "string — npm|PyPI|Go|crates.io|Maven|RubyGems|NuGet",
    "version": "string (optional) — specific version to check"
  },
  "returns": {
    "vulnerabilities": [
      {
        "id": "CVE-2021-23337",
        "summary": "...",
        "severity": "HIGH",
        "affected_versions": "< 4.17.21",
        "fixed_version": "4.17.21",
        "references": ["https://..."]
      }
    ]
  }
}
```
**Implementation:** Direct HTTP call to `https://api.osv.dev/v1/query`. Free, no auth. This lets the Hunter go beyond manifest scanning — it can spot a `require('lodash')` in code, check what version is actually installed, and query OSV for it. It can also investigate vendored/copy-pasted libraries that don't appear in package manifests.

**Tool 3: `web_search`**
Search the web for recent vulnerability disclosures, exploit techniques, and security advisories.
```json
{
  "name": "web_search",
  "description": "Search the web for security-related information. Use this when you want to check for recent vulnerability disclosures for a specific framework or library, find known exploit techniques for a pattern you've identified, look up security best practices for a specific technology, or check if a code pattern has been flagged in security advisories.",
  "parameters": {
    "query": "string — search query (e.g., 'Flask session fixation vulnerability 2025', 'Django CSRF bypass recent')"
  },
  "returns": {
    "results": [
      {
        "title": "...",
        "url": "https://...",
        "snippet": "..."
      }
    ]
  }
}
```
**Implementation:** Use Nemotron Super's built-in web search tool support via the API. This is the most powerful tool — it lets the agent research things it doesn't know about. If it sees an unusual framework or a custom auth pattern, it can look up whether similar patterns have been exploited in the wild.

**Tool 4: `get_file_content`**
Retrieve specific file contents from the repo when the agent needs to examine something more closely.
```json
{
  "name": "get_file_content",
  "description": "Get the full content of a specific file from the repository. Use this when the initial context was truncated or you need to re-examine a specific file in detail.",
  "parameters": {
    "file_path": "string — path relative to repo root"
  },
  "returns": {
    "content": "string — full file content",
    "language": "string — detected language",
    "line_count": "number"
  }
}
```
**Implementation:** Simple file read from the cloned repo. Useful if the flattened context was truncated for very large repos — the agent can pull in specific files it wants to examine more closely.

##### How the Hunter Agent Works (Agentic Loop)

The Hunter does NOT follow a fixed sequence. It runs in an autonomous loop:

```
1. OBSERVE: Read the attack surface map + codebase context
2. HYPOTHESIZE: "Based on the entry points and data flows, I suspect
   there may be injection vulnerabilities in the auth module and
   potential SSRF in the webhook handler."
3. INVESTIGATE: Call tools as needed:
   - cwe_lookup("injection") → learns about CWE-89, CWE-78, CWE-917
   - Follows related CWEs → discovers CWE-564 (Hibernate injection)
     which is relevant because the codebase uses an ORM
   - web_search("Express.js prototype pollution 2025") → finds recent advisory
   - osv_query("express", "npm", "4.17.1") → confirms known CVE
4. ANALYZE: Trace data flows through the code using chain-of-thought reasoning
5. REPORT: Emit each confirmed vulnerability as a structured finding
6. CONTINUE: "Are there more areas to investigate?" → if yes, go to step 2
7. DONE: "I have exhaustively analyzed the high-risk areas. Here are my findings."
```

The agent calls tools as many times as it needs. There is no artificial limit on tool calls. The agent decides when it has investigated thoroughly enough.

Each tool call and its result are streamed to the frontend in real-time, so the audience sees the agent actively researching — looking up CWEs, querying CVE databases, searching for recent exploits. This is the "wow" moment: it looks like watching a security researcher work, not watching a model generate text.

##### Hunter Agent Output Schema

For each vulnerability, the agent produces:
```json
{
  "id": "VULN-001",
  "title": "SQL Injection in user authentication",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cwe_id": "CWE-89",
  "cwe_name": "SQL Injection",
  "file": "path/to/file.py",
  "line_start": 42,
  "line_end": 47,
  "description": "Plain English explanation",
  "evidence": "The specific code pattern",
  "data_flow_trace": "request.form['email'] → validate_user(email) → db.execute(f'SELECT * FROM users WHERE email={email}')",
  "exploitation_scenario": "How an attacker could exploit this",
  "tool_references": [
    {"tool": "cwe_lookup", "result": "CWE-89 confirmed: improper neutralization of SQL elements"},
    {"tool": "web_search", "result": "Similar pattern exploited in CVE-2024-XXXX"},
    {"tool": "osv_query", "result": "Framework version has no patch for this pattern"}
  ],
  "confidence": "HIGH|MEDIUM|LOW"
}
```

The `tool_references` field is key — it shows the agent's research trail, making each finding more credible and traceable. During the demo, clicking a vulnerability card shows not just the code and the fix, but the agent's entire investigation chain.

#### Layer 5: Patcher Agent (Nemotron Super, Thinking ON)
- **Input:** All findings from Layers 1–4 + relevant code context
- **Output:** Fixes for each finding type:
  - **Secrets:** `.gitignore` additions + environment variable refactor
  - **Dependency CVEs:** Version bump commands (`npm install lodash@4.17.21`)
  - **Code vulns:** Git-style code patches with explanation
  - **Config issues:** Fixed Dockerfile / config file snippets
- **Tasks:**
  - Generate minimal, correct patches
  - Explain what each fix does and why
  - Flag if a fix might break existing functionality
- **Nemotron feature used:** Thinking mode ON for reasoning about patch correctness

#### Layer 6 (Stretch): Verifier Agent
- **Input:** Original code + proposed patch
- **Output:** Confidence score + potential issues with the patch
- **Tasks:**
  - Check if the patch introduces new issues
  - Verify the patch actually addresses the vulnerability
  - Score confidence (High / Medium / Low)
- **Purpose:** Prevents embarrassing hallucinated fixes during live demo

#### Stretch: License Risk Scanner (No LLM)
- **Input:** Dependency list from manifests
- **Output:** License compatibility warnings
- **How it works:** Check package registry APIs (npmjs.com, PyPI) for license metadata. Flag GPL dependencies in MIT/Apache projects, or any copyleft in proprietary codebases.
- **Why include:** Adds a "business value" angle judges appreciate. Trivial to implement if time permits.

### 3.4 Context Window Strategy

The 1M token window is the key differentiator. Strategy:

```
Token Budget (~1M tokens):
├── System prompt + agent instructions:     ~2K tokens
├── Full repository contents:              ~500-800K tokens
│   ├── Source code files (flattened)
│   ├── Package manifests (package.json, requirements.txt, etc.)
│   ├── Configuration files
│   └── README / docs (for understanding intent)
├── Attack surface map (from Recon):        ~5-10K tokens
├── Accumulated findings:                   ~10-20K tokens
└── Reasoning headroom:                     ~remaining
```

**Repo selection criteria for demo:** Target repos between 200-800 source files (~300-600K tokens). Sweet spot is a mid-size web application with known issues.

**Flattening strategy:**
```
For each file in repo:
  output: "=== FILE: {path} ===\n{contents}\n"
```
Skip: binary files, node_modules, vendor dirs, build artifacts, images, test fixtures.

---

## 4. Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **LLM** | Nemotron 3 Super via build.nvidia.com API | Required by hackathon; 1M context is the key feature |
| **Backend** | Python (FastAPI) | Fast to prototype, async for parallel agent calls |
| **Frontend** | React + Tailwind | Clean dashboard, quick to build |
| **Graph Viz** | D3.js or vis.js | Interactive attack surface graph |
| **Repo Ingestion** | GitHub API + gitpython | Clone and flatten repos |
| **Streaming** | Server-Sent Events (SSE) | Real-time agent output to frontend |
| **CVE Database** | OSV.dev API (free, no auth) | Deterministic dependency vulnerability scanning |
| **Secret Scanning** | Custom regex engine (Python `re`) | Deterministic secret/credential detection |

---

## 5. Frontend: The "War Room" Dashboard

### Layout

```
┌──────────────────────────────────────────────────────┐
│  CodeSentinel          [repo-url-input]    [SCAN]     │
├────────────┬─────────────────────┬───────────────────┤
│            │                     │                   │
│  FILE TREE │   ATTACK SURFACE    │  INVESTIGATION FEED  │
│            │      GRAPH          │                      │
│  (left     │                     │  Live tool calls     │
│   panel)   │  Interactive nodes  │  + agent reasoning:  │
│            │  = files/endpoints  │                      │
│  Color by  │  Edges = data flow  │  🔍 cwe_lookup(      │
│  risk tier │  Red pulse = vuln   │    "SQL injection")  │
│            │  found              │  → CWE-89 confirmed  │
│            │                     │                      │
│            │  Click node →       │  🌐 web_search(      │
│            │  detail panel       │    "Express 4.17     │
│            │                     │     advisory 2025")  │
│            │                     │  → Found CVE-...     │
│            │                     │                      │
│            │                     │  📦 osv_query(       │
│            │                     │    "jsonwebtoken")   │
│            │                     │  → CVE-2022-23529   │
├────────────┴─────────────────────┴───────────────────┤
│  VULNERABILITY CARDS (grouped by source)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │🔑 SECRET │ │📦 CVE    │ │🐛 CODE   │ │🐳 CONFIG │   │
│  │ AWS key  │ │ lodash   │ │ SQL Inj. │ │ root usr │   │
│  │ .env:3   │ │ 4.17.20  │ │ auth.py  │ │ Docker.. │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└──────────────────────────────────────────────────────┘
```

### Key Visual Elements

- **Attack graph animation:** Nodes appear one by one as Recon discovers them. When Hunter finds a vulnerability, the corresponding node pulses red with a ripple effect. This is the "wow" moment.
- **Investigation feed:** The star of the show. Shows the Hunter agent's tool calls and reasoning in real-time — each `cwe_lookup`, `osv_query`, and `web_search` appears as a card with the query, the result, and the agent's interpretation. It looks like watching a security researcher work. Color-code by tool type (blue for CWE, orange for OSV, green for web search, white for reasoning).
- **Vulnerability cards:** Click to expand — shows the vulnerable code snippet (syntax highlighted), explanation in plain English, severity badge, the generated patch as a diff view, AND the investigation trail (which tool calls led to this finding).

---

## 6. Demo Script (2 minutes)

> **"Security audits take weeks and cost $50K+. We didn't build a scanner — we built an autonomous security researcher."**

1. **(0:00)** Open dashboard. Ask audience for a repo or use pre-selected one.
2. **(0:10)** Paste URL, hit SCAN. Repo ingestion animation plays.
3. **(0:20)** Instant deterministic results — secret scanner finds a hardcoded API key, dependency scanner pulls 3 known CVEs from OSV. "These are deterministic — zero hallucination."
4. **(0:35)** Recon agent maps the attack surface. Graph builds on screen.
5. **(0:45)** Hunter agent activates. **This is where it gets interesting.** The agent feed shows it thinking: "I see raw SQL construction in auth.py. Let me investigate."
6. **(0:55)** Tool call streams to screen: `cwe_lookup("SQL injection")` → returns CWE-89 with related weaknesses. Agent follows the chain: `cwe_lookup("CWE-564")` → discovers Hibernate-specific injection pattern relevant to the ORM used.
7. **(1:10)** Another tool call: `web_search("Express.js 4.17 security advisory 2025")` → agent finds a recent advisory and cross-references it with the code. Red pulse on the graph.
8. **(1:20)** Agent calls `osv_query("jsonwebtoken", "npm", "8.5.1")` — finds a known CVE the manifest scanner missed because it was a transitive dependency. "It's not just following a checklist — it's investigating."
9. **(1:35)** Click a vulnerability card. Show the code, the patch, AND the investigation trail: "The agent made 4 tool calls to confirm this finding. Here's its research chain."
10. **(1:50)** Show the numbers: "12 findings — 2 secrets, 3 dependency CVEs, 7 code-level vulns discovered autonomously. The Hunter made 23 tool calls across CWE, OSV, and web search. Total time: 94 seconds."
11. **(2:00)** Close: "This isn't a scanner. It's an AI that investigates like a human researcher — but it holds your entire codebase in memory and never gets tired."

---

## 7. Pre-Selected Demo Repos

Have these tested and ready. Fall back to these if audience suggestions don't work:

| Repo | Why | Expected Findings |
|---|---|---|
| **OWASP WebGoat** | Deliberately vulnerable Java app | Injection, XSS, auth bypass — guaranteed hits |
| **Juice Shop** | Deliberately vulnerable Node.js app | Well-known vulns, great for demo |
| **A real mid-size Flask/Django app** | Shows it works on non-toy code | Realistic findings, more impressive |

**Critical:** Test all three the night before. Know exactly what the system finds so you can narrate confidently during demo.

---

## 8. Team Split (4 hours)

### Andrii — Backend & Agent Orchestration
**Hour 1:**
- Set up FastAPI server with SSE streaming endpoint
- Implement repo cloning + flattening pipeline
- Implement Layer 1: Secret scanner (regex patterns for AWS, GCP, Stripe, JWT, generic secrets)
- Test Nemotron Super API connectivity, verify tool use support

**Hour 2:**
- Implement Layer 2: OSV.dev dependency scanner (parse manifests, query API, collect CVEs)
- Build the Hunter agent's tool infrastructure:
  - `cwe_lookup`: Download CWE corpus from MITRE, build local search index
  - `osv_query`: Thin wrapper around OSV.dev API
  - `web_search`: Wire up Nemotron's built-in web search tool
  - `get_file_content`: Simple file read from cloned repo
- Define tool schemas for Nemotron API's tool use format

**Hour 3:**
- Build Orchestrator logic (Layers 1+2 in parallel → Recon → Hunter → Patcher)
- Implement Recon agent prompt + structured JSON output parsing
- Implement Hunter agent agentic loop (tool dispatch, result collection, streaming)
- Implement Patcher agent prompt (handles all finding types: secrets, deps, code, config)
- Wire up SSE events: stream every tool call + result + reasoning to frontend

**Hour 4:**
- Integration testing with pre-selected repos
- Test Hunter agent tool use end-to-end — verify it calls tools autonomously
- Performance tuning (parallelize where possible)
- Bug fixes + demo rehearsal

### Teammate — Frontend Dashboard
**Hour 1:**
- Scaffold React app with Tailwind
- Build layout: file tree panel, graph panel, investigation feed panel, vuln cards
- Set up SSE client to receive backend events (tool calls, findings, agent status)

**Hour 2:**
- Implement attack surface graph with D3/vis.js
- Node appearance animation, edge drawing, color coding by risk tier
- Red pulse animation when vulnerability is found
- Implement investigation feed: real-time stream of tool calls with color-coded cards (blue=CWE, orange=OSV, green=web search, white=reasoning)

**Hour 3:**
- Implement vulnerability cards with expand/collapse
- Code snippet display with syntax highlighting (use Prism.js or Highlight.js)
- Diff view for patches (use react-diff-viewer or similar)
- Investigation trail view inside each vuln card (which tool calls led to finding)

**Hour 4:**
- Polish animations and transitions
- Responsive layout fixes
- Demo rehearsal

### Teammate 2 (if available) — Data Pipeline & Polish
**Hour 1-2:**
- GitHub API integration (handle rate limits, private repos if applicable)
- Smart file filtering (skip binaries, vendor, tests, etc.)
- Token counting to ensure we stay within 1M budget

**Hour 3-4:**
- Export functionality (markdown report generation)
- Error handling and graceful fallbacks
- Help with demo rehearsal and edge case testing

---

## 9. Agent Prompt Templates

### Recon Agent System Prompt (draft)
```
You are a security reconnaissance agent. You have been given the complete source code
of a software repository. Your job is to map the attack surface.

Analyze the codebase and produce a JSON response with:
{
  "entry_points": [
    {"file": "path", "line": N, "type": "api_route|form_handler|cli|websocket", "description": "..."}
  ],
  "data_flows": [
    {"source": "entry_point_id", "sink": "file:line", "data_type": "user_input|credential|pii", "transforms": ["..."]}
  ],
  "dependencies": [
    {"name": "pkg", "version": "x.y.z", "risk_notes": "..."}
  ],
  "risk_tiers": {
    "critical": ["file1.py", "file2.py"],
    "high": [...],
    "medium": [...],
    "low": [...]
  }
}

Focus on: authentication, authorization, input handling, database queries,
file operations, cryptographic operations, configuration/secrets management,
and external API calls.
```

### Hunter Agent System Prompt (draft)
```
You are an autonomous security researcher. You have the complete source code of a
software repository and an attack surface map from a reconnaissance agent.

Your mission: find every security vulnerability in this codebase. You are not limited
to any checklist. Investigate whatever you find suspicious. Follow every thread.

You have access to the following tools — use them as often as you need:

- cwe_lookup(query, cwe_id?): Search the MITRE CWE database (933+ weaknesses).
  Use this to classify findings, discover related weakness patterns, and find
  detection methods. Follow related_cwes chains to uncover adjacent risks.

- osv_query(package_name, ecosystem, version?): Query the OSV vulnerability database.
  Use this for ANY dependency you see in the code — not just what's in manifests.
  Check vendored libraries, copy-pasted code, framework versions.

- web_search(query): Search the web for recent security advisories, exploit techniques,
  and vulnerability disclosures. Use this when you see an unfamiliar pattern, a
  specific framework version, or want to check for recently discovered attacks.

- get_file_content(file_path): Re-read a specific file for closer examination.

INVESTIGATION APPROACH:
1. Review the attack surface map. Identify the highest-risk areas.
2. For each suspicious pattern, form a hypothesis and investigate:
   - Trace data flows from user input to dangerous operations
   - Look up the relevant CWE to understand the full attack surface
   - Search for known vulnerabilities in the specific frameworks/versions used
   - Check if similar patterns have been exploited in the wild
3. Only report vulnerabilities you have evidence for. No speculation.
4. Keep investigating until you are satisfied you've covered the high-risk areas.
5. There is no limit on how many tools you can call. Be thorough.

For each confirmed vulnerability, emit a structured finding with:
- id, title, severity (CRITICAL/HIGH/MEDIUM/LOW)
- cwe_id and cwe_name (from cwe_lookup)
- file, line_start, line_end
- description (plain English)
- evidence (the specific code pattern)
- data_flow_trace (source → transforms → sink)
- exploitation_scenario (how an attacker would exploit this)
- tool_references (list of tool calls and results that support this finding)
- confidence (HIGH/MEDIUM/LOW)

IMPORTANT:
- Consider context. Parameterized queries are NOT injection vulnerabilities.
- A framework's built-in CSRF protection means CSRF is likely handled — verify before flagging.
- Think step by step. Use your reasoning capabilities extensively.
- When in doubt, use a tool to verify before reporting.
```

### Patcher Agent System Prompt (draft)
```
You are a security patch generator. You receive findings from multiple scanning layers:
- Exposed secrets (hardcoded credentials, API keys, tokens)
- Dependency CVEs (with known fix versions)
- Code-level vulnerabilities (injection, XSS, auth bypass, etc.)
- Configuration issues (Dockerfile, IaC misconfigurations)

For each finding, generate the appropriate fix:

{
  "patches": [
    {
      "vuln_id": "VULN-001",
      "finding_source": "secret_scanner|osv_cve|code_analysis|config_audit",
      "file": "path/to/file.py",
      "fix_type": "code_patch|version_bump|config_change|gitignore_add",
      "original_code": "the vulnerable code block (if applicable)",
      "patched_code": "the fixed code block",
      "explanation": "What this fix does and why it addresses the vulnerability",
      "commands": ["npm install lodash@4.17.21"],  // if version bump
      "breaking_risk": "LOW|MEDIUM|HIGH",
      "breaking_notes": "If medium/high, explain what might break"
    }
  ]
}

FIX STRATEGIES BY TYPE:
- Secrets: Move to environment variables, add to .gitignore, show .env.example pattern
- Dependency CVEs: Recommend exact safe version, provide install command
- Code vulns: Minimal code patch using established security patterns
- Config issues: Fixed config snippet (e.g., non-root Dockerfile USER directive)

RULES:
- Minimal changes only. Don't refactor unrelated code.
- The patch must be syntactically valid in the target language.
- Prefer well-established security patterns (parameterized queries, CSP headers, etc.)
- If you're not confident in a fix, say so — don't generate a wrong patch.
```

---

## 10. Risk Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Nemotron API is slow / rate-limited | Demo takes too long | Pre-cache results for backup repos; show cached run if live fails |
| Model hallucinates a vulnerability | Credibility destroyed | Verifier agent + only demo on pre-tested repos where you know the findings |
| Hunter agent makes too many tool calls | Demo stalls, audience loses attention | Pre-test to know the typical tool call count (~15-30). If live demo runs long, the investigation feed keeps the audience engaged — they're watching it work |
| Tool call fails (CWE corpus, OSV API, web search) | Incomplete investigation | Each tool has a graceful fallback: CWE falls back to local cache, OSV errors are skipped, web search is optional. Agent continues without failed tool |
| Repo is too large for 1M context | Ingestion fails | Token counter + smart filtering; have a right-sized repo ready |
| Frontend bugs during demo | Looks unprofessional | Keep UI simple; test obsessively in hour 4 |
| API key / auth issues on demo day | Dead in the water | Test API access BEFORE the hackathon starts; have backup key |
| WiFi at convention center is terrible | Can't hit API | Hotspot backup; pre-record a demo video as nuclear option |

---

## 11. Stretch Goals (if time permits)

- **Comparative mode:** Run the same repo through with thinking ON vs OFF, show accuracy difference
- **Historical CVE validation:** Feed a repo at a commit known to have a CVE, show the agent finds it independently
- **Multi-language support:** Show it works on Python, JavaScript, Go, and Rust repos
- **Export to SARIF:** Industry-standard format for security findings, integrates with GitHub Security tab

---

## 12. What to Prep Tonight

- [ ] Get Nemotron Super API key from build.nvidia.com and test basic completion
- [ ] **Test Nemotron tool use** — verify the API supports tool definitions and the model actually calls them
- [ ] Download CWE corpus from MITRE (https://cwe.mitre.org/data/xml/cwec_latest.xml.zip) — ~5MB, parse into searchable JSON
- [ ] Clone and flatten 2–3 demo repos, measure token counts
- [ ] Test OSV.dev API with a known-vulnerable package (e.g., `lodash 4.17.20`) — verify response format
- [ ] Write and test secret scanner regex patterns against a real repo — verify it catches planted secrets
- [ ] Test a basic Recon prompt against a flattened repo — verify JSON output quality
- [ ] **Test a Hunter prompt with tools** against a small repo — does it actually call tools autonomously? How many calls does it make? How long does it take?
- [ ] Scaffold the FastAPI backend with SSE endpoint (even if basic)
- [ ] Scaffold the React frontend layout (even if static)
- [ ] Share this PRD with teammates so they can start independently

---

## 13. Design Aesthetic: Terminal / Hacker UI with NVIDIA Branding

### Philosophy
Terminal-style, command-line aesthetic. Monospace fonts, dark backgrounds, glowing text. It signals "serious security tool built by serious engineers" — perfect for a GTC audience. Using NVIDIA's brand green (`#76B900`) as the primary text color ties the aesthetic naturally to the conference without being heavy-handed.

Practical benefit: terminal UI is faster to build than a polished design system. No component library fussing. Monospace text, solid backgrounds, simple borders. The frontend teammate can move fast.

### Color Palette

| Role | Color | Hex | Usage |
|---|---|---|---|
| **Primary text** | NVIDIA Green | `#76B900` | All main text, labels, borders |
| **Bright accent** | Light NVIDIA Green | `#93E100` | Highlights, active elements, glow effects |
| **Background** | Near-black | `#0a0a0a` | Main background |
| **Surface** | Dark gray | `#1a1a1a` | Card backgrounds, panels |
| **Border** | Dim gray | `#2a2a2a` | Panel dividers, card borders |
| **Critical severity** | Red | `#FF0033` | Critical vulnerability cards, graph pulses |
| **High severity** | Orange | `#FF6600` | High severity findings |
| **Medium severity** | Yellow | `#FFD600` | Medium severity findings |
| **Low severity** | Dim green | `#4a7a00` | Low severity findings |
| **Tool calls / info** | NVIDIA Green @ 70% | `rgba(118,185,0,0.7)` | Investigation feed tool call cards |
| **Dimmed text** | Gray | `#666666` | Timestamps, secondary info |

### Typography

- **Body / code / investigation feed:** `JetBrains Mono` or `Fira Code` (monospace, ligature support)
- **Logo "CodeSentinel":** `Barlow Semi Condensed` or similar geometric sans-serif (nod to NVIDIA's typography style), rendered in `#76B900` with glow
- **Everything else:** Monospace. No serif fonts anywhere.

### Key Visual Effects

**Phosphor glow on key elements:**
```css
text-shadow: 0 0 8px rgba(118, 185, 0, 0.4);
```
Apply to: logo, severity labels, active agent status, vulnerability count numbers. Don't apply to body text (readability).

**CRT scanline overlay (subtle):**
```css
.scanlines::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(
    0deg,
    rgba(0, 0, 0, 0.03) 0px,
    rgba(0, 0, 0, 0.03) 1px,
    transparent 1px,
    transparent 2px
  );
  pointer-events: none;
  z-index: 9999;
}
```
Apply to main background only. Keep it very subtle — it's a vibe element, not a readability obstacle.

**Attack surface graph — break the aesthetic intentionally:**
The graph lives inside a terminal-style bordered panel, but the graph itself uses vivid colors against the dark background: red pulses for vulnerabilities, orange for warnings, cyan (`#00D4FF`) for data flow edges, NVIDIA green for safe nodes. The contrast between the austere terminal chrome and the vivid graph makes both elements pop harder.

### Investigation Feed Styling

Style tool calls like terminal commands:
```
$ cwe_lookup --query "SQL injection"
  → CWE-89: Improper Neutralization of SQL Elements
  → Related: CWE-564, CWE-943

$ osv_query --pkg lodash --ecosystem npm --version 4.17.20
  → CVE-2021-23337 [HIGH] Prototype Pollution
  → Fix: upgrade to 4.17.21

$ web_search --query "Express 4.17 security advisory 2025"
  → Found: CVE-2025-XXXX — session fixation in Express <4.18.3

⚠ FINDING: SQL Injection in auth.py:42-47 [CRITICAL]
  CWE-89 | Confidence: HIGH | 3 tool calls supporting
```

Color-code by tool type:
- `cwe_lookup` calls: NVIDIA green
- `osv_query` calls: orange (`#FF6600`)
- `web_search` calls: cyan (`#00D4FF`)
- Findings: red (`#FF0033`) for critical, orange for high, yellow for medium
- Agent reasoning text: dimmed NVIDIA green (`rgba(118,185,0,0.5)`)

### Vulnerability Cards

Dark card (`#1a1a1a`) with left border colored by severity (4px solid). Content:
- Top: severity badge (colored pill) + title + file:line in monospace
- Middle: code snippet in syntax-highlighted monospace (dark code theme)
- Bottom: "View Patch" and "Investigation Trail" as terminal-style links (`> view_patch`, `> show_trail`)

### Top Bar

```
┌──────────────────────────────────────────────────────────────┐
│  ▓ CodeSentinel                    [git: repo-url    ] [▶ SCAN] │
│  ░ Not a scanner. A researcher.    status: HUNTING...        │
└──────────────────────────────────────────────────────────────┘
```

Logo uses Barlow font + glow. Tagline in dimmed monospace. Input field styled as a terminal input with `git:` prefix. SCAN button in NVIDIA green with subtle glow on hover.

---

## 14. Naming & Branding

**CodeSentinel** — clean, memorable, implies automated vigilance.

Alternative names if taken: VulnGraph, GuardRail, CodeHawk, RepoRadar.

Tagline for the demo slide: *"Not a scanner. A researcher."*
