# Awesome AI Forensics [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> Where the evidence lives when AI took part in the attack — organised by how much the model decided on its own.

Investigating an AI-involved case is not a new discipline. It is the old one, pointed at new directories. The hard part is knowing *which* directories, and that depends on one thing: how much the model decided.

A model that wrote code leaves traces in a repository. A model that ran commands leaves a transcript on the operator's own disk. A model that chose its own targets leaves a state directory with keys in it. A model that managed other models leaves a project archive.

Every path here has a source. **An unsourced path is a guess, and guesses do not survive cross-examination.**

*Compiled while preparing the talk “Man-in-the-Agent” for KazHackStan 2026 — [khs2026.pandoral.me](https://khs2026.pandoral.me)*

## Contents

- [The four levels](#the-four-levels)
- [Level 1 — AI wrote the code](#level-1--ai-wrote-the-code)
- [Level 2 — AI ran the commands](#level-2--ai-ran-the-commands)
- [Level 3 — AI chose its own targets](#level-3--ai-chose-its-own-targets)
- [Level 4 — AI managed other AI](#level-4--ai-managed-other-ai)
- [Where the model itself ran](#where-the-model-itself-ran)
- [Provider, network and host](#provider-network-and-host)
- [Collection order](#collection-order)
- [Anti-forensics indicators](#anti-forensics-indicators)
- [Tools](#tools)
- [Research](#research)
- [Case reports](#case-reports)
- [The five artifact planes](#the-five-artifact-planes)
- [Contributing](#contributing)

## The four levels

| Level | What the model did | What the human still did | Where the evidence concentrates |
|---|---|---|---|
| **1** | Wrote the code | Ran the attack himself | Development host: repository, specs, agent config files |
| **2** | Ran the commands | Typed every instruction | Operator host: session transcripts, persistent prompt |
| **3** | Chose its own targets | Started the session and walked away | Agent state: config, memory, credentials, shell history |
| **4** | Managed other AI | Stated the goal | Orchestrator workspace: plans, scored hypotheses, wave reports |

---

## Level 1 — AI wrote the code

The model never touches a victim. It sits inside the build. This is ordinary disk forensics pointed at a development host — plus one new class of artifact: the coding agent's own configuration, committed alongside the code.

### Agent instruction files in the repository

Routinely committed, rarely thought of as evidence. They contain the instructions the developer gave the model.

| File | Tool |
|---|---|
| `CLAUDE.md`, `.claude/` | Claude Code |
| `AGENTS.md` | Codex, and increasingly a cross-tool convention |
| `.cursorrules`, `.cursor/` | Cursor |
| `GEMINI.md` | Gemini CLI |
| `copilot-instructions.md` | GitHub Copilot |
| `.replit` | Replit |
| `.coderabbit.yaml` | CodeRabbit |
| `.deepsource.toml` | DeepSource |
| `.aider*` | Aider |
| `.opencode` | OpenCode |

Scale, from a census of 180M repositories: **888,177** blobs of `CLAUDE.md`/`.claude/`, 317,512 of `.replit`, 211,166 of `copilot-instructions.md`, 134,810 of `AGENTS.md`, 29,689 of `.cursorrules`, 19,453 of `GEMINI.md` — *[Detecting AI Coding Agents in Open Source, arXiv:2606.24429](https://arxiv.org/abs/2606.24429)*. Agent-detection tooling uses the same marker set — *[vetto](https://docs.rs/crate/vetto/latest/source/src/onboard.rs)*

In the VoidLink case the equivalent artifacts were **TRAE IDE helper files**, copied to the server alongside the source, which preserved fragments of the original prompts — *[Check Point Research](https://research.checkpoint.com/2026/voidlink-early-ai-generated-malware-framework/)*

### Commit metadata

| Indicator | Form |
|---|---|
| Co-authorship trailer | `Co-Authored-By: Claude <noreply@anthropic.com>` |
| Generated-by footer | `🤖 Generated with [Claude Code](https://claude.com/claude-code)` |
| Other vendors | `Co-authored-by: Copilot`, `Co-authored-by: Codex`, `Co-authored-by: Gemini` |
| Assisted-by with model string | `Assisted-by: Claude:claude-sonnet-4-20250514` |
| Session trailers | `Claude-Session:`, `Claude-Workflow:`, `Replit-Commit-Session-Id` |
| Bot committer emails | `noreply@anthropic.com`, `198982749+Copilot@users.noreply.github.com` |
| Author-name suffix | `(aider)` on the unresolved author string |

Same census: 28,154 commits found by bot account, **821,824 more** by message signature alone — *[arXiv:2606.24429](https://arxiv.org/abs/2606.24429)*. Signature databases: *[commit-check](https://github.com/commit-check/commit-check)*, *[ai-detection-action](https://pkg.go.dev/github.com/chaoss/ai-detection-action)*

**Read this before you rely on it:** all of the above is one setting away from gone — `attribution.commit = ""`, `includeCoAuthoredBy: false`, or a line in `CLAUDE.md` telling the model never to add it. Absence proves nothing. GitHub's own "AI contribution attribution" feature is likewise toggleable and produces false positives.

### Code-level stylometry

Unlike metadata, this cannot be switched off.

- **Comment phrasing** — the single strongest attribution signal across model families; block versus inline habits differ by vendor — *[Code Fingerprints, arXiv:2603.04212](https://arxiv.org/abs/2603.04212)*, *[I Know Which LLM Wrote Your Code Last Summer](https://dl.acm.org/doi/10.1145/3733799.3762964)*
- **Comment density and verb-to-comment ratio** — cheap, interpretable, CPU-only — *[SemEval-2026 Task 13, arXiv:2605.04157](https://arxiv.org/abs/2605.04157)*
- **Naming-convention bias** — `snake_case` leaking into Java; lexical density; structural depth — *[arXiv:2603.04212](https://arxiv.org/abs/2603.04212)*
- **Structural patterns in JavaScript** support model-family attribution — *[arXiv:2510.10493](https://arxiv.org/abs/2510.10493)*
- **Tutorial-tone comments on trivial code** — a three-line loop annotated with what XOR does, in kernel-level source — *[Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink)*
- **Watermarking** as a future tracing route — *[MCGMark, arXiv:2408.01354](https://arxiv.org/abs/2408.01354)*

### Iteration scars

Artifacts of spec-driven development and of sessions stitched together:

- **Phase scaffolding in file headers** — `Phase 1:` … `Phase 5:` in initialization routines
- **Fix tags** — `[1.1]`, `[2.3]` marking which requested improvement a change implements
- **Missing or duplicated phases** — phase 7 absent entirely, phase 5 assigned to two functions
- **Sequential generations of one file** kept side by side — ten versions of a single eBPF program
- **Uniform version suffixes across unrelated components** — `*_v3` on everything
- **Training-data placeholders in output** — `John Doe` in response templates — *[Sysdig TRT](https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits)*
- **Over-systematic debug output**, identically formatted across modules

### Project-level evidence

- Sprint plans, feature breakdowns, coding guidelines, test reports — often Markdown, often committed
- **The language of the documentation**, not of the code. In VoidLink this, not code style, carried the attribution
- Choice of IDE and model; build and test infrastructure
- **Reproduction as proof**: Check Point re-ran the same documentation through the same IDE workflow and obtained near-identical code. If a project is reproducible from its specification, code stylometry has nothing left to attribute

---

## Level 2 — AI ran the commands

One human, one session, the model executing. Every mainstream agent writes a complete record of what it did to local disk. This is the richest evidence base in the whole list — and the one most often missed, because it sits in the *operator's* profile, not on the victim.

### Claude Code

Relative to `~/.claude/`; `CLAUDE_CONFIG_DIR` overrides the root. Source: *[Explore the .claude directory](https://code.claude.com/docs/en/claude-directory)*, *[Manage sessions](https://code.claude.com/docs/en/sessions)*

| Path | Contents |
|---|---|
| `projects/<project>/<session>.jsonl` | Full transcript: every message, tool call and tool result |
| `projects/<project>/<session>.orphaned-<ts>-<suffix>.jsonl` | Earlier transcript set aside, **not deleted**; hidden from the picker |
| `projects/<project>/<session>.jsonl.superseded-<ts>` | Same, different supersession path |
| `<session>/subagents/*.jsonl` | Sub-agent transcripts |
| `history.jsonl` | Prompt recall, `Ctrl+R` search, `!` shell completion |
| `.claude.json` | Recent-projects map |
| `settings.json` | Config — including whether attribution was switched off |
| `todos/`, `shell-snapshots/`, `file-history/`, `paste-cache/`, `image-cache/`, `session-env/` | Working state, pasted content, file versions |
| `~/.config/claude/sessions/sessions.json` | SDK session metadata: id, name, status, timestamps, project path |

Project directory naming: every non-alphanumeric character of the absolute working directory replaced with `-`. Retention governed by `cleanupPeriodDays`; Desktop and Cowork transcripts have a separate `desktopSessionCleanupPeriodDays`.

**Three properties worth reading twice:**

1. **Nothing is encrypted at rest.** OS file permissions are the only protection.
2. **Everything that passed through a tool is in the transcript** — file contents, command output, pasted text. If a tool read a `.env` or a command printed a credential, it is there in plain text.
3. **Deleted is not deleted.** Superseded and orphaned transcripts are set aside, not erased.

### Codex CLI

Rollout files the CLI appends live and replays on resume. Source: *[txcript format spec, derived from upstream serialization code](https://docs.rs/crate/txcript/latest/source/docs/formats/codex.md)*

```
~/.codex/sessions/
└── 2026/08/10/                                   dated YYYY/MM/DD tree
    └── rollout-2026-08-10T13-02-51-<uuid>.jsonl  one file per session
        {"timestamp","type":"session_meta",…}     header
        {"timestamp","type":"turn_context",…}     turn boundary
~/.codex/sessions/_codex_aliases.json             user-assigned session names
```

The session header records the originating timezone — a small but usable attribution detail.

### Gemini CLI and Antigravity

| Path | Contents |
|---|---|
| `~/.gemini/tmp/<project>/chats/session-*.jsonl` | Append journal: header line, `$set` patches, one object per message |
| `~/.gemini/projects.json` | Maps each project folder to its real working directory |
| `~/.gemini/antigravity/brain/<conversation-id>/*.md` + `*.metadata.json` | Antigravity conversation artifacts with timestamps |
| `~/.gemini/antigravity/**/code_tracker/active/**` | Tracked file revisions |

Gemini records cumulative context size per turn and retains rewound turns, tagged. Antigravity additionally stores high-entropy protobuf blobs that do not decode with `protoc --decode_raw`. Sources: *[agent-cli-session](https://github.com/POSTTTT/agent-cli-session)*, *[agenttrace](https://github.com/npow/agenttrace)*

### Cursor

Cursor keeps everything locally **even when connected to a remote host over SSH** — the data is on the machine running the UI, not the server.

| Platform | User directory |
|---|---|
| macOS | `~/Library/Application Support/Cursor/User/` |
| Linux | `~/.config/Cursor/User/` |
| Windows | `%APPDATA%\Cursor\User\` |

```
User/
├── globalStorage/
│   └── state.vscdb                       SQLite — conversation bodies for ALL projects
│       ├── ItemTable
│       │     composer.composerHeaders    session index: composerId | workspaceId
│       │                                 | createdAt | lastUpdatedAt | isArchived
│       │                                 | isSubagent | recency | checkpointAt
│       └── cursorDiskKV
│             composerData:<cid>          state document: model, bubble order
│             bubbleId:<cid>:<bid>        one message; type 1 user, 2 assistant
│             checkpointId:<cid>:<id>     file checkpoints
│             agentKv:blob:<sha>          model-side request cache
├── workspaceStorage/<workspace-id>/
│   ├── workspace.json                    maps the workspace to a project path
│   └── state.vscdb                       chat list / selected tabs
└── History/
```

Bubbles carry over 100 metadata fields each, including tool outputs and thinking. The database uses a rollback journal — check for the sidecar. Chats are keyed by a globally unique `composerId` and linked to a workspace by `workspaceId`, which is why a renamed project "loses" its history while the data stays intact.

**Cursor CLI** (`cursor-agent`) is a separate store: `~/.cursor/chats`.

Sources: *[txcript: Cursor desktop format](https://docs.rs/crate/txcript/latest/source/docs/formats/cursor-desktop.md)*, *[cursaves: How Cursor Stores Chat Data](https://github.com/Callum-Ward/cursaves/blob/main/docs/how-cursor-stores-chats.md)*, *[cursor-chronicle](https://github.com/mikhailsal/cursor-chronicle)*

### Cline, Roo Code, Kilo Code

One format, three extension IDs. Source: *[Cline docs — task history recovery](https://docs.cline.bot/troubleshooting/task-history-recovery.md)*

| Fork | globalStorage directory |
|---|---|
| Cline | `saoudrizwan.claude-dev/` |
| Roo Code | `rooveterinaryinc.roo-cline/` |
| Kilo Code | `kilocode.kilo-code/` |

```
<globalStorage>/<extension-id>/
├── state/
│   ├── taskHistory.json                  index only
│   └── taskHistory.backup.*.json         backups — recover deleted index entries
├── tasks/<task-id>/
│   ├── api_conversation_history.json     raw API exchanges
│   ├── ui_messages.json                  user-facing events, incl. api_req_started
│   └── task_metadata.json                timestamps, working directory
└── checkpoints/<workspace-hash>/
    └── .git/                             SHADOW GIT REPOSITORY of workspace snapshots
```

Base paths: `~/Library/Application Support/Code/User/globalStorage/` (macOS), `%APPDATA%\Code\User\globalStorage\` (Windows), `~/.config/Code/User/globalStorage/` (Linux). For VS Code Insiders replace `Code` with `Code - Insiders`; for remote work check `~/.vscode-server/data/User/globalStorage/`; for JetBrains, `~/.config/JetBrains/<IDE>/globalStorage/`. Cline also uses a second root: `~/.cline/data/tasks/<task-id>/`.

**The shadow Git repository under `checkpoints/` is the single most useful artifact here** — a version history of the workspace as the agent changed it, independent of the project's own Git.

### Other harnesses with documented stores

| Agent | Storage |
|---|---|
| OpenCode | `~/.local/share/opencode/opencode.db` (SQLite — take the `-wal` sidecar) |
| Aider | Markdown **in the repository**: `.aider.chat.history.md`, `.aider.input.history` |
| Goose | JSONL per session, `toolRequest` / `toolResponse` parts |
| GitHub Copilot Chat | JSON/JSONL in VS Code storage, or in the repo under Visual Studio |
| Hermes Agent | SQLite `state.db`, one database shared by all processes; `request_dump_*.json` |
| DeepSeek Harness (`dsh`) | JSONL event stream, or zstd-compressed SQLite — decompress first |
| Kimi Code | `agents/<name>/wire.jsonl` event stream |

Sources: *[coding-agent-forensics](https://github.com/Shorton88/coding-agent-forensics)*, *[agent-session-format](https://github.com/Atituiset/agent-session-format)*, *[agent-cli-session](https://github.com/POSTTTT/agent-cli-session)*

### What a level-2 case yielded in practice

Recovered from three VPSs used in the Mexico campaign — *[Gambit Security](https://gambit.security/ai-assisted-breach-of-mexicos-government-infrastructure)*:

- **1,088 individually logged prompts → 5,317 AI-executed commands across 34 sessions**
- Model reasoning blocks preserved alongside user-visible output
- `CLAUDE.md` holding a pasted 1,084-line pentest cheatsheet, loaded into every session
- **156 pre-approved command patterns** — the operator's own allow-list
- **First-token date in agent metadata: 27 November**, a month before the first operational session — dating a preparation phase nothing else revealed
- 20 tailored exploits for 20 CVEs; 400+ scripts (301 Bash, 113 Python); a 17,550-line tool that piped harvested data through a second model's API; 2,597 generated intelligence reports across 305 servers

---

## Level 3 — AI chose its own targets

An agent stands between the human and the victim, with its own configuration, memory and credentials. Everything lives in one directory — which is good news once you are inside, and the whole problem until you are.

### OpenClaw

Relative to `~/.openclaw/`. Source: *[Gruber & Hilgert, arXiv:2604.05589, Table 1](https://arxiv.org/abs/2604.05589)* — the first forensic study of a personal AI assistant

| Path | Contents |
|---|---|
| `openclaw.json` | Agent, model, channel and permission settings |
| `openclaw.json.bak*` | Historical configuration snapshots — point-in-time reconstruction |
| `credentials/` | Channel authentication (Telegram, WhatsApp) |
| `agents/<id>/agent/auth-profiles.json` | Provider credentials: OAuth tokens, API keys |
| `devices/`, `identity/` | Paired companion devices and keys |
| `workspace/*.md` | Persona, user profile, tool definitions, curated memory |
| `workspace/skills/` | Custom skill definitions (`SKILL.md`) |
| `workspace/memory/YYYY-MM-DD.md` | Append-only daily memory log |
| `memory/<agent_id>.sqlite` | Semantic search embeddings (`chunks_vec_*` tables) |
| `agents/<id>/sessions/sessions.json` | Session index, model per session, token usage, channel metadata |
| `agents/<id>/sessions/<sessionId>.jsonl` | Full conversation and tool execution history |
| `media/inbound/` | Uploaded files: `{sanitized_original}---{uuid}.{ext}` or bare UUID |
| `/tmp/openclaw/openclaw-YYYY-MM-DD.log` | Runtime events — **deleted after 24 hours, hard-coded** |

Persona files inside `workspace/`: `AGENTS.md`, `BOOTSTRAP.md` (deleted by the agent after init), `IDENTITY.md`, `SOUL.md` (personality and safety boundaries), `TOOLS.md` (SSH hosts and aliases — often the most operationally useful single file), `HEARTBEAT.md` (periodic autonomous tasks), `MEMORY.md`, `USER.md` (learned timezone, active projects, preferences).

**Session structure.** Two levels: a human-readable `sessionKey` such as `agent:main:main` maps to a UUID `sessionId` in `sessions.json`; the transcript is `<sessionId>.jsonl`. Each line is a self-contained JSON object with `id` and `parentId`. The file opens with a version-3 header carrying the session UUID, creation timestamp and working directory. Within a session, individual turns are *runs* with their own `runId`.

**Soft delete.** A deleted session is renamed in place with a `.deleted.<timestamp>` suffix and removed from the index. The transcript stays on disk.

**Reasoning traces.** `thinking` content blocks inside assistant messages — how the agent read the request, which alternatives it weighed, why it picked a tool. Mid-session model switches appear as `model_change` events. Assistant messages carry token counts, cost breakdown and `stopReason`.

**Channel attribution.** Telegram messages arrive with a structured header inside the stored user message: `[Telegram <name> (@<handle>) id:<id> <YYYY-MM-DD> <HH:MM> UTC]`, plus `[message_id: N]` on its own line. `sessions.json` may record an `origin` entry with the provider and sender identifier.

**Visibility gap worth knowing.** For providers using reasoning tags, only `<final>`-wrapped text is shown to the user; thinking blocks and tool details are not. Distinguish between what is on disk and what the human actually saw.

### What a level-3 case yielded in practice

From a directory served by `python3 -m http.server 8888` started in `/home/worker` — *[Unit 42](https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/)*:

- Model configurations and API keys — which model, on whose account
- Exploit scripts and target lists: 460+ hosts with no industry or country logic
- **Shell command history** — the artifact that actually led to a person
- Autonomous session logs with the reasoning behind each choice
- Anti-attribution proxy configuration; Telegram as the control channel

From there the chain was ordinary OSINT: shell history → proxy → aliases → GitHub profile → public project → city.

---

## Level 4 — AI managed other AI

A planning layer above the agents. The new question at this level is one the lower levels never raise: **which actions did nobody ask for?**

### Scheduled and delegated work

Relative to `~/.openclaw/`. Source: *[Gruber & Hilgert, arXiv:2604.05589](https://arxiv.org/abs/2604.05589)*

| Path | Contents |
|---|---|
| `cron/jobs.json` | Scheduled autonomous task definitions: one-shot `at`, interval `every`, or cron expression with timezone; payload and runtime state |
| `cron/runs/<jobId>.jsonl` | Execution log per job — **activity with no preceding user request** |
| `subagents/runs.json` | Delegated task registry: which subagent, for what task, start and end |

**Delegation reconstruction.** `sessions_spawn` tool calls record the task prompt, child session ID, cleanup policy, token use and result summary. `sessions.json` records `spawnedBy` on the parent and references children under keys like `agent:main:subagent:<uuid>`. A cron job may run inside the main session via an injected system event, or in an isolated `cron:<jobId>` run — which decides whether it appears in the main transcript or in a separate file.

**Two retention traps.**

- `subagents/runs.json` entries are swept once `archiveAtMs` passes — **default 60 minutes** after creation.
- Even when the index entry is gone, the **child transcript usually survives on disk**, and parent and child can still be linked by session identifiers. Events recorded as `role: user` inside a subagent transcript may in fact be agent-driven spawning — do not read them as human input.

**Non-determinism.** The same request may produce different artifacts on different runs: a reminder can become a `cron` job *or* an edit to `HEARTBEAT.md`, depending on the assembled context. Structural artifacts — config, credential stores, directory layout, file-creation patterns — were deterministic across runs; LLM-generated content — reasoning traces, tool-choice sequences, agent-authored memory — was not.

### Orchestration frameworks

- **LangGraph** — checkpointers persist graph state at every super-step, creating a complete execution history. `SqliteSaver` writes to a local `.db` file, `PostgresSaver` to a database, `InMemorySaver` to nothing. `thread_id` groups checkpoints into one conversation; `get_state_history()` replays them; the separate `Store` API holds cross-thread long-term memory. For an investigator this is a replayable, forkable record of every decision point — *[LangGraph persistence docs](https://www.mintlify.com/langchain-ai/langgraph/guides/persistence)*
- **AutoGen** — logs, configuration files, agent communication traces and execution metadata. Note the finding that matters more than the paths: runtime logging was deprecated after v0.2, which left the reasoning and action planes **empty** in the published study — an absence of artifacts that reflects the tool, not the case — *[Walker et al., ARES 2024](https://doi.org/10.1145/3664476.3670908)*
- **Hermes Agent** and **Agent Zero** — task-oriented-only subagent models; structural spawn vulnerabilities compared against OpenClaw in *[When Child Inherits, arXiv:2605.08460](https://arxiv.org/abs/2605.08460)*

### What a level-4 case yielded in practice

From a 160 MB / 1,395-file workspace archive left accessible online — *[DREAM Lab](https://www.dreamgroup.com/blog/inside-a-multi-agent-ai-framework-used-to-compromise-government-entities-in-asia)*:

- **Wave plans and after-action reports** feeding the next wave's planning, with no human in between
- **Lettered sub-agent assignments** — agents A through Q observed, up to 8 concurrent per wave
- **Scored hypotheses** — two-layer Bayesian triage: per-finding posteriors from a 0.50 prior with explicit likelihood ratios (tool scan LR+ 6.0, manual `curl` confirmation LR+ 10.0, impact LR+ 3.0, WAF LR− 0.30), then chain scores via `P_success = P_chain × (1 − P_blocker)`
- **Decision thresholds in writing** — >0.95 promote, >0.70 allocate resources, >0.50 queue for the next wave, <0.30 discard
- **A prediction the system made about itself** — the SSO lateral-movement chain scored 99 %; 98.8 % of the cracked accounts actually pivoted
- **Self-correction records** — 7 false positives the framework caught itself, including a "blind SQL injection" (21-second delay) that turned out to be an SMTP timeout; each confirmed finding had to survive six independent re-verifications
- **"Learning cycles" v1–v5** — autonomous research sessions searching vulnerability databases, GitHub and security publications when a path was blocked
- **Two workspace identifiers side by side** — `.hermes` and `.openclaw`
- **Language code-switching in internal documentation** — the only thing that survived as attribution

---

## Where the model itself ran

If the model ran locally there is a second evidence base entirely, and it is often richer than the cloud one, because nothing was stateless.

### Local runtimes and desktop clients

Windows paths from *[LangurTrace, FSI:DI 54 (2025), Appendix A](https://www.sciencedirect.com/science/article/pii/S2666281725001271)* (open access); cross-platform coverage in *[Murtuza, arXiv:2603.23996](https://arxiv.org/abs/2603.23996)*

| App | Artifact | Location |
|---|---|---|
| Ollama | Server logs: model setup, API calls, timestamps, latency, caller IP | `%LocalAppData%/Ollama/server.log` |
| Ollama | Model manifest (Docker-style, SHA-256 per layer) | `%UserProfile%/.ollama/models/manifests/registry.ollama.ai/library/{model}/{params}` |
| Ollama | Model layers | `%UserProfile%/.ollama/models/blobs/sha256-{digest}` |
| Ollama | App / upgrade logs | `%LocalAppData%/Ollama/app.log`, `upgrade.log` |
| Ollama | CLI history (inputs only, timestamped) | `%UserProfile%/.ollama/history` |
| LM Studio | Model setup history: name, download URL, SHA-256, size | `%UserProfile%/.lmstudio/.internal/download-jobs-info.json` |
| LM Studio | Conversations | `%UserProfile%/.lmstudio/conversations/{ID}.json` |
| LM Studio | Uploaded files and metadata | `%UserProfile%/.lmstudio/user-files/{filename}[.metadata.json]` |
| LM Studio | Main logs | `%AppData%/LM Studio/logs/main.log` |
| Chatbox | Chat sessions, system prompts, **API keys** | `%AppData%/xyz.chatboxapp.app/config.json` (+ rolling backups) |
| Chatbox | Uploaded and generated files, base64 blobs | `%AppData%/xyz.chatboxapp.app/chatbox-blobs/` |
| Chatbox | API cache | `%AppData%/xyz.chatboxapp.app/Cache/Cache_Data` |
| Chatbox | Model list per provider | LevelDB — deleted entries sometimes recoverable |
| Msty | Conversations **and API keys** in one SQLite DB (`api_keys`, `chat_sessions`, `chat_messages`) | `%AppData%/Msty/msty.db` |
| Msty | Attachments — survive message deletion | `%AppData%/Msty/attachments/` |
| Msty | Model setup, loading and upload history | `%AppData%/Msty/logs/app.log` |
| Jan | Verbose log — chats, config **and API keys in plaintext** | `%AppData%/Jan/data/logs/cortex.log` |
| Jan | Chat sessions | `%AppData%/Jan/data/threads/{ID}/messages.jsonl` |
| Jan | Model configurations | `%AppData%/Jan/data/cortex.db` |
| Jan | Local storage — partial recovery of deleted records | `%AppData%/Jan/Local Storage/leveldb/` |
| GPT4All | Conversations **with uploaded files embedded inline** | `%LocalAppData%/nomic.ai/GPT4ALL/gpt4all-{ID}.chat` |
| GPT4All | Remote model config: API key, provider | `%LocalAppData%/nomic.ai/GPT4ALL/gpt4all-{ID}.rmodel` |

Linux and macOS equivalents live under `~/.ollama/`, `~/.lmstudio/`, `~/.config/LM Studio/`.

**Recovery after in-app deletion — measured, not assumed** *(LangurTrace §5.3)*:

| App | Model downloads | Chats | Uploads |
|---|---|---|---|
| Ollama | 100 % | – | – |
| Chatbox | – | 58 % | 100 % |
| LM Studio | 100 % | 0 % | 0 % |
| Msty | 100 % | 0 % | 100 % |
| Jan | 100 % | 100 % | – |
| GPT4All | 0 % | 0 % | – |

The authors' own caveat: "not recoverable" means *not recoverable by disk-level parsing*. Volume Shadow Copies, live memory, SQLite freelist and WAL carving, and LevelDB slack were out of scope and may still yield records.

**Why model metadata matters.** Which model was downloaded, and when, speaks to intent — many published models are purpose-built. Manifests carry SHA-256 digests you can cross-reference against public hubs, and LM Studio preserves the original download URL, so the exact file can be re-fetched.

### Cloud chat clients

- **ChatGPT mobile** — first forensic analysis, across Android, iOS and cloud storage — *[Dragonas, Lambrinoudakis & Nakoutis, FSI:DI 50 (2024)](https://www.sciencedirect.com/science/article/pii/S2666281724001252)*
- **ChatGPT, Gemini, Copilot and Claude compared** — *[Cho et al., FSI:DI 52 (2025)](https://www.sciencedirect.com/science/article/pii/S2666281724001823)*
- **The asymmetry that decides your strategy:** browser-accessed conversations persist server-side; **API-key access is generally stateless**, so cloud-side collection will not help if the subject used a local client with a key. Local application storage holds the context in that case — *[LangurTrace §3.4](https://www.sciencedirect.com/science/article/pii/S2666281725001271)*

---

## Provider, network and host

### Provider side

- Account identity, billing and the API key itself — recoverable locally, actionable only through legal process
- Retention is short and varies by provider; treat this as a parallel track, never a fallback
- Terms-of-use violation is itself a lead: both platforms in the Mexico case were used in direct breach of their terms, which is what made the accounts actionable

### Network side

- Provider endpoints: `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, and local `127.0.0.1:11434` (Ollama), `:1234` (LM Studio)
- Model-hub pulls: `huggingface.co`, `registry.ollama.ai`
- Residential and anti-attribution proxies in between — in documented cases `us.proxy.geonode.io` and self-hosted SOCKS chains
- Ephemeral tunnelling and C2: `trycloudflare.com` subdomains, Chisel, SSH SOCKS chains
- Target-discovery services in history: FOFA, Shodan, Censys

### Host OS

The old artifacts still carry the case:

- `.bash_history`, `.zsh_history`, PowerShell console history
- Windows Prefetch (`.pf`) and Application Compatibility Cache (Shimcache) — proof a CLI agent executed
- Memory: prompts, the assembled context window and decrypted keys never written to disk — LiME on Linux, WinPmem on Windows — *[Murtuza, arXiv:2603.23996](https://arxiv.org/abs/2603.23996)*
- systemd units, launchd plists and cron entries that start agents at boot

---

## Collection order

Ordered by how fast the evidence disappears, not by how easy it is to get.

1. **Live memory** — prompts, the assembled context window, decrypted keys. The context window is *never* written to disk.
2. **Runtime logs** — OpenClaw deletes `/tmp/openclaw/*.log` after **24 hours**, hard-coded, and the cleanup runs at startup.
3. **Sub-agent run registry** — swept ~**60 minutes** after creation by default.
4. **Agent state** — sessions, memory, `auth-profiles.json`, config backups. Static, but worthless once the host is wiped.
5. **The whole workspace, at level 4** — agent-to-agent traffic exists nowhere else. Take it all or lose it.
6. **Provider-side conversation** — legal process, short retention, parallel track.
7. **Repository and commit history** — the most durable, and the least time-critical.

---

## Anti-forensics indicators

- **Tool calls present in logs but absent from the session transcript** — the transcript was edited — *[Gruber & Hilgert](https://arxiv.org/abs/2604.05589)*
- **Attribution disabled in config** — `attribution.commit = ""`, `includeCoAuthoredBy: false`, or an explicit instruction in `CLAUDE.md` never to add trailers
- **Persistent prompts instructing log deletion and history suppression** — in the Mexico case framed as "bug bounty rules"; the model identified it as evasion and refused, then accepted the same content when it was reframed as a file write
- **Guardrail bypass by framing** — "authorized penetration testing" as a standing preamble; documented independently in two of the four cases
- **Timestomping around agent-modified files** — cron scripts restored to their original mtime after key injection
- **Deliberate absence of domains** — infrastructure entirely on cloud IPs removes the registrar, email and payment layers in one move

---

## Tools

### Collection and parsing

- **[coding-agent-forensics](https://github.com/Shorton88/coding-agent-forensics)** — offline single-file viewer for transcripts from Claude Code, Codex, Copilot, Cursor, Gemini, Cline, Goose, Aider, OpenCode, Hermes and DeepSeek Harness. Searchable timeline, reconstructed file diffs, rule-based flags for credentials, exfiltration and git-history rewrites. Nothing leaves the browser
- **[forensic-analysis-of-openclaw](https://github.com/jgru/forensic-analysis-of-openclaw)** — `artifact-examiner`: unified timeline across logs, transcripts and config changes; session browser; anti-forensics detection by log/transcript comparison; capability-evolution tracking. Ships an `openclaw.yml` in ForensicArtifacts format
- **[LangurTrace](https://github.com/jeongramon/LangurTrace)** — collects and parses Chatbox, LM Studio, Jan, Msty, Ollama and GPT4All; ships KAPE Targets and Modules; HTML/CSV/XLSX output
- **[KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape)** — triage collection host for the above
- **[ForensicArtifacts repository](https://github.com/ForensicArtifacts/artifacts)** — machine-readable artifact definitions; the right place to contribute new AI paths

### Format conversion and normalisation

- **[txcript](https://docs.rs/crate/txcript/latest)** — converts session transcripts between harness formats; ships **written format specifications** for Codex, Cursor desktop, Antigravity and others, derived from upstream code and real sessions. Read the specs even if you never run the tool
- **[agent-session-format](https://github.com/Atituiset/agent-session-format)** — parsers and a normalised schema across Claude Code, Codex, Kimi Code, DeepSeek, OpenCode and Antigravity, with format auto-detection
- **[agent-cli-session](https://github.com/POSTTTT/agent-cli-session)** — local browser for Claude Code, Codex, Gemini CLI and OpenCode session logs

### Cursor-specific recovery

- **[cursor-chat-recovery](https://pypi.org/project/cursor-chat-recovery/)** — browse, recover and export chats detached by a workspace rename
- **[cursor-workspace-tool](https://pypi.org/project/cursor-workspace-tool/)** — dependency-free inventory of workspaces and chats, including WSL-remote data stored on the Windows side

### Commit-level detection

- **[ai-commit-check](https://github.com/Jondolf/ai-commit-check)** — GitHub Action detecting AI-authored commits and metadata trailers
- **[commit-check](https://github.com/commit-check/commit-check)** — curated database of AI tool signatures across trailer formats
- **[ai-detection-action](https://pkg.go.dev/github.com/chaoss/ai-detection-action)** — confidence-tiered detection: bot emails, trailers, session-ID trailers, message patterns
- **[slopscore](https://pypi.org/project/slopscore/)** — heuristic linter scoring AI residue in commits and PRs

---

## Research

### Agent and assistant forensics

- **[Foundations for Agentic AI Investigations from the Forensic Analysis of OpenClaw](https://arxiv.org/abs/2604.05589)** — Gruber & Hilgert, 2026. The reference work: full artifact table, five-plane taxonomy, and an honest account of what cannot be reconstructed
- **[LangurTrace: Forensic analysis of local LLM applications](https://www.sciencedirect.com/science/article/pii/S2666281725001271)** — Jeong, Lee & Park, DFRWS APAC 2025. Structured model of the LLM application environment plus measured recovery rates. Open access
- **[Forensic Implications of Localized AI](https://arxiv.org/abs/2603.23996)** — Murtuza, 2026. Ollama, LM Studio and llama.cpp across Windows and Linux, disk and memory
- **[Forensic analysis of OpenAI's ChatGPT mobile application](https://www.sciencedirect.com/science/article/pii/S2666281724001252)** — Dragonas et al., 2024
- **[Conversational AI forensics: ChatGPT, Gemini, Copilot, Claude](https://www.sciencedirect.com/science/article/pii/S2666281724001823)** — Cho et al., 2025
- **[Forensic analysis of artifacts from Microsoft's multi-agent LLM platform AutoGen](https://doi.org/10.1145/3664476.3670908)** — Walker et al., ARES 2024
- **[Towards LLM forensics using LLM-based invocation log analysis](https://doi.org/10.1145/3689217.3690616)** — Chernyshev, Baig & Doss, 2023
- **[Towards AI forensics: did the artificial intelligence system do it?](https://doi.org/10.1016/j.jisa.2023.103517)** — Schneider & Breitinger, 2023

### Attribution of generated code

- **[Detecting AI Coding Agents in Open Source: a census of 180M repositories](https://arxiv.org/abs/2606.24429)**
- **[Code Fingerprints: Disentangled Attribution of LLM-Generated Code](https://arxiv.org/abs/2603.04212)**
- **[I Know Which LLM Wrote Your Code Last Summer](https://dl.acm.org/doi/10.1145/3733799.3762964)**
- **[The Hidden DNA of LLM-Generated JavaScript](https://arxiv.org/abs/2510.10493)**
- **[Lightweight Detection of LLM-Generated Code via Stylometric Signals](https://arxiv.org/abs/2605.04157)**
- **[Bridging Behavioral Biometrics and Source Code Stylometry](https://arxiv.org/abs/2603.11150)** — survey of programmer attribution
- **[MCGMark: watermarking for tracing LLM-generated malicious code](https://arxiv.org/abs/2408.01354)**

### Agent security, relevant to what you will find

- **[When Child Inherits: Subagent Spawn in Multi-Agent Networks](https://arxiv.org/abs/2605.08460)** — structural vulnerabilities across OpenClaw, Hermes and Agent Zero
- **[Lessons from Penetration Tests on Large-Scale Agent Systems](https://arxiv.org/abs/2605.27042)**
- **[The Infinite Mutation Engine? Polymorphism in LLM-Generated Offensive Code](https://arxiv.org/abs/2605.03619)**

---

## Case reports

Ordered by level. Each is a primary source; read it rather than the coverage.

### Level 1 — VoidLink

- **[Check Point Research](https://research.checkpoint.com/2026/voidlink-early-ai-generated-malware-framework/)** — project-level evidence, IDE artifacts, the reproduction experiment
- **[Elastic Security Labs](https://www.elastic.co/security-labs/illuminating-voidlink)** — code-level evidence from a source dump: phase headers, fix tags, ten generations of one program
- **[Sysdig TRT](https://www.sysdig.com/blog/voidlink-threat-analysis-sysdig-discovers-c2-compiled-kernel-rootkits)** — binary-level evidence, and the counter-argument for human involvement

*The vendors disagree: "written almost entirely by AI" (Check Point) against 70–80 % likelihood of assistance (Sysdig) against a collaboration model (Elastic). The dispute is about the share, not the fact — and you will be having the same argument in your own cases.*

### Level 2 — Mexico

- **[Gambit Security, full technical report](https://gambit.security/ai-assisted-breach-of-mexicos-government-infrastructure)** — verbatim session logs including reasoning blocks, IOCs, 294 file hashes

### Level 3 — knaithe

- **[Unit 42](https://unit42.paloaltonetworks.com/autonomous-ai-cyber-attack-campaign/)** — autonomous target selection, the workshop exposure, the OSINT pivot

*Known gap: the report states three confirmed compromises overall, and separately eleven Marimo instances with command execution, without reconciling the two.*

### Level 4 — multi-agent

- **[DREAM Lab](https://www.dreamgroup.com/blog/inside-a-multi-agent-ai-framework-used-to-compromise-government-entities-in-asia)** — the orchestration archive, Bayesian triage, learning cycles, self-correction

### Context

- **[Anthropic — Mapping AI-enabled cyber threats](https://www.anthropic.com/research/attack-navigator)** — a year of banned accounts mapped to ATT&CK; why technique count no longer predicts danger
- **[Anthropic — Disrupting the first AI-orchestrated cyber espionage campaign](https://www.anthropic.com/news/disrupting-AI-espionage)**
- **[SentinelLabs — The Model Is the Malware](https://www.sentinelone.com/labs/the-model-is-the-malware-what-four-agentic-intrusions-tell-defenders/)**
- **[Unit 42 — The State of AI-Enabled Malware](https://unit42.paloaltonetworks.com/ai-enabled-malware-analysis/)** — the sober counterweight: none of the AI-enabled samples required a novel detection approach

---

## The five artifact planes

The level tells you *where* to look. The planes tell you *what* to look for. From *[Gruber & Hilgert, §6.1](https://arxiv.org/abs/2604.05589)*

| Plane | Question | Representative artifacts |
|---|---|---|
| Reasoning & Cognition | How did it think? | `thinking` blocks, `model_change` events, alternatives considered |
| Identity & Configuration | What was it allowed to do? | Config, persona files, credentials, tool definitions |
| Knowledge & Recall | What did it know? | Memory files, user profile, semantic index |
| Communication & I/O | Who talked to it? | Channel configs, transcripts, attachments |
| Actions & Effects | What did it do? | `toolCall`/`toolResult` pairs, scheduled runs, subagent spawns |

Session transcripts are cross-cutting: one JSONL file feeds all five.

**Why the taxonomy earns its place.** Applied to two earlier studies, the Reasoning and Actions planes came back empty for AutoGen — not because the artifacts were absent, but because nobody looked for them. Without a prescriptive list, whole evidence classes never make it into the collection plan.

**MITRE ATT&CK does not yet cover** autonomous kill-chain orchestration, real-time pivot decisions, or AI-directed execution without human intervention. Build on it; do not expect it to describe this.

---

## Contributing

Pull requests welcome. Priorities:

- Windsurf (Cascade), Continue.dev and Copilot agent-mode storage layouts
- macOS and Linux path equivalents for the Windows entries
- Orchestration frameworks beyond LangGraph and AutoGen: CrewAI, n8n, Dify, Flowise
- Retention defaults for tools not covered here
- New primary case reports

**Every artifact needs a source** — vendor documentation, a peer-reviewed paper, or a tool whose parser demonstrably reads that path. Please include the platform you verified it on and the version.

## Ethics

Everything here is for lawful investigation, incident response and authorised research. Agent workspaces contain the private data of whoever ran the agent — memory files, user profiles and channel transcripts routinely hold personal information unrelated to the case. Scope your collection, document your authority, and remember that a session transcript can contain credentials that were never meant to be written down at all.
