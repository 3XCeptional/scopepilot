# ScopePilot — what actually earns GitHub stars

Goal: fast to install, trivial to start, something a bounty hunter / pentester
runs **every day**. Stars follow daily utility + a 30-second "wow", not feature
count. Ranked by star-leverage (do top-down).

## The one-line pitch (put at top of README)
> Put ScopePilot in front of your recon tools and you **physically cannot** send
> a request to an out-of-scope host. One proxy. Every tool. Every byte logged.

The universal daily fear in bug bounty = accidentally hitting out-of-scope
(account ban / legal). A proxy that makes that *impossible* is something people
leave running all day. That's the daily-use hook.

---

## TIER 1 — adoption blockers (no stars without these)

1. **Prebuilt binaries + one-line install.** Nobody stars a tool they must
   `go build`. Ship:
   - GitHub Releases with static binaries (linux/amd64, linux/arm64, darwin/arm64).
   - `go install github.com/.../pentest@latest`
   - `brew install scopepilot` (tap) and/or `curl -sSL get.scopepilot.sh | sh`
   - GoReleaser + a release CI workflow. **This is the single biggest unlock.**

2. **HTTPS CONNECT proxy (the daily driver).** Right now it validates but can't
   carry HTTPS traffic — so people validate then step around it with curl. Add
   CONNECT tunneling (scope-check the host, then tunnel). Then:
   `export https_proxy=127.0.0.1:8443` and curl/ffuf/nuclei/httpx/the browser
   are all scope-gated with zero per-tool config. **This is what makes it a
   daily tool instead of a one-off checker.**

3. **`scopepilot init` wizard.** No hand-written YAML. Interactive:
   paste a domain or a list → generates config + API key + prints the
   `https_proxy=` line to copy. 30 seconds from install to running.

## TIER 2 — the "wow" that gets shared

4. **Scope import from program URLs.** Paste a HackerOne / Bugcrowd / Intigriti /
   YesWeHack program link (or its scope JSON) → auto-build the include/exclude
   rules. Building scope by hand is the tedious part of every engagement; killing
   it is screenshot-worthy and saves real time daily.

5. **`scopepilot check <url>`** — instant, no server: "in scope ✅ / blocked ❌
   (reason)". A 2-second daily util people alias and reach for constantly.
   Pipe-friendly: `cat urls.txt | scopepilot check -`.

6. **Drop-in for Burp / ZAP / browser.** Document "set ScopePilot as the upstream
   proxy" — now their existing workflow is scope-safe. Meets people where they
   already work.

7. **README demo gif (asciinema/vhs).** 20–30s: init → proxy on → in-scope 200,
   out-of-scope 403. The demo earns more stars than any single feature. Add
   shields.io badges (build, release, go report card).

## TIER 3 — stickiness / trust

8. **Live `/health` one-liner + `scopepilot watch`** — scope loaded, kill-switch,
   rate pressure, last-denied, active conns. A status line hunters keep open.
9. **Real-time "did I go out of scope?" tail** (`get_recent_decisions` already
   landed — surface it in the CLI/TUI).
10. **Single static binary, no Podman for host mode** — already true; say it loud
    in the README ("no Docker required to run the gate").

---

## Sequencing (max stars per unit effort)
1. CONNECT proxy (#2) + `check` one-shot (#5) + `init` (#3) — the daily-use core.
2. GoReleaser + Releases + `go install`/brew (#1) — distribution.
3. Scope import (#4) + demo gif + README (#7) — the shareable wow.
4. health/watch (#8,#9) — stickiness.

## Non-goals (won't move stars, skip for now)
- MITM/intercept mode (heavy, security-sensitive — later).
- More config knobs. Fewer knobs + better defaults wins.
- A web dashboard nobody asked for; the CLI + proxy is the product.

> North star: a hunter installs in one line, runs `scopepilot init`, sets
> `https_proxy`, and forgets it's there — until it blocks the one request that
> would have ended their season.

---

# PART B — the GitHub-stars GROWTH PLAN (distribution, not features)

Good features earn stars only if people FIND the repo. Features = Part A above.
This is how it gets discovered, shared, and starred.

## B0. The hook (one sentence, reused everywhere)
> "A proxy that makes it physically impossible to hit an out-of-scope target."

Lead every README / post / tweet with this. Fear-of-out-of-scope is universal in
bug bounty → instant "I need this" → star.

## B1. Repo hygiene (do BEFORE any launch — a cold repo converts ~0)
- **README in 10 seconds:** hook line → 1 demo gif → 3-line quickstart
  (`install → init → export https_proxy`) → "why" → features. No wall of text.
- **Demo gif/asciinema (vhs):** the single biggest conversion lever. 20s:
  proxy on → in-scope 200 (green) → out-of-scope 403 (red). Put it at the top.
- **Badges:** build passing, latest release, `go report card` A+, license, stars.
- **GitHub Topics (the "trigger words" = how people SEARCH/find it):**
  `bug-bounty` `pentesting` `security-tools` `proxy` `mitmproxy` `burpsuite`
  `appsec` `recon` `scope` `osint` `red-team` `infosec` `hacktoberfest` `golang`
  `cli`. Topics drive GitHub's own discovery + the /topics pages.
- **`good first issue` + `help wanted` labels** seeded with 5–10 small tasks →
  contributor funnel (contributors star + evangelize).
- LICENSE (MIT/Apache), CONTRIBUTING, SECURITY.md (already have), CODEOWNERS.

## B2. Launch channels (ranked by infosec reach)
Launch ONLY after B1 + a working one-line install + the gif. One shot at "new".
1. **Hacker News — "Show HN: ScopePilot – a proxy that blocks out-of-scope
   requests"**. Post Tue–Thu ~8–10am ET. First comment = the "why I built it"
   story + asciinema. HN is the biggest single star spike.
2. **r/netsec, r/bugbounty, r/AskNetsec** — same hook + gif. r/netsec is
   high-signal; follow its self-promo rules (mod-gated, so make it genuinely useful).
3. **X/Twitter infosec** — tag/àla @NahamSec, @stokfredrik, @intigriti,
   @Hacker0x01, @Bugcrowd; thread with the gif. Bounty Twitter shares hard.
4. **Newsletters:** tldrsec (Clint Gibler), Hacker Newsletter, Bug Bytes
   (Intigriti), Critical Thinking podcast/newsletter. Email a 3-line pitch + gif.
5. **dev.to / Hashnode** post: "I built a proxy so I can never go out of scope."
6. **ProductHunt** (secondary; infosec PH reach is modest but adds backlinks).
7. **Awesome lists:** PR into `awesome-bug-bounty`, `awesome-pentest`,
   `awesome-hacking`, `awesome-go`. Evergreen discovery + backlinks.

## B3. Positioning (borrow trust from tools they know)
Frame against the familiar: "mitmproxy/Burp let you SEE traffic; ScopePilot makes
sure you never send it somewhere you shouldn't." Comparison table in README:
ScopePilot vs Burp scope vs raw curl — column "blocks out-of-scope at the network
layer" only ScopePilot ticks.

## B4. The trigger keywords (bake into README prose + topics + post titles)
These are the search/SEO terms people type — seed them naturally:
`bug bounty scope`, `out of scope`, `scope enforcement`, `recon proxy`,
`bbot proxy`, `nuclei scope`, `authorized testing`, `kill switch`, `rate limit
proxy`, `https_proxy security`, `responsible disclosure guardrails`.

## B5. Sustain (stars compound or decay)
- Respond to every issue/PR < 24h for the first month (responsiveness → trust → stars).
- Ship a visible CHANGELOG; cut releases often (each release = a re-share moment).
- Pin a "roadmap" issue; let users vote (engagement → return visits → stars).
- Screenshot real blocks ("ScopePilot just saved me from a ban") = best organic ad.

## B6. Launch-day timeline (one page)
- **T-7d:** finish Part-A Tier 1 (install + CONNECT + init) + record gif.
- **T-3d:** README polish, topics, badges, seed good-first-issues, awesome-list PRs.
- **T-1d:** draft Show HN title + first-comment story; line up newsletter emails.
- **T-0 (Tue–Thu am ET):** Show HN → r/netsec → X thread, same hour. Reply fast all day.
- **T+1..7:** newsletters land, dev.to post, respond to every comment/issue.

> Order of operations is the whole game: **Tier-1 features → gif → README →
> Show HN**. Launching without the one-line install or the gif wastes the spike.

---

# PART C — v0.2 refinement plan (from kratos's field report)

Verdict from a real hunt: "a scope gate you can trust today, not yet a hunt
platform you live in all day." Ranked by daily-driver leverage.

## R1 — Result orchestrator loop (closes the spawn gap) [HIGH]
`spawn` fires workers but nothing consumes their output — results sit in
`~/.scopepilot/results/` for the user to read by hand. Build an orchestrator:
poll/consume worker results, mark queue items done/failed, and auto-chain
(recon results → seed scan queue). `scopepilot run` = queue + spawn + consume
in one loop. This is what turns spawn from a toy into the hunt engine.

## R2 — Persistent decisions: SQLite-backed ring buffer [HIGH]
On crash you lose the last N minutes of decisions; `watch`/`health` only see
in-memory state. Persist audit decisions to a SQLite ring buffer so `watch`,
`/health`, and `get_recent_decisions` survive a restart and the audit trail is
durable. Foundational for trust.

## R3 — One-command startup, kill the friction [HIGH]
Startup friction is the #1 reason people abandon proxies. Add `scopepilot up`:
start server (daemon), print the exact `export https_proxy=…` line, confirm
health — one command from zero to gated. Polish `--daemon`/`stop` so it's
reliable.

## R4 — Windows / WSL support [MED]
Most pentesters are on Windows/WSL. `init` assumes a Unix home; `watch` uses raw
ANSI. Make home-dir resolution cross-platform, guard ANSI behind capability
detection, CI-test the windows build. Unlocks a big adoption slice.

## R5 — Menubar/tray status [MED, optional]
A green/red tray icon with "copy proxy line" + "open watch" removes the
keep-a-terminal-open tax. Nice daily-driver polish; heavier (native GUI) so
after R1–R3.

## R6 — Path-level HTTPS scope via MITM (`--mode intercept`) [DEFERRED]
CONNECT tunnels only scope-check the host, so path-prefix excludes don't apply
to HTTPS. MITM fixes it but installs a CA in the trust store — security-sensitive
(see Part A non-goals). Keep gated behind `--mode intercept --accept-mitm-risk`,
host-bound, easy uninstall. Do LAST, on its own.

## Build order
R1 → R2 → R3 (the daily-driver core) → R4 → R5 → R6 (separate, gated).
