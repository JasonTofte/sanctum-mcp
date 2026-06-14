# Sanctum — FIND EVIL! submission writeup

Paste-ready text for the Devpost form. Plain language, judge-facing.

## The problem

Incident response is moving to AI agents, and two failures make that dangerous. Both get worse as agents act on their own.

First, the evidence is written by the attacker. Malware names, log entries, and registry values can carry hidden text that hijacks an AI reading them. Sygnia showed this in August 2025: a crafted PowerShell block made an AI summarizer report a Mimikatz credential theft as routine maintenance. Second, an agent with a shell can destroy the evidence it is investigating, by mistake or by jailbreak.

The hackathon asks the right question: are the guardrails built into the system, or just written in the prompt? Prompt rules fail under jailbreak. Anthropic reported attackers doing exactly that at up to 90% automation in November 2025.

## What Sanctum does

Sanctum is a Model Context Protocol server. It gives an AI agent a small, fixed set of Windows forensic tools and nothing else. The safety lives in the server, not the prompt.

- No shell. No destructive tool exists, so none can be called.
- Evidence is read-only at the operating-system level. Every tool call is hashed into an append-only, HMAC-chained log.
- Findings pass through one typed function, `claim_finding`. It refuses claims it cannot trace to real evidence, and it grades them by how many independent evidence families agree.

One source is a DRAFT. Two agreeing families make it CORROBORATED. Three make it FINAL. If anti-forensic traces are present, the gate refuses to sound confident. Because the gate is a function at the server boundary, no prompt or jailbreak can switch it off.

## Results

On a 43-question DFIR-Metric subset (3 runs, Opus 4.7), Sanctum scored **99.2%** against **16.3%** for the same model with no server — an **82.9-point gap**. Precision on confirmed findings was 97.2%.

We then ran it against an independent case: the NIST CFReDS Data Leakage image, which ships with a NIST-authored answer key. Sanctum's parsers found all 8 applications the key lists. The three case-defining tools — Eraser, CCleaner, and Google Drive — were each confirmed across three separate families. The suspect had run Eraser and CCleaner to wipe traces, yet the execution evidence survived in every family. iCloud showed in only one family, and Sanctum reported it as a single-source draft rather than overclaiming. The answer key explains why: iCloud was uninstalled.

## How we built it

A Python MCP server on the official SDK. Six real parsers (regipy, python-evtx, windowsprefetch) for the five evidence families. A two-layer corroboration gate plus a timestamp-forgery check. An append-only audit log with an HMAC chain and optional RFC 3161 timestamps. Dependencies are hash-locked so a swapped wheel is rejected at install.

## Honest limits

- The model can still misread correct evidence; that is the model's job, and we measure it separately.
- The injection filter is a list of known patterns, not every possible one.
- The NIST check ran on Windows 7, where only three of five families exist, so live coverage is partial.
- A kernel rootkit that forges several families at once defeats the count by design.

## What's next

Memory-based artifacts, a modern host with all five families live, and a question set written by someone outside the team.

## Built with

Python, Model Context Protocol, Claude (Opus 4.7), regipy, python-evtx, windowsprefetch, SIFT, NIST CFReDS.
