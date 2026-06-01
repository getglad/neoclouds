---
name: cloud-security-posture
description: >
  Investigate and document a cloud platform's security posture from its public surface —
  documentation, API specifications, console, changelogs, trust center, community
  forums, and third-party media (blogs, news, analyst coverage) — across five signals
  (visibility, identity granularity, supply chain,
  organizational maturity, transparency) plus network protection and isolation, edge middleware, source-control integration, and organizational guardrails, then produce a
  structured assessment report together with deep-dive and comparison CSVs. Use this
  whenever someone asks you to evaluate, audit, threat-model, or compare the security of
  one or more cloud platforms, wants a factual, evidence-backed account of what a platform supports and documents (and where it doesn't), or
  asks for a side-by-side security comparison or a CSV of findings — for any cloud
  provider, large or small, familiar or not.
---

# Cloud Security Posture Evaluation

Evaluate a cloud platform's security posture by investigating its public surface and
producing two paired deliverables: a markdown assessment report and CSV(s). The probes
you run live in `references/probing-checklist.md`; the output schema and the CSV
generator live in `references/output-formats.md` and `scripts/generate_csv.py`. This file
is the workflow that drives them.

Read the platform's own claims skeptically. The same familiar term — "audit log," "RBAC,"
"scoped key" — can name a robust control on one platform and a hollow one on another, so
don't take the vocabulary at face value; verify what is actually behind it. For each
probe, record not just whether a capability exists but whether you can actually use it for
the security outcome you need — write a least-privilege policy, scope a token to a single
action, rotate a credential, get events into your SIEM — and whether the platform's own
documentation matches what you find. That skepticism is what keeps the assessment from
being a feature checklist.

This is objective evidence-gathering, not a safety verdict. Every finding is a concrete,
sourced statement of what the platform does, does not do, or does not document — and to
what extent, with caveats. Whether that adds up to "safe to adopt" is the reader's call,
not yours. When the public evidence isn't enough to conclude, say exactly that: an honest
"unknown" is a finding, not a failure — never manufacture a verdict the evidence doesn't
support. Treat the result as a first pass: a human or a follow-up agent then proofs the
findings and drives the `unknown`s to closure with deeper investigation — surfacing
exactly what still needs digging into is part of the deliverable, not a shortfall.

## Step 1 — Establish context

Pin down the deployment context first; it decides which signals matter most and how deep
to go.

1. **Platform(s)** — name the provider(s) under evaluation.
2. **Offerings in use** — which *services* are consumed: accelerated/GPU compute, general
   compute, object/block storage, managed/first-party services?
3. **Use cases** — what those services are *for*: model training, inference/serving
   endpoints, batch jobs, dev sandboxes. Offering and use case stress different controls.
4. **Assets at stake** — what the workloads carry: your own proprietary assets (source,
   model weights, internal documents), your customers' data and workloads, or both — and
   how sensitive it is (PII, regulated, proprietary, public). This sets the blast radius
   the rest of the evaluation is sized against.
5. **Trust boundary** — single team, multi-tenant org, external customers?
6. **Comparison baseline** — what controls does the user expect to exist (e.g. coming from
   AWS, GCP, or Azure)? Name where the platform diverges rather than restating it.

Then choose the mode: **single-platform deep dive**, **multi-platform comparison**, or a
**checklist scaffold** — the full probe set exported with every probe seeded `unknown`, so
a first pass can be filled in and the remaining unknowns driven to ground over time. In
every mode the output is a first pass meant to be proofed and extended, not a final
verdict: you (or a follow-up run) do the initial sweep, then a person or another agent
validates it and investigates the unknowns. The unknowns are the worklist. The mode
determines which outputs you generate in Step 4.

## Step 2 — Investigate, signal by signal

Work `references/probing-checklist.md` one signal at a time. It holds the full probe set
with the reason each probe matters — read it and use it; don't re-derive the probes here.
For each signal, gather evidence from these sources in order. Earlier sources are
authoritative; later ones fill gaps, reveal trajectory, and surface outside scrutiny.

1. **Official docs** — IAM, API references, security whitepapers. Note what is documented
   and what is conspicuously absent.
2. **API specifications** — reveal auth mechanisms and which operations exist.
3. **Console / screenshots** (when available) — settings pages often expose capabilities
   or gaps the docs don't mention.
4. **Changelogs / blog posts** — new security features land here before the docs catch
   up; they also show the platform's direction.
5. **Community forums / GitHub issues** — practitioners asking about the real gaps.
6. **Trust center / compliance pages** — SOC 2 / ISO scope, transparency reports.
7. **Third-party media & analyst coverage** — independent blogs, news, incident
   write-ups, and industry analysts (e.g. Gartner, Forrester). Surfaces outside scrutiny
   the platform won't self-report: breach coverage, practitioner critiques, and the
   market/business context that feeds organizational-maturity and transparency risk.

What each signal is checking — keep the probe enumeration in
`references/probing-checklist.md`; the notes below are only the cues for how to read what
you find:

- **Visibility** — can you reconstruct who did what and when, and get those events to your
  detection stack? Sharp cue: an "audit log" may be application stdout, and the export path
  is often API-query-only rather than a stream to your SIEM.
- **Identity granularity** — can you scope *any* principal (human, service, or agent) to
  least privilege? Probe two distinct kinds of credential, not as a hierarchy:
  **platform-access** (issued to you to act on the platform) and **brokered** (held by the
  platform to reach systems it doesn't own — secrets management). Record whether the
  primitives are actually usable, not just present. Don't expect a separate "agent
  identity" feature; an agent is just another caller, so a token you can't scope to a
  single action can't be safely delegated to automation either.
- **Supply chain** — can you verify what you're running and who can change it?
- **Organizational maturity** — does the provider have the machinery to respond when
  something breaks? The cheap tell is a VDP with safe-harbor language; watch the *actual*
  SOC 2 scope vs. what's assumed.
- **Transparency** — how the platform handles what it does *not* do. Classify each
  finding's documentation quality (Step 3); a platform that documents its own gaps is
  giving you something to act on, and that classification is itself a finding.

Then investigate the cross-cutting concerns that span signals: **network protection &
isolation** (often the weakest area on platforms built to expose endpoints publicly by default), **edge middleware**,
**source-control integration**, and the **organizational substrate** — the
hierarchy/policy-guardrail layer above individual accounts, often thin or absent.

## Step 3 — Record each probe as a structured finding

Capture these fields for every probe (full schema in `references/output-formats.md`):

- **status** — `present` / `partial` / `absent` / `misleading` / `unknown`. Assign it
  deliberately, from evidence. A finding that *states an absence* ("no workload identity
  surfaced") is `absent`, not `present` — don't let prose flip the verdict.
- **finding** — what is actually there, concretely.
- **evidence** — a URL or quote. No evidence means the status is at best `unknown`.
- **gap** — what is missing or weaker than the baseline from Step 1.
- **risk** — the consequence, sized to the workload and trust boundary, not in the
  abstract.
- **doc_quality** — `Documented` / `Documented but Misleading` / `Discoverable` /
  `Absent`. Orthogonal to status: a capability can be `present` but doc-quality `Absent`
  (you found it by testing), or documented yet `misleading` — a familiar term implying
  more than it delivers, which is the most dangerous case because it makes teams stop
  looking.
- **matrix_keys** (optional, multi-platform) — the comparison-matrix column ids this
  probe informs, so it lands in the right cell deterministically instead of by keyword
  guess.

## Step 4 — Generate the outputs

Every evaluation produces a markdown report **and** CSV(s) — one deliverable in two forms,
built from the same JSON so they never drift. See `references/output-formats.md` for the
JSON schema, CSV columns, and report templates.

1. **Build the JSON assessment** — one file per platform, populated with the Step 3
   fields.
2. **Run the generator** (don't hand-roll CSVs — the script escapes correctly and keeps
   columns stable across runs):
   ```bash
   python scripts/generate_csv.py --mode deep-dive --in <platform>.json --out-dir ./out
   # multi-platform: --mode matrix --in a.json b.json c.json   (also writes comparison-matrix.csv)
   # checklist only: --mode checklist                          (no JSON needed)
   ```
3. **Write the report from the same JSON** — `<platform>-assessment.md` (single) or
   `<platforms>-comparison.md` (multi): context, a top-line read, per-signal findings,
   cross-cutting, and recommendations.
4. **Deliver report + CSV(s) together**, with the CSV path(s) referenced at the top of the
   report so the reader knows where the spreadsheet-ready data is.

## Calibration

Habits that keep the assessment trustworthy and usable:

- **Status follows evidence, not impression.** When you can't substantiate it, use
  `unknown` — don't round up to `present`.
- **Documentation quality is a finding**, not metadata. Silence about a limitation is its
  own signal.
- **Don't universalize.** Report where *this* platform sits ("on this platform, X is
  absent"), not class-wide verdicts ("providers like this never have X").
- **Stay factual; credit strengths alongside gaps.** You're producing an objective record
  for the reader to act on — not a verdict, a score, or a takedown. Note what is genuinely
  well done as readily as what is missing, and keep the tone neutral.
