# Example output — AWS & GCP (multi-platform comparison)

A complete, real run of the `cloud-security-posture` skill, kept here so you can see
exactly what it produces before running it yourself. Generated 2026-06-01.

**Scenario:** a multi-team organization protecting its **own proprietary IP** (source,
model weights, internal docs), running AI/GPU + general compute + serverless across many
accounts (AWS) / projects (GCP) under one organization. Each platform is evaluated as an
**absolute deep-dive against its own well-architected best practice** — not against the
other for a "winner" — and then compared side by side.

## What's here

**Reports (start here):**
- [`aws-assessment.md`](./aws/aws-assessment.md) — AWS single-platform report (122 probes)
- [`gcp-assessment.md`](./gcp/gcp-assessment.md) — GCP single-platform report (115 probes)
- [`aws-gcp-comparison.md`](./comparison/aws-gcp-comparison.md) — the side-by-side comparison

**CSV outputs (by generator mode):**
| File | `generate_csv.py --mode` | What it is |
|---|---|---|
| [`aws-deep-dive.csv`](./aws/aws-deep-dive.csv), [`gcp-deep-dive.csv`](./gcp/gcp-deep-dive.csv) | `deep-dive` | one row per probe (status / finding / gap / risk / doc_quality / evidence) |
| [`comparison-matrix.csv`](./comparison/comparison-matrix.csv) | `matrix` | platforms × 21 capability dimensions; cells are `<status> — <note>` |
| [`aws-audit-checklist.csv`](./aws/aws-audit-checklist.csv), [`gcp-audit-checklist.csv`](./gcp/gcp-audit-checklist.csv) | `audit` | the recommendations as an **account-runnable** punch-list (how-to-check / pass-criterion / remediation; `current_state` blank to fill in) |
| [`aws-corrections.csv`](./aws/aws-corrections.csv), [`gcp-corrections.csv`](./gcp/gcp-corrections.csv) | `corrections` | the adversarial fact-check ledger (see caveat below) |
| [`probing-checklist.csv`](./probing-checklist.csv) | `checklist` | the platform-agnostic probe scaffold (every probe seeded `unknown`) |

**Source data:**
- [`aws.json`](./aws/aws.json), [`gcp.json`](./gcp/gcp.json) — the JSON assessments the CSVs and
  reports are built from. These double as a worked example of the schema in
  [`../plugins/cloud-security-posture/skills/cloud-security-posture/references/output-formats.md`](../plugins/cloud-security-posture/skills/cloud-security-posture/references/output-formats.md).
  To regenerate any CSV: `python3 ../plugins/cloud-security-posture/skills/cloud-security-posture/scripts/generate_csv.py --mode matrix --in aws/aws.json gcp/gcp.json --out-dir /tmp/regen`

## Honest caveat about the `*-corrections.csv` files

These were recorded as a **full verification ledger**, not a corrections-only list: ~95%
of the rows are `verdict=confirmed` (the fact-check ran and the claim held), and only ~10
per platform are the real overturns (`refuted`/`outdated`) that changed a finding — e.g.
AWS CodeCommit returned to GA Nov 2025, the AWS CISO is now Amy Herzog, `ec2:RunInstances`
spans twelve resource types. The human-facing reports summarize this correctly ("N checks,
M overturned" + a corrections table). The overturns are the rows where `correction` is
non-empty and `reconciled=true`. This is a known characteristic of the current run, kept
here as-is rather than trimmed.
