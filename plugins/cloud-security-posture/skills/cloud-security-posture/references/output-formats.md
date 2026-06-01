# Output Formats

This skill produces two paired deliverables per evaluation: a human-readable markdown
report AND CSV(s) for spreadsheet use. Both are mandatory. They're built from the same
underlying JSON assessment data so they always stay consistent.

## The JSON assessment schema

This is the data source for both the markdown report and the CSVs. Build it once
per platform from your research, then feed it to `scripts/generate_csv.py` and use
the same data to write the markdown.

**Example (illustrative — uses a placeholder platform name; replace with the real
name when you populate this for a real run):**

```json
{
  "platform": "ExamplePlatform",
  "evaluated_at": "YYYY-MM-DD",
  "context": {
    "offerings": "GPU compute, object storage",
    "use_cases": "inference endpoints, model training",
    "assets_at_stake": "proprietary model weights + customer prompt data (sensitive)",
    "trust_boundary": "single workspace, multiple environments",
    "comparison_baseline": "AWS"
  },
  "signals": {
    "visibility": [
      {
        "probe": "Admin/audit log separation",
        "status": "partial",
        "finding": "Audit events separated from container/app logs; SOC 2 confirmed.",
        "evidence": "<platform docs URL>",
        "gap": "No SIEM-stream export documented; dashboard-only access on this tier.",
        "risk": "Detection logic can't run on platform events without periodic API polling.",
        "doc_quality": "Documented",
        "matrix_keys": ["visibility_export", "audit_schema"]
      }
    ],
    "identity_granularity": [
      {
        "probe": "Workload identity (OIDC)",
        "status": "present",
        "finding": "Short-lived OIDC token injected per container; discovery endpoint published.",
        "evidence": "<platform docs URL>",
        "gap": "Destination cloud sub-claim matching only (no custom claims) — practitioner gotcha.",
        "risk": "Low; sub claim is rich enough for most use cases.",
        "doc_quality": "Documented",
        "matrix_keys": ["workload_identity"]
      },
      {
        "probe": "RBAC granularity",
        "status": "partial",
        "finding": "Two-tier model: workspace roles plus environment-scoped contributor/viewer.",
        "evidence": "<platform docs URL>",
        "gap": "No custom roles. Environment-level RBAC requires highest tier.",
        "risk": "Medium for lower-tier customers — collapses to workspace-wide privilege.",
        "doc_quality": "Documented",
        "matrix_keys": ["custom_roles"]
      },
      {
        "probe": "Brokered registry credentials",
        "status": "partial",
        "finding": "Container images can be pulled via OIDC federation for one destination cloud; secret-based auth elsewhere.",
        "evidence": "<platform docs URL>",
        "gap": "Other registries still require long-lived secrets stored in the platform's secrets store.",
        "risk": "Brokered-credential leak path; partially mitigated.",
        "doc_quality": "Documented",
        "matrix_keys": ["brokered_secrets_management"]
      }
    ],
    "supply_chain": [],
    "org_maturity": [],
    "transparency": []
  },
  "cross_cutting": {
    "network_architecture": [],
    "serverless_edge_middleware": [],
    "source_control": [],
    "organizational_substrate": []
  },
  "recommendations": [
    "Use restricted environments for production with explicit contributor grants.",
    "Use service users + service tokens for any automation, including AI agents."
  ]
}
```

**Field notes:**

- `platform` — short canonical name. Use this for filenames too.
- `signals` — keys must be one of: `visibility`, `identity_granularity`, `supply_chain`,
  `org_maturity`, `transparency`. Each is an array of probe findings (possibly empty
  if you didn't dig into that signal).
- `cross_cutting` — same shape; keys: `network_architecture`,
  `serverless_edge_middleware`, `source_control`, `organizational_substrate`.
- `status` — **required per probe.** Exactly one of: `present`, `partial`, `absent`,
  `misleading`, `unknown`. This is your explicit judgment of whether the capability is
  there, and it is what the comparison matrix reads. Do **not** leave the matrix to infer
  it from prose — a finding that *states an absence* ("No workload identity surfaced") is
  an `absent`, not a `present`. Assign it deliberately.
- `matrix_keys` — optional list of comparison-matrix column ids this probe should
  populate (e.g. `["workload_identity"]`; ids are the short names in the canonical
  column list below). If omitted, the script falls back to keyword matching, which is
  best-effort. Tag anything you want reliably placed in the matrix.
- `doc_quality` — exactly one of: `Documented`, `Documented but Misleading`,
  `Discoverable`, `Absent`. Case matters for the CSV. This is orthogonal to `status`:
  a capability can be `present` but `Absent` from docs (you found it by testing), or
  documented yet `misleading`.

## Output 1: Per-platform deep-dive CSV

One row per probe. Generated by `scripts/generate_csv.py --mode deep-dive`.

Columns:

| Column | Source |
|---|---|
| `platform` | top-level `platform` field |
| `signal` | which signal category the probe lives under (`visibility`, `identity_granularity`, ..., or one of the cross-cutting keys with a `cross_cutting:` prefix, e.g. `cross_cutting:network_architecture`) |
| `probe` | `probe` field |
| `status` | `status` field (`present` / `partial` / `absent` / `misleading` / `unknown`) |
| `finding` | `finding` field |
| `gap` | `gap` field |
| `risk` | `risk` field |
| `doc_quality` | `doc_quality` field |
| `evidence` | `evidence` field |

Example file: `<platform>-deep-dive.csv` (using the actual platform's name in your run).

## Output 2: Comparison matrix CSV (multi-platform only)

Rows = platforms, columns = capability dimensions. Cells = `<status> — <brief note>`.
Generated by `scripts/generate_csv.py --mode matrix`.

The columns are a fixed canonical set (defined in the script) so matrices across
runs stay comparable. They are:

```
visibility_export, audit_schema, container_log_retention,
custom_roles, workload_identity, short_lived_creds, brokered_secrets_management,
image_signing, hardware_attestation,
hierarchy, policy_guardrails, central_identity_sso,
network_isolation, edge_authorizers, edge_rate_limiting,
composable_scoping_primitives, source_control_integration,
soc2_scope, vdp_or_bug_bounty, security_changelog,
incorporation_jurisdiction
```

How a cell is populated:

1. The script collects the probe(s) you tagged with that column's id in `matrix_keys`.
   If none are tagged, it falls back to keyword matching within the column's signal
   category (best-effort, for JSON that predates `matrix_keys`).
2. **Status is read directly from the contributing probe's `status` field — never
   inferred from the prose.** When several probes map to one column, the most cautionary
   status wins (`misleading` > `absent` > `partial` > `present` > `unknown`) so a gap is
   never masked by a rosier sibling probe.
3. A `Documented but Misleading` `doc_quality` surfaces as a `misleading` status so the
   reader is warned that a familiar term is hiding a weaker reality.
4. If no probe maps to a column, the cell is `unknown`.

Example file: `comparison-matrix.csv`.

The matrix is meant to be loaded into a spreadsheet — the note is trimmed at a word
boundary so the matrix stays scannable. For the full detail behind any cell (gap, risk,
evidence, doc-quality), the reader goes to the per-platform deep-dive CSV or the markdown
report.

## Output 3: Markdown report

Always paired with the CSV(s). One report file per evaluation run.

**Single-platform mode:** `<platform>-assessment.md`.

```markdown
# <Platform> — Security Posture Assessment

**Evaluated**: <date>
**CSV outputs**: `<platform>-deep-dive.csv`
**Source data**: `<platform>.json`

## Context
- Offerings in use: ...
- Use cases: ...
- Assets at stake: ... (your proprietary assets vs. customer data/workloads, and sensitivity)
- Trust boundary: ...
- Comparison baseline: ...
- Timeline: ... (how much runway before go-live — drives what gets flagged as
  pre-go-live vs. trackable ongoing risk)

## Top-line read
2–3 short paragraphs the busy reader reads first: the overall posture, the 1–2 things
the platform does genuinely well (credit them), and the 1–2 gaps that need compensating
controls before go-live.

## Signal 1: Visibility
One sub-block per probe (a signal usually has several). For each probe give:
**Probe** · **Status** (present/partial/absent/misleading/unknown) · **Finding** ·
**Evidence** · **Gap** · **Risk** · **Documentation quality**.

## Signal 2: Identity Granularity
...

(repeat per signal, then one section per relevant cross-cutting concern)

## Recommendations
1. ...
2. ...
```

**Multi-platform mode:** `<short-platform-list>-comparison.md`.

```markdown
# <Platforms> — Comparison

**Evaluated**: <date>
**CSV outputs**:
- `comparison-matrix.csv` (side-by-side)
- `<platform1>-deep-dive.csv`, `<platform2>-deep-dive.csv`, ...

## Top-line summary
2–3 paragraphs: which platforms cluster together, which are outliers, what surprised
the evaluator. Don't repeat the matrix — point at it.

## Where each platform sits
Per-platform mini-section, 1–2 paragraphs each. What's their best signal, their worst
signal, and the one thing a practitioner needs to know if they're about to adopt.

## Per-signal observations
Optional section. For each signal category, note the cluster of platforms that handle
it well, the cluster that don't, and any outliers worth crediting or flagging.

## Recommendations
Per-platform recommendations (concise). Don't repeat what's in the per-platform
markdown if those exist — point at them.
```

## Running the CSV script

```bash
# Single platform — produces just the deep-dive CSV
python scripts/generate_csv.py --mode deep-dive --in platform-a.json --out-dir ./output

# Single platform with markdown report path printed
python scripts/generate_csv.py --mode deep-dive --in platform-a.json --out-dir ./output --print-paths

# Multi-platform — produces deep-dive CSVs for each + the matrix
python scripts/generate_csv.py --mode matrix --in platform-a.json platform-b.json platform-c.json --out-dir ./output

# Checklist scaffold — full probe set as a fill-in CSV, every probe seeded `unknown` (no JSON needed)
python scripts/generate_csv.py --mode checklist --out-dir ./output
```

Always pass `--out-dir`. The script creates the directory if missing. It depends only on
the Python standard library, so it runs anywhere `python3` does.

## File naming convention

- `<platform>-deep-dive.csv` (lowercase, hyphens)
- `comparison-matrix.csv`
- `<platform>-assessment.md`
- `<platforms-joined>-comparison.md`
- `<platform>.json` — the source data file

Keep the casing and hyphenation consistent — downstream tooling and re-evaluations
depend on stable filenames.
