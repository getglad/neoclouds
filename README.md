# neoclouds

A [Claude Code](https://code.claude.com) plugin marketplace. Currently ships one plugin:

- **`cloud-security-posture`** — evaluate a cloud platform's security posture from its
  public surface (docs, API specs, console, changelogs, trust center, forums, third-party
  media) across five signals — visibility, identity granularity, supply chain,
  organizational maturity, transparency — plus network, edge-middleware, source-control,
  and organizational-substrate cross-cutting concerns. Includes an adversarial fact-check
  pass on time-sensitive claims. Produces a markdown assessment report paired with
  deep-dive and comparison CSVs, a corrections log, and an account-runnable audit
  punch-list.

## Installation

Add the marketplace, then install the plugin:

```
/plugin marketplace add getglad/neoclouds
/plugin install cloud-security-posture@neoclouds
```

To update later, refresh the marketplace and the plugin picks up new releases:

```
/plugin marketplace update neoclouds
```

The plugin is version-pinned (currently `0.0.1`), so you receive updates only when a new
version is released — not on every commit.

### Verify before installing (optional)

```
git clone https://github.com/getglad/neoclouds
claude plugin validate ./neoclouds
claude plugin validate ./neoclouds/plugins/cloud-security-posture
```

## Usage

Once installed, the skill activates automatically when you ask Claude Code to evaluate,
audit, threat-model, or compare the security of one or more cloud platforms. You can also
invoke it explicitly:

```
/cloud-security-posture:cloud-security-posture
```

The bundled CSV generator (`scripts/generate_csv.py`, standard library only) supports
five modes:

```bash
# Single platform — one row per probe
python scripts/generate_csv.py --mode deep-dive --in <platform>.json --out-dir ./out

# Multiple platforms — per-platform CSVs plus a side-by-side comparison matrix
python scripts/generate_csv.py --mode matrix --in a.json b.json c.json --out-dir ./out

# Blank scaffold — the full probe set seeded `unknown`, no JSON needed
python scripts/generate_csv.py --mode checklist --out-dir ./out

# Fact-check pass — refuted/outdated/uncertain claims with sources
python scripts/generate_csv.py --mode corrections --in <platform>.json --out-dir ./out

# Audit punch-list — recommendations as account-runnable checks (distinct from `checklist`)
python scripts/generate_csv.py --mode audit --in <platform>.json --out-dir ./out
```

Run the generator's tests with `python3 -m unittest discover -s scripts -p 'test_*.py'`.

## Examples

A complete real run — AWS and GCP evaluated and compared side by side — lives in
[`examples/`](./examples/), so you can see what the skill produces before running it:
the per-platform reports, the comparison report and matrix, the account-runnable audit
punch-lists, the fact-check ledgers, and the source JSON. See
[`examples/README.md`](./examples/README.md) for a guide. (Examples live at the repo root,
not under `plugins/`, so they don't ship with the installed plugin.)

## Repository layout

```
.claude-plugin/marketplace.json                 # marketplace catalog
plugins/cloud-security-posture/
  .claude-plugin/plugin.json                     # plugin manifest
  skills/cloud-security-posture/
    SKILL.md                                      # the skill
    references/                                   # baseline, probe checklist, output formats
    scripts/generate_csv.py                       # CSV generator
    scripts/test_generate_csv.py                  # generator tests (stdlib unittest)
examples/                                         # a full AWS+GCP run (not shipped on install)
  aws/  gcp/                                       # per-provider reports + CSVs + source JSON
  comparison/                                      # side-by-side report + comparison matrix
  probing-checklist.csv                            # the platform-agnostic probe scaffold
```

## License

[MIT](./LICENSE)
