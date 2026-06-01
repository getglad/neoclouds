#!/usr/bin/env python3
"""
generate_csv.py — CSV outputs for the cloud-security-posture skill.

Modes:
  deep-dive   — one CSV per platform, rows = probes (default for single-platform input)
  matrix      — one CSV across platforms, rows = platforms (requires ≥2 inputs)
  checklist   — full probe set as a first-pass scaffold CSV, every probe seeded unknown (no JSON input)
  corrections — one CSV per platform: fact-check verdicts (refuted/outdated/...) with sources
  audit       — one CSV per platform: recommendations as an account-runnable audit punch-list

The `checklist` and `audit` modes are different deliverables: `checklist` exports the
probing *questions* as a blank scaffold; `audit` turns the assessment's *recommendations*
into account-runnable check items. They never share a filename.

Schema for JSON inputs: see references/output-formats.md
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path


# Canonical matrix columns. Stable order so matrices across runs stay comparable.
MATRIX_COLUMNS = [
    # Visibility
    ("visibility_export", "Visibility — Audit log export to your stack",
     ["visibility"], ["log export", "siem", "stream", "webhook"]),
    ("audit_schema", "Visibility — Audit log schema documented",
     ["visibility"], ["schema", "fields", "documented"]),
    ("container_log_retention", "Visibility — Container/app log retention",
     ["visibility"], ["container", "stdout", "application log", "retention"]),
    # Identity Granularity
    ("custom_roles", "Identity — Custom roles supported",
     ["identity_granularity"], ["custom role", "custom roles", "rbac"]),
    ("workload_identity", "Identity — Workload identity / OIDC",
     ["identity_granularity"], ["oidc", "workload identity", "federation"]),
    ("short_lived_creds", "Identity — Short-lived credential exchange",
     ["identity_granularity"], ["short-lived", "sts", "token exchange", "expir"]),
    ("brokered_secrets_management", "Identity — Brokered secrets controls",
     ["identity_granularity"], ["brokered", "secrets management", "registry credential", "secrets broker"]),
    # Supply Chain
    ("image_signing", "Supply Chain — Container image signing/verification",
     ["supply_chain"], ["signing", "cosign", "sigstore", "image verification"]),
    ("hardware_attestation", "Supply Chain — Hardware/firmware attestation",
     ["supply_chain"], ["attestation", "firmware", "tpm", "secure boot"]),
    # Distinct from hardware_attestation: that column is provider-side integrity ("has
    # this machine been tampered with"); this one is tenant-facing confidentiality ("can
    # I run workloads the provider itself cannot read"). Keyword hints avoid bare "tee"
    # and "sev" — substrings of common words (committee, severity).
    ("confidential_compute", "Supply Chain — Confidential compute / TEE for tenant workloads",
     ["supply_chain"], ["confidential", "sev-snp", "tdx", "sgx", "enclave", "memory encryption"]),
    # Organizational substrate / cross-cutting
    ("hierarchy", "Org Substrate — Hierarchy (Org/Folder/Project)",
     ["cross_cutting:organizational_substrate"], ["hierarchy", "organization", "folder", "project"]),
    ("policy_guardrails", "Org Substrate — Policy guardrails (SCP-equivalent)",
     ["cross_cutting:organizational_substrate"], ["scp", "policy", "guardrail", "org policy"]),
    ("central_identity_sso", "Org Maturity — Central identity / SSO / SCIM",
     ["org_maturity", "identity_granularity"], ["sso", "saml", "scim", "oidc", "entra"]),
    # Network
    ("network_isolation", "Network — Protection & isolation",
     ["cross_cutting:network_architecture"],
     ["vpc", "isolation", "peering", "private network", "firewall", "egress", "public"]),
    # Edge
    ("edge_authorizers", "Edge Middleware — Custom authorizers",
     ["cross_cutting:serverless_edge_middleware"], ["authorizer", "jwt", "oauth introspect"]),
    ("edge_rate_limiting", "Edge Middleware — Rate limiting",
     ["cross_cutting:serverless_edge_middleware"], ["rate limit", "rate-limit", "throttl"]),
    # Composable scoping primitives — these live under identity and apply to ANY principal
    # (human, service, or agent), not a separate "agentic" capability.
    ("composable_scoping_primitives",
     "Identity — Composable scoping primitives (token exchange, session policy/metadata)",
     ["identity_granularity"],
     ["token exchange", "session tag", "session policy", "source identity", "session metadata"]),
    # Source control
    ("source_control_integration", "Source Control — Repo integration scoping",
     ["cross_cutting:source_control"], ["github", "gitlab", "bitbucket", "oauth app", "repo scope"]),
    # Org maturity
    ("soc2_scope", "Org Maturity — SOC 2 scope (product coverage)",
     ["org_maturity"], ["soc 2", "soc2", "type ii", "type 2"]),
    ("vdp_or_bug_bounty", "Org Maturity — VDP or bug bounty",
     ["org_maturity"], ["vdp", "bug bounty", "vulnerability disclosure"]),
    ("security_changelog", "Org Maturity — Security changelog / advisories",
     ["org_maturity"], ["changelog", "advisor", "security release"]),
    # Geopolitical
    ("incorporation_jurisdiction", "Org Maturity — Incorporation jurisdiction & data center locations",
     ["org_maturity"], ["incorporat", "jurisdiction", "data center", "sovereign"]),
    ("operational_track_record", "Org Maturity — Operational track record (age, team size)",
     ["org_maturity"], ["founded", "team size", "headcount", "track record", "operating since"]),
]


# Controlled vocabulary for a probe's explicit status. The author assigns this in the
# JSON; the matrix reads it directly rather than inferring it from prose. Inference
# inverts whenever a finding states an absence (e.g. "No workload identity surfaced"
# was being scored "yes"), so the status is now an explicit, author-owned field.
STATUS_VOCAB = {"present", "partial", "absent", "misleading", "unknown"}

# Most-cautionary-first ordering, used to pick a single status when several probes map
# to one matrix column. A gap must never be hidden behind a rosier sibling probe.
STATUS_SEVERITY = {"misleading": 0, "absent": 1, "partial": 2, "present": 3, "unknown": 4}

# Controlled vocab for a verification verdict (the adversarial fact-check pass). An
# unrecognized value is coerced to "uncertain" rather than raising — same defensive
# posture as raw_status().
VERDICT_VOCAB = {"confirmed", "refuted", "outdated", "uncertain"}

# A verdict that means "the draft finding was wrong" — these get surfaced as correction
# rows even when only recorded inline on a probe's `verification` object.
VERDICT_NEEDS_CORRECTION = {"refuted", "outdated"}

# Recommendation priority vocab for the audit punch-list. Missing/invalid -> P2.
PRIORITY_VOCAB = {"P0", "P1", "P2"}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}


def _collapse(text: str) -> str:
    """Collapse runs of whitespace (including embedded newlines) to single spaces."""
    return " ".join((text or "").split())


def _slug(name: str) -> str:
    """Filename-safe slug: lowercase, with any run of non-alphanumerics collapsed to a
    single hyphen (e.g. 'Fly.io' -> 'fly-io', 'Lambda Labs' -> 'lambda-labs'). Keeps the
    documented `<platform>-deep-dive.csv` convention (lowercase, hyphens) intact even when
    the platform name contains dots or punctuation."""
    import re
    return re.sub(r"[^a-z0-9]+", "-", (name or "unknown").lower()).strip("-") or "unknown"


def _trim(text: str, limit: int = 80) -> str:
    """Trim to <= limit chars on a word boundary, adding an ellipsis if cut."""
    text = _collapse(text)
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


def _iter_all_probes(platform_data: dict):
    """Yield (signal_key, probe) for every probe across signals + cross_cutting."""
    for sk, probes in (platform_data.get("signals") or {}).items():
        for p in probes:
            yield sk, p
    for sk, probes in (platform_data.get("cross_cutting") or {}).items():
        for p in probes:
            yield f"cross_cutting:{sk}", p


def raw_status(p: dict) -> str:
    """The author-assigned status, validated against the controlled vocabulary."""
    s = (p.get("status") or "").strip().lower()
    return s if s in STATUS_VOCAB else "unknown"


def _verdict(entry: dict) -> str:
    """A verification verdict validated against VERDICT_VOCAB; unknown -> 'uncertain'.
    Mirrors raw_status(): coerce, don't raise. Works on both a top-level correction and a
    probe's inline `verification` object (both carry a `verdict` key)."""
    s = (entry.get("verdict") or "").strip().lower()
    return s if s in VERDICT_VOCAB else "uncertain"


def probe_status(p: dict) -> str:
    """Status for the comparison matrix. A 'Documented but Misleading' doc_quality
    forces 'misleading' — a familiar term hiding a weaker reality is a warning that
    overrides the nominal status."""
    if (p.get("doc_quality") or "").strip().lower() == "documented but misleading":
        return "misleading"
    return raw_status(p)


def find_probes_for_column(platform_data: dict, col_spec: tuple) -> list:
    """Probes relevant to a matrix column.

    Primary path: probes the author explicitly tagged with this column's id in their
    `matrix_keys` list. Fallback (only when nothing is tagged): keyword match within the
    column's signal_keys, preserved for back-compat with JSON predating matrix_keys.
    """
    name, _label, signal_keys, keyword_hints = col_spec
    explicit = [p for _sk, p in _iter_all_probes(platform_data)
                if name in (p.get("matrix_keys") or [])]
    if explicit:
        return explicit
    matches = []
    for sk in signal_keys:
        if ":" in sk:
            top, sub = sk.split(":", 1)
            probes = platform_data.get(top, {}).get(sub, [])
        else:
            probes = platform_data.get("signals", {}).get(sk, [])
        for p in probes:
            haystack = (_collapse(p.get("probe", "")) + " " + _collapse(p.get("finding", ""))).lower()
            if any(kw in haystack for kw in keyword_hints):
                matches.append(p)
    return matches


def cell_value(probes: list) -> str:
    """Render a matrix cell as '<status> - <brief note>'.

    Status is read from the probe's explicit `status` (never inferred from prose). When
    several probes map to one column, the most cautionary status wins so a gap is never
    masked. Empty/unmapped columns render as 'unknown'.
    """
    if not probes:
        return "unknown"
    p = min(probes, key=lambda pr: STATUS_SEVERITY.get(probe_status(pr), 4))
    status = probe_status(p)
    note = _trim(p.get("finding", ""))
    return f"{status} — {note}" if note else status


def write_deep_dive_csv(platform_data: dict, out_path: Path) -> None:
    """One row per probe across all signals + cross-cutting."""
    platform = platform_data.get("platform", "unknown")
    fieldnames = ["platform", "signal", "probe", "status", "finding",
                  "gap", "risk", "doc_quality", "evidence"]

    def row(signal: str, p: dict) -> dict:
        return {
            "platform": platform,
            "signal": signal,
            "probe": p.get("probe", ""),
            "status": raw_status(p),
            "finding": p.get("finding", ""),
            "gap": p.get("gap", ""),
            "risk": p.get("risk", ""),
            "doc_quality": p.get("doc_quality", ""),
            "evidence": p.get("evidence", ""),
        }

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for sig_name, probes in (platform_data.get("signals") or {}).items():
            for p in probes:
                w.writerow(row(sig_name, p))
        for sub_name, probes in (platform_data.get("cross_cutting") or {}).items():
            for p in probes:
                w.writerow(row(f"cross_cutting:{sub_name}", p))


def write_matrix_csv(platforms_data: list, out_path: Path):
    """Rows = platforms, columns = capability dimensions."""
    fieldnames = ["platform"] + [c[1] for c in MATRIX_COLUMNS]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for pdata in platforms_data:
            row = {"platform": pdata.get("platform", "unknown")}
            for col_spec in MATRIX_COLUMNS:
                probes = find_probes_for_column(pdata, col_spec)
                row[col_spec[1]] = cell_value(probes)
            w.writerow(row)


def write_checklist_csv(checklist_path: Path, out_path: Path):
    """Export the probing checklist as a first-pass scaffold CSV.

    Parses the markdown checklist into one row per probe with fill-in columns
    (status seeded 'unknown', plus finding/evidence/gap/risk/doc_quality), so the
    probes still marked unknown are the validation worklist.
    """
    import re
    with open(checklist_path, "r", encoding="utf-8") as f:
        content = f.read()

    rows = []
    current_signal = None
    current_subsection = None
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        # H2 signal heading like "## 1. Visibility"
        m_sig = re.match(r"^## \d+\. (.+)$", line)
        if m_sig:
            current_signal = m_sig.group(1).strip()
        # H3 subsection
        m_sub = re.match(r"^### (.+)$", line)
        if m_sub:
            current_subsection = m_sub.group(1).strip()
        # Probe: "- **Question?** ..." optionally followed by "Why: ..."
        m_probe = re.match(r"^- \*\*(.+?)\*\*", line)
        if m_probe:
            probe = m_probe.group(1).strip()
            # Look ahead for "Why:" line
            why = ""
            for j in range(i + 1, min(i + 6, len(lines))):
                wm = re.match(r"^\s+Why:\s*(.+)$", lines[j])
                if wm:
                    why = wm.group(1).strip()
                    # collect continuation lines
                    for k in range(j + 1, min(j + 8, len(lines))):
                        if lines[k].startswith("  ") and not lines[k].lstrip().startswith("-"):
                            why += " " + lines[k].strip()
                        else:
                            break
                    break
            if current_signal:
                rows.append({
                    "signal": current_signal,
                    "subsection": current_subsection or "",
                    "probe": probe,
                    "why": why,
                    # First-pass scaffold: every probe starts unknown; the remaining
                    # columns are filled in as the evaluation proceeds, so the probes
                    # still marked unknown are the worklist for validation.
                    "status": "unknown",
                    "finding": "",
                    "evidence": "",
                    "gap": "",
                    "risk": "",
                    "doc_quality": "",
                })
        i += 1

    fieldnames = ["signal", "subsection", "probe", "why",
                  "status", "finding", "evidence", "gap", "risk", "doc_quality"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def _bool_cell(value) -> str:
    """Render an optional JSON bool as a stable CSV cell: 'true'/'false'/'' (absent)."""
    if value is None:
        return ""
    return "true" if value else "false"


def normalize_recommendation(rec) -> dict:
    """Normalize a recommendation to a uniform object so the audit punch-list can render
    any mix of legacy and enriched forms.

    Back-compat rule: a plain string -> {title: <string>, priority: "P2", audit: {}}.
    An object uses its fields with safe defaults (priority -> "P2" if absent/invalid;
    audit -> {} if absent or not a dict). Mirrors raw_status()'s never-raise posture.
    """
    if isinstance(rec, str):
        return {"priority": "P2", "title": rec, "rationale": "", "audit": {}}
    rec = rec or {}
    priority = (rec.get("priority") or "P2").strip().upper()
    if priority not in PRIORITY_VOCAB:
        priority = "P2"
    audit = rec.get("audit")
    return {
        "priority": priority,
        "title": rec.get("title", ""),
        "rationale": rec.get("rationale", ""),
        "audit": audit if isinstance(audit, dict) else {},
    }


def write_audit_checklist_csv(platform_data: dict, out_path: Path) -> int:
    """Audit punch-list: the assessment's recommendations as account-runnable check items.

    One row per recommendation (string or object), sorted P0<P1<P2 (stable, so author
    order is preserved within a tier). `current_state` is always blank — it is filled in
    when the checklist is actually run against an account. Distinct from the `checklist`
    mode, which exports the probing *questions*.
    """
    platform = platform_data.get("platform", "unknown")
    fieldnames = ["platform", "priority", "control", "rationale", "how_to_check",
                  "pass_criterion", "current_state", "remediation", "owner", "evidence"]
    recs = [normalize_recommendation(r) for r in (platform_data.get("recommendations") or [])]
    recs.sort(key=lambda r: PRIORITY_ORDER.get(r["priority"], 2))

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in recs:
            a = r["audit"]
            w.writerow({
                "platform": platform,
                "priority": r["priority"],
                "control": r["title"],
                "rationale": r["rationale"],
                "how_to_check": a.get("how_to_check", ""),
                "pass_criterion": a.get("pass_criterion", ""),
                "current_state": "",  # fill-in: pass / fail / n-a
                "remediation": a.get("remediation", ""),
                "owner": a.get("owner", ""),
                "evidence": a.get("evidence", ""),
            })
    return len(recs)


def write_corrections_csv(platform_data: dict, out_path: Path) -> int:
    """Fact-check pass output: every claim a verification step refuted/flagged, with the
    corrected statement and source.

    Primary rows come from the top-level `corrections` array. Rows are also synthesized
    from any probe carrying an inline `verification` object whose verdict means the draft
    was wrong (refuted/outdated), so nothing is lost if the author only recorded it inline.
    A probe already referenced by a top-level correction (same `probe` name) is not
    duplicated. Legacy JSON with neither field yields a valid header-only CSV.
    """
    platform = platform_data.get("platform", "unknown")
    fieldnames = ["platform", "signal", "probe", "claim", "verdict",
                  "correction", "evidence", "reconciled"]
    rows = []
    referenced_probes = set()

    for c in (platform_data.get("corrections") or []):
        verdict = _verdict(c)
        probe = c.get("probe", "")
        if probe:
            referenced_probes.add(probe)
        rows.append({
            "platform": platform,
            "signal": c.get("signal", ""),
            "probe": probe,
            "claim": c.get("claim", ""),
            "verdict": verdict,
            "correction": c.get("correction", ""),
            "evidence": c.get("evidence", ""),
            "reconciled": _bool_cell(c.get("reconciled")),
        })

    for sig_key, p in _iter_all_probes(platform_data):
        v = p.get("verification")
        if not isinstance(v, dict):
            continue
        verdict = _verdict(v)
        if verdict not in VERDICT_NEEDS_CORRECTION:
            continue
        if p.get("probe", "") in referenced_probes:
            continue
        rows.append({
            "platform": platform,
            "signal": sig_key,
            "probe": p.get("probe", ""),
            "claim": v.get("checked", ""),
            "verdict": verdict,
            "correction": v.get("correction", ""),
            "evidence": v.get("evidence", ""),
            "reconciled": _bool_cell(v.get("reconciled")),
        })

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description="Generate CSV outputs for cloud-security-posture")
    parser.add_argument("--mode",
                        choices=["deep-dive", "matrix", "checklist", "corrections", "audit"],
                        required=True)
    parser.add_argument("--in", dest="inputs", nargs="*", default=[],
                        help="One or more platform JSON files")
    parser.add_argument("--out-dir", required=True, help="Directory to write CSV files into")
    parser.add_argument("--checklist-path", default=None,
                        help="Path to probing-checklist.md (for --mode checklist)")
    parser.add_argument("--print-paths", action="store_true", help="Print resulting file paths")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    if args.mode == "checklist":
        # Default to the checklist alongside this script's parent
        if args.checklist_path:
            cl_path = Path(args.checklist_path)
        else:
            cl_path = Path(__file__).parent.parent / "references" / "probing-checklist.md"
        if not cl_path.exists():
            print(f"Error: checklist not found at {cl_path}", file=sys.stderr)
            sys.exit(1)
        out_path = out_dir / "probing-checklist.csv"
        count = write_checklist_csv(cl_path, out_path)
        written.append(out_path)
        print(f"Wrote checklist CSV: {out_path} ({count} probes)")

    else:
        if not args.inputs:
            print("Error: --in is required for all modes except checklist", file=sys.stderr)
            sys.exit(1)

        platforms_data = []
        for in_path in args.inputs:
            with open(in_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            platforms_data.append(data)

        # deep-dive and matrix both emit per-platform deep-dive CSVs; corrections/audit
        # each emit a single per-platform CSV instead (no surprise deep-dive).
        if args.mode in ("deep-dive", "matrix"):
            for pdata in platforms_data:
                platform = _slug(pdata.get("platform", "unknown"))
                out_path = out_dir / f"{platform}-deep-dive.csv"
                write_deep_dive_csv(pdata, out_path)
                written.append(out_path)
                print(f"Wrote deep-dive CSV: {out_path}")

        if args.mode == "matrix":
            if len(platforms_data) < 2:
                print("Warning: matrix mode requested with only 1 platform; producing matrix anyway", file=sys.stderr)
            out_path = out_dir / "comparison-matrix.csv"
            write_matrix_csv(platforms_data, out_path)
            written.append(out_path)
            print(f"Wrote comparison matrix CSV: {out_path}")

        elif args.mode == "corrections":
            for pdata in platforms_data:
                out_path = out_dir / f"{_slug(pdata.get('platform', 'unknown'))}-corrections.csv"
                count = write_corrections_csv(pdata, out_path)
                written.append(out_path)
                print(f"Wrote corrections CSV: {out_path} ({count} corrections)")

        elif args.mode == "audit":
            for pdata in platforms_data:
                out_path = out_dir / f"{_slug(pdata.get('platform', 'unknown'))}-audit-checklist.csv"
                count = write_audit_checklist_csv(pdata, out_path)
                written.append(out_path)
                print(f"Wrote audit checklist CSV: {out_path} ({count} items)")

    if args.print_paths:
        for p in written:
            print(p)


if __name__ == "__main__":
    main()
