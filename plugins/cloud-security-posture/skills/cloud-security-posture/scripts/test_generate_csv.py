#!/usr/bin/env python3
"""Tests for generate_csv.py — the two new modes (corrections, audit) plus
back-compat guarantees for the existing modes. Standard library only.

Run: python3 -m unittest discover -s scripts -p 'test_*.py'
"""

import csv
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import generate_csv as g  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generate_csv.py")


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def header_line(path):
    with open(path, encoding="utf-8") as f:
        return f.readline()


def write_json(tmp, name, data):
    p = Path(tmp) / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# A legacy assessment: plain-string recommendations, no corrections/verification.
LEGACY = {
    "platform": "Fly.io",
    "signals": {
        "visibility": [
            {"probe": "Audit log export", "status": "partial",
             "finding": "Dashboard only.", "gap": "No SIEM stream.",
             "risk": "Polling required.", "doc_quality": "Documented",
             "evidence": "https://example/docs"},
        ],
        "identity_granularity": [], "supply_chain": [],
        "org_maturity": [], "transparency": [],
    },
    "cross_cutting": {"network_architecture": [], "serverless_edge_middleware": [],
                      "source_control": [], "organizational_substrate": []},
    "recommendations": [
        "Use service users + service tokens for any automation.",
    ],
}


class TestNormalizeRecommendation(unittest.TestCase):
    def test_string_backcompat(self):
        r = g.normalize_recommendation("Do the thing.")
        self.assertEqual(r["priority"], "P2")
        self.assertEqual(r["title"], "Do the thing.")
        self.assertEqual(r["audit"], {})

    def test_object_defaults(self):
        r = g.normalize_recommendation({"title": "T"})
        self.assertEqual(r["priority"], "P2")
        self.assertEqual(r["audit"], {})

    def test_bad_priority_defaults_p2(self):
        r = g.normalize_recommendation({"title": "T", "priority": "URGENT"})
        self.assertEqual(r["priority"], "P2")

    def test_priority_case_normalized(self):
        r = g.normalize_recommendation({"title": "T", "priority": "p0"})
        self.assertEqual(r["priority"], "P0")

    def test_non_dict_audit_coerced(self):
        r = g.normalize_recommendation({"title": "T", "audit": "oops"})
        self.assertEqual(r["audit"], {})


class TestAuditChecklistCSV(unittest.TestCase):
    def test_object_recommendation_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.csv"
            g.write_audit_checklist_csv({
                "platform": "P",
                "recommendations": [{
                    "priority": "P0", "title": "Enforce X", "rationale": "because",
                    "audit": {"how_to_check": "aws foo list", "pass_criterion": "empty",
                              "remediation": "fix it", "owner": "", "evidence": ""},
                }],
            }, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "P0")
            self.assertEqual(rows[0]["control"], "Enforce X")
            self.assertEqual(rows[0]["how_to_check"], "aws foo list")
            self.assertEqual(rows[0]["pass_criterion"], "empty")
            self.assertEqual(rows[0]["current_state"], "")  # always a fill-in

    def test_string_recommendation_backcompat(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.csv"
            g.write_audit_checklist_csv(LEGACY, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["priority"], "P2")
            self.assertTrue(rows[0]["control"].startswith("Use service users"))
            self.assertEqual(rows[0]["how_to_check"], "")

    def test_mixed_recommendations_priority_sort(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.csv"
            g.write_audit_checklist_csv({
                "platform": "P",
                "recommendations": [
                    "a plain P2 string",
                    {"priority": "P0", "title": "the P0 object"},
                ],
            }, out)
            rows = read_csv(out)
            self.assertEqual([r["priority"] for r in rows], ["P0", "P2"])
            self.assertEqual(rows[0]["control"], "the P0 object")

    def test_missing_audit_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.csv"
            g.write_audit_checklist_csv({
                "platform": "P",
                "recommendations": [{"priority": "P1", "title": "no audit block"}],
            }, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["how_to_check"], "")
            self.assertEqual(rows[0]["remediation"], "")

    def test_empty_recommendations_header_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "audit.csv"
            g.write_audit_checklist_csv({"platform": "P"}, out)
            self.assertEqual(read_csv(out), [])
            # header still present
            self.assertIn("how_to_check", header_line(out))


class TestCorrectionsCSV(unittest.TestCase):
    def test_basic_corrections(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv({
                "platform": "P",
                "corrections": [
                    {"claim": "X is deprecated", "verdict": "refuted",
                     "correction": "X is GA again", "evidence": "https://e",
                     "signal": "supply_chain", "probe": "X availability",
                     "reconciled": True},
                    {"claim": "Y default on", "verdict": "confirmed",
                     "correction": "", "evidence": "https://e2"},
                ],
            }, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["verdict"], "refuted")
            self.assertEqual(rows[0]["correction"], "X is GA again")
            self.assertEqual(rows[0]["reconciled"], "true")

    def test_synthesized_from_probe_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv({
                "platform": "P",
                "signals": {"supply_chain": [
                    {"probe": "Build service", "status": "present", "finding": "...",
                     "verification": {"verdict": "outdated", "checked": "availability",
                                      "evidence": "https://v"}},
                ]},
            }, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["verdict"], "outdated")
            self.assertEqual(rows[0]["probe"], "Build service")
            self.assertEqual(rows[0]["signal"], "supply_chain")

    def test_probe_verification_confirmed_is_not_emitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv({
                "platform": "P",
                "signals": {"visibility": [
                    {"probe": "Log export", "verification": {"verdict": "confirmed"}},
                ]},
            }, out)
            self.assertEqual(read_csv(out), [])

    def test_synthesized_deduped_against_toplevel(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv({
                "platform": "P",
                "corrections": [{"claim": "c", "verdict": "refuted", "probe": "Dup probe"}],
                "signals": {"visibility": [
                    {"probe": "Dup probe", "verification": {"verdict": "refuted"}},
                ]},
            }, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)  # not double-counted

    def test_invalid_verdict_defaults_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv({
                "platform": "P",
                "corrections": [{"claim": "c", "verdict": "totally-bogus"}],
            }, out)
            self.assertEqual(read_csv(out)[0]["verdict"], "uncertain")

    def test_legacy_json_header_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corr.csv"
            g.write_corrections_csv(LEGACY, out)
            self.assertEqual(read_csv(out), [])
            self.assertIn("verdict", header_line(out))


class TestRegressionDeepDive(unittest.TestCase):
    def test_deep_dive_unchanged_with_new_fields(self):
        # New optional fields present should be inert to the existing deep-dive output.
        data = json.loads(json.dumps(LEGACY))
        data["signals"]["visibility"][0]["verification"] = {"verdict": "confirmed"}
        data["recommendations"] = [{"priority": "P0", "title": "x", "audit": {}}]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "dd.csv"
            g.write_deep_dive_csv(data, out)
            rows = read_csv(out)
            self.assertEqual(len(rows), 1)
            self.assertEqual(set(rows[0].keys()),
                             {"platform", "signal", "probe", "status", "finding",
                              "gap", "risk", "doc_quality", "evidence"})
            self.assertEqual(rows[0]["status"], "partial")


class TestConfidentialComputeColumn(unittest.TestCase):
    """The confidential-compute matrix column: tenant-facing TEE support is a first-class
    comparison dimension, distinct from hardware_attestation (provider-side integrity)."""

    @staticmethod
    def _column(col_id):
        return next(c for c in g.MATRIX_COLUMNS if c[0] == col_id)

    def test_column_ids_present_and_unique(self):
        ids = [c[0] for c in g.MATRIX_COLUMNS]
        self.assertIn("confidential_compute", ids)
        self.assertIn("operational_track_record", ids)
        self.assertEqual(len(ids), len(set(ids)))

    def test_explicit_matrix_key_tagging(self):
        data = {
            "platform": "P",
            "signals": {"supply_chain": [
                {"probe": "Confidential VM support", "status": "present",
                 "finding": "SEV-SNP confidential VMs GA.",
                 "matrix_keys": ["confidential_compute"]},
            ]},
        }
        probes = g.find_probes_for_column(data, self._column("confidential_compute"))
        self.assertEqual(len(probes), 1)
        self.assertTrue(g.cell_value(probes).startswith("present"))

    def test_keyword_fallback_for_untagged_probe(self):
        # Legacy JSON without matrix_keys: a supply-chain probe mentioning a TEE
        # technology should still map via keyword hints.
        data = {
            "platform": "P",
            "signals": {"supply_chain": [
                {"probe": "VM isolation model", "status": "partial",
                 "finding": "Hypervisor exposes AMD SEV-SNP memory encryption to tenant VMs."},
            ]},
        }
        probes = g.find_probes_for_column(data, self._column("confidential_compute"))
        self.assertEqual(len(probes), 1)

    def test_matrix_csv_renders_new_columns(self):
        data = {"platform": "P", "signals": {}, "cross_cutting": {}}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "matrix.csv"
            g.write_matrix_csv([data], out)
            header = header_line(out)
            self.assertIn("Confidential compute", header)
            self.assertIn("Operational track record", header)


class TestChecklistCoverage(unittest.TestCase):
    """The shipped probing checklist must include the confidential-compute subsection and
    the org-maturity track-record probes (team size, years operating)."""

    @classmethod
    def setUpClass(cls):
        checklist = Path(SCRIPT).parent.parent / "references" / "probing-checklist.md"
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name) / "probing-checklist.csv"
        g.write_checklist_csv(checklist, out)
        cls.rows = read_csv(out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_confidential_computing_subsection_present(self):
        subsections = {r["subsection"] for r in self.rows}
        self.assertIn("Confidential Computing & TEEs", subsections)
        cc_rows = [r for r in self.rows if r["subsection"] == "Confidential Computing & TEEs"]
        self.assertGreaterEqual(len(cc_rows), 4)
        self.assertEqual({r["signal"] for r in cc_rows}, {"Supply Chain"})

    def test_org_maturity_track_record_probes_present(self):
        om_probes = [r["probe"].lower() for r in self.rows
                     if r["signal"] == "Organizational Maturity"]
        self.assertTrue(any("how long has the platform been operating" in p
                            for p in om_probes))
        self.assertTrue(any("security function" in p for p in om_probes))


class TestCLIModes(unittest.TestCase):
    """End-to-end via subprocess: mode wiring, filenames, and the no-stray-deep-dive guard."""

    def _run(self, *args, cwd=None):
        return subprocess.run([sys.executable, SCRIPT, *args],
                              capture_output=True, text=True, cwd=cwd)

    def test_audit_mode_writes_only_audit_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            jp = write_json(tmp, "Fly.io.json", LEGACY)
            out = Path(tmp) / "out"
            r = self._run("--mode", "audit", "--in", jp, "--out-dir", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            files = sorted(p.name for p in out.iterdir())
            self.assertEqual(files, ["fly-io-audit-checklist.csv"])  # slug + no deep-dive

    def test_corrections_mode_writes_only_corrections_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            jp = write_json(tmp, "Fly.io.json", LEGACY)
            out = Path(tmp) / "out"
            r = self._run("--mode", "corrections", "--in", jp, "--out-dir", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            files = sorted(p.name for p in out.iterdir())
            self.assertEqual(files, ["fly-io-corrections.csv"])

    def test_deep_dive_mode_still_writes_deep_dive(self):
        with tempfile.TemporaryDirectory() as tmp:
            jp = write_json(tmp, "Fly.io.json", LEGACY)
            out = Path(tmp) / "out"
            r = self._run("--mode", "deep-dive", "--in", jp, "--out-dir", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((out / "fly-io-deep-dive.csv").exists())

    def test_checklist_mode_still_writes_probing_checklist(self):
        # The probe scaffold mode must keep its name/filename (no collision with audit).
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            r = self._run("--mode", "checklist", "--out-dir", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((out / "probing-checklist.csv").exists())


if __name__ == "__main__":
    unittest.main()
