# GCP — Security Posture Assessment

**Evaluated**: 2026-06-01
**Mode**: Single-platform absolute deep-dive (run in parallel with an AWS evaluation; see `aws-gcp-comparison.md`)
**CSV outputs**: [`gcp-deep-dive.csv`](./gcp-deep-dive.csv) (115 probes) · [`gcp-corrections.csv`](./gcp-corrections.csv) (110 fact-checks) · [`gcp-audit-checklist.csv`](./gcp-audit-checklist.csv) (12 account-runnable controls)
**Source data**: [`gcp.json`](./gcp.json)
**Comparison**: [`comparison-matrix.csv`](../comparison/comparison-matrix.csv) · [`aws-gcp-comparison.md`](../comparison/aws-gcp-comparison.md)

> A note on framing. This framework was built to evaluate smaller GPU/AI "neoclouds" *against a hyperscaler baseline*. Here it is pointed **at GCP itself** — so the question is never "does GCP have capability X" (it almost always does) but **"is X the default, is it ergonomically usable, and do the docs match reality."** Every gap below is phrased as *opt-in vs. default-on*, not *present vs. absent*.

## Context

| Dimension | Value |
|---|---|
| **Platform** | Google Cloud Platform |
| **Offerings in use** | AI/GPU compute (Vertex AI, GKE w/ GPUs/TPUs, Compute Engine A3/A2); general compute + storage (Compute Engine, Cloud Storage, Cloud Run, Cloud SQL); broad managed services; serverless/edge (Cloud Run, Cloud Functions, API Gateway/Apigee, Cloud Load Balancing + Cloud Armor) |
| **Use cases** | Model training & inference endpoints, batch jobs, general application workloads, dev/prod across many teams |
| **Assets at stake** | The organization's **own proprietary IP** — source code, model weights, internal documents (sensitive). Blast radius = IP theft / exfiltration |
| **Trust boundary** | **Multi-team organization** — many **projects** (grouped under folders) under one Google Cloud Organization; IAM and Org Policies inherit down the Org→Folder→Project tree |
| **Comparison baseline** | Google Cloud security foundations / CIS GCP (GCP judged on its own merits) |
| **Timeline** | Treated as pre-go-live hardening for a multi-project landing zone; P0 = before production IP lands, P1/P2 = trackable ongoing |

## Top-line read

**GCP has essentially every control a security team would ask for, and a few genuine differentiators — but, as on any hyperscaler, the secure configuration is opt-in.** Across 115 probes the distribution is **64 present, 44 partial, 5 absent, 2 misleading**, with **34 "Documented but Misleading"** findings where a familiar term ships a weaker default than the name implies. The single most repeated pattern is the same one that defines the AWS posture: *the capability exists; the safe default does not.* Data Access audit logs — the only record of who **read** a Cloud Storage object, Secret Manager secret, or model artifact — are **off by default** for every service except BigQuery. The `default` VPC ships with internet-open firewall rules. VPC Flow Logs are off by default. The secure-by-default Org Policy baseline only auto-applies to organizations **created on or after May 3, 2024** and is **not retroactive**, so an established company inherits the legacy footguns: service-account JSON keys allowed, and the Compute Engine default service account silently granted project-wide **Editor**.

**What GCP does genuinely well, and deserves credit for, includes several real differentiators over the baseline:** the **Org→Folder→Project hierarchy** gives lightweight, cheap isolation units that fit a multi-team org better than account-per-boundary models; **VPC Service Controls** is a first-class data-exfiltration perimeter that blocks egress to outside a service boundary even with valid stolen credentials; **Binary Authorization** is a native deploy-time attestation gate for GKE and Cloud Run; **Workload Identity Federation** cleanly removes long-lived keys for CI/CD; **Confidential Computing** (SEV-SNP/TDX, and emerging Confidential GPU) protects data in use; and **Access Transparency / Access Approval** log and gate Google's *own* staff access to customer content — a transparency lever with no exact AWS-default equivalent. Cloud Run and Cloud Functions are **private-by-default** (a stronger default than a bare function elsewhere). The threat-intelligence and research bench (GTIG/Mandiant, Project Zero) and the famously generous Vulnerability Reward Program are first-tier.

**The gaps that need compensating controls before production IP lands** cluster in four places: **(1) read-access visibility** — Data Access logs off by default leaves exfiltration of source/weights untraced; **(2) the exfil perimeter** — VPC Service Controls is the right control but is opt-in and must be *enforced* (not dry-run) and cover the exact IP-bearing services; **(3) standing credentials and over-broad roles** — SA JSON keys, basic roles (Owner/Editor/Viewer), and the legacy default-SA Editor grant on any org predating May 2024; and **(4) detection tiering** — the behavioral threat detection that matters (Event/Container/VM Threat Detection) is gated to Security Command Center Premium/Enterprise, and the Standard tier is being narrowed. None of these are GCP *lacking* a control; all are GCP shipping the permissive default.

## Methodology

Produced by a multi-agent workflow: nine research agents (one per signal / cross-cutting area) gathered evidence from Google Cloud documentation, release notes, and the security blog; each signal's findings were **adversarially fact-checked** by an independent agent targeting falsifiable, time-sensitive claims; a completeness critic identified missing controls (Security Command Center tiering, VPC-SC service coverage, default-SA Editor, Confidential GPU, Access Transparency coverage, OS Login) which a fill round investigated. The fact-check pass ran **110 verifications and overturned 13 claims** (5 refuted, 8 outdated) plus 2 left uncertain; every refuted/outdated claim was reconciled into the finding text (see *Fact-check & corrections*). Per-probe evidence URLs, gaps, and risks live in `gcp-deep-dive.csv`; this report synthesizes by signal. The most important column is often `doc_quality`: **"Documented but Misleading" (DbM)** flags a familiar term hiding a weaker default.

---

## Signal 1 — Visibility  ·  8 present / 7 partial

**Posture:** Excellent model and schema; the read-access default is the gap. The four Cloud Audit Log streams (Admin Activity, Data Access, System Event, Policy Denied) are cleanly separated from application logs, share a consistent, well-documented `protoPayload`/`AuditLog` schema, and capture rich identity (`principalEmail`, impersonation chains via `serviceAccountDelegationInfo`). Admin Activity + System Event are **always-on, free, and immutable for 400 days** in the `_Required` bucket — a genuinely strong default. Export is first-class (Log Router sinks to Pub/Sub, BigQuery, GCS, or Google Security Operations; org/folder aggregated sinks an attacker in one project can't disable).

**The footguns:**
- **Data Access (read) logging is OFF by default** (*partial, DbM*) for every service except BigQuery — so a read of a Cloud Storage object, a Secret Manager secret, or a model artifact produces **no audit record** until `auditConfigs` are explicitly set, and enabling it carries ingestion cost. This is GCP's direct analogue of exfil-blindness, and the highest-value visibility gap for this org.
- **Security Command Center threat detection is tier-gated** (*partial, DbM*) — Event/Container/VM Threat Detection require Premium/Enterprise; the *fact-check note* flags that the **Feb 2026 "enhanced Standard" migration narrows the Standard tier**, so the free baseline is eroding.
- **Vertex AI prompt/response content logging is opt-in** (*present but DbM*), and the `_Default` bucket (Data Access + app logs) ages out at **30 days** unless extended.
- **A project owner can blind the audit trail** within their own project (*partial*) unless an org-level aggregated sink and locked bucket are in place.

→ **Recommendations P0-1 (Data Access logs + immutable org sink), P1-5 (SCC Premium/Enterprise).**

## Signal 2 — Identity Granularity  ·  10 present / 6 partial / 2 absent

**Posture:** Strong primitives, with two signature footguns. Per-permission granularity is real (the "reset a VM but not delete it" litmus passes), custom roles and IAM Conditions exist, short-lived credentials are well-supported (SA impersonation, downscoped/Credential Access Boundary tokens), and **Workload Identity Federation** is a clean keyless pattern for external IdPs and GKE. **IAM Deny policies and Principal Access Boundary** add composable scoping.

**The footguns (GCP's signature credential risks):**
- **Basic roles (Owner/Editor/Viewer)** (*present, but the central RBAC footgun*) are project-wide; Google itself warns against them, but they remain the path of least resistance.
- **Long-lived service-account JSON keys** (*present, the #1 GCP credential risk*) never expire; the org-policy constraints `iam.disableServiceAccountKeyCreation/Upload` block them but are only default-enforced on orgs created on/after May 3, 2024.
- **Compute Engine default SA → automatic Editor** (*partial*) — historically auto-granted project-wide Editor; suppressed by `automaticIamGrantsForDefaultServiceAccounts` only on post-May-2024 orgs, and **not retroactive** (and enforcing it doesn't revoke an Editor already granted). *(Fact-check confirmed the draft's May-3-2024 cutoff and non-retroactivity.)*
- **OS Login vs metadata SSH keys + external-IP-by-default** (*absent* as a default guardrail) and the **WIF `pull_request`-from-fork token-minting** risk (*absent* as a documented warning) are real exposure gaps for this context.
- **Workload Identity Federation attribute conditions** (*partial, DbM*) — an over-broad provider (trusting a whole GitHub org, or fork PRs) is a confused-deputy hole.

→ **Recommendations P0-3 (kill SA keys + tighten WIF), P0-4 (basic roles + default-SA Editor).**

## Signal 3 — Supply Chain  ·  7 present / 7 partial / 1 absent

**Posture:** A native signing gate (a real differentiator) and strong key custody, undercut by opt-in defaults. **Binary Authorization** is a genuine native deploy-time attestation gate for GKE and Cloud Run; **Confidential Computing** (Confidential VM/GKE, SEV-SNP/TDX, emerging Confidential GPU) protects data in use; **Cloud KMS / CMEK / Cloud HSM / Cloud EKM** give layered key custody up to hold-your-own-key; Container Registry (gcr.io) is correctly noted as **shut down and replaced by Artifact Registry**.

**The footguns:**
- **Binary Authorization is opt-in and ships in dry-run** (*present, DbM*) — the native gate exists but unsigned/unattested images deploy until you flip it to enforce.
- **Default Google-managed encryption gives zero cross-project key-IAM isolation** (*absent*) — only **CMEK in a dedicated key project** with separated key IAM creates an independent blast-radius boundary (*partial*).
- **Public Access Prevention is NOT in the May-2024 secure-by-default bundle** (*partial, DbM*) — only Uniform Bucket-Level Access is; a new bucket defaults PAP to `inherited`, so buckets can still be made public via IAM unless `storage.publicAccessPrevention` is separately enforced. *(Fact-check confirmed the draft already had this right.)*
- **Shielded VM** secure-boot/vTPM defaults vary by image (*partial*); **Secret Manager** GKE add-on auto-rotation has *no default interval — minimum 120 s, must be set explicitly* (*fact-check corrected the draft's "1 minute" / "~2 min default"*).
- **Confidential GPU** in-use protection of model weights is GA-limited by machine type (*partial*).

→ **Recommendations P1-8 (CMEK + dedicated key project), P1-9 (Binary Authorization enforce-mode).**

## Signal 4 — Organizational Maturity  ·  9 present / 3 partial

**Posture:** Best-in-class and largely **present**. The threat-intelligence bench — **GTIG (TAG + Mandiant under Sandra Joyce), Project Zero** — is first-tier (*fact-check corrected the GTIG figure to **75 zero-days** exploited in 2024, down from 98 in 2023*). The **Vulnerability Reward Program** is famously generous with safe harbor; **Mandiant** provides customer IR; compliance scope (SOC, ISO, PCI, FedRAMP High, HIPAA) is broad and self-service via Compliance Reports Manager (scope is **per-product** — verify the services holding IP). Jurisdiction is stated plainly: Google LLC / Alphabet (NASDAQ: GOOGL), Delaware/US, subject to the CLOUD Act, with residency via region and sovereignty via Assured Workloads and EU partnerships (T-Systems, S3NS).

**The nuances:**
- **Google Cloud CISO seat** (*partial*) — **Phil Venables stepped down in March 2025** (now a part-time strategic advisor; later Ballistic Ventures); Google consolidated the function rather than naming a single public successor. *(Fact-check confirmed the draft already states this correctly — a stale "Venables is the current CISO" claim would have been the easy error to make.)*
- **Sovereignty levers** (*partial, DbM*) — Access Transparency is **now positioned as a default control but still requires an enablement action and a qualifying paid support tier** (*fact-check corrected the flat "opt-in" framing*); Access Approval and Assured Workloads are likewise opt-in and may carry coverage/tier prerequisites.

## Signal 5 — Transparency  ·  5 present / 5 partial / 1 misleading / 1 absent

**Posture:** A real strength, anchored by a control with no AWS-default equivalent. The shared-responsibility model is explicit; **Access Transparency logs Google's own staff access to your content** (with justifications) and **Access Approval** can require your consent first — genuine, creditable transparency. Google documents the **basic-role over-permissioning** honestly ("we don't recommend basic roles in production"), and permission-denied errors are informative without leaking resource existence.

**The gaps:**
- **'Scoped' IAM Conditions vary by service** (*partial, DbM*) — condition-key support is uneven and the variance is not loudly surfaced.
- **Access Approval is opt-in/per-service with break-glass auto-approval nuances**, and **Access Transparency coverage for Vertex AI / AI-GPU services has gaps** (*partial, DbM*) worth confirming for this workload.
- **'BeyondProd' / 'zero trust' / 'secure by design'** (*misleading*) are architecture-narrative terms describing Google's *own* internal posture, not turnkey customer controls.
- **No public, committed security-feature roadmap** (*absent*) — customers track release notes.

## Cross-cutting A — Network Protection & Isolation  ·  6 present / 5 partial

**Posture:** The marquee anti-exfil control lives here. **VPC Service Controls** creates a service perimeter that blocks data egress outside the boundary even with valid credentials — the single most important control for this context (**present** as a capability). Global VPC, hierarchical firewall policies, Private Service Connect, Private Google Access, Shared VPC for multi-team networking, and **Identity-Aware Proxy** for bastion-less zero-trust access round out a deep stack.

**The footguns:**
- **VPC Service Controls is opt-in and must be enforced, not dry-run** (*partial*), and its **per-service coverage must include the exact IP-bearing services** (Cloud Storage, BigQuery, Vertex AI, Artifact Registry) (*partial, DbM*) — a perimeter that omits a service holding IP is a hole. There are documented **bypass/break-glass vectors** (e.g. Cloud Build) to close (*partial*).
- **The `default` VPC is internet-open** (*present, footgun*) — auto-created with permissive SSH/RDP rules; `compute.skipDefaultNetworkCreation` fixes it but is **not in the secure-by-default baseline** (*fact-check corrected the baseline enumeration to seven managed constraints; skip-default-network is not among them*).
- **VPC Flow Logs off by default; egress to the internet allowed by default** (*partial*).

→ **Recommendations P0-2 (enforce VPC-SC over IP services), P2-12 (egress + Flow Logs + private access).**

## Cross-cutting B — Serverless / Edge Middleware  ·  6 present / 5 partial / 1 misleading

**Posture:** Strong private-by-default posture, with a clear public toggle and an enforcement layer that's opt-in. Cloud Run / Cloud Functions are **private by default** — Cloud Run enforces the per-service Invoker IAM check by default (*fact-check corrected the draft's conflation: the **org-policy** constraint `run.managed.requireInvokerIam` is opt-in, not default-on*). **Cloud Armor** provides WAF + Adaptive Protection, **always-on L3/L4 volumetric DDoS protection is default-on** for load-balanced traffic, and **IAP / API Gateway / Apigee** supply edge auth.

**The footguns:**
- **"Allow unauthenticated invocations" / `allUsers`** (*partial, DbM*) is a one-toggle public endpoint; **Domain Restricted Sharing** (`iam.allowedPolicyMemberDomains`) blocks it but is opt-in.
- **Cloud Run default ingress "all"** (*partial, DbM*) lets the raw `run.app` URL bypass the load balancer / Cloud Armor / WAF entirely.
- **Cloud Armor L7 WAF / Adaptive Protection require an attached security policy** on an external LB (*partial, DbM*) — not automatic.
- **API Gateway / Cloud Endpoints OpenAPI request validation is NOT enforced** (*misleading*) — the schema is advisory unless you wire validation.

→ **Recommendations P1-7 (block allUsers + restrict ingress + require invoker IAM), P2-10 (Cloud Armor on all LBs + stop run.app bypass).**

## Cross-cutting C — Source Control & CI/CD  ·  6 present / 3 partial / 1 absent

**Posture:** Keyless CI/CD and native build provenance are strengths; first-party Git for a fresh org is the gap. **Cloud Source Repositories is closed to new customers** (*absent* for a fresh org; Secure Source Manager is the paid replacement, *partial*). But the keyless pattern — **Workload Identity Federation for GitHub Actions → impersonate a least-privileged SA** — is well documented (*present*), **Cloud Build generates SLSA provenance and can sign images for Binary Authorization** (*present*, a supply-chain strength), and you can push prebuilt artifacts to Artifact Registry without giving Google source access.

**The footguns:**
- **WIF attribute-condition scoping** (*present, DbM*) — same confused-deputy risk as in Identity.
- **Cloud Build service-account blast radius** (*partial*) — historically over-privileged; *fact-check confirmed the draft is current*: over May–June 2024 the default moved to the Compute Engine default SA, and for orgs created on/after May 3, 2024 that SA has **no Editor** — but projects predating the change keep the legacy broad SA.

## Cross-cutting D — Organizational Substrate  ·  7 present / 3 partial

**Posture:** This is GCP's structural strength for a multi-team org. The **Organization → Folder → Project** hierarchy gives lightweight, inheritable isolation units (cheaper than account-per-boundary); **Org Policy Service** is a rich, declarative SCP-equivalent (boolean + list managed constraints + CEL custom constraints); **IAM Deny policies + Principal Access Boundary** add composable guardrails; **Cloud Identity / Workspace** provides central IdP/SSO/SCIM; **Policy Intelligence** (Recommender, Analyzer, Troubleshooter) supports least-privilege at scale; **Assured Workloads** overlays residency/personnel constraints.

**The footguns:**
- **Nothing is enforced by default on organizations created before May 3, 2024** (*partial, DbM*) — the entire guardrail surface is opt-in for established orgs, and even new orgs get a **narrow seven-constraint baseline** (*fact-check corrected the date from March 20 → May 3, 2024 and the bundle from six → seven managed constraints*).
- **Default IAM grants on project creation** (*partial*) and the default-SA Editor interaction (cross-referenced from Identity).
- **Super-admin blast radius** (Cloud Identity / Workspace super administrator) sits above Org Policy and must be tightly held (*present, but a concentration risk*).

→ **Recommendations P0-4 (enforce baseline org-wide), P1-6 (full Org Policy guardrail baseline).**

---

## Fact-check & corrections

The adversarial verification pass ran **110 checks (95 confirmed)** and overturned **13 claims** (5 refuted, 8 outdated; 2 left uncertain), each reconciled into the finding text (full ledger in `gcp-corrections.csv`):

| Signal | Verdict | What changed |
|---|---|---|
| identity | uncertain→softened | "secure-by-default exemptions are per-resource via tags" reworded to org/folder/project-level overrides |
| supply_chain | refuted | GKE Secret Manager rotation: **minimum 120 s, no default** (was "default ~2 min, min 1 min") |
| org_maturity | refuted | GTIG tracked **75** zero-days exploited in 2024 (not 75–78), down from 98 in 2023 |
| org_maturity | outdated | Access Transparency now framed as a **default control** but still needs an enablement action + paid support tier |
| network | outdated | Secure-by-default baseline is **seven managed constraints**; enumeration corrected (adds essential-contacts, protocol-forwarding) |
| edge | refuted | Cloud Run per-service invoker check is default-on, but the **`run.managed.requireInvokerIam` org-policy constraint is opt-in** |
| edge | uncertain→softened | The verbatim "four-role" Cloud Run quote reworded as paraphrase |
| org_substrate | refuted | Secure-by-default enforcement date is **May 3, 2024**, not March 20, 2024 (the announcement date) |
| org_substrate | outdated | Baseline bundle is **seven** constraints (managed namespace), not six |
| *(confirmed-current)* | — | The draft was **already correct** on: the CISO seat (Venables stepped down Mar 2025), Public Access Prevention (not default-enforced), default-SA Editor (suppressed only post-May-2024), and the Cloud Build SA change |

The CISO note is the standout near-miss: the verify pass specifically hunted for a stale "Phil Venables is the current Google Cloud CISO" claim — the draft had already gotten it right.

## Recommendations

Full account-runnable checks (how-to-check, pass-criterion, remediation) are in [`gcp-audit-checklist.csv`](./gcp-audit-checklist.csv). Summary:

**P0 — before production IP lands**
1. **Enable Data Access (DATA_READ) audit logs** on IP-bearing services + an immutable org-level aggregated log sink — close read-access exfil-blindness.
2. **Enforce a VPC Service Controls perimeter** (not dry-run) around the projects/services holding IP, with tight ingress/egress rules.
3. **Eliminate service-account JSON keys**; adopt Workload Identity Federation with exact attribute conditions (guard fork PRs).
4. **Stamp out basic roles and the default-SA Editor grant** — enforce the secure-by-default baseline on the *whole* hierarchy, including orgs predating May 3, 2024.

**P1 — shortly after go-live**
5. Security Command Center Premium/Enterprise org-wide for Event/Container/VM Threat Detection.
6. Apply the full Org Policy guardrail baseline (skip-default-network, deny external IP, require OS Login, domain-restricted sharing, allowed locations).
7. Lock down serverless exposure — Domain Restricted Sharing + `run.managed.requireInvokerIam` + ingress `internal-and-cloud-load-balancing`.
8. CMEK in a dedicated key project with separated key IAM (Cloud HSM/EKM where sovereignty matters).
9. Binary Authorization **enforce-mode** + Artifact Analysis for GKE and Cloud Run.

**P2 — hardening / ongoing**
10. Cloud Armor on every external load balancer (WAF + rate-based + Adaptive Protection); prevent `run.app` direct-URL bypass.
11. Enable Access Transparency + Access Approval over IP-bearing workloads (note Vertex AI coverage gaps).
12. Network egress + private-access controls — Flow Logs on, no external IPs (Cloud NAT), egress filtering, Private Google Access.

## Worklist / what to drive to ground

This is a first pass meant to be proofed and extended. Highest-value follow-ups: (a) confirm **VPC Service Controls per-service coverage** against the exact services holding your IP and close documented bypass vectors; (b) re-verify the **per-product compliance scope** for Vertex AI / GKE before relying on attestation; (c) decide whether **Vertex AI request/response content logging** is required for IP/abuse forensics; (d) for any org created **before May 3, 2024**, treat the secure-by-default baseline as *not applied* and roll it out manually across folders/projects; and (e) re-verify the **Google Cloud CISO** seat-holder before publishing any name (the function was consolidated after March 2025).
