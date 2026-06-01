# AWS — Security Posture Assessment

**Evaluated**: 2026-06-01
**Mode**: Single-platform absolute deep-dive
**CSV outputs**: [`aws-deep-dive.csv`](./aws-deep-dive.csv) (122 probes) · [`aws-corrections.csv`](./aws-corrections.csv) (105 fact-checks) · [`aws-audit-checklist.csv`](./aws-audit-checklist.csv) (12 account-runnable controls)
**Source data**: [`aws.json`](./aws.json)

> A note on framing. This framework was built to evaluate smaller GPU/AI "neoclouds" *against AWS as the gold-standard baseline*. Here it is pointed **at AWS itself** — so the question is never "does AWS have capability X" (it almost always does) but **"is X the default, is it ergonomically usable, and do the docs match reality."** That inversion is why almost every gap below is phrased as *opt-in vs. default-on*, not *present vs. absent*.

## Context

| Dimension | Value |
|---|---|
| **Platform** | Amazon Web Services |
| **Offerings in use** | AI/GPU compute (SageMaker, Bedrock, EC2 GPU, EKS); general compute + storage (EC2, S3, Lambda, RDS, EBS); broad first-party managed services; serverless/edge (Lambda, API Gateway, CloudFront, WAF) |
| **Use cases** | Model training & inference endpoints, batch jobs, general application workloads, dev/prod across many teams |
| **Assets at stake** | The organization's **own proprietary IP** — source code, model weights, internal documents (sensitive). Blast radius = IP theft / exfiltration |
| **Trust boundary** | **Multi-team organization** — many accounts under one AWS Organization; the AWS *account* is the strong isolation unit |
| **Comparison baseline** | AWS Well-Architected Security Pillar / CIS AWS Foundations (AWS judged on its own merits, not against another provider) |
| **Timeline** | Treated as pre-go-live hardening for a multi-account landing zone; P0 items below are "before production IP lands," P1/P2 are trackable ongoing |

## Top-line read

**AWS has essentially every control a security team would ask for; the risk is not absence, it is default.** Across 122 probes the distribution is **70 present, 46 partial, 3 misleading, 3 absent** — and **24 findings are "Documented but Misleading,"** meaning a familiar term ships a weaker default than the name implies. The single most repeated pattern in this assessment is that **the secure configuration is opt-in.** CloudTrail's default is a 90-day rolling buffer of *management* events only; the S3 object-level reads that would reveal model-weight exfiltration are *data events* that are off by default and cost money to enable. GuardDuty's "default-on" covers only base feeders — the S3, Malware, EKS-runtime and RDS protection plans that matter for IP are per-plan opt-in. VPC Flow Logs, WAF, WAF logging, API Gateway logging, EBS encryption-by-default, and Config recording are all off until someone turns them on. For a multi-team org, every newly-vended account starts from this less-safe baseline unless the *organizational substrate* (SCPs, RCPs, Control Tower, delegated admin, auto-enable) forces the safe default. That substrate is AWS's real differentiator — and it is also opt-in.

**What AWS does genuinely well, and deserves credit for:** IAM is truly action-level (the `RebootInstances`-allowed / `TerminateInstances`-denied litmus test passes cleanly), with mature composable scoping primitives — STS, session policies, session tags, source identity, permission boundaries, ABAC — that constrain *any* principal including agents, exactly the right standard. The CloudTrail record schema is exhaustively documented down to the `userIdentity` block. **Transparency is a standout:** the Shared Responsibility Model is a clear statement of what AWS does *not* secure; AWS explicitly documents that API Gateway "API keys" are **not** an authorization mechanism, that the root user cannot be constrained by IAM policy, and that security groups have no deny rules — these are the rare, valuable "here's what we don't do" disclosures. Hardware integrity (Nitro System, NitroTPM, Nitro Enclaves) and organizational maturity (named CISO, VDP with safe harbor, broad SOC 2 / FedRAMP scope, customer-engageable CIRT) are best-in-class.

**The gaps that need compensating controls before production IP lands** are concentrated in three places: **(1) exfiltration visibility** — the default audit posture is blind to data-plane reads of S3/model stores; **(2) the data perimeter** — without a composed SCP + RCP + VPC-endpoint-policy perimeter, leaked credentials work from anywhere and data can be copied to an attacker's account (RCPs, launched Nov 2024, finally close the resource-policy side); and **(3) standing credentials and encryption defaults** — long-lived IAM access keys, IMDSv1-reachable legacy instances, EBS-encryption-by-default off per new region/account, and the KMS stock key policy that delegates `kms:*` to the account root so a CMK alone isolates nothing. None of these are AWS *failing* to offer the control; all of them are AWS shipping the permissive default and leaving the secure posture to you.

## Methodology

This assessment was produced by a multi-agent workflow: nine research agents (one per signal / cross-cutting area) gathered evidence from AWS documentation, the Service Authorization Reference, What's-New announcements, and the security blog; each signal's findings were then **adversarially fact-checked** by an independent agent targeting falsifiable, time-sensitive claims; a completeness critic identified missing controls (GuardDuty/Security Hub/Inspector/Macie, Bedrock guardrails, IMDSv2, the data-perimeter triad, KMS key-policy footguns, confused-deputy protections) which a fill round then investigated. The fact-check pass ran **105 verifications and overturned 10 claims** (5 refuted, 5 outdated); every one was reconciled back into the finding text (see *Fact-check & corrections* below). Per-probe evidence URLs, gaps, and risks live in `aws-deep-dive.csv`; this report synthesizes by signal. Status vocabulary: `present` / `partial` / `absent` / `misleading` / `unknown`. The most important column is often `doc_quality`: **"Documented but Misleading" (DbM)** flags a familiar term hiding a weaker default.

---

## Signal 1 — Visibility  ·  7 present / 9 partial

**Posture:** The *plumbing* is excellent; the *defaults* are blind to your crown-jewel threat. Control-plane activity (CloudTrail management events) is structurally separated from application stdout (CloudWatch Logs) — different services, schemas, IAM. The CloudTrail record schema and `userIdentity` block are exhaustively documented (**present**), export paths are rich (S3, EventBridge, Kinesis Firehose, CloudTrail Lake, Security Lake/OCSF), and immutability is achievable (org trail + log file validation + S3 Object Lock).

**The footguns (all DbM or partial):**
- **CloudTrail "on by default" is a 90-day management-event buffer, not durable logging** (*partial, DbM*). Long-term retention, SIEM export, and *any* data-event capture require explicitly creating a trail or event data store. A freshly-vended member account with no org-trail coverage retains nothing past 90 days.
- **Data events are OFF by default** (*partial*). S3 `GetObject`/`PutObject`, SageMaker `InvokeEndpoint`, and the Bedrock runtime ops are data events that cost extra and are disabled by default — so **mass download of source or model weights produces no durable CloudTrail evidence by default.** This is the most important visibility gap for this org's threat model. *(Fact-check correction: the common Bedrock invocation APIs — `InvokeModel`, `Converse`, etc. — are actually **management** events, logged by default; what's still off is S3 object access and the SageMaker/Bedrock-runtime data events, and prompt/response *content* always requires separate Bedrock model-invocation logging.)*
- **GuardDuty's default-on covers only base feeders** (*partial, DbM*). S3 Protection, Malware Protection, EKS/Runtime, RDS, and Lambda plans are per-plan opt-in, per-region — a vanilla org enablement can leave the most IP-relevant detections off, and new accounts can land uncovered.
- **Security Hub, Inspector, Macie, Detective** (*partial, DbM*) — the multi-account posture brain, CVE scanning, sensitive-data discovery, and graph investigation are all opt-in per account/region and need delegated-admin + auto-enable to actually cover the org.
- **CloudWatch Logs default retention is "Never Expire"** — auto-created Lambda log groups keep data forever unless you set retention, a cost and data-minimization issue for logs that may contain sensitive payloads.

→ **Recommendations P0-1 (durable immutable org trail incl. S3 data events), P0-2 (org-wide GuardDuty + plans), P1-5 (Security Hub).**

## Signal 2 — Identity Granularity  ·  10 present / 8 partial / 1 misleading

**Posture:** AWS's strongest signal, and the place where "is least privilege *writable*" is genuinely yes. IAM is action-level with explicit-Deny-wins evaluation; the **composable scoping primitives are the right model** — STS token exchange, session policies (time scoping), session tags + source identity (logged, propagated metadata), permission boundaries, and ABAC let you constrain humans, services, and agents alike without any special "agent identity" type. Workload identity is comprehensive: instance/task/Lambda roles, IRSA, EKS Pod Identity (late 2023), IAM Roles Anywhere (X.509), and OIDC federation. Credentials transit as SigV4-signed headers, never in URLs. Official AWS MCP servers honor the boto3 credential chain and support read-only scoping via the IAM principal.

**The footguns:**
- **KMS default key policy is misleading** (*misleading, DbM*). The stock "Enable IAM User Permissions" statement delegates `kms:*` to the account root, so **a customer-managed CMK does not by itself isolate data** — any sufficiently broad IAM admin in the same account can decrypt. Isolation only materializes with scoped key policies and/or account separation.
- **`ec2:RunInstances` least-privilege is ergonomically hard** (*partial, DbM*) — a single action that requires permissions across up to **twelve** resource types simultaneously; AWS's own guidance resorts to wildcards. *(Fact-check: corrected from "eight" to twelve resource types; `spot-instances-request` dropped.)*
- **Resource-level permission coverage varies by action** (*partial*) — some actions only accept `*`, so per-action least privilege is not uniformly expressible.
- **OIDC sub-claim footgun** (*partial, DbM*) — GitHub Actions trust policies with a missing or wildcard `sub` condition are a confused-deputy exposure (the `sub` format also changes when a job uses a GitHub environment).
- **Confused-deputy protections are opt-in** (*partial*) — external IDs on vendor roles and `aws:SourceArn`/`aws:SourceAccount` on service resource policies are conditions AWS does not add for you.
- **Secrets Manager rotation is not on by default; Parameter Store has no rotation at all** (*partial*). Long-lived IAM user access keys remain supported with no expiry and no native auto-rotation.

→ **Recommendations P0-4 (kill standing creds), P1-7 (confused-deputy hygiene), P1-8 (scoped KMS key policies), P1-10 (Access Analyzer).**

## Signal 3 — Supply Chain  ·  7 present / 5 partial

**Posture:** Strong hardware-integrity story, weak default *enforcement* of artifact integrity. Nitro System / NitroTPM / Nitro Enclaves give measured boot and isolated execution where even root on the parent EC2 instance cannot read enclave memory (**present**). ECR uses IAM exclusively (no shared/cross-tenant registry credentials), and **S3 is secure-by-default**: SSE-S3 on all new objects since Jan 2023, Block Public Access auto-enabled and ACLs disabled (Object Ownership = BucketOwnerEnforced) for all new buckets since April 2023 (**present**, and a genuine improvement AWS made the default).

**The footguns:**
- **Image signing is off by default and there is NO native gate** (*partial, DbM*). ECR supports AWS Signer (managed signing went GA Nov 2025), but **out of the box an unsigned or tampered image runs everywhere.** *(Fact-check correction: neither EKS nor ECS ships a native AWS-managed verification gate — EKS needs a customer-installed admission controller, Gatekeeper+Ratify or Kyverno with the Signer plugin; ECS needs a custom Lambda; raw EC2/Lambda container images have no gate at all.)*
- **ECR basic scanning is shallow** (*partial*) — continuous CVE/EOL coverage requires enabling Inspector (enhanced) scanning.
- **Bedrock Guardrails are not enforced unless an IAM condition requires them** (*partial, DbM*) — `bedrock:GuardrailIdentifier` must be pinned in policy, or a guardrail is merely available, not mandatory.
- **Marketplace third-party AMI/container trust** (*partial, DbM*) — AWS scans and re-scans listings but the trust boundary for third-party images is real.

→ **Recommendations P1-9 (signing + verification enforcement + enhanced scanning), P2-12 (Bedrock guardrail enforcement).**

## Signal 4 — Organizational Maturity  ·  10 present / 3 partial

**Posture:** Best-in-class and largely **present**. Named security leadership (Amazon CSO Steve Schmidt; AWS VP & CISO Amy Herzog *— fact-check correction: succeeded Chris Betz in June 2025*), a VDP with safe-harbor language, a customer-engageable CIRT (any customer, any support plan, no separate charge for AWS-infrastructure incidents), broad self-service compliance evidence via AWS Artifact, a security-bulletin/advisory feed, and post-incident transparency. Jurisdiction is stated plainly: Amazon.com Inc. is a US (Delaware) entity subject to the CLOUD Act, with data **residency** controllable via Region but **jurisdiction** mitigated only via sovereign offerings — GovCloud (US Persons, ITAR/FedRAMP High) and the **AWS European Sovereign Cloud (GA Jan 15 2026** *— fact-check corrected the date from Jan 14)*.

**The nuances:**
- **SOC 2 scope is per-service** (*present, DbM*) — "AWS has SOC 2" is true but scope is per-service/per-feature (e.g. SageMaker AI in scope but Studio Lab excluded; Bedrock in scope but Bedrock Marketplace excluded). Check the *Services in Scope* list for the exact services holding IP.
- **Public bug bounty is scoped** (*partial, DbM*) — the paid HackerOne bounty (up to ~$25k) centers on Amazon retail/consumer/devices, not the full AWS infrastructure surface.
- **The SRT requires both Shield Advanced AND a Business/Enterprise Support plan** (*present — fact-check corrected to add the support-plan prerequisite*).
- **AWS Config recording and the compliance/drift backbone are opt-in** (*partial*) — Config is not on by default in every account/region, and Control Tower detective guardrails / conformance packs silently don't evaluate without it.

→ **Recommendation P1-6 (org-wide Config + conformance packs).**

## Signal 5 — Transparency  ·  9 present / 1 partial / 1 absent

**Posture:** A genuine strength, and worth crediting explicitly. AWS publishes clear negatives — the **Shared Responsibility Model** (what AWS does not secure), **API Gateway "API keys" are explicitly not authorization**, the **root user cannot be constrained by IAM**, **security groups have no deny rules**, and the **account is the hard isolation boundary**. Encoded authorization-failure messages and explicit-vs-implicit `AccessDenied` phrasing (naming the blocking policy) are informative without leaking.

**The gaps:**
- **"Scoped" IAM varies by action** (*partial*) — resource-level and condition-key support is per-action; documented in the Service Authorization Reference but a discoverability footgun.
- **No public, unified security-feature roadmap** (*absent*) — AWS explicitly declines specific target dates ("job zero is security"), so a multi-team org cannot plan around upcoming default-on changes or new condition keys from one source.
- **"Well-Architected"** (*present, DbM*) is a self/partner review framework, not a certification — credit AWS for documenting the scope, but the term is marketing-adjacent.

## Cross-cutting A — Network Protection & Isolation  ·  10 present / 2 partial / 1 absent

**Posture:** The deepest network stack in the industry, with isolation **present** by construction (account + VPC isolated by default, cross-account requires explicit grants) and rich private connectivity (PrivateLink interface/gateway endpoints, VPC peering, Transit Gateway, Direct Connect, Site-to-Site VPN, Client VPN — *fact-check corrected Client VPN auth to mutual-cert / AD / SAML, no standalone "IAM" mode*). SSM Session Manager provides keyless, portless, audited instance access (the modern no-bastion pattern).

**The footguns:**
- **Default VPC is public-by-default** (*present, footgun*) — default subnets auto-assign public IPv4 and have an IGW route; nondefault subnets are private.
- **Egress is open by default** (*present, footgun*) — a new security group has no inbound rules but one allow-all-outbound rule to `0.0.0.0/0`, and there is **no egress filtering by default** — a direct data-exfiltration path for proprietary IP unless Network Firewall / DNS Firewall domain allowlisting is added.
- **VPC Flow Logs are off by default** (*present, footgun*).
- **IMDSv2 enforcement** (*partial → absent*) — enforcing IMDSv2 at launch org-wide is possible via Declarative Policy/SCP, but there is **no default-on or retroactive control** that converts an existing heterogeneous fleet of long-lived instances off IMDSv1.

→ **Recommendations P0-3 (data perimeter incl. egress), P0-4 (IMDSv2 enforcement).**

## Cross-cutting B — Serverless / Edge Middleware  ·  6 present / 7 partial / 1 misleading

**Posture:** Multiple real defense layers exist (CloudFront, API Gateway, ALB, Lambda@Edge, authorizers — IAM SigV4, Cognito, Lambda authorizers, JWT), and **Shield Standard is default-on and free**. But most of the *enforcement* layers are opt-in.

**The footguns:**
- **API Gateway usage-plan throttling is not a security control** (*misleading, DbM*) — AWS explicitly says don't rely on usage-plan API keys/quotas for cost control or authorization.
- **WAF is opt-in and must be explicitly associated** (*partial*), and **WAF rate-based rules have a documented multi-minute detection lag** (*partial*) — a real cost-abuse hole for GPU-backed inference, where a burst can run up the bill before a block engages. *(Fact-check: the 10-request minimum limit landed Aug 2024, not May 2025.)*
- **Lambda Function URL `AuthType: NONE`** (*present, footgun*) is a one-toggle public endpoint (since Oct 2025 it auto-creates a `Principal: *` resource policy and requires explicit `AuthType`).
- **API Gateway access/exec logging and WAF logging are off by default** (*partial*); request/response validation is opt-in per method (*partial*).
- **Cognito guest roles and threat-protection** (*partial, DbM*) — identity-pool unauthenticated roles and user-pool threat protection have default/paid-tier nuances worth checking.

→ **Recommendation P2-11 (edge hardening for public endpoints).**

## Cross-cutting C — Source Control & CI/CD  ·  5 present / 6 partial

**Posture:** **The headline correction of this assessment lives here.** The draft found CodeCommit closed to new customers — the fact-check **reversed it**: **AWS CodeCommit returned to full general availability on Nov 24, 2025**, new sign-ups are open again, and AWS reversed its no-new-features stance (Git LFS Q1 2026). So a multi-team org *can* once again use a first-party, IAM-native Git host (**present**, status flipped from `absent`). The strong keyless pattern — **GitHub Actions OIDC → `AssumeRoleWithWebIdentity`** — is well documented, CodeConnections uses a scoped GitHub App (not a broad PAT), and you can decouple entirely by pushing prebuilt images to ECR.

**The footguns:**
- **OIDC sub-claim scoping** (*partial, DbM*) — the same confused-deputy risk as in Identity: a missing/wildcard `sub` condition trusts the whole org.
- **Build-secret exposure in CodeBuild** (*partial, DbM*) — env vars, build logs, and source-URL credential leakage; Security Hub control `CodeBuild.1` flags PATs embedded in source URLs as Critical.
- **CodeConnections GitHub App breadth + single-install-per-org** (*partial, DbM*), and CloudTrail covers the token vend / `UseConnection` but **not which repository content was actually cloned** (*partial*).
- **Build provenance / downstream signature verification is not enforced end-to-end** (*partial, DbM*) — ties back to the supply-chain signing gap.

→ **Recommendations P1-7 (OIDC sub-claim), P1-9 (build provenance + verification).**

## Cross-cutting D — Organizational Substrate  ·  6 present / 5 partial / 1 absent / 1 misleading

**Posture:** This is the layer that *makes or breaks* a multi-team AWS org, and AWS's model is the one others copy. **Present:** the Organization → OU → Account hierarchy (account = isolation unit; note there is no in-account project/folder layer like GCP, so multi-team = many accounts), **Resource Control Policies (GA Nov 2024)** closing the external-principal/resource-policy blind spot SCPs never covered, **Declarative Policies (Dec 2024)** for durable desired-state config, **centralized root access management (Nov 2024)** to remove member-account root credentials, **IAM Identity Center** (SAML/SCIM/external IdP, permission sets across accounts), and **Control Tower** for landing-zone guardrails.

**The footguns:**
- **The data-perimeter triad is opt-in to compose** (*partial, DbM*) — SCP (identity perimeter) + RCP (resource perimeter) + VPC endpoint policy is the prescribed closed perimeter, but you author it, and **RCP service coverage doesn't yet span every service** holding this org's IP (verify Bedrock/SageMaker/EC2-EBS/Lambda/RDS/EKS and compensate with resource policies where unsupported).
- **SCP default is `FullAWSAccess`** (*partial*) — guardrails are deny-by-addition; nothing is restricted until you write the deny.
- **EBS encryption-by-default is opt-in per account/region** (*absent as an org default*) — a new GPU account or newly-enabled region can create unencrypted volumes/snapshots of training data.
- **Tag Policies don't force tags to exist** (*misleading, DbM*) — they standardize values but only an SCP can require a `team`/`data-classification` tag at creation, which ABAC and isolation depend on.
- **IAM Identity Center SCIM doesn't expand nested groups** (*partial*); the "3000" quota is a *combined accounts-or-applications* quota (*fact-check corrected from the mislabeled "account-instance quota"*).

→ **Recommendations P0-3 (data perimeter), P1-8 (EBS encryption default), P2-13 (tag governance via SCP).**

---

## Fact-check & corrections

The adversarial verification pass ran **105 checks (95 confirmed)** and overturned **10 claims**, each reconciled into the finding text above (full ledger in `aws-corrections.csv`):

| # | Signal | Verdict | What changed |
|---|---|---|---|
| 1 | visibility | refuted | Bedrock `InvokeModel`/`Converse` are **management** events (logged by default), not data events; only certain runtime ops + SageMaker `InvokeEndpoint` are data events |
| 2 | identity | outdated | `ec2:RunInstances` spans **twelve** resource types, not eight; `spot-instances-request` removed |
| 3 | supply_chain | refuted | **Neither** EKS nor ECS has a native managed signature-verification gate — both require customer-assembled enforcement |
| 4 | org_maturity | outdated | Current AWS CISO is **Amy Herzog** (since June 2025), not Chris Betz |
| 5 | org_maturity | refuted | European Sovereign Cloud GA was **Jan 15 2026**, not Jan 14 |
| 6 | org_maturity | outdated | SRT engagement requires **Shield Advanced AND a Business/Enterprise Support plan** |
| 7 | network | outdated | Client VPN auth is mutual-cert / AD / **SAML** (no standalone "IAM" mode) |
| 8 | edge | refuted | WAF 10-request minimum rate limit landed **Aug 2024**, not May 2025 |
| 9 | source_control | outdated | **CodeCommit returned to GA Nov 24 2025** — the draft's central "closed to new customers" finding was reversed (status flipped `absent` → `present`) |
| 10 | org_substrate | refuted | IAM Identity Center 3000 is a **combined accounts-or-applications** quota, not an "account-instance" quota |

## Recommendations

Full account-runnable checks (how-to-check, pass-criterion, remediation) are in [`aws-audit-checklist.csv`](./aws-audit-checklist.csv). Summary:

**P0 — before production IP lands**
1. **Durable, immutable, org-wide CloudTrail including S3 object-level data events on IP stores** — close the default exfil-blindness; deliver to a locked log-archive account with Object Lock + log file validation.
2. **Org-wide GuardDuty with the relevant protection plans (S3/Malware/EKS-runtime/RDS/Lambda), delegated admin, and auto-enable for new accounts.**
3. **Build the data perimeter** — SCP (identity perimeter) + RCP (resource perimeter, `aws:PrincipalOrgID`) + VPC endpoint policies; verify RCP coverage for the services holding IP.
4. **Eliminate standing credentials** — retire IAM user access keys (→ Identity Center), enforce IMDSv2 fleet-wide via Declarative Policy, centralize/remove member-account root.

**P1 — shortly after go-live**
5. Security Hub org-wide aggregation (FSBP + CIS, auto-enable).
6. AWS Config org-wide recording + encryption/public-access conformance packs.
7. Confused-deputy hygiene — external IDs, `aws:SourceArn`/`SourceAccount`, OIDC `sub`-claim conditions.
8. Encryption-at-rest defaults — EBS encryption-by-default per region/account + per-team KMS CMKs with **scoped** key policies (not stock `kms:*` to root).
9. Supply-chain integrity — ECR enhanced scanning + AWS Signer signing + deploy-time verification gate per compute platform.
10. IAM Access Analyzer (external + unused) org-wide + CI custom-policy checks.

**P2 — hardening / ongoing**
11. Edge hardening for public AI/inference endpoints — WAF associated + rate-based rules + request validation + access/WAF logging; block Lambda Function URL `AuthType: NONE`.
12. Bedrock/SageMaker AI controls — mandatory Guardrails via `bedrock:GuardrailIdentifier`, model-scoped IAM, PrivateLink to Bedrock, SageMaker VPC-only.
13. Tag governance + ABAC enforced by **SCP** (Tag Policies alone don't force tags to exist).

## Worklist / what to drive to ground

This is a first pass meant to be proofed and extended. The highest-value follow-ups: (a) confirm **current RCP service coverage** against the exact services holding your IP (it expands over time); (b) re-verify the **SOC 2 *Services in Scope*** list for your specific managed services before relying on attestation; (c) decide whether **Bedrock model-invocation content logging** is required for IP/abuse forensics (it's the only way to capture prompt/response, and it carries its own data-sensitivity tradeoff); and (d) validate that **auto-enable for new accounts** actually fires for every security service as the org vends accounts — the recurring failure mode in a multi-team AWS org is a freshly-created account that silently starts from the permissive default.
