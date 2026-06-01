# Cloud Security Posture — Probing Checklist

This is the full set of questions to ask when evaluating a cloud platform's security
posture. Organized by the five signal categories. Each question includes *why* it
matters — the threat or assumption it's testing.

Use this reference when generating platform-specific checklists or when doing a guided
evaluation. Not every question applies to every platform or deployment context; skip
questions that aren't relevant to the workload.

---

## Framings to carry through every probe

Before walking the probe list, hold these framings — they reshape how individual
questions land.

**Ergonomics, not just presence.** For every capability you check, ask not only *"is
it there?"* but *"is it expressible and operable?"* — can least privilege be
*written down*, can the blast radius be *articulated*, can the session be *limited
in time and traffic origin*? A capability that exists but has no policy primitive
attached is fundamentally different from one that does.

**Two distinct kinds of credential — not a hierarchy.** The "API keys" category
collapses two different things that need different probes. They aren't a class and a
subclass; they're separate concerns with different threat models:
- **Platform-access credentials**: credentials the platform issues to *you*
  for acting on the platform. The IAM questions live here.
- **Brokered credentials**: credentials the platform holds *on your behalf*
  so it can talk to systems it doesn't own (your registry, your GitHub, your object
  storage, your secrets store). This is *secrets management*, not platform IAM —
  different threat model, different controls, different probes. It exists because
  neoclouds *conglomerate adjacent services* to cover gaps where they don't have
  first-party offerings.

When inventorying credentials, separate platform-access from brokered before
evaluating ergonomics.

**Documentation quality is itself a finding.** Classify every probe answer as one of:
- **Documented** — clearly stated, does what the docs say.
- **Documented but misleading** — present in docs but the terminology implies more than
  what's delivered (*"RBAC"* with two identical roles, *"audit logs"* that are
  application stdout, *"scoped keys"* that scope to resources but not operations). The
  most dangerous category — familiar terms make teams stop looking.
- **Discoverable** — findable but not prominently documented.
- **Absent** — no documentation; you inferred or tested.

**Don't universalize.** When you write findings, frame patterns as questions to ask
on the next platform, not as class-wide claims. *"On the platforms I've evaluated, X is
uncommon"* — not *"all neoclouds lack X."* The framework's value is identifying *where
on the spectrum* each platform sits.

**Container-workload visibility compounds.** Ephemeral container logs aren't unique to
neoclouds — that's just the shape of containerized workloads. What's different is that
hyperscalers shipped batteries-included observability (CloudWatch, Cloud Logging,
Activity Logs). Neoclouds often don't. So the same problem you'd have anywhere
compounds because the safety net is gone. Probe this as a *visibility* concern, not
just an audit-log concern.

**Scoping primitives compose; an "agent identity" type is the wrong standard.** No
hyperscaler ships "agent identity" as a built-in type, and you shouldn't expect a
neocloud to either. What matters are *primitives you can compose* to constrain any
principal — human, service, or agent: token exchange (STS AssumeRole,
AssumeRoleWithWebIdentity), session-time scoping (session policies), session metadata
that propagates and gets logged (session tags, source identity), and policy conditions
that consume that metadata. Probe for these primitives — not for an "AgentRole" feature.

---

## Table of Contents

1. [Visibility](#1-visibility)
2. [Identity Granularity](#2-identity-granularity)
3. [Supply Chain](#3-supply-chain)
4. [Organizational Maturity](#4-organizational-maturity)
5. [Transparency](#5-transparency)
6. [Control Plane Security (Bonus)](#6-control-plane-security)
7. [Network & Endpoint Exposure](#7-network--endpoint-exposure)

---

## 1. Visibility

The goal: determine whether you can reconstruct what happened during an incident using
only the platform's native capabilities.

### Audit Logging

- **Are admin actions logged separately from application stdout?**
  Why: If administrative events (key creation, instance deletion, permission changes)
  are mixed into the same stream as container stdout, you can't build reliable detection
  rules. An attacker deleting an instance looks the same as a noisy application logger.

- **What is the audit log schema? Is it documented?**
  Why: Without a known schema, you can't write parsers, build dashboards, or create
  alerting rules. You're flying blind on what fields exist.

- **What is the retention period? Is it configurable?**
  Why: Most compliance frameworks require 12+ months. Some neocloud providers retain
  for 6 months or less. If you can't configure it, you may fail audits.

- **Can you export logs to external systems (S3, SIEM, webhook)?**
  Why: Platform-native log viewers are fine for debugging but insufficient for incident
  response. You need logs in your own systems where you control retention and can
  correlate across platforms.

- **Are logs immutable? Can an admin (or compromised key) delete them?**
  Why: If the same key that can delete infrastructure can also delete the logs recording
  that deletion, you have no forensic trail.

- **Is there real-time log streaming or alerting?**
  Why: If you can only view logs through a web console with no streaming API, your mean
  time to detect is however often someone manually checks the console.

- **Do logs capture the identity (key ID, user, role) that performed each action?**
  Why: "Something was deleted" is less useful than "key rpa_abc123 associated with user
  jane@corp.com deleted serverless endpoint X at 14:32 UTC."

### Application Logging

- **Where do container stdout/stderr go?**
  Why: Understanding the log pipeline helps you know what's captured, what's dropped,
  and whether sensitive data in application logs is being stored somewhere you don't
  control.

- **Can you disable or filter application log capture?**
  Why: If your application logs contain sensitive data (tokens, PII), and the platform
  captures everything, that data now lives in the platform's log storage.

- **Is there a distinction between log levels/streams?**
  Why: Some platforms capture only stdout, dropping stderr. Others capture both but
  can't distinguish them. This matters for error detection.

---

## 2. Identity Granularity

The goal: determine how close you can get to least privilege on this platform.

### Roles & Permissions

- **How many distinct roles exist? What can each one do?**
  Why: Two roles with identical permissions (a common shape: Admin and Member both
  able to create keys, launch instances, terminate workloads) means RBAC is cosmetic.

- **Can you create custom roles?**
  Why: Without custom roles, you're limited to the vendor's idea of what permission
  boundaries matter. If the gap between "read-only" and "full admin" is too wide, you
  can't express real-world access patterns.

- **Is there a role that can restart/reboot but not create or delete?**
  Why: This is a practical litmus test. "Restart a stuck GPU pod but don't provision
  $10k/day of H100s" is a common real-world need. If you can't express it, your
  operators have more power than they should.

- **Are role permissions documented with specificity, or just labels?**
  Why: A role called "Developer" tells you nothing. A role documented as "can call
  POST /instances, DELETE /instances, GET /instances but not POST /api-keys or
  PUT /team/members" tells you everything.

### Credential Inventory

Before probing individual credential types, start by mapping the full inventory.
Platforms often have more credential types than you expect, and the relationships
between them — which are control plane, which are data plane, which are infrastructure
— determine your actual blast radius.

- **How many distinct credential types exist on this platform?**
  Why: "API keys" is usually not one thing. A platform might have: management API keys
  (control plane), endpoint invocation keys (data plane), storage access keys, container
  registry credentials, SSH keys, pod-scoped tokens, and more. Each has a different
  blast radius, lifecycle, and transmission mechanism. If you treat them as one category
  you'll miss the security boundaries between them — or discover there aren't any.

- **For each credential type: does it grant control plane or data plane access?**
  Why: This is the most important classification. A key that can invoke a serverless
  endpoint (data plane) is a different risk than a key that can delete infrastructure
  (control plane). On some neocloud platforms, the same key does both. On others, data
  plane keys and control plane keys are genuinely separate — which is good. Map each
  credential to what it can actually touch.

- **For each credential type: how is it transmitted?**
  Why: Keys in URL query parameters (`?api_key=...`) appear in server logs, browser
  history, referrer headers, and proxy logs. Keys in Authorization headers are
  significantly less exposed. Different APIs on the same platform may use different
  transmission mechanisms — one API might use Bearer headers while another puts keys in
  the URL. Check each one.

- **For each credential type: does it expire? Can you rotate it?**
  Why: Long-lived keys with no expiration are credentials that work forever if leaked.
  Automated rotation requires programmatic expiration. Zero-downtime rotation requires
  overlapping validity periods. Check each credential type independently — storage keys
  may have different lifecycle controls than management keys.

- **Are there auto-generated credentials you didn't create and can't revoke?**
  Why: Some platforms inject pod-scoped or instance-scoped keys automatically. If you
  didn't create them, you may not know their permissions or lifecycle. These are easy to
  miss in a credential inventory because they don't show up in the key management UI.

### API Key Scoping

- **Are API keys scoped to specific operations or just endpoints/resources?**
  Why: A key that can invoke a serverless endpoint but can also delete that endpoint
  isn't scoped in any meaningful security sense. Scoping to "which resource" without
  scoping to "which action" is half a control. Ask specifically: if I scope a key to
  endpoint X, can that key also modify or delete endpoint X?

- **Can you have multiple keys with different scopes simultaneously?**
  Why: Separation of duties requires different keys for different systems (CI/CD vs.
  monitoring vs. manual operations).

- **Are there short-lived credential mechanisms (STS, OIDC, OAuth, service accounts)?**
  Why: Without short-lived credentials, every automated system holds a long-lived secret.
  There's no way to scope credentials to a CI/CD pipeline run or a specific session.

### Workload Identity & Off-Platform Assertion

Workload identity is how a running workload proves who it is to external services —
without embedding long-lived secrets. On hyperscalers, this is table stakes (AWS
AssumeRole, GCP Workload Identity Federation, Azure Managed Identity). On neoclouds,
it ranges from well-implemented (short-lived OIDC tokens with proper discovery) to
completely absent (no workload identity at all; every outbound call needs a long-lived
secret).

- **Does the platform issue identity tokens to running workloads?**
  Why: Without workload identity, every service-to-service call requires a long-lived
  secret embedded in the workload. With workload identity, the platform itself attests
  "this is function X in workspace Y" via a signed token — no secret management needed.

- **Can workload identity tokens be used off-platform for identity assertion?**
  Why: The real power of workload identity is federation — using the platform-issued
  token to authenticate to external services (AWS, GCP, your own IdP) without
  exchanging secrets. If the token is only valid within the platform, it solves internal
  service-to-service auth but doesn't help with external integration. Check: can you
  configure AWS IAM to trust the neocloud's OIDC issuer? Can you present the token to
  your corporate identity provider?

- **Is there an OIDC discovery endpoint?**
  Why: Standard OIDC discovery (`/.well-known/openid-configuration`) means any service
  that supports OIDC federation can validate the platform's tokens without custom
  integration. This is what makes workload identity composable across cloud boundaries.

- **What claims are in the identity token? How granular is the identity?**
  Why: A token that says "this is from workspace X" is less useful than one that says
  "this is function Y, version Z, running in environment prod, in workspace X." The
  granularity of claims determines how precisely you can scope external access. Can you
  write an AWS IAM policy that trusts only a specific function, or only "anything from
  this workspace"?

- **What is the token lifetime? Is it auto-refreshed?**
  Why: Short-lived tokens (minutes) limit blast radius if intercepted. But if the
  token isn't auto-refreshed, your workload needs to handle expiration and re-request.
  Check whether the platform injects fresh tokens automatically or whether you need to
  implement refresh logic.

- **Can you use workload identity to authenticate to the platform's own services?**
  Why: Some platforms issue identity tokens that work for external federation but
  require separate API keys for their own services. The ideal is a single identity
  mechanism that works both internally and externally.

### API Tooling & MCP Integration

AI-assisted workflows (Claude, Copilot, custom agents) increasingly interact with cloud
platforms via MCP servers, SDKs, and APIs. The question is whether the platform's auth
model supports giving a tool less access than the human using it — without requiring IT
to create a special service account.

- **Does the platform offer an MCP server or official API integration for AI tools?**
  Why: An MCP server means the platform is explicitly designed to be operated by AI
  agents. This is becoming a baseline expectation. If there's no MCP server, users will
  build unofficial ones — and those are more likely to require full-access API keys
  because the builder took the path of least resistance.

- **Can a user create a token scoped to read-only access for tool use?**
  Why: When you hand an API key to an MCP server or AI agent, you want to give it the
  minimum permissions necessary. "Read infrastructure state but can't create, modify, or
  delete anything" is the obvious first scope. If the platform only offers full-access
  keys, every AI tool interaction carries the blast radius of a full admin session. Can
  a user self-service a read-only token, or does it require IT/admin intervention?

- **Can you scope tool tokens to specific operations without admin involvement?**
  Why: Beyond read-only, the ideal is fine-grained delegation — "this token can invoke
  endpoints but not create or delete them," "this token can read logs but not
  infrastructure." If the only way to get a scoped token is to ask IT to create a
  service account with custom permissions, adoption will be slow and most users will
  just hand their full-access key to the tool instead.

- **Is there an OAuth or OIDC flow for tool authorization?**
  Why: OAuth consent flows let users grant scoped access to tools without sharing their
  API key at all. The tool gets a short-lived token with only the permissions the user
  approved. This is the gold standard for tool integration — it's how GitHub Apps,
  Slack, and mature platforms handle third-party access. Long-lived API keys pasted into
  tool configs are the fallback when this doesn't exist.

- **Can you audit which tools or MCP servers are using which credentials?**
  Why: If five different AI tools all use the same API key, you can't distinguish their
  actions in audit logs. Separate tokens per tool (ideally with a tool identifier in the
  token metadata) let you trace "this action was performed by the Claude MCP server
  using Jane's read-only delegation" vs. "this action was performed by the CI pipeline."

### Source Control & CI/CD Integration

Many neocloud platforms encourage you to connect your source code repository directly —
for automated deployments, image builds, or function syncing. This creates a trust
relationship between the platform and your code. The question is how much access that
relationship requires and how much visibility you have into it.

- **Does the platform integrate with source control (GitHub, GitLab, Bitbucket)?**
  Why: Direct repo integration is convenient but creates a bidirectional trust
  relationship. The platform can read your code, and depending on the integration, may
  be able to write to it (status checks, deployment markers, webhooks). Understanding
  what the integration can do is step one.

- **What permissions does the source control integration require?**
  Why: There's a big difference between a GitHub App with scoped read access to a single
  repo and a personal access token with full read/write to every repo in your org. Some
  platforms request `repo` scope (full read/write to all repositories) when all they
  need is read access to one. Check whether it's an OAuth App, a GitHub App (more
  granular), or a raw PAT. Check the actual scope — not just what the docs say, but what
  the OAuth consent screen requests.

- **Can you scope the integration to specific repositories?**
  Why: If the platform needs access to the repo containing your serverless function
  code, that's reasonable. If it gets access to every repo in your GitHub org — including
  your infrastructure-as-code, secrets management configs, and internal tools — that's
  an unnecessary blast radius. Can you limit it to specific repos, or is it all-or-nothing?

- **Is the integration read-only, or does it require write access?**
  Why: Read access to pull code for builds is one thing. Write access means the platform
  can push commits, create branches, modify workflows, or update deployment status.
  Write access to your source control is write access to your supply chain. Does the
  platform actually need write, or is it requesting it "just in case"?

- **Where are builds executed, and what has access during the build?**
  Why: If the platform builds your container images from source, the build environment
  has access to your code and potentially to build secrets (npm tokens, pip credentials,
  private registry auth). Is the build environment isolated per tenant? Are build logs
  retained, and do they contain secrets? Can a malicious Dockerfile exfiltrate build
  secrets?

- **Can you use your own CI/CD pipeline instead of the platform's integration?**
  Why: If you can push pre-built images or artifacts rather than giving the platform
  source access, you keep your code supply chain under your own control. The platform
  only sees the built artifact, not the source. This is the more secure pattern, but
  some platforms make it significantly harder than the "connect your GitHub" flow.

- **Can you audit what the platform accessed in your repository?**
  Why: GitHub audit logs will show API calls from OAuth apps and GitHub Apps, but the
  granularity varies. Can you tell whether the platform only read the repo it needs, or
  whether it enumerated your entire org? If the integration uses a PAT, all access looks
  like the user who created the token.

### Team/Org Key Management

- **Can team admins see, manage, or revoke keys created by other team members?**
  Why: If a team member leaves and their keys can't be revoked by an admin, you have
  orphaned credentials with no lifecycle management.

- **Is key creation logged? Can you audit who created which key and when?**
  Why: Key provenance matters for incident response. "Which key was compromised?"
  requires knowing which human created it and for what purpose.

- **Can you enforce policies on key creation (naming conventions, expiration, scope)?**
  Why: Without policy enforcement, you get key sprawl — dozens of undocumented
  full-access keys with no owner and no expiration.

---

## 3. Supply Chain

The goal: determine what you're actually running on and who controls the artifacts.

### Compute Environment

- **What base images are available? Who maintains them?**
  Why: You're running on someone else's base image. If it has unpatched CVEs or
  unexpected software, your workload inherits those risks.

- **Can you bring your own base image, or are you limited to the vendor's?**
  Why: If you must use vendor images, you're trusting their patching cadence and
  software choices. If you can bring your own, you control the supply chain.

- **What GPU drivers and CUDA versions are installed? Who patches them?**
  Why: GPU driver vulnerabilities can allow container escape. The patching cadence for
  GPU drivers on neocloud providers is often opaque.

- **Is the container runtime documented? What isolation model is used?**
  Why: Some GPU cloud providers use shared GPU contexts across tenants. Understanding
  the isolation boundary matters for data leakage risk.

### Hardware & Firmware

- **What attestations does the provider make about hardware and firmware updates?**
  Why: GPU firmware, BMC firmware, NIC firmware — these are the layers you cannot
  update yourself. On a hyperscaler, you get documented maintenance windows and fleet
  update policies. On a neocloud, especially one running leased or collocated hardware,
  the firmware update cadence may be undefined. An unpatched GPU firmware vulnerability
  is invisible to your container and invisible to your monitoring — you'd never know.

- **Who owns the hardware? What is the chain of custody for patching?**
  Why: Ownership affects patching authority, but the real question is the chain of
  custody. If the provider leases GPU racks from a colo facility, firmware updates may
  depend on a third party's schedule — and that third party's compliance may not be
  attested. If the provider is an orchestration layer on top of data center partners
  (as some neoclouds are), then firmware patching authority sits with partners whose
  names you may not know, whose patching cadence is opaque, and whose compliance is
  verified only by the provider's partner requirements — if at all.

- **Is there any hardware-level attestation or integrity measurement?**
  Why: Secure boot, TPM measurements, and firmware integrity checks give you evidence
  that the machine you're running on hasn't been tampered with. Without attestation,
  you're trusting the provider's rack ops team implicitly.

- **Can you verify the GPU model and configuration you're actually running on?**
  Why: "H100" can mean different things — SXM vs. PCIe, different memory
  configurations, different NVLink topologies. If you're paying for H100 SXM5 80GB and
  getting something else, that's a procurement issue. If the platform has no mechanism
  to verify, it's also a trust issue.

### Container Registry

- **How does the platform authenticate to your container registry?**
  Why: If registry credentials are stored in plaintext, anyone with platform access may
  be able to pull your images. If the platform uses a shared credential, all tenants may
  have access to each other's registries.

- **Can you use a private registry, or must images go through the vendor's registry?**
  Why: Pushing images to a vendor registry means your container contents (potentially
  including model weights and proprietary code) live on vendor infrastructure.

- **Is there image signing or verification?**
  Why: Without image verification, a compromised registry credential can inject
  malicious images that the platform will happily run.

### Secrets Management

- **How are secrets injected into workloads?**
  Why: Environment variables visible to all processes? Mounted files? A secrets API?
  The injection mechanism determines exposure surface.

- **Are secrets write-only (can't be read back after creation)?**
  Why: If anyone with console access can read secrets in plaintext, a compromised
  account exposes all secrets — not just future access.

- **Can secrets be scoped to specific workloads or environments?**
  Why: A secret available to all workloads means a compromised dev instance can read
  production credentials.

- **Is there an automatic rotation mechanism for secrets?**
  Why: Manual rotation doesn't happen. If the platform doesn't support rotation, secrets
  are effectively permanent.

### Object/Blob Storage

- **Is there platform-native object storage? How is access controlled?**
  Why: If the storage uses the same API key as compute management, you can't give a
  data scientist read access to storage without also giving them permission to delete
  infrastructure.

- **Are storage access keys separate from compute management keys?**
  Why: Separation of storage and compute credentials is basic privilege separation.

- **Is storage encrypted at rest? Who holds the encryption keys?**
  Why: Vendor-managed encryption keys mean the vendor (and anyone who compromises the
  vendor) can read your data.

- **Can you restrict storage access by network (VPC, IP allowlist)?**
  Why: Publicly accessible storage with only key-based auth is one leaked key away
  from data exfiltration.

### Community & Marketplace Trust

Some neocloud platforms have marketplace or community models — community-contributed
templates, community-provided compute capacity, or third-party integrations. These
introduce trust boundaries that don't exist on hyperscalers.

- **Does the platform aggregate compute from third-party providers?**
  Why: "Community cloud" or "peer provider" models offer cheaper capacity by
  aggregating spare GPUs from external operators. Your workload may run on hardware
  owned and operated by someone other than the platform vendor. The security posture
  of these community providers may differ from the platform's own infrastructure.

- **Can you distinguish first-party from community-provided resources?**
  Why: If you can't tell whether your pod is running on the platform's own
  infrastructure or a community provider's spare GPU, you can't make informed
  decisions about what workloads to run where.

- **Who vets community templates, images, or integrations?**
  Why: A marketplace of community-contributed templates means someone else's Dockerfile
  is running in your account. What's the review process? Is there a distinction between
  "official" and "community" templates? Can a malicious template exfiltrate your
  environment variables (including secrets)?

- **What are the attestation requirements for community infrastructure providers?**
  Why: If the platform requires partners to meet specific security standards, that's
  useful — but only if compliance is verified, not just required. "Must update firmware
  to latest stable version" in a partner agreement is different from "firmware versions
  are attested and audited."

---

## 4. Organizational Maturity

The goal: determine whether the vendor has the organizational capability to handle
security incidents and evolve their security posture.

- **Is there a named product security team or lead?**
  Why: If there's no one whose job it is to own security, security improvements are
  accidental.

- **Is there a vulnerability disclosure program (VDP) or bug bounty?**
  Why: A VDP signals that the organization expects to have vulnerabilities and has a
  process for handling reports. No VDP means external researchers have no safe way to
  report issues.

- **Is there documented incident response?**
  Why: When something goes wrong, you need to know who to call, what their SLAs are, and
  what information they'll share with you.

- **What is the SOC 2 Type II scope?**
  Why: "We have SOC 2" can mean anything from "our corporate email has MFA" to "our
  entire production infrastructure is audited." The scope matters. Ask for the trust
  services criteria that are covered.

- **Is there a security changelog or advisory feed?**
  Why: If the platform silently patches security issues without telling customers,
  you can't assess whether issues you noticed were addressed.

- **Does the vendor publish post-incident reports?**
  Why: Post-incident transparency signals organizational maturity. Silence after
  incidents signals the opposite.

### Leadership, Funding & Geopolitical Risk

Technical controls exist within a business context. Who founded the company, who funds
it, where it's incorporated, where the data centers are physically located, and what
regulatory regimes apply — these all affect your risk calculus in ways that API
documentation reviews don't capture. This isn't about making political judgments; it's
about ensuring your organization has the facts to make informed decisions about data
residency, regulatory exposure, and supply chain risk.

- **Where is the company incorporated? Where are the data centers physically located?**
  Why: Incorporation jurisdiction determines which government can compel data disclosure.
  Data center location determines which data residency and sovereignty laws apply. A
  company incorporated in one country with data centers in another may be subject to
  legal obligations from both. For regulated workloads (HIPAA, GDPR, ITAR, FedRAMP),
  this isn't optional — it's a compliance prerequisite. Even for unregulated workloads,
  your organization may have policies about where data can reside.

- **Who are the primary investors and funding sources?**
  Why: Venture capital, sovereign wealth funds, strategic investors, and government
  grants all carry different implications. A neocloud funded by a strategic investor in
  the same industry as your business may raise competitive concerns. A neocloud with
  sovereign wealth fund backing from a specific government may trigger your
  organization's geopolitical risk policies. This isn't about the money being "bad" —
  it's about your organization having the facts to apply their own risk framework.

- **Who is on the leadership team and board? What are their prior affiliations?**
  Why: Leadership backgrounds signal organizational priorities and potential conflicts.
  A founding team with deep infrastructure and security backgrounds is a different
  signal than one from pure ML research with no infrastructure operations experience.
  Board composition may also reveal strategic relationships or obligations that affect
  the platform's independence and direction.

- **Is the company subject to any export controls, sanctions, or regulatory restrictions?**
  Why: If the provider or its parent entity is subject to sanctions or export controls,
  your use of the platform may create compliance exposure for your organization. This is
  especially relevant for defense, aerospace, financial services, and any organization
  with US government contracts. Check OFAC, BIS Entity List, and equivalent lists in
  your jurisdiction.

- **Are there any known government contracts, partnerships, or data-sharing obligations?**
  Why: A provider with government contracts may be subject to additional data access
  requirements. A provider with partnerships that include data-sharing terms may expose
  your workload metadata or usage patterns to third parties. This is discoverable
  through public filings, press releases, and government contract databases.

- **What is the company's financial stability and runway?**
  Why: A neocloud that runs out of funding takes your workloads and data with it. The
  wind-down process for a cloud provider is rarely orderly. Understanding the company's
  financial position — recent funding rounds, revenue trajectory, burn rate if
  discoverable — helps you assess the risk of sudden service termination and plan
  accordingly (data portability, multi-cloud redundancy, exit clauses in contracts).

---

## 5. Transparency

The goal: determine whether the platform's documentation is honest about what it
doesn't do, not just what it does.

- **Does the documentation explicitly state what is NOT a security boundary?**
  Why: A platform explicitly saying "X is NOT a security boundary" is more useful than ten pages
  of marketing about their network security. Explicit negatives give you actionable
  information.

- **Does "scoped" mean what you think it means?**
  Why: A common pattern: "scoped keys" restrict which serverless endpoint you can call — but a key
  that can invoke an endpoint can also delete it. "Scoped" can mean "scoped to a
  resource" without meaning "scoped to an action." Always verify the actual granularity.

- **Are there features that the platform's marketing implies but doesn't deliver?**
  Why: "Enterprise-grade security" and "role-based access control" are marketing terms.
  Two roles with identical permissions is technically RBAC but functionally useless.

- **Is there a public roadmap for security features?**
  Why: A platform that's transparent about planned security improvements gives you a
  timeline for when gaps might close. This affects deployment timing decisions.

- **Are API error messages informative without being leaky?**
  Why: Overly verbose error messages can leak internal architecture. Overly terse
  messages make debugging impossible. The balance reveals security thinking.

---

## 6. Control Plane Security

This is a cross-cutting concern that touches several signal categories but deserves
specific attention because it's where the most dangerous gaps tend to live.

- **Is there more than one management API? Do they share the same auth model?**
  Why: Some platforms have multiple control plane APIs that evolved at different times —
  an original GraphQL API and a newer REST API, for example. These may have materially
  different security postures: one might put keys in URL query parameters while the
  other uses Bearer headers; one might have full schema introspection enabled while the
  other doesn't. If you only evaluate one API, you may miss that the other has weaker
  security properties. The same key might work on both, meaning the weakest API
  determines your actual exposure.

- **What protocols does each management API use?**
  Why: REST with Bearer token auth, GraphQL with query-parameter auth, gRPC with mTLS —
  these have very different security properties. A GraphQL management API with full
  introspection enabled and no query depth limits is a different risk profile than a
  REST API with per-operation IAM.

- **Is the management API the same endpoint as the data plane API?**
  Why: If management operations (create, delete, configure) share an endpoint with data
  operations (invoke, query), a key leaked from a data context may grant management
  access. Conversely, if they're separate, check whether the credential types are also
  separate — a data plane key that also works on the management endpoint isn't really
  separated.

- **Is API schema introspection enabled in production?**
  Why: GraphQL introspection lets anyone with a valid key enumerate all available
  operations, types, and fields. This is useful for development and useful for
  attackers. Hyperscalers disable introspection in production.

- **Are there query complexity limits, depth limits, or rate limits?**
  Why: Without these, the management API is vulnerable to alias-based amplification,
  deeply nested queries, and batch operations that can DoS the control plane or
  enumerate resources.

- **Can management operations be performed through the same SDK/CLI that runs workloads?**
  Why: If your workload runner can also delete other workloads, the blast radius of a
  compromised workload extends to the entire account.

---

## 7. Network & Endpoint Exposure

- **Are deployed endpoints (serverless, inference, etc.) exposed to the public internet
  by default?**
  Why: If every deployed model endpoint gets a public URL with only API key auth, your
  attack surface is the entire internet. On hyperscalers, you'd need explicit action to
  make an endpoint public.

- **Can you restrict endpoint access by network (VPC, private link, IP allowlist)?**
  Why: Network-level restrictions add defense in depth beyond key-based auth.

- **Is there tenant network isolation?**
  Why: On shared GPU infrastructure, can other tenants' workloads reach yours over the
  network? Is there a VPC equivalent?

- **What ports are open by default on compute instances?**
  Why: Open SSH with key-only auth is different from open SSH with password auth is
  different from no SSH at all. The default network posture matters.

- **How are SSH keys managed?**
  Why: Are SSH keys per-instance, per-user, or per-account? Can you rotate them? Are
  they injected automatically? Can you disable SSH entirely?

- **Is there a bastion/jump host model, or is every instance directly addressable?**
  Why: Direct addressability means every instance is independently attackable from the
  internet. A bastion model reduces the attack surface to a single entry point.

### VPC Interconnectivity & Network Architecture

On hyperscalers, network isolation and interconnection are deeply configurable — VPC
peering, Transit Gateway, PrivateLink, Direct Connect, ExpressRoute. Teams expect to
isolate projects from each other, peer them when needed, and connect back to corporate
networks. On neoclouds, the question is whether any of this exists at all.

- **If I have two projects or workspaces, are their networks isolated from each other?**
  Why: Project-level network isolation is fundamental to multi-team or multi-environment
  deployments. If project A's pods can reach project B's pods by default, a compromised
  workload in dev can reach production. On hyperscalers, VPCs are isolated by default
  and peering is explicit. What's the default here?

- **Can I peer networks between projects when I need connectivity?**
  Why: Isolation is the default you want, but controlled peering is the capability you
  need. Training jobs in project A may need to read data from a storage service in
  project B. If there's no peering mechanism, you're forced into either no isolation
  (everything on one flat network) or no connectivity (fully siloed with data copying).

- **Is there a transit or hub-and-spoke network model?**
  Why: At scale, pairwise VPC peering becomes unmanageable. Hyperscalers offer Transit
  Gateway (AWS), Cloud Interconnect + NCC (GCP), and Virtual WAN (Azure) for centralized
  routing. If the neocloud only supports flat networking or pairwise peering, network
  architecture gets brittle as you scale.

- **Can I establish a private interconnect to my corporate network?**
  Why: Many enterprise deployments require private connectivity between cloud workloads
  and on-premises infrastructure — for data gravity, compliance, or security reasons.
  Hyperscalers offer Direct Connect (AWS), Cloud Interconnect (GCP), and ExpressRoute
  (Azure). Does this neocloud support any form of private interconnect, VPN gateway, or
  dedicated circuit? If not, all traffic between your corpnet and the neocloud traverses
  the public internet.

- **Is there a PrivateLink equivalent for accessing platform services without public endpoints?**
  Why: Even if your workloads are on a private network, API calls to the platform's
  management plane may still go over the public internet. PrivateLink-style connectivity
  keeps management traffic on private infrastructure.

- **What network-level security controls exist (security groups, NACLs, firewall rules)?**
  Why: Without per-workload firewall rules, you can't restrict which pods can talk to
  which. A flat network where all pods can reach all other pods within an account is a
  larger blast radius than most teams expect.

- **Can workloads access the internet by default, or is egress controlled?**
  Why: Unrestricted egress means a compromised workload can exfiltrate data or establish
  C2 channels. On hyperscalers, you can configure NAT gateways, egress firewall rules,
  and VPC flow logs. What's available here?

### Serverless / Edge Middleware

When serverless functions or inference endpoints are a primary offering, the middleware
layer between the internet and your function is where most of your security controls
would normally live. On a hyperscaler, you'd put API Gateway, WAF, CloudFront, or a
Lambda authorizer in front of a function. On a neocloud, that layer may not exist —
meaning your function is directly exposed with whatever auth the platform provides.

- **What auth mechanism protects the endpoint, and what are its actual security properties?**
  Why: "Bearer token," "API key," "proxy auth token," and "custom auth" are labels, not
  security properties. For any auth mechanism the platform provides, you need to
  classify it along several axes:

  - **Static or exchanged?** A static token is the same string every time — if it leaks,
    it works until someone manually revokes it. An exchanged token (OAuth client
    credentials, STS, OIDC token exchange) is short-lived and issued per session or per
    request. The blast radius of a leaked static token is unbounded in time; a leaked
    exchanged token expires. Most neocloud endpoint auth uses static tokens.

  - **Is it the same credential as the control plane?** If the token that invokes your
    endpoint is also the token that can delete it (or delete other infrastructure), a
    leaked invocation token is a full account compromise. On hyperscalers, API Gateway
    keys are separate from IAM credentials. On some neoclouds, it's the same account
    API key for both.

  - **Where does the token travel?** Bearer header, URL query parameter, custom header,
    or request body all have different exposure profiles. Tokens in URL query parameters
    end up in server logs, CDN logs, browser history, and referrer headers. Tokens in
    Authorization headers don't.

  - **Can you have multiple tokens with different scopes?** One token per endpoint, or
    one token for everything? Per-endpoint tokens limit blast radius. A single token
    that authenticates to all your endpoints means one leak exposes everything.

  - **Does it expire? Can you rotate it without downtime?** Rotation requires either
    overlapping validity periods (two tokens active simultaneously during rotation) or
    an exchange mechanism. If rotation means "delete the old one, create a new one, hope
    you update all clients fast enough," you'll never rotate.

  - **Can auth be optional?** Some platforms let you deploy endpoints with auth disabled
    entirely — a public URL with no authentication. If this is the default, or if it's
    a single toggle away from the default, it will happen by accident.

- **Is there an edge middleware or gateway layer in front of serverless endpoints?**
  Why: Without middleware, there's nowhere to enforce rate limiting, request validation,
  payload inspection, or custom auth logic before a request hits your function. Your
  function code is your only defense layer. On AWS, API Gateway + WAF + CloudFront
  give you three layers before a request touches Lambda. What's the equivalent here?

- **Can you attach custom auth logic (authorizers, middleware functions) to endpoints?**
  Why: API key auth may not be sufficient. You might need JWT validation, OAuth token
  introspection, HMAC signature verification, or IP-based rules. If the platform
  doesn't support custom authorizers, you're implementing auth inside your handler —
  which means every endpoint needs its own auth implementation rather than having it
  at the gateway level.

- **Is there platform-level rate limiting or abuse prevention?**
  Why: A public inference endpoint with no rate limiting is an open invitation for
  abuse — either cost-based (someone runs up your GPU bill) or availability-based
  (someone DoS-es your endpoint). On hyperscalers, API Gateway provides per-key
  throttling. What's available here?

- **Is there request/response transformation or validation at the edge?**
  Why: Schema validation, payload size limits, content type enforcement, and header
  manipulation at the edge prevent malformed requests from reaching your function.
  Without edge validation, your function has to handle every malformed request itself.

- **Can you add WAF rules or DDoS protection to endpoints?**
  Why: GPU inference endpoints are expensive to invoke. A DDoS attack that forces
  cold starts or saturates your GPU allocation has direct financial impact. WAF rules
  that block abusive patterns at the edge protect both availability and budget.

- **Is there observability at the edge layer (request logs, latency metrics, error rates)?**
  Why: If the only logging is inside your function, you can't see requests that were
  rejected at the edge, timeouts that occurred before reaching your function, or
  traffic patterns across all your endpoints. Edge-level observability is how you
  detect abuse and troubleshoot routing issues.
