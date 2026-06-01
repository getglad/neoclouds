# Hyperscaler Security Baseline

This reference describes the security controls that practitioners trained on AWS, GCP,
and Azure expect to exist. When evaluating a neocloud provider, these are the
assumptions that transfer — or don't.

Use this as the comparison baseline when generating the Comparison Matrix in an
evaluation report. The gap between what's listed here and what the target platform
offers is where ambiguous threats live.

---

## IAM & Identity

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Per-action permissions | Yes (hundreds per service) | Yes (predefined + custom roles) | Yes (RBAC + custom) |
| Resource-level policies | Yes (ARN-scoped) | Yes (resource hierarchy) | Yes (scope to resource) |
| Explicit deny | Yes (IAM policy deny) | Yes (deny policies, org level) | Yes (deny assignments) |
| Temporary credentials | STS, AssumeRole | Service account impersonation | Managed identity |
| OIDC/Federation | Yes | Workload Identity Federation | Azure AD federation |
| Service accounts / machine identity | IAM roles for services | Service accounts | Managed identities |
| MFA enforcement | Yes (per-user, per-role) | Yes (Google Workspace) | Yes (Conditional Access) |
| Session policies | Yes (session tags, duration) | Yes (session duration) | Yes (CAE) |
| Permission boundaries | Yes | Yes (org policies) | Yes (management groups) |
| Custom roles | Yes (IAM policies) | Yes | Yes |

## Audit & Logging

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Management event logging | CloudTrail (all API calls) | Cloud Audit Logs (admin) | Activity Log |
| Data event logging | CloudTrail data events | Cloud Audit Logs (data) | Diagnostic settings |
| Immutable logs | Yes (log file validation) | Yes (admin logs immutable) | Yes (immutable storage) |
| Retention | Configurable, default 90d, indefinite in S3 | 400d admin, 30d data (configurable) | 90d (configurable) |
| Real-time streaming | CloudWatch, EventBridge | Pub/Sub, Cloud Logging | Event Hubs, Monitor |
| Log export | S3, CloudWatch Logs | Cloud Storage, BigQuery | Storage, Event Hubs |
| Identity in log entries | Yes (ARN, principal, source IP) | Yes (caller, IP, user agent) | Yes (caller, IP, claims) |
| Admin/app log separation | Yes (CloudTrail vs CloudWatch) | Yes (audit vs application) | Yes (activity vs diagnostic) |

## Workload Identity & Off-Platform Federation

On hyperscalers, running workloads can prove their identity to external services without
embedding long-lived secrets. This is the baseline that makes "inject an API key as an
env var" on a neocloud feel like a step backward.

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Workload identity tokens | IAM roles for EC2/ECS/Lambda (instance metadata) | Workload Identity Federation (OIDC/SAML) | Managed Identity (system/user-assigned) |
| Off-platform federation | STS AssumeRoleWithWebIdentity, OIDC provider trust | Workload Identity pools (trust external OIDC/SAML) | Federated credentials (trust external OIDC) |
| OIDC discovery | N/A (STS is the exchange, not OIDC issuer) | Yes (accounts.google.com) | Yes (login.microsoftonline.com) |
| Token granularity | Per-role (role trust policy scopes to service/resource) | Per-service-account (bound to specific workloads) | Per-identity (scoped to resource/subscription) |
| Token lifetime | 1-12hr (configurable per AssumeRole call) | 1hr default (configurable) | Auto-refreshed (transparent to workload) |
| External service auth | AssumeRole → temp creds for any AWS service | Access token → any GCP API or federated service | Managed identity → any Azure resource or federated service |
| Cross-cloud federation | Trust GCP/Azure OIDC providers in IAM | Trust AWS/Azure OIDC in Workload Identity pools | Trust AWS/GCP OIDC in federated credentials |

Key expectation: a workload should be able to authenticate to external services (other
clouds, SaaS APIs, corporate IdPs) using platform-issued identity tokens — no secrets
to manage, rotate, or leak. When a neocloud only offers long-lived API keys, every
service-to-service call requires a secret, and every secret is a potential leak vector.

## Network

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| VPC / network isolation | Yes | Yes | Yes (VNet) |
| Private endpoints | PrivateLink | Private Service Connect | Private Link |
| Security groups / firewall | SGs + NACLs | Firewall rules | NSGs + Azure Firewall |
| Default: private | Yes (explicit public required) | Yes | Yes |
| Service mesh / internal only | Yes (VPC endpoints) | Yes (VPC-SC) | Yes (service endpoints) |

## VPC Interconnectivity

On hyperscalers, network isolation is the default and interconnection is deeply
configurable. Teams expect to isolate projects, peer them when needed, and connect
back to corporate networks with dedicated circuits.

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Cross-project/account isolation | VPCs isolated by default | VPCs isolated by default | VNets isolated by default |
| VPC peering | Yes (same/cross-region, cross-account) | Yes (same/cross-project) | VNet peering (same/cross-region) |
| Transit / hub-and-spoke | Transit Gateway | Cloud Interconnect + NCC | Virtual WAN, Hub-Spoke |
| Private interconnect to corpnet | Direct Connect | Cloud Interconnect (Dedicated/Partner) | ExpressRoute |
| VPN gateway | Site-to-Site VPN, Client VPN | Cloud VPN (HA VPN) | VPN Gateway |
| Private access to platform services | VPC endpoints (Gateway/Interface) | Private Google Access, PSC | Private Endpoints, Service Endpoints |
| Per-workload firewall | Security groups (per-ENI) | Firewall rules (per-instance tags) | NSGs (per-NIC/subnet) |
| Egress control | NAT Gateway, egress-only IGW | Cloud NAT, firewall egress rules | NAT Gateway, Azure Firewall |
| Network flow logging | VPC Flow Logs | VPC Flow Logs | NSG Flow Logs |

Key expectation: practitioners assume they can isolate projects from each other by
default, peer them with explicit action, connect to their corporate network via a
dedicated circuit, and control egress per workload. When a neocloud provides a flat
network with no isolation controls, the blast radius of a compromised workload is
every other workload in the account.

## API Tooling & Delegated Access

AI tools (MCP servers, agents, copilots) need API access with less privilege than the
human using them. On hyperscalers, the auth model already supports this through OAuth,
scoped tokens, and service accounts. This is the baseline that makes "paste your full
API key into the tool config" on a neocloud feel dangerous.

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| OAuth/OIDC for tool auth | Yes (Cognito, IAM Identity Center) | Yes (OAuth consent, Workload Identity) | Yes (Azure AD app registrations) |
| Read-only scoping | Yes (ReadOnlyAccess managed policy) | Yes (Viewer role) | Yes (Reader role) |
| User self-service scoped tokens | Yes (IAM user can create scoped sessions) | Yes (service account impersonation) | Yes (app registration + scoped consent) |
| Per-tool credential separation | Yes (separate IAM roles per tool) | Yes (separate service accounts) | Yes (separate managed identities) |
| Tool action auditability | Yes (CloudTrail shows assumed role / source) | Yes (audit logs show service account) | Yes (activity log shows app ID) |
| Short-lived tool tokens | STS (1-12hr) | OAuth access tokens (1hr) | Azure AD tokens (1hr) |

Key expectation: a user should be able to grant an AI tool scoped, short-lived,
auditable access without sharing their own credentials and without filing an IT ticket.
When a neocloud only offers long-lived full-access API keys, every tool gets admin-level
access and there's no way to distinguish tool actions from human actions in logs.

## Secrets & Key Management

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Secrets manager | Secrets Manager | Secret Manager | Key Vault |
| Automatic rotation | Yes (Lambda-based) | Yes (rotation policies) | Yes (auto-rotation) |
| Encryption at rest | KMS (customer or AWS-managed) | Cloud KMS | Key Vault + CMK |
| HSM-backed keys | CloudHSM | Cloud HSM | Dedicated HSM |
| Write-only secrets | Yes (IAM-gated read) | Yes (IAM-gated read) | Yes (access policies) |

## Control Plane

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| API protocol | REST | REST + gRPC | REST |
| Auth mechanism | SigV4 (signed headers) | OAuth 2.0 Bearer | OAuth 2.0 Bearer |
| Per-operation IAM | Yes (every API call is an IAM action) | Yes | Yes |
| Rate limiting | Yes (per-account, per-service) | Yes | Yes |
| No introspection | N/A (REST, no schema exposure) | N/A | N/A |
| Single control plane API | Yes (one REST API per service) | Yes | Yes |

## Credential Types

On hyperscalers, practitioners expect multiple credential types with clear separation
between control plane and data plane. This is the baseline that makes "API keys" on a
neocloud feel deceptively simple.

| Credential Type | AWS | GCP | Azure |
|----------------|-----|-----|-------|
| Management credentials | IAM user/role + SigV4 | Service account + OAuth | Azure AD + OAuth |
| Temporary credentials | STS AssumeRole (1-12hr) | Workload Identity (1hr) | Managed identity (auto) |
| Storage credentials | S3 presigned URLs, IAM | Signed URLs, IAM | SAS tokens, RBAC |
| Container registry | ECR token (12hr auto-refresh) | Artifact Registry IAM | ACR token + RBAC |
| SSH keys | EC2 key pairs (per-instance) | OS Login (per-project) | Azure AD SSH (per-VM) |
| Service-to-service | IAM roles, VPC endpoints | Service accounts, VPC-SC | Managed identity, PE |
| Serverless invocation | IAM auth, API Gateway keys | IAM, API Gateway | Azure AD, Function keys |

Key expectation: each credential type has its own lifecycle, scoping mechanism, and
transmission method. They are not interchangeable.

## Serverless Edge & Middleware

On hyperscalers, serverless functions never face the internet naked. There's always
a middleware layer that handles auth, rate limiting, and request validation before
a request reaches your code.

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| API Gateway | API Gateway (REST/HTTP/WebSocket) | API Gateway, Cloud Endpoints | API Management |
| Custom authorizers | Lambda authorizers | IAM, API key, JWT | Policy expressions, OAuth |
| WAF | AWS WAF (API Gateway integrated) | Cloud Armor | Azure WAF |
| DDoS protection | Shield (Standard free, Advanced paid) | Cloud Armor | DDoS Protection |
| Rate limiting | API Gateway throttling (per-key) | API Gateway quotas | APIM rate limiting |
| Request validation | API Gateway models/validators | OpenAPI validation | APIM policies |
| CDN / edge caching | CloudFront | Cloud CDN | Front Door |
| Edge observability | CloudWatch, X-Ray | Cloud Monitoring, Trace | Application Insights |
| Default endpoint visibility | Private (explicit public required) | Depends on service | Private by default |

Key expectation: practitioners assume they can put auth, rate limiting, and WAF in
front of any function without writing middleware code. When a neocloud provides none of
this, every handler needs its own auth implementation and there's no platform-level
abuse prevention.

## Hardware & Firmware

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Hardware ownership | AWS-owned data centers | Google-owned data centers | Microsoft-owned data centers |
| Firmware attestation | Nitro System, Nitro Enclaves | Titan chip, Shielded VMs | Azure Attestation, Cerberus |
| Secure boot | Yes (Nitro) | Yes (Shielded VMs) | Yes (Trusted Launch) |
| Maintenance windows | Documented, scheduled | Documented, live migration | Documented, scheduled |
| GPU firmware updates | AWS-managed, transparent | Google-managed | Microsoft-managed |

Key expectation: the provider owns the hardware and manages firmware with documented
update cadence. Practitioners don't think about firmware because someone else is
transparently handling it. On a neocloud with leased or partner-owned hardware, this
assumption breaks down silently.

## Confidential Computing

Distinct from firmware attestation above: that is the provider proving its own stack is
intact; this is the tenant running workloads the provider cannot read. Status as of
mid-2026 — these facts are volatile, re-verify them during the fact-check pass.

| Control | AWS | GCP | Azure |
|---------|-----|-----|-------|
| Confidential VMs (CPU TEE) | SEV-SNP only (M6a/C6a/R6a, two regions) | SEV / SEV-SNP / TDX across N2D, C2D–C4D, C3 | SEV-SNP (DCasv5/ECasv5), TDX (DCesv6/ECesv6) |
| Application enclaves | Nitro Enclaves (all regions) | Confidential Space | SGX (DCsv2/DCsv3), confidential containers (ACI) |
| GPU confidential computing | Announced (GB200 + Nitro Enclaves), not shipped | H100 on A3, single-GPU (TDX + NVIDIA CC mode) | H100 NVL (NCCadsH100v5, SEV-SNP), single-GPU |
| Tenant-verifiable attestation | KMS attestation-gated key release (enclave PCRs, NitroTPM) | Google Cloud Attestation (EAT tokens, OIDC/PKI) | Microsoft Azure Attestation (itself runs in a TEE) |

Key expectation: a confidential-computing option exists when a workload needs it, and
attestation can gate key release so the tenant — not the provider — decides whether the
environment is trustworthy. Note how narrow even the hyperscaler reality is: specific
SKUs in specific regions, and GPU confidential computing is single-GPU H100-only where
it ships at all. NVIDIA's own documentation confirms that on Hopper (H100/H200) the
PCIe path is encrypted but on-package HBM is protected by an access-control firewall,
not encryption at rest. So when any platform — hyperscaler or neocloud — says
"confidential computing," the probe is: which slice, on which hardware, protecting
exactly what, verifiable by whom.

## Corporate Structure & Geopolitical Baseline

On hyperscalers, the corporate structure and geopolitical questions are mostly settled.
They're publicly traded US companies (or in Microsoft's case, also operating Azure from
sovereign regions with distinct legal entities). Practitioners don't usually research
"who funds AWS" — the answer is obvious. On neoclouds, these questions are often
unanswered and the answers can materially affect your risk posture.

| Factor | AWS | GCP | Azure |
|--------|-----|-----|-------|
| Incorporation | US (Delaware) | US (Delaware) | US (Washington) |
| Public/private | Public (AMZN) | Public (GOOG) | Public (MSFT) |
| Data center locations | 30+ regions, documented | 35+ regions, documented | 60+ regions, documented |
| Data residency controls | Region selection, dedicated regions | Region selection, Assured Workloads | Region selection, sovereign clouds |
| Regulatory compliance programs | FedRAMP, HIPAA, PCI, SOC, ISO, etc. | FedRAMP, HIPAA, PCI, SOC, ISO, etc. | FedRAMP, HIPAA, PCI, SOC, ISO, etc. |
| Government data access transparency | Transparency reports, law enforcement guidelines | Transparency reports | Transparency reports |
| Financial stability | ~$80B+ annual cloud revenue | ~$30B+ annual cloud revenue | ~$60B+ annual cloud revenue |

Key expectation: practitioners assume they know who owns the infrastructure, which
government can compel data disclosure, where data physically resides, and that the
provider will exist next year. On a neocloud — especially one that's VC-funded,
incorporated in an unfamiliar jurisdiction, or running on partner-owned data centers in
multiple countries — none of these assumptions hold by default. Your organization needs
the facts to apply their own risk framework.

---

## What Practitioners Expect (the Mental Model)

When a security team trained on hyperscalers evaluates a new platform, they
instinctively look for:

1. A way to give someone read-only access to one resource
2. Credentials that expire automatically
3. An immutable log of who did what
4. Network-level isolation as a default
5. The ability to separate management from data plane access
6. Documented security controls with clear boundaries
7. Multiple distinct credential types with clear control/data plane separation
8. A middleware layer (gateway, WAF, authorizers) in front of serverless functions
9. Platform-managed hardware with attested firmware updates
10. Workload identity tokens that can federate to external services without secrets
11. VPC isolation between projects with explicit peering, and private interconnects to corpnet
12. Scoped, short-lived token delegation to AI tools without sharing full credentials
13. A known corporate structure, jurisdiction, and financial stability you don't have to research
14. A confidential-computing option (TEE-backed compute with tenant-verifiable attestation) available when a workload needs it

These expectations are so ingrained that their absence doesn't always register as a gap.
It registers as confusion — "I can't find the page where I set up resource-level
policies" — which gets rationalized as "maybe it's in a different section" rather than
"maybe it doesn't exist."

This is the ambiguous threat: the gap between what you expect and what exists, filled
with silence rather than documentation.
