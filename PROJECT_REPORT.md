# Unified Cloud Security Findings Dashboard

**Multi-cloud security posture aggregator secured with Microsoft Entra ID SSO.**
Pulls live findings from **AWS Security Hub** and **Microsoft Defender for Cloud**, normalizes them into a single schema, and renders persona-specific charts + tables for executives, SecOps, auditors, engineers, and remediation teams.

---

## 1. Overview

| | |
|---|---|
| **Type** | Reactive Java web application |
| **Auth** | Microsoft Entra ID (Azure AD) — OAuth 2.0 / OIDC Authorization Code |
| **Providers** | AWS Security Hub, Microsoft Defender for Cloud |
| **UI** | Server-rendered Thymeleaf + Chart.js 4 |
| **Runtime** | JDK 21, Spring Boot 3.5.6 on Netty (WebFlux) |
| **Build** | Gradle 8, Spring Boot Gradle plugin |

### Problem

Security teams working across AWS and Azure juggle two consoles, two data models, and two severity taxonomies. SecOps analysts lose time context-switching; executives lack a unified risk view.

### Solution

A single Entra-authenticated portal where an operator can paste AWS / Azure credentials, pull live findings from each provider on demand, and see one normalized view — with charts and tables tuned for different stakeholders.

---

## 2. Architecture

```
                           ┌──────────────────────────┐
                           │   Microsoft Entra ID     │
                           │  (OIDC Authorization)    │
                           └─────────────┬────────────┘
                                         │
                       Auth Code /Refresh│Token
                                         ▼
┌──────────┐   HTTPS    ┌────────────────────────────────┐   SDK/REST    ┌───────────────────────┐
│ Browser  │ ─────────▶ │  Spring Boot 3.5 / WebFlux     │ ────────────▶ │ AWS Security Hub      │
│ (Thyme + │            │  (Netty, Reactive)             │               │   (GetFindings, SDK)  │
│ Chart.js)│ ◀───────── │                                │ ◀──────────── │                       │
└──────────┘   HTML/JSON│  • HomeController (routes)     │   findings[]  └───────────────────────┘
                        │  • AuthController (/api/auth)  │
                        │  • SecurityHubController       │               ┌───────────────────────┐
                        │  • DefenderController          │  Bearer/REST  │ Microsoft Defender    │
                        │  • SecurityConfig (OIDC)       │ ────────────▶ │   for Cloud (Azure    │
                        │                                │               │   Resource Manager)   │
                        │  Normalizers + Aggregators     │ ◀──────────── │                       │
                        └────────────────────────────────┘   alerts[]    └───────────────────────┘
```

Key design choice: **every HTTP path from browser → provider is non-blocking.** Reactive WebClient calls Entra + Azure ARM; AWS SDK v2 calls are wrapped in `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())` so the Netty event loop never blocks on an AWS response.

---

## 3. Tech stack

| Layer | Choice | Why |
|---|---|---|
| JVM | Java 21 | Records, pattern-matching `instanceof`, virtual-thread ready |
| Framework | Spring Boot 3.5.6 (WebFlux) | Reactive HTTP; matches external-API-heavy workload |
| Security | Spring Security 6 OAuth2 Client | First-class OIDC support for Entra |
| Templating | Thymeleaf 3 (reactive) | Simple server-rendered pages; Model-driven |
| UI charting | Chart.js 4.4 (CDN) | Zero-build, lightweight, enough for dashboards |
| AWS | AWS SDK v2 `securityhub` (BOM 2.27.21) | Official, active, supports pagination & sort criteria |
| Azure | Reactive `WebClient` | No heavyweight Azure SDK needed for REST + OAuth |
| Build | Gradle 8 | Spring Boot plugin, dependency-management |
| Persistence | Spring Data JPA + MySQL (wired, reserved for RBAC) | Ready for role/audit tables in next phase |

---

## 4. Authentication

### 4.1 End-user login (Entra ID)

- `spring-boot-starter-oauth2-client` with a single registration named `azure`
- Issuer: `https://login.microsoftonline.com/{tenantId}/v2.0`
- Scopes: `openid, profile, email`
- Flow: **Authorization Code with PKCE** (Spring Security default for confidential web clients)
- Redirect URI: `http://localhost:8000/login/oauth2/code/azure` (configurable)

Post-login success handler is wired to redirect users to `/dashboard`:

```java
RedirectServerAuthenticationSuccessHandler loginSuccess =
        new RedirectServerAuthenticationSuccessHandler("/dashboard");
```

### 4.2 Logout (OIDC front-channel)

The app uses `OidcClientInitiatedServerLogoutSuccessHandler` so `/logout` does more than kill the local session — it also calls Entra's end-session endpoint, which lets Entra clear its SSO cookie. After Entra is done, the browser is sent back to `/login?logout=success`, which shows a toast.

```java
handler.setPostLogoutRedirectUri("{baseUrl}/login?logout=success");
```

Note: the exact post-logout URI must be registered under **Front-channel logout URL** in the Entra app registration, otherwise Entra ends the session but does not redirect back.

### 4.3 Server-to-cloud auth

- **AWS**: operator pastes access key / secret (optionally session token) into the browser; server wraps them in `StaticCredentialsProvider.create(AwsBasicCredentials | AwsSessionCredentials)` — **never persisted**.
- **Azure**: operator pastes Service Principal (`tenantId`, `clientId`, `clientSecret`) + `subscriptionId`. Server executes **OAuth 2.0 Client Credentials grant** against `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with scope `https://management.azure.com/.default`, receives an ARM access token, attaches it as `Authorization: Bearer ...` on the ARM call.

---

## 5. Route map

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/` | Redirects — `/dashboard` if authenticated, else `/login` |
| `GET` | `/login` | Renders `login.html`; shows logout toast when `?logout=success`; already-authed users get redirected to `/dashboard` |
| `GET` | `/dashboard` | Renders `dashboard.html` (banner + Entra name/email + provider tabs + shared results area) |
| `GET` | `/oauth2/authorization/azure` | Spring Security's OAuth2 entry point (triggered by the Sign-in button) |
| `POST` | `/logout` | Kills session → Entra end-session → `/login?logout=success` |
| `GET` | `/api/auth/status` | Public. `{authenticated, user}` or `{authenticated:false, loginUrl}` |
| `GET` | `/api/auth/me` | Authed. Full OIDC user + claims |
| `GET` | `/api/roles` | Authed. `roles` claim from ID token |
| `GET` | `/api/groups` | Authed. `groups` claim from ID token |
| `GET` | `/api/group-names` | Authed. Calls Microsoft Graph `/me/memberOf` with the registered client's access token |
| `POST` | `/api/securityhub/findings` | Authed. `{accessKey, secretKey, sessionToken?, region?, maxResults?}` |
| `POST` | `/api/defender/alerts` | Authed. `{tenantId, clientId, clientSecret, subscriptionId, maxResults?}` |

---

## 6. Provider integrations

### 6.1 AWS Security Hub

- Client: `SecurityHubClient.builder().region(...).credentialsProvider(...).build()`
- Call: `GetFindings` without filters → returns every finding in the account, severity-sorted by default
- **Pagination**: loop on `response.nextToken()`, accumulate up to `maxResults` (capped at **1000**), with a 20-page safety stop
- Returns per-finding fields: `id, title, description, severity, severityNormalized, productName, companyName, awsAccountId, region, createdAt, updatedAt, workflowStatus, recordState, complianceStatus, resources[], types[], remediation`
- Aggregates: `severityCounts, workflowStatusCounts, complianceStatusCounts, recordStateCounts, productCounts, resourceTypeCounts, topResources, ageBuckets`

Why paginate here? AWS caps a single response at ≤100 findings. In testing, accounts with >100 active findings were showing only one page — classic "forgot the cursor" bug.

### 6.2 Microsoft Defender for Cloud

- Token: POST `x-www-form-urlencoded` to `https://login.microsoftonline.com/{tid}/oauth2/v2.0/token` with `grant_type=client_credentials`
- Data: GET `https://management.azure.com/subscriptions/{sid}/providers/Microsoft.Security/alerts?api-version=2022-01-01`
- **Pagination**: follow `nextLink` until empty; same cap + safety stop as AWS
- Required role on the Service Principal: **Security Reader** (or higher) scoped to the subscription
- Normalization work: flatten the nested `properties.*` structure, map `severity` (`Low/Medium/High/Informational` → uppercase), map `status` (`Active → NEW`, `Dismissed → SUPPRESSED`, `Resolved → RESOLVED`) so the same charts/tables render without branching
- Resources are built from `resourceIdentifiers[].azureResourceId` (falling back to `compromisedEntity`)
- `remediation.text` is joined from the `remediationSteps[]` array

### 6.3 Normalized finding schema

Every finding, regardless of provider, has at minimum:

```json
{
  "id": "...",
  "title": "...",
  "description": "...",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL",
  "severityNormalized": 0-100,
  "productName": "...",
  "awsAccountId": "..." | null,
  "subscriptionId": "..." | null,
  "region": "...",
  "createdAt": "ISO-8601",
  "updatedAt": "ISO-8601",
  "workflowStatus": "NEW | NOTIFIED | RESOLVED | SUPPRESSED | ...",
  "complianceStatus": "PASSED | FAILED | WARNING | ..." | null,
  "resources": [{ "id": "...", "type": "...", "region": "...", "partition": "..." }],
  "types": ["..."],
  "remediation": { "text": "...", "url": "..." }
}
```

Because both controllers emit this shape, the frontend renderers (`renderCharts`, `renderTopResources`, `renderAgeTable`, `renderFindings`) work unchanged across providers.

---

## 7. UI & personas

The dashboard renders five distinct content blocks, each designed for a specific persona:

| Block | Persona | What they see |
|---|---|---|
| KPI tiles (Total + per-severity) | Everyone / CISO | Headline risk numbers |
| Severity doughnut | CISO / executive | Where risk is concentrated |
| Workflow Status bar | SecOps lead | Triage pipeline health |
| Compliance pie | Auditor | Pass vs. fail posture |
| Findings-by-Product horizontal bar | Platform team | Which upstream product is surfacing issues |
| Findings-by-Resource-Type horizontal bar | Cloud engineer | What kind of resources are affected |
| Age-of-Findings bar | Remediation team | How stale the backlog is |
| Top Affected Resources table | Cloud engineer | Top 10 resources with per-severity breakdown |
| Age Buckets table | Remediation team | Counts + share with inline bar |
| Findings list + filter bar | Analyst | Full triage view, live search + severity filter |

Shared via a **provider tab bar** above the forms: switching tabs keeps the dashboard renderers intact but resets the result state and retitles the header (e.g. "AWS Security Hub · Findings Dashboard" ↔ "Microsoft Defender for Cloud · Findings Dashboard").

---

## 8. Security considerations

| Concern | Mitigation |
|---|---|
| OIDC state / replay | Handled by Spring Security OAuth2 client (state param + nonce) |
| Cleartext cloud credentials in transit | App must be fronted by HTTPS in any non-local environment; long-lived AWS keys are discouraged in favor of STS session creds |
| Cloud credentials at rest | Never persisted; held only in the request payload and in-memory for the single API call |
| Session fixation / CSRF | CSRF disabled globally (all mutating endpoints are JSON behind session auth with SameSite cookies); acceptable for the internal-tool threat model, but for a public deployment re-enable CSRF and include the token in the logout form + JSON clients |
| Privilege minimization | Docs recommend AWS IAM policy with only `securityhub:GetFindings` and Azure `Security Reader` on the subscription |
| Token scope on user-level | Entra scopes restricted to `openid, profile, email` — no Graph write scopes |
| Error disclosure | AWS + Azure SDK errors surface as structured `{error}` responses with status codes, not stack traces |

---

## 9. Configuration

`src/main/resources/application.properties`:

```properties
# Entra ID
spring.security.oauth2.client.registration.azure.client-id=...
spring.security.oauth2.client.registration.azure.client-secret=...
spring.security.oauth2.client.registration.azure.scope=openid,profile,email
spring.security.oauth2.client.provider.azure.issuer-uri=https://login.microsoftonline.com/{tenantId}/v2.0

# HTTP
server.port=8000

# MySQL (reserved for RBAC phase)
spring.datasource.url=jdbc:mysql://.../...
spring.datasource.username=...
spring.datasource.password=...
spring.jpa.hibernate.ddl-auto=update
```

Entra app registration needs:

- **Redirect URI (Web)**: `http://localhost:8000/login/oauth2/code/azure`
- **Front-channel logout URL**: `http://localhost:8000/login?logout=success`
- Optional token claims: `groups`, `roles` — enabled via "Token configuration"

---

## 10. How to run (dev)

```bash
# 1. Start the app (JDK 21 must be on PATH)
./gradlew bootRun

# 2. Visit the portal
open http://localhost:8000/         # redirects to /login

# 3. Sign in with your Entra account → lands on /dashboard

# 4. Paste creds per provider, click Go, watch charts render
```

AWS cred prep: IAM user or role with `securityhub:GetFindings`; Security Hub must be enabled in the chosen region.

Azure cred prep:
```bash
az ad sp create-for-rbac --role "Security Reader" --scopes /subscriptions/<sub>
# returns tenant, appId, password → paste into Azure tab
```

---

## 11. Source tree

```
src/main/java/tech/exora/apiGateway/
  Main.java                              # SpringApplication bootstrap
  config/SecurityConfig.java             # OAuth2 client + OIDC logout + route auth
  controller/HomeController.java         # /, /login, /dashboard routes
  controller/AuthController.java         # /api/auth/* + /api/roles + /api/groups + Graph call
  controller/SecurityHubController.java  # /api/securityhub/findings — AWS SDK v2
  controller/DefenderController.java     # /api/defender/alerts — Azure ARM REST

src/main/resources/
  application.properties                 # Entra + DB config
  templates/login.html                   # Public login page with feature grid
  templates/dashboard.html               # Authenticated dashboard shell
  static/css/app.css                     # Fluent-style palette, tabs, charts, tables
  static/js/dashboard.js                 # Chart.js bootstrap, filters, tab switcher
```

---

## 12. Roadmap (worth queuing)

- **Multi-region fan-out** — run AWS Security Hub queries across a selected region set in parallel and merge results
- **Defender recommendations** — union `Microsoft.Security/assessments` into the Azure payload for full posture coverage
- **Secure Score** card for Azure and Security Hub Summary for AWS
- **STS AssumeRole** flow so ops users enter an ARN + MFA instead of long-lived keys
- **"Load more" pagination** driven by server-persisted `nextToken` / `nextLink` cursors
- **CSV / JSON export** of the current filtered finding set
- **Role-based page guards** using the Entra `roles` claim (`@PreAuthorize("hasRole('SecurityAnalyst')")`) backed by the wired-but-unused MySQL JPA layer
- **Trend panel** — persist daily snapshots to MySQL and chart severity counts over time
- **Dark mode** — tokenized color variables are already in CSS; flip `--bg-*` and `--surface` on a `[data-theme="dark"]` root

---

## 13. Learnings

- Spring Security's reactive OAuth2 stack is terse once you understand the split between `ServerHttpSecurity`, the success/failure handlers, and the OIDC client-initiated logout handler — but that third one is easy to miss and is the difference between "app logout" and "SSO logout."
- AWS SDK v2 is excellent for reactive apps *if* you accept that its own API is still synchronous; wrapping in `Mono.fromCallable` with `Schedulers.boundedElastic()` is the cleanest bridge.
- **Normalize at the edge, not in the UI**. Keeping the frontend free of provider-specific branching was the single best design call — charts, tables, and filters all work across AWS and Azure because the two controllers emit the same JSON shape.
- Always paginate. The "only one finding" bug looked like an AWS problem but was a missing `NextToken` loop — and the same shape of bug appears when consuming Azure ARM's `nextLink`.

---