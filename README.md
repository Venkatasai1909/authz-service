# Authentication & Authorization Service

A stateless, policy-based authorization microservice built with Java 21 and Spring Boot. It validates OAuth2 JWT tokens and evaluates fine-grained access control decisions using a custom Policy Engine with hierarchical resource matching and specificity-based conflict resolution.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Policy Engine Deep Dive](#policy-engine-deep-dive)
- [API Reference](#api-reference)
- [Permission Model](#permission-model)
- [Decision Flow](#decision-flow)
- [Setup & Run](#setup--run)
- [Sample Requests](#sample-requests)
- [Testing](#testing)
- [Assumptions & Trade-offs](#assumptions--trade-offs)
- [Future Improvements](#future-improvements)

---

## Overview

This service answers a single question: **is this user allowed to perform this action on this resource?**

It sits in front of downstream services as an authorization sidecar. Any service that receives a request can call `POST /authorize` with the user's access token, HTTP method, and target path. The service validates the token, resolves the user's permissions from a database, and returns an `ALLOW` or `DENY` decision with the matched rule and reason.

The design is intentionally decoupled: token validation, permission storage, and policy evaluation are independent components that can be replaced or extended independently.

---

## Features

- **JWT Validation** — verifies signature (RS256 via JWKS), expiry (`exp`), not-before (`nbf`), issuer (`iss`), and optional audience (`aud`)
- **Policy Engine** — evaluates permissions using exact, wildcard, and hierarchical resource matching
- **Specificity Scoring** — position-weighted scoring ensures the most specific rule always wins over broader wildcards
- **Deny Overrides** — when rules of equal specificity conflict, DENY always wins
- **Default Deny** — any request without a matching permission is denied; access must be explicitly granted
- **Caffeine Cache** — permission lookups are cached per `(userId, action)` and user identity lookups are cached per `externalUserId`, both with configurable TTL and size
- **Strategy Pattern** — authorization logic is pluggable; additional strategies (RBAC, ABAC) can be registered without modifying existing code
- **Structured Error Responses** — typed error codes and machine-readable error payloads for all failure modes
- **Input Validation** — all request fields validated via Bean Validation before processing

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                AuthorizationController               │
│                  POST /authorize                     │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│               AuthorizationServiceImpl               │
│  1. Authenticate token   2. Build AuthContext        │
│  3. Load permissions     4. Evaluate policy          │
└────┬──────────────────────────────────┬─────────────┘
     │                                  │
┌────▼────────────────┐    ┌────────────▼─────────────┐
│  JwtAuthenticator   │    │   AuthorizationManager   │
│                     │    │   (strategy dispatch)    │
│  TokenValidator     │    └────────────┬─────────────┘
│  NimbusJwtDecoder   │                 │
└─────────────────────┘    ┌────────────▼─────────────┐
                           │    PolicyEngineStrategy   │
                           └────────────┬─────────────┘
                                        │
┌───────────────────────────────────────▼─────────────┐
│                     PolicyEngine                     │
│                                                      │
│  Phase 1: ResourceMatcher  (match candidates)        │
│  Phase 2: SpecificityScorer (rank by specificity)   │
│  Phase 3: ConflictResolver  (deny overrides allow)  │
└───────────────────────────────────────┬─────────────┘
                                        │
┌───────────────────────────────────────▼─────────────┐
│              JdbcPermissionRepository                │
│              (Caffeine-cached, SQLite)               │
└─────────────────────────────────────────────────────┘
```

### Package Structure

```
src/main/java/com/venkatasai/auth/authz_service/
│
├── authentication/          # JWT decoding, signature verification, claim validation
│   ├── JwtDecoder.java
│   ├── NimbusJwtDecoderImpl.java
│   ├── TokenValidator.java
│   └── JwtAuthenticator.java
│
├── authorization/           # Strategy dispatch layer
│   ├── AuthorizationManager.java
│   ├── factory/
│   │   └── AuthorizationFactory.java
│   └── strategy/
│       ├── AuthorizationStrategy.java
│       └── PolicyEngineStrategy.java
│
├── config/                  # Spring configuration
│   ├── SecurityConfig.java
│   └── CacheConfig.java
│
├── controller/
│   └── AuthorizationController.java
│
├── dto/
│   ├── request/AuthorizationRequest.java
│   └── response/
│       ├── AuthorizationResponse.java
│       └── ErrorResponse.java
│
├── exception/
│   ├── AuthenticationException.java
│   ├── AuthorizationException.java
│   └── GlobalExceptionHandler.java
│
├── mapper/
│   └── AuthorizationMapper.java
│
├── model/                   # Shared domain types
│   ├── AuthContext.java
│   ├── AuthorizationResult.java
│   ├── AuthorizationType.java
│   ├── Decision.java
│   └── Permission.java
│
├── policy/                  # Self-contained policy evaluation engine
│   ├── engine/PolicyEngine.java
│   ├── matcher/
│   │   ├── ResourceMatcher.java
│   │   └── DefaultResourceMatcher.java
│   ├── model/
│   │   ├── ScoredPermission.java
│   │   └── PolicyEngineResult.java
│   ├── resolver/
│   │   ├── ConflictResolver.java
│   │   └── DenyOverridesResolver.java
│   └── scorer/
│       ├── Scorer.java
│       └── SpecificityScorer.java
│
├── repository/
│   ├── PermissionRepository.java
│   ├── UserRepository.java
│   └── impl/
│       ├── JdbcPermissionRepository.java
│       └── JdbcUserRepository.java
│
├── service/
│   ├── AuthorizationService.java
│   └── impl/AuthorizationServiceImpl.java
│
└── util/PathUtils.java
```

### Layering Rules

| Layer | Depends on | Must not depend on |
|---|---|---|
| `controller` | `service` interface, DTOs | `policy`, `repository`, `authentication` |
| `service` | `authentication`, `authorization`, `repository`, `mapper` | `controller` |
| `authorization` | `policy`, `model` | `service`, `controller`, `repository` |
| `policy` | `model` | everything above |
| `repository` | `model` | everything above |

---

## Policy Engine Deep Dive

The `PolicyEngine` is a pure, stateless component with no Spring dependencies in its core logic. It runs three sequential phases on every evaluation.

### Phase 1 — Resource Matching

`ResourceMatcher` implements three distinct matching semantics:

| Pattern type | Example | Matches |
|---|---|---|
| Exact | `wallets/wallet-789` | Only `wallets/wallet-789` — not children |
| Non-terminal wildcard | `wallets/*/transactions` | One segment in middle, literal suffix required |
| Terminal wildcard | `wallets/*` | `wallets/wallet-789`, `wallets/wallet-789/transactions`, any depth beneath |
| Global wildcard | `*` | Any path at any depth |

**Critical distinction:** a plain exact-match rule does not grant access to child resources. Only a terminal wildcard does. This makes it possible to write `wallets/wallet-789` (write) + `wallets/wallet-789` (deny-at-child) independently.

### Phase 2 — Specificity Scoring

After matching, every candidate rule is scored. The scoring formula is position-weighted to ensure rules that match earlier segments more precisely score higher:

```
Let totalSegments = number of segments in the resource pattern.
For segment at 0-based resourceIndex:
  weight      = totalSegments - resourceIndex   (leftmost segment has highest weight)
  exact match : segment score = weight × 2
  wildcard    : segment score = weight × 1

Special case: global "*" → fixed score of 1 (lowest possible)
```

**Worked example** — evaluating path `wallets/w1/transactions` (totalSegments=3, weights: 3, 2, 1):

| Pattern | Scoring | Total |
|---|---|---|
| `wallets/w1/transactions` | 3×2 + 2×2 + 1×2 | **12** |
| `wallets/w1/*` | 3×2 + 2×2 + 1×1 | **11** |
| `wallets/*/transactions` | 3×2 + 2×1 + 1×2 | **10** |
| `wallets/*` | 2×2 + 1×1 | **5** |
| `*` | — | **1** |

The most specific rule always wins regardless of its effect (ALLOW or DENY). This means an explicit ALLOW at score 12 overrides a global DENY at score 1, and vice versa.

### Phase 3 — Conflict Resolution

If two rules share the top score (a genuine tie), `DenyOverridesResolver` is applied: any DENY in the tied set produces a final DENY decision. This is the safest default for a security control.

### Default Deny

If no permission matches the request path, the engine returns `DENY` with no matched permission. Access is never implicitly granted.

---

## API Reference

### `POST /authorize`

Evaluates whether the token holder is permitted to perform the given action on the given resource.

**Request**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "method": "GET",
  "path": "/wallets/wallet-789/transactions"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `access_token` | string | yes | Bearer JWT issued by configured IdP |
| `method` | string | yes | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `path` | string | yes | Resource path; leading slash is normalized |

**HTTP method → action mapping**

| HTTP method | Action stored in DB |
|---|---|
| `GET` | `read` |
| `POST`, `PUT`, `PATCH` | `write` |
| `DELETE` | `delete` |

**Response — ALLOW**

```json
{
  "decision": "ALLOW",
  "user_id": "user456",
  "reason": "Access granted by rule: read on wallets/wallet-789/transactions",
  "matched_permissions": [
    {
      "action": "read",
      "resource": "wallets/wallet-789/transactions",
      "effect": "allow"
    }
  ]
}
```

**Response — DENY (explicit rule)**

```json
{
  "decision": "DENY",
  "user_id": "user123",
  "reason": "Access denied by rule: delete on transactions",
  "matched_permissions": [
    {
      "action": "delete",
      "resource": "transactions",
      "effect": "deny"
    }
  ]
}
```

**Response — DENY (default, no match)**

```json
{
  "decision": "DENY",
  "user_id": "user456",
  "reason": "No matching permission found; default deny applied",
  "matched_permissions": []
}
```

**Error responses**

| Scenario | HTTP status | Error code |
|---|---|---|
| Invalid / expired / tampered token | `401 Unauthorized` | `AUTH_001` |
| Authorization processing failure | `403 Forbidden` | `AUTHZ_001` |
| Missing or blank request fields | `400 Bad Request` | `REQ_001` |
| Unsupported HTTP method | `400 Bad Request` | `REQ_001` |
| Internal server error | `500 Internal Server Error` | `GEN_001` |

**Error response shape**

```json
{
  "code": "AUTH_001",
  "message": "Token has expired",
  "timestamp": "2025-01-15T10:30:00Z",
  "path": "/authorize"
}
```

---

## Permission Model

### Database Schema

```sql
CREATE TABLE user_permissions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  TEXT NOT NULL,
    action   TEXT NOT NULL,     -- 'read' | 'write' | 'delete'
    resource TEXT NOT NULL,     -- resource pattern (supports wildcards)
    effect   TEXT NOT NULL,     -- 'allow' | 'deny'
    UNIQUE(user_id, action, resource)
);

-- Maps an external IdP user ID (e.g. Clerk's sub claim) to the internal user_id
-- used in user_permissions. This keeps the permission schema IdP-agnostic.
CREATE TABLE users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          TEXT NOT NULL,     -- internal user ID (used in user_permissions)
    external_user_id TEXT NOT NULL,     -- IdP user ID extracted from JWT 'sub' claim
    UNIQUE(external_user_id)
);

CREATE INDEX idx_user_id_action      ON user_permissions(user_id, action);
CREATE INDEX idx_user_id_ext_user_id ON users(external_user_id);
```

The index on `(user_id, action)` matches the exact query issued at authorization time, so no full-table scan occurs even with large permission sets. The index on `external_user_id` makes the user-mapping lookup a single key scan.

### Seeded Test Users

#### Permissions (`user_permissions`)

| User | Action | Resource | Effect |
|---|---|---|---|
| `user123` | read | `transactions` | allow |
| `user123` | write | `transactions` | allow |
| `user123` | delete | `transactions` | **deny** |
| `user123` | read | `accounts` | allow |
| `user456` | read | `wallets/*` | allow |
| `user456` | write | `wallets/wallet-789` | allow |
| `user456` | read | `wallets/wallet-789/transactions` | allow |
| `user789` | write | `wallets/*/transactions/*` | allow |
| `admin789` | read / write / delete | `*` | allow |

#### Identity Mapping (`users`)

This project uses **[Clerk](https://clerk.com)** to issue JWTs for local testing. Clerk's `sub` claim contains a Clerk-specific user ID. The `users` table maps each Clerk ID to an internal user ID:

| Internal user ID | Clerk external user ID |
|---|---|
| `user123` | `user_3DJ8wQ65vmgaH5SogzTltSPhQZF` |
| `user456` | `user_3DJ90IUzAhSJWgsuPGSJOe9L59T` |
| `user789` | `user_3DJ938xEXC9cxJE5diLDaX9rWdN` |
| `admin789` | `user_3DJ95erzmggthgHoQhayVoxfGCw` |

> **Using a different IdP?** The `external_user_id` column stores whatever value your IdP puts in the JWT `sub` claim. To switch providers, simply update the `users` rows to match the `sub` values your IdP issues — no code or permission changes required.

### Resource Pattern Reference

| Pattern | Matches |
|---|---|
| `transactions` | Exactly `/transactions` |
| `wallets/*` | `/wallets/<any>` and all sub-paths beneath it |
| `wallets/wallet-789` | Exactly `/wallets/wallet-789` only |
| `wallets/*/transactions` | `/wallets/<any>/transactions` — literal suffix required |
| `wallets/*/transactions/*` | `/wallets/<any>/transactions/<any>` and below |
| `*` | Every path at every depth |

---

## Decision Flow

```
POST /authorize
      │
      ▼
1. INPUT VALIDATION
   • Reject blank access_token / method / path → 400

      │
      ▼
2. TOKEN VALIDATION  (TokenValidator + NimbusJwtDecoder)
   • Decode JWT, verify RS256 signature against JWKS endpoint
   • Check exp (must be in future)
   • Check nbf (if present, must not be in future)
   • Check iss (must equal jwt.issuer config)
   • Check aud (if jwt.audience configured, must be present in token)
   → Failure: AuthenticationException → 401

      │
      ▼
3. IDENTITY EXTRACTION  (JwtAuthenticator)
   • Extract sub claim → externalUserId (e.g. Clerk user ID)
   • Extract email claim (optional)
   → Build UserPrincipal { externalUserId }

      │
      ▼
4. USER MAPPING  (UserRepository)
   • SELECT user_id FROM users WHERE external_user_id = ?
   • Resolves Clerk (or any IdP) sub → internal user_id
   → Failure (no mapping): AuthenticationException → 401

      │
      ▼
5. CONTEXT BUILDING  (AuthorizationMapper)
   • Map HTTP method → action (GET→read, POST→write, etc.)
   • Normalize path (strip leading/trailing slashes)
   → Build AuthContext { userId (internal), action, path }

      │
      ▼
6. PERMISSION LOAD  (JdbcPermissionRepository)
   • SELECT WHERE user_id = ? AND action = ?
   • Result served from Caffeine cache if warm
   → List<Permission>

      │
      ▼
7. POLICY EVALUATION  (PolicyEngine)
   │
   ├── Phase 1: ResourceMatcher
   │   Filter permissions whose resource pattern matches the request path.
   │   Empty match set → default DENY immediately.
   │
   ├── Phase 2: SpecificityScorer
   │   Score each matched permission using position-weighted formula.
   │   Identify the top score.
   │
   ├── Phase 3: Winner selection
   │   Single top-scored rule → its effect is the decision.
   │
   └── Phase 4: ConflictResolver (tie only)
       Multiple rules share top score → DenyOverridesResolver:
       any DENY in the tied set → final DENY.

      │
      ▼
8. RESPONSE
   • decision: ALLOW | DENY
   • reason: human-readable explanation
   • matched_permissions: the winning rule (empty on default deny)
```

---

## Setup & Run

### Prerequisites

| Tool | Version |
|---|---|
| Java | 21+ |
| Maven | 3.9+ |

An internet-accessible OAuth2 / OIDC provider is required for JWT signature verification (JWKS endpoint). This project is configured for **Clerk** — set `JWT_JWKS_URI` to your Clerk instance's JWKS URL and `JWT_ISSUER` to your Clerk issuer. If you are using a different IdP, point these variables at that provider's endpoints instead and update the `users` table rows to match the `sub` values it issues.

### Configuration

Copy and set environment variables (or override in `application.yml`):

```bash
export JWT_JWKS_URI=https://your-idp/.well-known/jwks.json
export JWT_ISSUER=https://your-idp
export JWT_AUDIENCE=authz-service      # optional; leave unset to skip audience check
export JWT_ALGORITHM=RS256             # optional; default RS256
```

### Run the application

```bash
./mvnw spring-boot:run
```

The service starts on port `8080`. On first run, `authz.db` is created in the working directory and the schema + seed data are applied automatically.

```bash
# Verify it is up
curl -s http://localhost:8080/actuator/health | jq .
```

### Run tests

```bash
# All tests
./mvnw test

# Specific test class
./mvnw test -Dtest=PolicyEngineTest

# With verbose output
./mvnw test -Dtest=PolicyEngineTest -pl . --no-transfer-progress
```

---

## Sample Requests

### ALLOW — user reads an explicitly permitted resource

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "<user123-jwt>",
    "method": "GET",
    "path": "/transactions"
  }' | jq .
```

```json
{
  "decision": "ALLOW",
  "user_id": "user123",
  "reason": "Access granted by rule: read on transactions",
  "matched_permissions": [
    { "action": "read", "resource": "transactions", "effect": "allow" }
  ]
}
```

---

### DENY — explicit deny rule overrides

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "<user123-jwt>",
    "method": "DELETE",
    "path": "/transactions"
  }' | jq .
```

```json
{
  "decision": "DENY",
  "user_id": "user123",
  "reason": "Access denied by rule: delete on transactions",
  "matched_permissions": [
    { "action": "delete", "resource": "transactions", "effect": "deny" }
  ]
}
```

---

### ALLOW — terminal wildcard grants access to nested path

`user456` has `read` on `wallets/*`. The terminal wildcard inherits to all sub-paths.

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "<user456-jwt>",
    "method": "GET",
    "path": "/wallets/wallet-789/transactions"
  }' | jq .
```

```json
{
  "decision": "ALLOW",
  "user_id": "user456",
  "reason": "Access granted by rule: read on wallets/*",
  "matched_permissions": [
    { "action": "read", "resource": "wallets/*", "effect": "allow" }
  ]
}
```

---

### DENY — exact rule does NOT cover child resources

`user456` has `write` on `wallets/wallet-789` (exact). Writing to `wallets/wallet-789/transactions` (a child) is denied because exact rules have no inheritance.

```bash
curl -s -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "<user456-jwt>",
    "method": "POST",
    "path": "/wallets/wallet-789/transactions"
  }' | jq .
```

```json
{
  "decision": "DENY",
  "user_id": "user456",
  "reason": "No matching permission found; default deny applied",
  "matched_permissions": []
}
```

---

### ALLOW — specificity overrides broader deny

Specific ALLOW at score 12 beats global DENY at score 1.

```bash
# admin789 has global allow (*). Imagine a scenario:
# deny(delete, *) score=1  vs  allow(delete, wallets/wallet-789) score=6
# → specific allow wins
curl -s -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "<admin789-jwt>",
    "method": "DELETE",
    "path": "/accounts/acc-123/settings"
  }' | jq .
```

```json
{
  "decision": "ALLOW",
  "user_id": "admin789",
  "reason": "Access granted by rule: delete on *",
  "matched_permissions": [
    { "action": "delete", "resource": "*", "effect": "allow" }
  ]
}
```

---

## Testing

### Test coverage summary

| Test class | What it covers |
|---|---|
| `PolicyEngineTest` | Full engine: default deny, terminal wildcard inheritance, specificity ranking, deny-overrides, conflicting overlapping wildcards, edge cases |
| `DefaultResourceMatcherTest` | All matching semantics: exact, non-terminal wildcard, terminal wildcard, global wildcard, boundary conditions |
| `SpecificityScorerTest` | Position-weighted scoring: score ordering, tie detection, global wildcard baseline |
| `TokenValidatorTest` | JWT claim validation: expiry, nbf, issuer, audience, optional audience skip |
| `AuthorizationServiceImplTest` | End-to-end service with real PolicyEngine; mocked JWT provider, Users table mapping, and DB layer |
| `PermissionCacheTest` | Caffeine cache behaviour for permission lookups: cache hit, cache miss, key isolation, repeated calls |
| `UserCacheTest` | Caffeine cache behaviour for user identity lookups: cache hit, cache miss, empty-result caching, composite key isolation |
| `PathUtilsTest` | HTTP method mapping, path normalization |

### Key edge cases tested

- `wallets/*` matches `wallets/wallet-789/transactions` (terminal wildcard inheritance — regression from original segment-count check)
- `wallets/wallet-789` does NOT match `wallets/wallet-789/transactions` (exact has no child inheritance)
- Specific ALLOW at score 12 overrides broad DENY at score 1
- Specific DENY at score 12 overrides broad ALLOW at score 5
- Tied rules at the same score → deny-overrides-allow resolver fires
- Valid token whose `sub` has no matching row in the `users` table → `AuthenticationException`
- Token with missing `sub` claim → `AuthenticationException`
- Token with `nbf` in the past → accepted; `nbf` in the future → rejected
- Unsupported HTTP method → `IllegalArgumentException` → 400

### Run with coverage

```bash
./mvnw test jacoco:report
# Report: target/site/jacoco/index.html
```

---

## Assumptions & Trade-offs

### Permissions are user-scoped only

The current model is `(user_id, action, resource)`. There is no concept of roles or groups. Assigning permissions to a role and resolving group membership is a common extension but was out of scope; the strategy pattern in the `authorization` layer makes it a natural addition.

### Action is derived from HTTP method, not stored

HTTP methods are mapped to semantic actions (`read`, `write`, `delete`) at request time rather than storing HTTP verbs in the DB. This keeps the permission store HTTP-agnostic: a gRPC call for the same resource would map to the same action without schema changes.

### SQLite for storage

SQLite is used for simplicity and zero-dependency local operation. The repository is behind a `PermissionRepository` interface; swapping to PostgreSQL or MySQL requires only a new `JdbcPermissionRepository` implementation and a JDBC URL change — no service-layer code changes.

### Permissions and user mappings are cached, not real-time

The Caffeine cache holds two entry types:
- `(userId, action)` → `List<Permission>` — permission lookups
- `externalUserId` → `Optional<User>` — IdP-to-internal identity mappings

Both share the same `users` and `permissions` caches with a configurable TTL (default 5 minutes). A permission revocation or user mapping change takes effect within one TTL window. This is an explicit trade-off: lower DB load at the cost of eventual consistency on revocations.

### Token validation is self-contained

This service validates JWTs directly (JWKS fetch, claim checking) rather than delegating to an introspection endpoint. This is faster and avoids a network hop per request, but means revoked tokens remain valid until they expire. For use cases requiring immediate revocation, token introspection or a short token lifetime should be used.

### One matched permission returned

The response includes the single winning permission (the most specific match). In cases of a default deny, `matched_permissions` is empty. Only the deciding rule is returned, not the full candidate list.

---

## Future Improvements

### Role-based and group-based permissions

Add a `roles` table and a `user_roles` join. Expand the `PermissionRepository` to resolve permissions by `(userId + all user roles)` in a single query. The `AuthorizationStrategy` interface and factory already support registering a new `RbacStrategy` without touching existing code.

### Permission administration API

A `CRUD /permissions` API to manage rules at runtime without direct DB access. Combined with cache eviction endpoints (`DELETE /cache/permissions/{userId}`), this would make the service operationally complete.

### Audit logging

Emit a structured audit event (to a log aggregator or message queue) for every authorization decision containing `userId`, `action`, `path`, `decision`, `matched_rule`, and `timestamp`. Essential for security compliance.

### Multi-tenant support

Add a `tenant_id` column to `user_permissions` and include it in all queries and the cache key. The matching and scoring logic is tenant-agnostic and requires no changes.

### Performance at scale

For large permission sets per user, move resource matching from the application layer into the DB using pattern-indexed columns, or use a purpose-built policy store (e.g., OPA, Casbin). The `PolicyEngine` interface boundary makes this substitution straightforward.

### Token introspection mode

Add an alternative `JwtDecoder` implementation that calls an IdP introspection endpoint instead of validating the JWT locally. This enables real-time revocation checking at the cost of latency. The `AuthorizationFactory` pattern would allow selecting the validation strategy per request or per configuration.

---

## Tech Stack

| Component | Technology |
|---|---|
| Runtime | Java 21 |
| Framework | Spring Boot 3.2.5 |
| JWT library | Nimbus JOSE + JWT (via `spring-security-oauth2-resource-server`) |
| Database | SQLite (via `sqlite-jdbc`) |
| DB access | Spring JDBC (`JdbcTemplate`) |
| Cache | Caffeine (via `spring-boot-starter-cache`) |
| Validation | Jakarta Bean Validation |
| Boilerplate | Lombok |
| Testing | JUnit 5, Mockito, AssertJ |
| Build | Maven |